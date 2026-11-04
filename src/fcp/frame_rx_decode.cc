// FrameRx, RS decoding half (design doc §6, 协议规格.md §4.5).
//
// Split out of frame_rx.cc so the anchor/tombstone state machine there reads as
// routing, and this file reads as "can this set be decoded, and is whatever RS
// handed back structurally sound". Errata A9 (geometry guard) and A23 (retry on
// a bad reconstruction) both live here.

#include <algorithm>
#include <cstring>
#include <vector>

#include "fcp/frame_rx.h"
#include "fcp/rs.h"

namespace fcp {

void FrameRx::try_decode(RxSet* set, int64_t now_ms) {
  if (!set->n_known || !set->k_known || set->k == 0) {
    return;
  }
  if (set->symbol_count < set->n) {
    return;
  }

  std::vector<size_t> missing;
  for (size_t i = 0; i < set->n; ++i) {
    if (!set->orig_mask.test(i) && !set->recov_mask.test(i)) {
      missing.push_back(i);
    }
  }
  if (missing.empty()) {
    return;
  }

  const size_t n = set->n;
  const size_t k = set->k;
  if (missing.size() > k || set->symbol_max < 2) {
    return;
  }
  // A9: an n + k above the shard limit cannot decode (rs.cc rejects it), so
  // never allocate the padded buffers for geometry the codec cannot handle.
  if (n + k > kRsMaxShards) {
    return;
  }
  const size_t symbol_max = set->symbol_max;

  // Reuse the scratch buffers across attempts; a nested attempt (a synchronous
  // host re-entering on_datagram from the deliver callback below) uses locals,
  // because it would otherwise overwrite rows the outer loop is still reading.
  std::vector<std::vector<uint8_t>> local_padded;
  std::vector<std::vector<uint8_t>> local_recovered;
  const bool nested = decode_depth_ > 0;
  std::vector<std::vector<uint8_t>>& padded = nested ? local_padded : decode_padded_;
  std::vector<std::vector<uint8_t>>& recovered = nested ? local_recovered : decode_recovered_;
  ++decode_depth_;
  struct DepthGuard {
    int& depth;
    ~DepthGuard() { --depth; }
  } guard{decode_depth_};

  padded.resize(n + k);
  std::vector<const uint8_t*> symbols(n + k, nullptr);
  // Missing indices stay nullptr (erasures), so their padded rows are never
  // read and do not need clearing -- only the tail past a short symbol does.
  for (size_t i = 0; i < n; ++i) {
    if (!set->orig_mask.test(i)) {
      continue;
    }
    const std::vector<uint8_t>& s = set->symbols[i];
    std::vector<uint8_t>& row = padded[i];
    row.resize(symbol_max);
    const size_t n_copy = std::min(s.size(), symbol_max);
    std::memcpy(row.data(), s.data(), n_copy);
    std::fill(row.begin() + static_cast<std::ptrdiff_t>(n_copy), row.end(), 0);
    symbols[i] = row.data();
  }
  // No parity for j in [k_eff, k): those rows are ghost erasures.
  for (size_t r = 0; r < k; ++r) {
    const size_t idx = n + r;
    if (idx >= kMaxS || !set->parity_mask.test(idx)) {
      continue;
    }
    const std::vector<uint8_t>& s = set->symbols[idx];
    std::vector<uint8_t>& row = padded[idx];
    row.resize(symbol_max);
    const size_t n_copy = std::min(s.size(), symbol_max);
    std::memcpy(row.data(), s.data(), n_copy);
    std::fill(row.begin() + static_cast<std::ptrdiff_t>(n_copy), row.end(), 0);
    symbols[idx] = row.data();
  }

  ++set->decode_attempts;
  ++decode_attempts_;
  if (!decode(symbols.data(), n, k, symbol_max, &recovered)) {
    return;
  }

  for (const size_t i : missing) {
    const std::vector<uint8_t>& s = recovered[i];
    // A23: a structurally unusable reconstruction is not final (§4.5 makes
    // decoding a retry: every new symbol may recover a different set of
    // erasures). Leave the index open so later parity can still repair it,
    // but count each bad index once -- retries must not inflate the
    // struct_fail that the peer sees in FECSTAT.
    if (s.size() != symbol_max) {
      note_bad_recon(set, i);
      continue;
    }
    // The reconstruction carries its own 2-byte length prefix; everything past
    // it must be padding. Both checks are per-index, so a set with several bad
    // indices counts each of them once.
    const size_t declared = static_cast<size_t>(s[0]) | (static_cast<size_t>(s[1]) << 8);
    bool ok = declared >= 2 && declared <= symbol_max;
    for (size_t b = declared; ok && b < symbol_max; ++b) {
      if (s[b] != 0) {
        ok = false;
      }
    }
    if (!ok) {
      note_bad_recon(set, i);
      continue;
    }
    set->bad_recon.reset(i);
    set->recov_mask.set(i);
    ++recovered_;
    const int64_t waited = now_ms - set->t_first_ms;
    const uint32_t repair_ms = static_cast<uint32_t>(
        std::clamp<int64_t>(waited, 0, static_cast<int64_t>(0xFFFFFFFF)));
    // Recovered-late deliveries are already outside the expected identity
    // (they are counted in delivered_le_sum only), so the unexpected flag only
    // matters for originals.
    deliver_payload(s.data() + 2, declared - 2, true,
                    set->phase == SetPhase::kAccounted, false, now_ms, repair_ms);
  }
}

// Count an index whose reconstruction is structurally unusable as struct_fail,
// once. Retries may repair it later, so the index stays open.
void FrameRx::note_bad_recon(RxSet* set, size_t index) {
  if (set->bad_recon.test(index)) {
    return;
  }
  set->bad_recon.set(index);
  ++struct_fail_;
}

}  // namespace fcp
