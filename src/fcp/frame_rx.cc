#include "fcp/frame_rx.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "fcp/hdr.h"
#include "fcp/rs.h"

namespace fcp {

SnDedup::SnDedup() : slots_(std::make_unique<std::array<Slot, kSnWindow>>()) {
  slots_->fill(Slot{});
}

bool SnDedup::accept(uint32_t sn, int64_t now_ms) {
  Slot& slot = (*slots_)[sn % kSnWindow];
  if (slot.used && slot.sn == sn) {
    return false;
  }
  slot.used = true;
  slot.sn = sn;
  slot.ts_ms = now_ms;
  return true;
}

bool SnDedup::seen(uint32_t sn) const {
  const Slot& slot = (*slots_)[sn % kSnWindow];
  return slot.used && slot.sn == sn;
}

void SnDedup::reset() { slots_->fill(Slot{}); }

FrameRx::FrameRx(uint8_t d, uint8_t p, DeliverFn deliver, OobFn oob, SnFn sn_of)
    : d_(d),
      p_(p),
      deliver_(std::move(deliver)),
      oob_(std::move(oob)),
      sn_of_(std::move(sn_of)) {}

void FrameRx::on_datagram(const uint8_t* plaintext, size_t len, int64_t now_ms) {
  FecHdr hdr{};
  if (!parse_hdr(plaintext, len, &hdr)) {
    ++struct_fail_;
    return;
  }
  const uint8_t* symbol = plaintext + kFecHdrLen;
  const size_t symbol_len = len - kFecHdrLen;

  const SymbolType type = hdr_type(hdr.type_k);
  if (type == SymbolType::kOob) {
    if (oob_) {
      oob_(symbol, symbol_len, now_ms);
    }
    return;
  }
  if (!valid_symbol_type(type)) {
    // The 2-bit type field can encode 3; erratum #25 retired it, so it has no
    // meaning and must never create set state.
    ++struct_fail_;
    return;
  }

  // Window anchor = highest *structurally valid* set_id seen so far. A malformed
  // header must not advance it, or one forged far-future set_id would make every
  // subsequent genuine set look stale. Staleness is a modular half-window test
  // (§14.5): a set_id more than kMaxActiveSets behind the anchor is stale.
  if (anchor_valid_ &&
      static_cast<uint32_t>(anchor_ - hdr.set_id) > kMaxActiveSets &&
      static_cast<uint32_t>(anchor_ - hdr.set_id) < 0x80000000u) {
    ++stale_;
    return;
  }

  const uint16_t s = static_cast<uint16_t>(d_) + p_;
  const auto existing = sets_.find(hdr.set_id);
  const bool n_known = existing != sets_.end() && existing->second.n_known;
  const uint8_t n = existing != sets_.end() ? existing->second.n : 0;
  if (validate_hdr(hdr, d_, s, n_known, n) != HdrStatus::kOk) {
    ++struct_fail_;
    return;
  }
  if (symbol_len < 2) {
    ++struct_fail_;
    return;
  }
  const uint8_t k_field = hdr_k(hdr.type_k);
  const uint8_t j_field = hdr_j(hdr.type_k);
  uint8_t n_new = 0;
  if (type == SymbolType::kData) {
    const size_t declared =
        static_cast<size_t>(symbol[0]) | (static_cast<size_t>(symbol[1]) << 8);
    if (declared != symbol_len) {
      ++struct_fail_;
      return;
    }
  } else {
    n_new = static_cast<uint8_t>(hdr.index - j_field);
    if (n_known && n != n_new) {
      ++struct_fail_;
      return;
    }
  }

  // Accounting for this set is already final (§5.3: the tombstone was
  // released). Re-creating the state would let one late fragment settle the
  // same set a second time, inflating expected/rx and the peer's loss sample.
  if (retired_.find(hdr.set_id) != retired_.end()) {
    ++retired_dropped_;
    return;
  }

  // The symbol is well formed: only now may it create set state and move the
  // window (plus materialise gap placeholders).
  const bool had_anchor = anchor_valid_;
  const uint32_t prev_anchor = anchor_;
  if (!anchor_valid_ || set_id_after(anchor_, hdr.set_id)) {
    anchor_ = hdr.set_id;
    anchor_valid_ = true;
    prune_retired();
  }
  if (had_anchor && set_id_after(prev_anchor + 1, hdr.set_id)) {
    create_placeholders(prev_anchor + 1, hdr.set_id, now_ms);
  }

  RxSet& set = get_or_create(hdr.set_id, now_ms);
  if (!note_k(&set, k_field)) {
    ++struct_fail_;
    return;
  }

  if (type == SymbolType::kData) {
    const uint8_t index = hdr.index;
    if (set.orig_mask.test(index)) {
      ++late_dup_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
    if (set.recov_mask.test(index)) {
      // Already credited as recovered; masks must stay disjoint or settlement
      // would double count this index.
      ++late_dup_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
    set.orig_mask.set(index);
    set.max_data_index = std::max(set.max_data_index, index);
    store_symbol(&set, index, symbol, symbol_len);
    deliver_payload(symbol + 2, symbol_len - 2, false,
                    set.phase == SetPhase::kAccounted, now_ms, 0);
    try_decode(&set, now_ms);
    return;
  }

  // Parity: n = index - j, and this is the only source of n.
  if (set.parity_mask.test(hdr.index)) {
    return;  // duplicate fragment: no store, no re-decode
  }
  set.n = n_new;
  set.n_known = true;
  set.saw_parity = true;
  set.parity_mask.set(hdr.index);
  store_symbol(&set, hdr.index, symbol, symbol_len);
  try_decode(&set, now_ms);
}

std::vector<uint32_t> FrameRx::active_set_ids() const {
  std::vector<uint32_t> ids;
  ids.reserve(sets_.size());
  for (const auto& kv : sets_) {
    ids.push_back(kv.first);
  }
  return ids;
}

void FrameRx::set_event_sink(EventFn fn) { event_ = std::move(fn); }

bool FrameRx::mark_eligible(uint32_t set_id) {
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  if (it->second.phase == SetPhase::kActive) {
    it->second.phase = SetPhase::kEligible;
  }
  return true;
}

bool FrameRx::mark_accounted(uint32_t set_id, int64_t tombstone_until_ms) {
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  it->second.phase = SetPhase::kAccounted;
  it->second.tombstone_until_ms = tombstone_until_ms;
  return true;
}

bool FrameRx::release_set(uint32_t set_id) {
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  if (it->second.phase == SetPhase::kAccounted) {
    retired_.insert(set_id);
    prune_retired();
  }
  sets_.erase(it);
  return true;
}

void FrameRx::prune_retired() {
  // Only ids inside the staleness window can still reach the retired check;
  // anything further behind is already dropped as stale at ingress.
  for (auto it = retired_.begin(); it != retired_.end();) {
    const uint32_t behind = static_cast<uint32_t>(anchor_ - *it);
    if (behind > kMaxActiveSets && behind < 0x80000000u) {
      it = retired_.erase(it);
    } else {
      ++it;
    }
  }
}

void FrameRx::create_placeholders(uint32_t first, uint32_t last, int64_t now_ms) {
  // last is strictly after first in the modular half-window sense; the gap may
  // span the u32 wrap (e.g. first = 0xFFFFFFFE, last = 2).
  const uint32_t gap = static_cast<uint32_t>(last - first);
  if (gap == 0 || gap > kMaxGapPlaceholders || sets_.size() + gap >= kMaxActiveSets) {
    return;
  }
  for (uint32_t id = first; id != last; ++id) {
    RxSet& set = sets_.emplace(id, RxSet{}).first->second;
    set.set_id = id;
    set.t_first_ms = now_ms;
  }
}

void FrameRx::emit_event(RxEvent event, uint32_t value) {
  if (event_) {
    event_(event, value);
  }
}

bool FrameRx::view(uint32_t set_id, RxSetView* out) const {
  if (out == nullptr) {
    return false;
  }
  const auto it = sets_.find(set_id);
  if (it == sets_.end()) {
    return false;
  }
  const RxSet& s = it->second;
  out->set_id = s.set_id;
  out->phase = s.phase;
  out->k = s.k;
  out->k_known = s.k_known;
  out->n = s.n;
  out->n_known = s.n_known;
  out->max_data_index = s.max_data_index;
  out->saw_parity = s.saw_parity;
  out->has_any_symbol = s.has_any_symbol;
  out->symbol_count = s.symbol_count;
  out->symbol_max = s.symbol_max;
  out->t_first_ms = s.t_first_ms;
  out->tombstone_until_ms = s.tombstone_until_ms;
  out->decode_attempts = s.decode_attempts;
  out->orig_mask = s.orig_mask;
  out->recov_mask = s.recov_mask;
  out->parity_mask = s.parity_mask;
  out->decoded_once = s.decoded_once;
  return true;
}

FrameRx::RxSet& FrameRx::get_or_create(uint32_t set_id, int64_t now_ms) {
  const auto it = sets_.find(set_id);
  if (it != sets_.end()) {
    return it->second;
  }
  if (sets_.size() >= kMaxActiveSets) {
    // Tombstones outrank capacity pressure: evict the oldest unaccounted set.
    auto victim = sets_.end();
    for (auto sit = sets_.begin(); sit != sets_.end(); ++sit) {
      if (sit->second.phase != SetPhase::kAccounted) {
        victim = sit;
        break;
      }
    }
    if (victim == sets_.end()) {
      // Everything is a tombstone: still bound the map by evicting the oldest
      // grave instead of growing past the cap (an authenticated peer flooding
      // fresh set ids between settle ticks must not balloon memory).
      victim = sets_.begin();
    }
    if (victim->second.phase == SetPhase::kAccounted) {
      // Evicted after accounting: never let the id be settled again.
      retired_.insert(victim->first);
      prune_retired();
    } else {
      // Unaccounted set dropped under capacity pressure: same bookkeeping as
      // the settle module's 1s tail drop, so delivered stays bounded by
      // expected + tail_delivered.
      const uint32_t delivered = static_cast<uint32_t>(
          (victim->second.orig_mask | victim->second.recov_mask).count());
      emit_event(RxEvent::kSetTailDropped, delivered);
    }
    sets_.erase(victim);
    ++tail_dropped_;
  }
  RxSet& set = sets_.emplace(set_id, RxSet{}).first->second;
  set.set_id = set_id;
  set.t_first_ms = now_ms;
  return set;
}

bool FrameRx::note_k(RxSet* set, uint8_t k) {
  if (set->k_known) {
    return set->k == k;
  }
  set->k = k;
  set->k_known = true;
  return true;
}

void FrameRx::store_symbol(RxSet* set, uint8_t index, const uint8_t* symbol, size_t len) {
  set->symbols[index].assign(symbol, symbol + len);
  ++set->symbol_count;
  set->has_any_symbol = true;
  set->symbol_max = std::max(set->symbol_max, len);
}

void FrameRx::deliver_payload(const uint8_t* payload, size_t len, bool recovered, bool late,
                              int64_t now_ms, uint32_t repair_ms) {
  if (sn_of_) {
    uint32_t sn = 0;
    // Payloads too short to carry a KCP sn (control/keepalive-sized segments)
    // bypass the dedup window: they share no key, and collapsing them onto one
    // slot would silently swallow every short segment after the first.
    if (sn_of_(payload, len, &sn) && !sn_dedup_.accept(sn, now_ms)) {
      ++late_dup_;
      emit_event(RxEvent::kDataDuplicate, 0);
      return;
    }
  }
  ++data_delivered_;
  if (deliver_) {
    deliver_(payload, len);
  }
  if (recovered) {
    if (late) {
      ++late_recovered_;
      emit_event(RxEvent::kRecoveredLate, repair_ms);
    } else {
      emit_event(RxEvent::kRecovered, repair_ms);
    }
  } else if (late) {
    ++late_data_;
    emit_event(RxEvent::kDataLate, 0);
  } else {
    emit_event(RxEvent::kDataDelivered, 0);
  }
}

void FrameRx::try_decode(RxSet* set, int64_t now_ms) {
  if (!set->n_known || !set->k_known || set->k == 0) {
    return;
  }
  if (set->symbol_count < set->n) {
    return;
  }

  std::vector<size_t> missing;
  bool any_untried = false;
  for (size_t i = 0; i < set->n; ++i) {
    if (!set->orig_mask.test(i) && !set->recov_mask.test(i)) {
      missing.push_back(i);
      if (!set->decoded_once.test(i)) {
        any_untried = true;
      }
    }
  }
  if (missing.empty() || !any_untried) {
    return;
  }

  const size_t n = set->n;
  const size_t k = set->k;
  if (missing.size() > k || set->symbol_max < 2) {
    return;
  }
  const size_t symbol_max = set->symbol_max;

  std::vector<std::vector<uint8_t>> padded(n + k, std::vector<uint8_t>(symbol_max, 0));
  std::vector<const uint8_t*> symbols(n + k, nullptr);
  for (size_t i = 0; i < n; ++i) {
    if (!set->orig_mask.test(i)) {
      continue;
    }
    const std::vector<uint8_t>& s = set->symbols[i];
    std::memcpy(padded[i].data(), s.data(), std::min(s.size(), symbol_max));
    symbols[i] = padded[i].data();
  }
  // No parity for j in [k_eff, k): those rows are ghost erasures.
  for (size_t r = 0; r < k; ++r) {
    const size_t idx = n + r;
    if (idx >= kMaxS || !set->parity_mask.test(idx)) {
      continue;
    }
    const std::vector<uint8_t>& s = set->symbols[idx];
    std::memcpy(padded[idx].data(), s.data(), std::min(s.size(), symbol_max));
    symbols[idx] = padded[idx].data();
  }

  std::vector<std::vector<uint8_t>> recovered;
  ++set->decode_attempts;
  ++decode_attempts_;
  if (!decode(symbols.data(), n, k, symbol_max, &recovered)) {
    return;
  }

  for (const size_t i : missing) {
    if (set->decoded_once.test(i)) {
      continue;  // structurally rejected earlier; never retried
    }
    set->decoded_once.set(i);
    const std::vector<uint8_t>& s = recovered[i];
    if (s.size() != symbol_max) {
      ++struct_fail_;
      continue;
    }
    const size_t declared = static_cast<size_t>(s[0]) | (static_cast<size_t>(s[1]) << 8);
    bool ok = declared >= 2 && declared <= symbol_max;
    for (size_t b = declared; ok && b < symbol_max; ++b) {
      if (s[b] != 0) {
        ok = false;
      }
    }
    if (!ok) {
      ++struct_fail_;
      continue;
    }
    set->recov_mask.set(i);
    ++recovered_;
    const int64_t waited = now_ms - set->t_first_ms;
    const uint32_t repair_ms = static_cast<uint32_t>(
        std::clamp<int64_t>(waited, 0, static_cast<int64_t>(0xFFFFFFFF)));
    deliver_payload(s.data() + 2, declared - 2, true,
                    set->phase == SetPhase::kAccounted, now_ms, repair_ms);
  }
}

}  // namespace fcp
