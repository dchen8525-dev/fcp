#include "fcp/frame_rx.h"

#include <cstring>
#include <vector>

#include "fcp/frame_tx.h"
#include "fcp/hdr.h"
#include "test_util.h"

namespace {

std::vector<uint8_t> SegPayload(uint32_t sn, size_t len = 4) {
  std::vector<uint8_t> out(len < 4 ? 4 : len, 0);
  out[0] = static_cast<uint8_t>(sn);
  out[1] = static_cast<uint8_t>(sn >> 8);
  out[2] = static_cast<uint8_t>(sn >> 16);
  out[3] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 4; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(sn + 7 * i);
  }
  return out;
}

uint32_t SnOf(const uint8_t* p, size_t len) {
  if (len < 4) {
    return 0;
  }
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

bool SnFnAdapter(const uint8_t* p, size_t len, uint32_t* sn) {
  if (len < 4) {
    return false;
  }
  *sn = SnOf(p, len);
  return true;
}

struct Fixture {
  uint8_t d;
  std::vector<std::vector<uint8_t>> delivered;
  std::vector<std::vector<uint8_t>> oobs;
  fcp::FrameRx rx;

  explicit Fixture(uint8_t d_in = 10, uint8_t p_in = 3)
      : d(d_in),
        rx(d_in, p_in,
           [this](const uint8_t* p, size_t len) { delivered.emplace_back(p, p + len); },
           [this](const uint8_t* m, size_t len, int64_t) { oobs.emplace_back(m, m + len); },
           &SnFnAdapter) {}

  void feed(uint32_t set_id, uint8_t index, uint8_t type_k, const std::vector<uint8_t>& symbol,
            int64_t now_ms = 0) {
    uint8_t hdr[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, hdr);
    std::vector<uint8_t> dg(hdr, hdr + fcp::kFecHdrLen);
    dg.insert(dg.end(), symbol.begin(), symbol.end());
    rx.on_datagram(dg.data(), dg.size(), now_ms);
  }

  void feed_tx(const fcp::TxSymbol& s, int64_t now_ms = 0) {
    feed(s.set_id, s.index, s.type_k, s.symbol, now_ms);
  }

  size_t count_sn(uint32_t sn) const {
    size_t count = 0;
    for (const auto& m : delivered) {
      if (SnOf(m.data(), m.size()) == sn) {
        ++count;
      }
    }
    return count;
  }

  bool saw_payload(const std::vector<uint8_t>& payload) const {
    for (const auto& m : delivered) {
      if (m == payload) {
        return true;
      }
    }
    return false;
  }
};

std::vector<fcp::TxSymbol> BuildSet(uint8_t d, uint8_t k,
                                    const std::vector<std::vector<uint8_t>>& segs) {
  const fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(d, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });
  tx.set_k(k);
  tx.set_srtt_ms(25);
  int64_t now = 0;
  for (const auto& seg : segs) {
    tx.on_kcp_output(seg.data(), seg.size(), now);
    ++now;
  }
  tx.on_tick(now + 1000);  // idle close when fewer than d segments
  return out;
}

bool IsData(const fcp::TxSymbol& s) { return fcp::hdr_type(s.type_k) == fcp::SymbolType::kData; }
bool IsParity(const fcp::TxSymbol& s) {
  return fcp::hdr_type(s.type_k) == fcp::SymbolType::kParity;
}

bool Erased(uint8_t index, uint8_t a, uint8_t b) { return index == a || index == b; }

void TestDataDeliveryAndDedup() {
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 10; ++i) {
    segs.push_back(SegPayload(100 + i, 32));
  }
  const auto tx = BuildSet(10, 2, segs);
  CHECK_EQ(tx.size(), 12u);  // 10 data + 2 parity

  Fixture f(10, 3);
  for (const auto& s : tx) {
    f.feed_tx(s);
  }
  CHECK_EQ(f.delivered.size(), 10u);
  CHECK_EQ(f.rx.data_delivered(), 10u);
  CHECK_EQ(f.rx.recovered(), 0u);
  for (uint32_t i = 0; i < 10; ++i) {
    CHECK_EQ(f.count_sn(100 + i), 1u);
  }

  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK(v.k_known);
  CHECK_EQ(v.k, 2);
  CHECK(v.n_known);
  CHECK_EQ(v.n, 10);
  CHECK(v.saw_parity);
  CHECK_EQ(v.orig_mask.count(), 10u);
  CHECK_EQ(v.recov_mask.count(), 0u);
  CHECK_EQ(v.parity_mask.count(), 2u);

  // Replaying every symbol is harmless: data duplicates count late_dup, parity
  // duplicates are dropped silently, delivery never repeats.
  for (const auto& s : tx) {
    f.feed_tx(s);
  }
  CHECK_EQ(f.delivered.size(), 10u);
  CHECK_EQ(f.rx.late_dup(), 10u);
}

void TestNoParityNoDecode() {
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 9; ++i) {
    segs.push_back(SegPayload(200 + i));
  }
  const auto tx = BuildSet(10, 2, segs);
  CHECK_EQ(tx.size(), 11u);  // idle close still sends k_eff = 2

  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s)) {
      f.feed_tx(s);
    }
  }
  CHECK_EQ(f.delivered.size(), 9u);
  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK(v.k_known);
  CHECK(!v.n_known);  // n comes only from parity
  CHECK(!v.saw_parity);
  CHECK_EQ(f.rx.decode_attempts(), 0u);

  // First parity teaches n = 9; nothing is missing, so no decode attempt.
  for (const auto& s : tx) {
    if (IsParity(s)) {
      f.feed_tx(s);
      break;
    }
  }
  CHECK(f.rx.view(0, &v));
  CHECK(v.n_known);
  CHECK_EQ(v.n, 9);
  CHECK_EQ(f.rx.decode_attempts(), 0u);
  CHECK_EQ(f.delivered.size(), 9u);
}

void TestRecoveryMasksDisjoint() {
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 10; ++i) {
    segs.push_back(SegPayload(300 + i, 20 + 5 * i));
  }
  const auto tx = BuildSet(10, 3, segs);

  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s) && Erased(s.index, 2, 7)) {
      continue;
    }
    f.feed_tx(s);
  }
  CHECK_EQ(f.delivered.size(), 10u);
  CHECK_EQ(f.rx.recovered(), 2u);
  CHECK_EQ(f.rx.decode_attempts(), 1u);
  for (uint32_t i = 0; i < 10; ++i) {
    CHECK_EQ(f.count_sn(300 + i), 1u);
  }

  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK_EQ(v.orig_mask.count(), 8u);
  CHECK_EQ(v.recov_mask.count(), 2u);
  CHECK(v.recov_mask.test(2));
  CHECK(v.recov_mask.test(7));
  CHECK_EQ((v.orig_mask & v.recov_mask).count(), 0u);  // erratum #2: disjoint

  // A retransmitted original for an already-recovered index must not flip the
  // masks: it is a late duplicate and stays credited as recovered.
  for (const auto& s : tx) {
    if (IsData(s) && Erased(s.index, 2, 7)) {
      f.feed_tx(s);
    }
  }
  CHECK_EQ(f.rx.view(0, &v), true);
  CHECK_EQ(v.orig_mask.count(), 8u);
  CHECK_EQ(v.recov_mask.count(), 2u);
  CHECK_EQ(f.rx.late_dup(), 2u);
  CHECK_EQ(f.delivered.size(), 10u);

  // Plain duplicate of a symbol that was always original.
  for (const auto& s : tx) {
    if (IsData(s) && s.index == 0) {
      f.feed_tx(s);
      break;
    }
  }
  CHECK_EQ(f.rx.late_dup(), 3u);
  CHECK_EQ(f.delivered.size(), 10u);
}

void TestGhostParity() {
  // n = 7 < D = 10, k = 4 -> k_eff = ceil(4 * 7 / 10) = 3; j = 3 is a ghost.
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 7; ++i) {
    segs.push_back(SegPayload(400 + i, 100 + 100 * i));
  }
  const auto tx = BuildSet(10, 4, segs);
  CHECK_EQ(tx.size(), 10u);  // 7 data + 3 parity

  Fixture f(10, 3);
  size_t parity_seen = 0;
  for (const auto& s : tx) {
    if (IsParity(s)) {
      ++parity_seen;
    }
    if (IsData(s) && (s.index == 1 || s.index == 3 || s.index == 5)) {
      continue;
    }
    f.feed_tx(s);
  }
  CHECK_EQ(parity_seen, 3u);
  CHECK_EQ(f.rx.recovered(), 3u);
  CHECK_EQ(f.rx.decode_attempts(), 1u);
  CHECK_EQ(f.delivered.size(), 7u);
  for (uint32_t i = 0; i < 7; ++i) {
    CHECK(f.saw_payload(segs[i]));
  }

  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK_EQ(v.k, 4);
  CHECK_EQ(v.n, 7);
  CHECK_EQ(v.parity_mask.count(), 3u);
  CHECK_EQ(v.recov_mask.count(), 3u);
}

void TestIncrementalTrigger() {
  // k = 1: parity arrives first, then data trickles in; the decode attempt only
  // starts once rx_count reaches n.
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 10; ++i) {
    segs.push_back(SegPayload(500 + i));
  }
  const auto tx = BuildSet(10, 1, segs);

  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsParity(s)) {
      f.feed_tx(s);
    }
  }
  // 1 parity + 7 data = 8 < n: below the rx_count floor, no attempt yet.
  for (const auto& s : tx) {
    if (!IsData(s) || s.index >= 8 || s.index == 3) {
      continue;
    }
    f.feed_tx(s);
  }
  CHECK_EQ(f.delivered.size(), 7u);
  CHECK_EQ(f.rx.decode_attempts(), 0u);
  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK_EQ(v.symbol_count, 8u);
  CHECK_EQ(v.n, 10);

  // Reaching rx_count == n triggers the attempt; the single erase is within
  // the k = 1 budget once both remaining data symbols arrive.
  for (const auto& s : tx) {
    if (IsData(s) && s.index >= 8) {
      f.feed_tx(s);
    }
  }
  CHECK_EQ(f.rx.decode_attempts(), 1u);
  CHECK_EQ(f.rx.recovered(), 1u);
  CHECK_EQ(f.delivered.size(), 10u);
  CHECK_EQ(f.count_sn(503), 1u);
}

void TestStructFail() {
  Fixture f(10, 3);
  const std::vector<uint8_t> len8{2, 0};

  f.rx.on_datagram(nullptr, 0, 0);  // shorter than the 6-byte header

  f.feed(10, 0, fcp::pack_type_k(2, 0, 0), {5});              // symbol_len < 2
  f.feed(11, 0, fcp::pack_type_k(2, 0, 0), {3, 0, 9, 9});     // declared mismatch
  f.feed(12, 10, fcp::pack_type_k(2, 0, 0), len8);            // data index >= D
  f.feed(13, 10, fcp::pack_type_k(2, 2, 1), len8);            // parity j >= k
  f.feed(14, 0, fcp::pack_type_k(2, 0, 1), len8);             // parity n = 0
  f.feed(15, 11, fcp::pack_type_k(2, 0, 1), len8);            // parity n > D

  // n known = 8, so data index 8 is past the code length.
  f.feed(16, 8, fcp::pack_type_k(2, 0, 1), len8);
  f.feed(16, 8, fcp::pack_type_k(2, 0, 0), len8);

  // k is locked per set.
  f.feed(17, 0, fcp::pack_type_k(2, 0, 0), len8);
  f.feed(17, 1, fcp::pack_type_k(3, 0, 0), len8);

  // n is consistent across parity of the same set.
  f.feed(18, 8, fcp::pack_type_k(2, 0, 1), len8);
  f.feed(18, 10, fcp::pack_type_k(2, 1, 1), len8);

  CHECK_EQ(f.rx.struct_fail(), 10u);

  // None of the rejected symbols were stored.
  fcp::RxSetView v;
  CHECK(f.rx.view(16, &v));
  CHECK(!v.orig_mask.test(8));
  CHECK_EQ(v.parity_mask.count(), 1u);
  CHECK(f.rx.view(17, &v));
  CHECK_EQ(v.k, 2);
  CHECK_EQ(v.orig_mask.count(), 1u);
}

void TestSnDedupWindow() {
  fcp::SnDedup dedup;
  CHECK(dedup.accept(5, 0));
  CHECK(!dedup.accept(5, 1));
  CHECK(dedup.seen(5));
  CHECK(!dedup.seen(6));

  // Slot reuse: sn + 4096 collides with sn's slot and evicts it.
  CHECK(dedup.accept(5 + fcp::kSnWindow, 2));
  CHECK(!dedup.seen(5));
  CHECK(dedup.seen(5 + fcp::kSnWindow));
  CHECK(!dedup.accept(5 + fcp::kSnWindow, 3));

  dedup.reset();
  CHECK(!dedup.seen(5 + fcp::kSnWindow));
  CHECK(dedup.accept(5, 4));

  // Cross-set duplicates are suppressed by sn too.
  Fixture f(10, 3);
  const std::vector<uint8_t> sym = {6, 0, 42, 0, 0, 0};
  f.feed(20, 0, fcp::pack_type_k(2, 0, 0), sym);
  f.feed(21, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.delivered.size(), 1u);
  CHECK_EQ(f.count_sn(42), 1u);
  CHECK_EQ(f.rx.late_dup(), 1u);
  CHECK_EQ(f.rx.data_delivered(), 1u);
  fcp::RxSetView v;
  CHECK(f.rx.view(21, &v));
  CHECK(v.orig_mask.test(0));  // received, just not delivered twice
}

void TestInvalidTypeAndOobBypass() {
  Fixture f(10, 3);
  // Type 3 was the inline control channel; erratum #25 retired it, so it is
  // undefined and must be rejected as struct_fail without creating any set state.
  const std::vector<uint8_t> stale_control = {'F', 'C', 'P', '_', 'H'};
  f.feed(7, 0, fcp::pack_type_k(0, 0, 3), stale_control);
  CHECK_EQ(f.rx.struct_fail(), 1u);
  CHECK_EQ(f.rx.active_sets(), 0u);

  // oob is dispatched by magic, never enters a set, never counts as failure.
  const std::vector<uint8_t> report = {1, 2, 3, 4};
  f.feed(7, 0, fcp::pack_type_k(0, 0, 2), report);
  CHECK_EQ(f.oobs.size(), 1u);
  CHECK(f.oobs[0] == report);
  CHECK_EQ(f.rx.active_sets(), 0u);

  // Neither an undefined type nor oob moves the window anchor.
  CHECK_EQ(f.rx.anchor(), 0u);
  CHECK_EQ(f.rx.struct_fail(), 1u);
  CHECK_EQ(f.rx.stale(), 0u);
  CHECK_EQ(f.delivered.size(), 0u);
}

void TestStaleAnchor() {
  Fixture f(10, 3);
  const std::vector<uint8_t> sym = {2, 0};
  f.feed(300, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.rx.anchor(), 300u);

  // anchor - 256 = 44 is still inside the window.
  f.feed(44, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.rx.stale(), 0u);
  CHECK_EQ(f.rx.anchor(), 300u);

  f.feed(43, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.rx.stale(), 1u);
  CHECK_EQ(f.rx.active_sets(), 2u);
  fcp::RxSetView v;
  CHECK(!f.rx.view(43, &v));
}

// A malformed symbol must not advance the window anchor: otherwise one forged
// far-future set_id would make every genuine subsequent set look stale.
void TestMalformedDoesNotMoveAnchor() {
  Fixture f(10, 3);
  const std::vector<uint8_t> sym = {4, 0, 7, 7};
  f.feed(5, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.rx.anchor(), 5u);

  f.feed(900, 11, fcp::pack_type_k(2, 0, 0), sym);  // data index >= D
  CHECK_EQ(f.rx.anchor(), 5u);
  CHECK_EQ(f.rx.struct_fail(), 1u);
  CHECK_EQ(f.rx.active_sets(), 1u);  // and no empty set was created

  f.feed(5000, 10, fcp::pack_type_k(0, 0, 1), sym);  // parity with j >= k
  CHECK_EQ(f.rx.anchor(), 5u);
  CHECK_EQ(f.rx.struct_fail(), 2u);

  f.feed(6000, 0, fcp::pack_type_k(2, 0, 0), {});  // data without len prefix
  CHECK_EQ(f.rx.anchor(), 5u);
  CHECK_EQ(f.rx.struct_fail(), 3u);
  CHECK_EQ(f.rx.active_sets(), 1u);

  // A well-formed symbol at the same far-future id still moves the window.
  f.feed(900, 0, fcp::pack_type_k(2, 0, 0), sym);
  CHECK_EQ(f.rx.anchor(), 900u);
  fcp::RxSetView v;
  CHECK(f.rx.view(900, &v));
}

void TestCapacityEviction() {
  Fixture f(10, 3);
  for (uint32_t sid = 0; sid <= 255; ++sid) {
    f.feed(sid, 0, fcp::pack_type_k(2, 0, 0), {6, 0, static_cast<uint8_t>(sid), 0, 0, 0});
  }
  CHECK_EQ(f.rx.active_sets(), 256u);
  CHECK_EQ(f.rx.tail_dropped(), 0u);

  f.feed(256, 0, fcp::pack_type_k(2, 0, 0), {6, 0, 1, 2, 3, 4});
  CHECK_EQ(f.rx.active_sets(), 256u);
  CHECK_EQ(f.rx.tail_dropped(), 1u);
  fcp::RxSetView v;
  CHECK(!f.rx.view(0, &v));
  CHECK(f.rx.view(1, &v));
  CHECK(f.rx.view(256, &v));
}

void TestZeroK() {
  std::vector<std::vector<uint8_t>> segs;
  for (uint32_t i = 0; i < 10; ++i) {
    segs.push_back(SegPayload(700 + i));
  }
  const auto tx = BuildSet(10, 0, segs);
  CHECK_EQ(tx.size(), 10u);  // no parity at all

  Fixture f(10, 3);
  for (const auto& s : tx) {
    f.feed_tx(s);
  }
  CHECK_EQ(f.delivered.size(), 10u);
  CHECK_EQ(f.rx.recovered(), 0u);
  CHECK_EQ(f.rx.decode_attempts(), 0u);
  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK(v.k_known);
  CHECK_EQ(v.k, 0);
  CHECK(!v.n_known);
  CHECK_EQ(v.orig_mask.count(), 10u);
}

}  // namespace

int main() {
  TestDataDeliveryAndDedup();
  TestNoParityNoDecode();
  TestRecoveryMasksDisjoint();
  TestGhostParity();
  TestIncrementalTrigger();
  TestStructFail();
  TestSnDedupWindow();
  TestInvalidTypeAndOobBypass();
  TestStaleAnchor();
  TestMalformedDoesNotMoveAnchor();
  TestCapacityEviction();
  TestZeroK();
  return fcp_test::finish();
}
