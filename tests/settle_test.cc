#include "fcp/settle.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "fcp/frame_rx.h"
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

// A wire data symbol: len(2 LE) | payload, where len covers the whole symbol
// including the prefix (FrameTx's framing).
std::vector<uint8_t> DataSymbol(uint32_t sn) {
  std::vector<uint8_t> out = SegPayload(sn);
  const size_t len = out.size() + 2;
  out.insert(out.begin(), {static_cast<uint8_t>(len & 0xFF),
                           static_cast<uint8_t>((len >> 8) & 0xFF)});
  return out;
}

bool SnOf(const uint8_t* p, size_t len, uint32_t* sn) {
  if (len < 4) {
    return false;
  }
  *sn = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  return true;
}

struct Fixture {
  std::vector<std::vector<uint8_t>> delivered;
  fcp::FrameRx rx;
  fcp::FcpSettle settle;

  explicit Fixture(uint8_t d = 10, uint8_t p = 3)
      : rx(d, p,
           [this](const uint8_t* payload, size_t len) {
             delivered.emplace_back(payload, payload + len);
           },
           [](const uint8_t*, size_t, int64_t) {}, &SnOf),
        settle(d) {
    settle.attach(&rx);
  }

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

  void feed_as(uint32_t set_id, const std::vector<fcp::TxSymbol>& symbols, int64_t now_ms = 0) {
    for (const auto& s : symbols) {
      feed(set_id, s.index, s.type_k, s.symbol, now_ms);
    }
  }

  const fcp::SettleCounters& c() const { return settle.counters(); }
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
  tx.on_tick(now + 1000);
  return out;
}

bool IsData(const fcp::TxSymbol& s) { return fcp::hdr_type(s.type_k) == fcp::SymbolType::kData; }
bool IsParity(const fcp::TxSymbol& s) {
  return fcp::hdr_type(s.type_k) == fcp::SymbolType::kParity;
}

std::vector<std::vector<uint8_t>> Payloads(uint32_t base, size_t count, size_t len = 4) {
  std::vector<std::vector<uint8_t>> out;
  for (size_t i = 0; i < count; ++i) {
    out.push_back(SegPayload(base + static_cast<uint32_t>(i), len));
  }
  return out;
}

void TestClamps() {
  CHECK_EQ(fcp::FcpSettle::late_guard_ms(50), 100);
  CHECK_EQ(fcp::FcpSettle::late_guard_ms(100), 100);
  CHECK_EQ(fcp::FcpSettle::late_guard_ms(300), 300);
  CHECK_EQ(fcp::FcpSettle::late_guard_ms(700), 700);  // #29a: door opens to the
  CHECK_EQ(fcp::FcpSettle::late_guard_ms(800), 700);  // handshake backoff range

  CHECK_EQ(fcp::FcpSettle::tombstone_ms(50), 200);
  CHECK_EQ(fcp::FcpSettle::tombstone_ms(100), 200);
  CHECK_EQ(fcp::FcpSettle::tombstone_ms(300), 600);
  CHECK_EQ(fcp::FcpSettle::tombstone_ms(700), 1400);
}

void TestBasicAccounting() {
  const auto tx = BuildSet(10, 2, Payloads(100, 10));
  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s) && (s.index == 2 || s.index == 7)) {
      continue;
    }
    f.feed_tx(s);
  }

  f.settle.tick(99, 100);  // late_guard = 100
  CHECK_EQ(f.c().sets_expected, 0u);
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 1u);
  CHECK_EQ(f.c().data_expected, 10u);
  CHECK_EQ(f.c().data_rx_orig, 8u);
  CHECK_EQ(f.c().data_recovered_dl, 2u);
  CHECK_EQ(f.c().parity_rx, 2u);
  CHECK_EQ(f.c().parity_expected, 2u);
  CHECK_EQ(f.c().sets_full, 1u);
  CHECK_EQ(f.c().sets_partial, 0u);
  CHECK_EQ(f.c().data_delivered, 10u);
  CHECK_EQ(f.c().data_late_rx, 0u);
  CHECK_EQ(f.settle.data_lost(), 0u);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());
  CHECK(!f.settle.untrusted());
  CHECK_EQ(f.settle.accounted_through_set_id(), 0u);

  fcp::RxSetView v;
  CHECK(f.rx.view(0, &v));
  CHECK(v.phase == fcp::SetPhase::kAccounted);
  CHECK_EQ(v.tombstone_until_ms, 300);

  f.settle.tick(299, 100);
  CHECK(f.rx.view(0, &v));
  f.settle.tick(300, 100);
  CHECK(!f.rx.view(0, &v));
  CHECK_EQ(f.rx.active_sets(), 0u);
}

void TestTailDrop() {
  const auto tx = BuildSet(10, 2, Payloads(200, 3));
  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s)) {
      f.feed_tx(s);  // no parity: never eligible on its own
    }
  }
  f.settle.tick(999, 100);
  CHECK_EQ(f.c().sets_tail_dropped, 0u);
  CHECK_EQ(f.rx.active_sets(), 1u);

  f.settle.tick(1000, 100);
  CHECK_EQ(f.c().sets_tail_dropped, 1u);
  CHECK_EQ(f.rx.active_sets(), 0u);
  CHECK_EQ(f.c().sets_expected, 0u);
  CHECK_EQ(f.c().data_expected, 0u);
  // Deliveries still happened; they are just not part of expected.
  CHECK_EQ(f.c().data_delivered, 3u);
}

void TestEligibleByHigherSet() {
  Fixture f(10, 3);
  for (const auto& s : BuildSet(10, 2, Payloads(300, 4))) {
    if (IsData(s)) {
      f.feed(0, s.index, s.type_k, s.symbol, 0);  // data only: no parity credential
    }
  }
  f.feed_as(1, BuildSet(10, 2, Payloads(400, 4)), 0);  // data + one parity

  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 2u);
  CHECK_EQ(f.c().data_expected, 8u);  // n unknown for set 0 -> max_data_index + 1
  CHECK_EQ(f.c().data_rx_orig, 8u);
  CHECK_EQ(f.c().parity_rx, 1u);
  CHECK_EQ(f.c().parity_expected, 4u);  // planned k = 2 per set
  CHECK_EQ(f.c().sets_full, 2u);
  CHECK_EQ(f.c().sets_partial, 2u);
  CHECK_EQ(f.settle.accounted_through_set_id(), 1u);
}

void TestKUnknownAndUntrusted() {
  Fixture f(10, 3);
  f.feed_as(0, BuildSet(10, 1, Payloads(500, 3)), 0);  // 3 data + 1 parity
  // Jump 0 -> 5: ids 1..4 were completely lost. Set 5 stays open (data only).
  for (const auto& s : BuildSet(10, 1, Payloads(600, 1))) {
    if (IsData(s)) {
      f.feed(5, s.index, s.type_k, s.symbol, 0);
    }
  }

  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_k_unknown, 4u);
  CHECK_EQ(f.c().sets_expected, 1u);
  CHECK_EQ(f.c().data_expected, 3u);
  CHECK_EQ(f.c().data_rx_orig, 3u);
  CHECK(f.settle.untrusted());  // 4 unknown vs 1 expected

  // Set 5 never closed: no parity, not superseded -> tail drop at 1s.
  f.settle.tick(1000, 100);
  CHECK_EQ(f.c().sets_tail_dropped, 1u);
  CHECK_EQ(f.rx.active_sets(), 0u);
  // Tail-dropped sets are never accounted, so the key stops at the placeholders.
  CHECK_EQ(f.settle.accounted_through_set_id(), 4u);
}

void TestTrustedRatio() {
  Fixture f(10, 3);
  for (uint32_t sid = 0; sid <= 18; ++sid) {
    f.feed_as(sid, BuildSet(10, 1, Payloads(1000 + sid, 1)), 0);
  }
  f.feed_as(20, BuildSet(10, 1, Payloads(2000, 1)), 0);  // placeholder 19

  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_k_unknown, 1u);
  CHECK_EQ(f.c().sets_expected, 20u);
  CHECK(!f.settle.untrusted());  // 1/20 = 5%
  CHECK_EQ(f.c().data_expected, 20u);
  CHECK_EQ(f.c().parity_expected, 20u);
  CHECK_EQ(f.c().sets_partial, 20u);
}

void TestLateAccounting() {
  const auto tx = BuildSet(10, 2, Payloads(700, 10));
  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s) && (s.index == 8 || s.index == 9)) {
      continue;
    }
    if (IsParity(s) && fcp::hdr_j(s.type_k) != 0) {
      continue;
    }
    f.feed_tx(s, 0);
  }
  f.settle.tick(100, 100);  // accounted: rx_orig 8, one parity, two losses
  CHECK_EQ(f.c().data_expected, 10u);
  CHECK_EQ(f.c().data_rx_orig, 8u);
  CHECK_EQ(f.c().data_recovered_dl, 0u);
  CHECK_EQ(f.c().parity_rx, 1u);
  CHECK_EQ(f.settle.data_lost(), 2u);

  // Late original: first delivery counts data_late_rx, and it unlocks the
  // reconstruction of the last index (still inside the tombstone).
  for (const auto& s : tx) {
    if (IsData(s) && s.index == 8) {
      f.feed_tx(s, 150);
    }
  }
  CHECK_EQ(f.c().data_late_rx, 1u);
  CHECK_EQ(f.c().data_recovered_late, 1u);
  CHECK_EQ(f.c().data_recovered_dl, 0u);   // no backfill of settlement
  CHECK_EQ(f.c().data_rx_orig, 8u);        // ditto
  CHECK_EQ(f.c().parity_rx, 1u);           // late parity never re-counted
  CHECK_EQ(f.c().data_delivered, 10u);
  CHECK_EQ(f.settle.data_lost(), 1u);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());

  // Repeat of the same late original is a duplicate, not a second late count.
  for (const auto& s : tx) {
    if (IsData(s) && s.index == 8) {
      f.feed_tx(s, 160);
    }
  }
  CHECK_EQ(f.c().data_late_rx, 1u);
  CHECK_EQ(f.c().late_dup, 1u);
  CHECK_EQ(f.c().data_delivered, 10u);

  // A late parity is stored but must not change any settled counter.
  for (const auto& s : tx) {
    if (IsParity(s) && fcp::hdr_j(s.type_k) == 1) {
      f.feed_tx(s, 170);
    }
  }
  CHECK_EQ(f.c().parity_rx, 1u);
  CHECK_EQ(f.c().data_recovered_late, 1u);
  CHECK_EQ(f.c().data_delivered, 10u);
  CHECK_EQ(f.c().data_late_rx, 1u);

  f.settle.tick(300, 100);
  CHECK_EQ(f.rx.active_sets(), 0u);
}

void TestGhostPlanValue() {
  const auto tx = BuildSet(10, 4, Payloads(800, 7));  // k_eff = 3, n = 7
  Fixture f(10, 3);
  for (const auto& s : tx) {
    f.feed_tx(s);
  }
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 1u);
  CHECK_EQ(f.c().data_expected, 7u);
  CHECK_EQ(f.c().data_rx_orig, 7u);
  CHECK_EQ(f.c().parity_rx, 3u);
  CHECK_EQ(f.c().parity_expected, 4u);  // planned k, not k_eff
  CHECK_EQ(f.c().sets_partial, 1u);
  CHECK_EQ(f.c().sets_full, 1u);
  CHECK_EQ(f.c().data_recovered_dl, 0u);
}

// §5.3: settlement is final. Once the tombstone is released, a late fragment
// for that set_id must not recreate the set and account it a second time (a
// late parity used to inflate expected/rx and therefore the peer's loss).
// Erratum #23⑨ is the deliberate exception: a set that never became eligible
// was never accounted, so it may be rebuilt by later fragments.
void TestNoReaccountAfterRelease() {
  Fixture f(10, 3);
  for (uint8_t i = 0; i < 5; ++i) {
    f.feed(0, i, fcp::pack_type_k(2, 0, 0), DataSymbol(1000 + i));
  }
  f.feed(0, 5, fcp::pack_type_k(2, 0, 1), DataSymbol(2000));  // n = 5

  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 1u);
  CHECK_EQ(f.c().data_expected, 5u);
  CHECK_EQ(f.c().data_rx_orig, 5u);
  CHECK_EQ(f.c().parity_rx, 1u);
  CHECK_EQ(f.delivered.size(), size_t{5});

  f.settle.tick(300, 100);  // accounted at 100 + tombstone 200
  fcp::RxSetView v;
  CHECK(!f.rx.view(0, &v));

  f.feed(0, 6, fcp::pack_type_k(2, 0, 0), DataSymbol(1006), 310);
  f.feed(0, 5, fcp::pack_type_k(2, 0, 1), DataSymbol(2001), 320);
  CHECK_EQ(f.rx.retired_dropped(), 2u);
  CHECK(!f.rx.view(0, &v));
  CHECK_EQ(f.delivered.size(), size_t{5});
  CHECK_EQ(f.rx.anchor(), 0u);

  f.settle.tick(1500, 100);
  CHECK_EQ(f.c().sets_expected, 1u);
  CHECK_EQ(f.c().data_expected, 5u);
  CHECK_EQ(f.c().data_rx_orig, 5u);
  CHECK_EQ(f.c().sets_tail_dropped, 0u);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());

  // A tail-dropped (never accounted) set is still re-creatable.
  f.feed(1, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(3000), 1600);
  f.settle.tick(2600, 100);  // 1s without parity and not superseded
  CHECK_EQ(f.c().sets_tail_dropped, 1u);
  CHECK_EQ(f.c().tail_delivered, 1u);
  CHECK(!f.rx.view(1, &v));

  f.feed(1, 1, fcp::pack_type_k(1, 0, 1), {2, 0}, 2700);  // n = 1, rebuilds id 1
  CHECK(f.rx.view(1, &v));
  f.settle.tick(2800, 100);
  CHECK_EQ(f.c().sets_expected, 2u);
  CHECK_EQ(f.c().data_expected, 6u);
  CHECK_EQ(f.rx.retired_dropped(), 2u);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());
}

// Capacity pressure evicts the oldest unaccounted set. That drop must be
// reported to settle (sets_tail_dropped + tail_delivered), and an evicted
// tombstone id must never be accounted again (design #9, spec §5.3).
void TestCapacityEvictionAccounting() {
  Fixture f(10, 3);
  for (uint32_t sid = 0; sid < 256; ++sid) {
    f.feed(sid, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(10000 + sid));
    f.feed(sid, 1, fcp::pack_type_k(1, 0, 1), {2, 0});  // n = 1, eligible
  }
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 256u);
  CHECK_EQ(f.c().data_expected, 256u);
  CHECK_EQ(f.c().data_rx_orig, 256u);
  CHECK_EQ(f.c().sets_tail_dropped, 0u);

  // The map is full of tombstones: this evicts id 0 without accounting it
  // twice; since it was already accounted, no tail-drop event is emitted.
  f.feed(256, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(30000), 200);
  CHECK_EQ(f.rx.tail_dropped(), 1u);
  CHECK_EQ(f.c().sets_tail_dropped, 0u);

  f.feed(0, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(30001), 210);
  f.feed(0, 1, fcp::pack_type_k(1, 0, 1), {2, 0}, 220);
  CHECK_EQ(f.rx.retired_dropped(), 2u);
  fcp::RxSetView v;
  CHECK(!f.rx.view(0, &v));

  f.settle.tick(400, 100);  // tombstones 1..255 expire
  CHECK_EQ(f.c().sets_expected, 256u);
  f.settle.tick(1500, 100);  // set 256 never closed -> tail drop
  CHECK_EQ(f.c().sets_tail_dropped, 1u);
  CHECK_EQ(f.c().tail_delivered, 1u);
  CHECK_EQ(f.c().sets_expected, 256u);
  CHECK_EQ(f.c().data_expected, 256u);
  CHECK_EQ(f.c().data_delivered, 257u);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());
}

void TestIdentityFuzz() {
  constexpr uint32_t kSets = 200;
  Fixture f(10, 3);
  int64_t now = 1;
  uint32_t expected_data = 0;
  uint32_t expected_parity = 0;
  uint32_t sets_with_symbols = 0;
  for (uint32_t sid = 0; sid < kSets; ++sid) {
    const auto tx = BuildSet(10, 3, Payloads(10000 + 10 * sid, 10, 16));
    bool any = false;
    bool any_data = false;
    bool parity_kept = false;
    uint8_t max_index = 0;
    for (const auto& s : tx) {
      ++now;
      if (sid + 1 < kSets && (fcp_test::rng()() % 100) < 20) {
        continue;  // 20% symbol loss; the final set stays complete
      }
      f.feed(sid, s.index, s.type_k, s.symbol, now);
      any = true;
      if (IsParity(s)) {
        parity_kept = true;
        ++expected_parity;
      } else {
        any_data = true;
        max_index = std::max(max_index, s.index);
      }
    }
    if (any) {
      ++sets_with_symbols;
    }
    // Erratum #3: no parity credential -> n_used is the max_data_index + 1 bound.
    expected_data += parity_kept ? 10u : (any_data ? max_index + 1u : 0u);
  }
  f.settle.tick(now + 300, 200);        // late_guard = 200
  f.settle.tick(now + 300 + 400, 200);  // tombstone = 400

  CHECK_EQ(f.c().sets_expected, sets_with_symbols);
  CHECK_EQ(f.c().sets_k_unknown, kSets - sets_with_symbols);
  CHECK_EQ(f.c().data_expected, expected_data);
  CHECK_EQ(f.c().parity_rx, expected_parity);
  CHECK_EQ(f.c().parity_expected, sets_with_symbols * 3);
  CHECK_EQ(f.c().sets_tail_dropped, 0u);
  CHECK(f.c().data_rx_orig <= f.c().data_expected);
  CHECK(f.c().parity_rx <= f.c().parity_expected);
  CHECK(f.c().data_recovered_dl > 0);
  CHECK_EQ(f.c().data_late_rx, 0u);
  CHECK_EQ(f.c().data_recovered_late, 0u);
  CHECK_EQ(f.c().late_dup, 0u);
  CHECK_EQ(f.c().data_delivered,
           f.c().data_rx_orig + f.c().data_recovered_dl);
  CHECK(f.settle.identity_ok());
  CHECK(f.settle.delivered_le_sum());
  CHECK(!f.settle.untrusted());
  CHECK_EQ(f.rx.active_sets(), 0u);
  CHECK_EQ(f.settle.accounted_through_set_id(), kSets - 1);

  // Interval reset keeps the session-level monotonic key.
  f.settle.reset_interval();
  CHECK_EQ(f.c().sets_expected, 0u);
  CHECK_EQ(f.c().data_delivered, 0u);
  CHECK_EQ(f.settle.accounted_through_set_id(), kSets - 1);
}

}  // namespace

// M3 R(k) ledger (FCP_M3_CONTROL.md §1.2): only full-size groups with known
// k >= 1 enter; runs are RAW loss (recovered slots still count as lost).
void TestLedgerRecovery() {
  const auto tx = BuildSet(10, 2, Payloads(400, 10));
  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s) && (s.index == 2 || s.index == 7)) {
      continue;  // both recovered by parity — raw runs stay 1 and 1
    }
    f.feed_tx(s);
  }
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().ledger_groups, 1u);
  CHECK_EQ(f.c().ledger_groups_failed, 0u);
  CHECK_EQ(f.c().ledger_k_hist[2], 1u);
  CHECK_EQ(f.settle.ledger_k(), 2);
  CHECK_EQ(f.c().ledger_data, 10u);
  CHECK_EQ(f.c().ledger_data_lost, 2u);
  CHECK_EQ(f.c().run_hist[1], 1u);
}

// More holes than parity: RS is underdetermined, nothing recovers, the whole
// set settles as failed with its max missing run recorded.
void TestLedgerFailedRun() {
  const auto tx = BuildSet(10, 2, Payloads(500, 10));
  Fixture f(10, 3);
  for (const auto& s : tx) {
    if (IsData(s) && (s.index == 3 || s.index == 4 || s.index == 8 || s.index == 9)) {
      continue;  // 4 holes vs k=2: no unique solution, zero recovery
    }
    f.feed_tx(s);
  }
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().ledger_groups, 1u);
  CHECK_EQ(f.c().ledger_groups_failed, 1u);
  CHECK_EQ(f.c().data_recovered_dl, 0u);
  CHECK_EQ(f.settle.data_lost(), 4u);
  CHECK_EQ(f.c().run_hist[2], 1u);
  CHECK_EQ(f.settle.ledger_k(), 2);
}

// Partial sets (n_used < D) and k-unknown sets stay outside the ledger even
// when accounted; the dominant k still reflects the full-size population.
void TestLedgerExclusions() {
  Fixture f(10, 3);
  // Set 0: k=0, data only — becomes eligible when set 1's symbols arrive.
  for (const auto& s : BuildSet(10, 0, Payloads(600, 10))) {
    if (IsData(s)) {
      f.feed(0, s.index, s.type_k, s.symbol, 0);
    }
  }
  // Set 1: partial (4 data) with parity, fully delivered.
  for (const auto& s : BuildSet(10, 2, Payloads(700, 4))) {
    f.feed(1, s.index, s.type_k, s.symbol, 0);
  }
  // Set 2: full size with k=3, one hole recovered.
  for (const auto& s : BuildSet(10, 3, Payloads(800, 10))) {
    if (IsData(s) && s.index == 5) {
      continue;
    }
    f.feed(2, s.index, s.type_k, s.symbol, 0);
  }
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().sets_expected, 3u);
  CHECK_EQ(f.c().ledger_groups, 1u);
  CHECK_EQ(f.c().ledger_groups_failed, 0u);
  CHECK_EQ(f.c().ledger_k_hist[3], 1u);
  CHECK_EQ(f.c().ledger_k_hist[2], 0u);
  CHECK_EQ(f.settle.ledger_k(), 3);
  // Set 2's single hole recovered — raw run is still 1.
  CHECK_EQ(f.c().run_hist[1], 1u);
}

// Dominant k is the mode of the k histogram (ties to the lower k).
void TestLedgerDominantK() {
  Fixture f(10, 3);
  f.feed_as(0, BuildSet(10, 2, Payloads(900, 10)));
  f.feed_as(1, BuildSet(10, 3, Payloads(1000, 10)));
  f.feed_as(2, BuildSet(10, 3, Payloads(1100, 10)));
  f.settle.tick(100, 100);
  CHECK_EQ(f.c().ledger_groups, 3u);
  CHECK_EQ(f.c().ledger_k_hist[2], 1u);
  CHECK_EQ(f.c().ledger_k_hist[3], 2u);
  CHECK_EQ(f.settle.ledger_k(), 3);
}

// --- #26 burst detection (FCP_M3_CONTROL.md §3) ---

// Exact i.i.d. reference via brute force over all 2^d loss masks (d = 10).
void RunDistBruteForce(double out[9], double p, uint8_t d) {
  for (int l = 0; l < 9; ++l) {
    out[l] = 0.0;
  }
  const uint32_t n = 1u << d;
  for (uint32_t mask = 0; mask < n; ++mask) {
    double prob = 1.0;
    unsigned best = 0;
    unsigned run = 0;
    for (uint8_t i = 0; i < d; ++i) {
      if (mask & (1u << i)) {
        prob *= p;
        ++run;
        best = std::max(best, run);
      } else {
        prob *= 1.0 - p;
        run = 0;
      }
    }
    out[std::min<unsigned>(best, 8)] += prob;
  }
}

void TestRunDistIidMatchesBruteForce() {
  for (const double p : {0.02, 0.10, 0.35, 0.70, 1.0}) {
    double dp[9];
    double bf[9];
    fcp::run_dist_iid(dp, p, 10);
    RunDistBruteForce(bf, p, 10);
    double sum = 0.0;
    for (int l = 0; l < 9; ++l) {
      CHECK(std::fabs(dp[l] - bf[l]) < 1e-12);
      sum += dp[l];
    }
    CHECK(std::fabs(sum - 1.0) < 1e-12);
  }
  // p = 0: no loss, all mass at run 0.
  double q[9];
  fcp::run_dist_iid(q, 0.0, 10);
  CHECK(std::fabs(q[0] - 1.0) < 1e-12);
  // Degenerate group smaller than the largest bucket: run 9 impossible.
  fcp::run_dist_iid(q, 0.5, 5);
  CHECK(q[8] == 0.0);
}

void TestBurstKlMath() {
  double q[9];
  fcp::run_dist_iid(q, 0.10, 10);
  // An empirical histogram equal to the reference has zero distance (up to
  // the rounding of counts).
  uint32_t hist[9] = {};
  const uint32_t n = 100000;
  for (int l = 0; l < 9; ++l) {
    hist[l] = static_cast<uint32_t>(q[l] * n + 0.5);
  }
  CHECK(fcp::burst_kl_iid(hist, n, 0.10, 10) < 0.001);
  // A point mass at bucket l sits at exactly -ln Q(l) from the reference.
  for (int l = 0; l < 9; ++l) {
    if (q[l] <= 0.0) {
      continue;
    }
    uint32_t delta[9] = {};
    delta[l] = 64;
    CHECK(std::fabs(fcp::burst_kl_iid(delta, 64, 0.10, 10) + std::log(q[l])) < 1e-9);
  }
  // Empty ledger: zero, not inf.
  uint32_t empty[9] = {};
  CHECK(fcp::burst_kl_iid(empty, 0, 0.10, 10) == 0.0);
}

// Clean ledger: no loss -> the reference is a point mass at 0 too -> kl == 0.
// A low-loss link with run-of-3 bursts sits far from i.i.d. -> kl > 1 nat.
void TestBurstKlScenarios() {
  Fixture clean(10, 3);
  for (uint32_t g = 0; g < 30; ++g) {
    clean.feed_as(g, BuildSet(10, 2, Payloads(2000 + 100 * g, 10)));
  }
  clean.settle.tick(100, 100);
  CHECK_EQ(clean.c().ledger_groups, 30u);
  CHECK_EQ(clean.c().ledger_data_lost, 0u);
  CHECK(std::fabs(clean.settle.burst_kl()) < 1e-12);

  Fixture bursty(10, 3);
  for (uint32_t g = 0; g < 100; ++g) {
    const auto tx = BuildSet(10, 2, Payloads(5000 + 100 * g, 10));
    for (const auto& s : tx) {
      if (IsData(s) && g % 10 < 3 && s.index < 3) {
        continue;  // 30 of 100 groups lose slots 0..2 as one run
      }
      bursty.feed(g, s.index, s.type_k, s.symbol, 0);
    }
  }
  bursty.settle.tick(100, 100);
  CHECK_EQ(bursty.c().ledger_groups, 100u);
  CHECK_EQ(bursty.c().ledger_data_lost, 90u);
  CHECK_EQ(bursty.c().run_hist[3], 30u);
  CHECK_EQ(bursty.c().run_hist[0], 70u);
  CHECK(bursty.settle.burst_kl() > 1.0);
}

int main() {
  TestClamps();
  TestBasicAccounting();
  TestTailDrop();
  TestEligibleByHigherSet();
  TestKUnknownAndUntrusted();
  TestTrustedRatio();
  TestLateAccounting();
  TestGhostPlanValue();
  TestNoReaccountAfterRelease();
  TestCapacityEvictionAccounting();
  TestIdentityFuzz();
  TestLedgerRecovery();
  TestLedgerFailedRun();
  TestLedgerExclusions();
  TestLedgerDominantK();
  TestRunDistIidMatchesBruteForce();
  TestBurstKlMath();
  TestBurstKlScenarios();
  return fcp_test::finish();
}
