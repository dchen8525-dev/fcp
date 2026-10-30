// End-to-end tests over real UDP loopback sockets (task C2).
//
// Two sessions talk through a pair of connected 127.0.0.1 UDP sockets. Loss
// injection happens at the application layer, before sendto, so every dropped
// datagram is known; KCP retransmission is emulated explicitly by the ARQ loop.
//
// Scenarios: T3 (k=0 lossless), T7 (reconstruction and retransmission collide
// on one sn), T8 (auth_fail leaves the set machinery untouched), T10
// (FRAMED_STATS never uses RS) and a 20% random-loss fuzz with ARQ.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "e2e_link.h"
#include "test_util.h"

namespace {

using namespace fcp_e2e;

// T3: with k=0 and no loss every original arrives, rx == expect and pre == 0.
// The client never leaves FEC off.
void TestT3LosslessKZero() {
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3)));
  CHECK(h.Handshake());
  CHECK(h.a->mode() == fcp::SessionMode::kFramedRepair);

  // 401 segments: 40 full sets plus one tail set that is never eligible and is
  // tail-dropped after 1s, so it stays out of data_expected.
  h.Inject(0, 401, 0);
  CHECK_EQ(h.a_data, 401u);
  CHECK_EQ(h.a_parity, 0u);

  // Stop one tick before B's first FECSTAT (t=2000) clears its interval.
  h.TickTo(25, 1975);

  CHECK_EQ(h.b->rx()->data_delivered(), 401u);
  CHECK_EQ(h.delivered_b.size(), 401u);
  for (const Bytes& payload : h.delivered_b) {
    CHECK_EQ(payload.size(), 16u);
    CHECK(payload == Segment(SnOf(payload)));
  }
  CHECK_EQ(h.corrupt_b, 0u);

  const fcp::SettleCounters& c = h.b->settle()->counters();
  CHECK_EQ(c.sets_expected, 40u);
  CHECK_EQ(c.data_expected, 400u);
  CHECK_EQ(c.data_rx_orig, 400u);
  CHECK_EQ(c.data_recovered_dl, 0u);
  CHECK_EQ(c.data_recovered_late, 0u);
  CHECK_EQ(c.data_late_rx, 0u);
  CHECK_EQ(c.data_delivered, 401u);
  CHECK_EQ(c.parity_rx, 0u);
  CHECK_EQ(c.parity_expected, 0u);
  CHECK_EQ(c.sets_k_unknown, 0u);
  CHECK_EQ(c.sets_full, 40u);
  CHECK_EQ(c.sets_partial, 0u);
  CHECK_EQ(c.sets_tail_dropped, 1u);
  CHECK_EQ(c.late_dup, 0u);
  CHECK(h.b->settle()->identity_ok());
  CHECK_EQ(h.b->rx()->active_sets(), 0u);

  // The 2s report crosses the loopback socket and drives the client strategy.
  h.TickAt(2000);
  // b's oob stream so far: HELLO + HELLO_ACK during the handshake, then FECSTAT
  // sent twice (#28⑤ F3).
  CHECK_EQ(h.b_oob, 4u);
  FecstatLogFields f;
  CHECK(ParseFecstatLog(h.log_a, &f));
  CHECK_EQ(f.expect, 400u);
  CHECK_EQ(f.rx, 400u);
  CHECK_EQ(f.rec, 0u);
  CHECK_EQ(f.late, 0u);
  CHECK_EQ(f.lost, 0u);
  CHECK_EQ(f.pre, 0u);
  CHECK_EQ(f.usable, 0u);
  CHECK_EQ(f.k, 0u);
  CHECK_EQ(f.state, std::string("OFF"));
  CHECK_EQ(h.a->k(), 0u);
  CHECK(h.a->strategy()->state() == fcp::FecState::kOff);
}

// T7: the parity reconstruction of sn=7 and a later KCP retransmission of the
// same sn collide at the delivery layer; the sn window lets it through once.
void TestT7RecoveryRetransmitCollision() {
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3, 1),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3, 1)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 1u);
  CHECK(h.a->strategy()->state() == fcp::FecState::kOn);

  // Drop the only data symbol; the set closes at T_flush=200ms with one parity.
  const Bytes seg = Segment(7);
  h.drop_next_data_a = true;
  h.now = 0;
  h.a->on_kcp_output(seg.data(), seg.size(), 0);
  CHECK_EQ(h.a_data, 1u);
  CHECK_EQ(h.a_parity, 0u);
  h.pump();
  CHECK_EQ(h.delivered_b.size(), 0u);

  h.TickAt(200);
  CHECK_EQ(h.a_parity, 1u);
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(SnOf(h.delivered_b[0]), 7u);
  CHECK_EQ(h.b->rx()->recovered(), 1u);
  CHECK_EQ(h.b->rx()->data_delivered(), 1u);

  // KCP retransmits the segment into a fresh set; dedup keeps one delivery.
  h.now = 300;
  h.a->on_kcp_output(seg.data(), seg.size(), 300);
  h.pump();
  CHECK_EQ(h.a_data, 2u);
  CHECK_EQ(h.delivered_b.size(), 1u);
  CHECK_EQ(h.b->rx()->data_delivered(), 1u);
  CHECK_EQ(h.b->rx()->late_dup(), 1u);

  h.TickTo(325, 1400);
  const fcp::SettleCounters& c = h.b->settle()->counters();
  CHECK_EQ(c.sets_expected, 2u);       // the recovery set and the resend set
  CHECK_EQ(c.data_expected, 2u);
  CHECK_EQ(c.data_rx_orig, 1u);        // the resend is counted, not delivered
  CHECK_EQ(c.data_recovered_dl, 1u);
  CHECK_EQ(c.parity_rx, 2u);           // both sets flush with one parity
  CHECK_EQ(c.parity_expected, 2u);     // planned k on both sets
  CHECK_EQ(c.data_delivered, 1u);
  CHECK_EQ(c.late_dup, 1u);
  CHECK(h.b->settle()->identity_ok());
  CHECK(h.b->settle()->delivered_le_sum());
  CHECK_EQ(h.b->rx()->active_sets(), 0u);
  CHECK_EQ(h.b_oob, 2u);  // only the handshake HELLO/ACK, no report yet
}

// T8: a tampered datagram fails authentication and must not reach FrameRx or
// the settlement counters, only auth_fail.
void TestT8AuthFailDoesNotTouchSets() {
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3)));
  CHECK(h.Handshake());

  h.Inject(0, 20, 0);
  h.TickTo(25, 300);

  const fcp::SettleCounters before = h.b->settle()->counters();
  const uint32_t active_before = static_cast<uint32_t>(h.b->rx()->active_sets());
  const uint32_t anchor_before = h.b->rx()->anchor();
  const uint32_t delivered_before = h.b->rx()->data_delivered();
  const uint32_t dup_before = h.b->rx()->late_dup();
  const uint32_t struct_before = h.b->struct_fail();
  const uint32_t auth_before = h.b->auth_fail();
  const size_t vec_before = h.delivered_b.size();

  CHECK(!h.last_a_wire.empty());
  CHECK(h.last_a_type == fcp::SymbolType::kData);
  Bytes tampered = h.last_a_wire;
  tampered.back() ^= 0x01;  // corrupt the GCM tag

  CHECK(h.sock_a.Send(tampered.data(), tampered.size()));
  h.now = 300;
  h.pump();

  CHECK_EQ(h.b->auth_fail(), auth_before + 1);
  CHECK_EQ(h.b->struct_fail(), struct_before);
  CHECK_EQ(h.b->rx()->anchor(), anchor_before);
  CHECK_EQ(h.b->rx()->active_sets(), active_before);
  CHECK_EQ(h.b->rx()->data_delivered(), delivered_before);
  CHECK_EQ(h.b->rx()->late_dup(), dup_before);
  CHECK_EQ(h.delivered_b.size(), vec_before);
  CHECK(SameCounters(h.b->settle()->counters(), before));
  CHECK_EQ(h.b_oob, 2u);  // only the handshake HELLO/ACK
}

// T10: FRAMED_STATS negotiates P'=0, the strategy is pinned at k=0 and no RS
// parity is ever produced, even though D is unchanged.
void TestT10FramedStats() {
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 0),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 0)));
  CHECK(h.Handshake());
  CHECK(h.a->mode() == fcp::SessionMode::kFramedStats);
  CHECK(h.b->mode() == fcp::SessionMode::kFramedStats);
  CHECK(h.a->strategy() != nullptr);
  CHECK(h.a->strategy()->state() == fcp::FecState::kOff);

  h.Inject(0, 401, 0);
  CHECK_EQ(h.a_data, 401u);
  CHECK_EQ(h.a_parity, 0u);

  h.TickTo(25, 1975);

  CHECK_EQ(h.a->k(), 0u);
  CHECK_EQ(h.a->tx()->parity_symbols(), 0u);
  CHECK_EQ(h.b->rx()->data_delivered(), 401u);

  const fcp::SettleCounters& c = h.b->settle()->counters();
  CHECK_EQ(c.sets_expected, 40u);
  CHECK_EQ(c.data_expected, 400u);
  CHECK_EQ(c.data_rx_orig, 400u);
  CHECK_EQ(c.data_recovered_dl, 0u);
  CHECK_EQ(c.parity_rx, 0u);
  CHECK_EQ(c.parity_expected, 0u);
  CHECK_EQ(c.sets_tail_dropped, 1u);
  CHECK(h.b->settle()->identity_ok());

  h.TickAt(2000);
  CHECK_EQ(h.b_oob, 4u);  // HELLO + HELLO_ACK + the FECSTAT, sent twice (#28⑤ F3)
  FecstatLogFields f;
  CHECK(ParseFecstatLog(h.log_a, &f));
  CHECK_EQ(f.expect, 400u);
  CHECK_EQ(f.rx, 400u);
  CHECK_EQ(f.rec, 0u);
  CHECK_EQ(f.lost, 0u);
  CHECK_EQ(f.pre, 0u);
  CHECK_EQ(f.k, 0u);
  CHECK_EQ(f.state, std::string("OFF"));
}

// 20% random loss with k=2 pinned plus KCP-style ARQ: every injected segment
// is delivered exactly once (original, reconstructed or retransmitted) and the
// settlement identity holds on every tick.
void TestFuzzLoss20Percent() {
  constexpr uint32_t kCount = 1000;
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 3, 2),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 3, 2)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 2u);

  h.loss_enabled = true;
  h.loss_percent = 20;
  h.Inject(0, kCount, 0);
  h.hits_b.resize(kCount, 0);

  auto missing = [&h]() {
    std::vector<uint32_t> out;
    for (uint32_t sn = 0; sn < kCount; ++sn) {
      if (sn >= h.hits_b.size() || h.hits_b[sn] == 0) {
        out.push_back(sn);
      }
    }
    return out;
  };

  for (int round = 0; round < 12; ++round) {
    const std::vector<uint32_t> lost = missing();
    if (lost.empty()) {
      break;
    }
    const int64_t t = 100 * (round + 1);
    h.now = t;
    for (const uint32_t sn : lost) {
      h.SendA(sn, t);
      h.pump();
    }
    h.a->on_tick(t);
    h.pump();
  }

  // Flush, decode, settle and release; stop before the 2s report would clear
  // the interval counters.
  for (int64_t t = 1225; t <= 1950; t += fcp::kSessionTickMs) {
    h.TickAt(t);
    CHECK(h.b->settle()->identity_ok());
  }

  CHECK(missing().empty());
  for (uint32_t sn = 0; sn < kCount; ++sn) {
    CHECK_EQ(h.hits_b[sn], 1u);
  }
  CHECK_EQ(h.delivered_b.size(), static_cast<size_t>(kCount));
  CHECK_EQ(h.corrupt_b, 0u);
  CHECK_EQ(h.b->rx()->data_delivered(), kCount);
  CHECK(h.b->rx()->recovered() > 0);
  CHECK(h.a_parity > 0);

  const fcp::SettleCounters& c = h.b->settle()->counters();
  CHECK(h.b->settle()->identity_ok());
  CHECK(c.data_recovered_dl > 0);   // reconstruction carried part of the load
  CHECK(c.data_rx_orig + c.data_recovered_dl + c.data_late_rx <=
        c.data_expected);           // data_lost() covers the remainder
  CHECK_EQ(h.b->reporter()->reports(), 0u);
}

// E2 (spec #27②): deterministic burst loss vs the i.i.d. binomial model.
//
// 20% average loss shaped as 5-in-a-row bursts every 25 data symbols (5 % 25),
// D=10 sets, k pinned to 4. Under the binomial table (§8) k=4 repairs 87.0% of
// the sets at 20% loss; under 5-bursts every hit set loses 5 consecutive
// symbols — more than k — so not a single hit set is FEC-repairable. The test
// quantifies the shortfall (60% vs 87% per-set repair here) and asserts the
// invariants: identity holds, ARQ delivers every segment exactly once.
void TestBurstLossRepairRate() {
  constexpr uint32_t kCount = 1000;  // exactly 100 full sets of D=10
  Harness h;
  CHECK(h.Init(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, 4, 4),
               MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, 4, 4)));
  CHECK(h.Handshake());
  CHECK_EQ(h.a->k(), 4u);

  // Phase 1: one injection pass, no ARQ yet. sn and the injector's data
  // counter advance 1:1, so sn % 25 < 5 is dropped: 40 bursts of 5, each
  // wiping idx 0-4 or 5-9 of exactly one set.
  h.burst_enabled = true;
  h.Inject(0, kCount, 0);
  h.burst_enabled = false;
  h.burst_data_seen = 0;
  h.TickTo(25, 1950);

  const fcp::SettleCounters c1 = h.b->settle()->counters();
  CHECK(h.b->settle()->identity_ok());
  CHECK_EQ(c1.sets_expected, 100u);
  CHECK_EQ(c1.data_expected, 1000u);
  CHECK_EQ(c1.data_rx_orig, 800u);   // 60 intact sets + 5 of 10 per hit set
  CHECK_EQ(c1.data_recovered_dl, 0u);  // 5 consecutive losses > k=4: unfixable
  CHECK_EQ(c1.data_delivered, 800u);
  CHECK_EQ(c1.sets_full, 60u);
  CHECK_EQ(c1.sets_tail_dropped, 0u);
  CHECK_EQ(h.delivered_b.size(), 800u);
  CHECK_EQ(h.corrupt_b, 0u);

  // Measured per-set repair rate vs the binomial table value at 20% loss.
  const double measured = static_cast<double>(c1.sets_full) /
                          static_cast<double>(c1.sets_expected);
  std::printf(
      "BURST loss=20%% pattern=5-in-25 sets=%u hit=%u k=4 "
      "binomial_repair=87.0%% measured_repair=%.1f%% recovered=%u "
      "arq_pending=%u identity=ok\n",
      c1.sets_expected, c1.sets_expected - c1.sets_full,
      measured * 100.0, c1.data_recovered_dl,
      c1.data_expected - c1.data_rx_orig - c1.data_recovered_dl);
  CHECK(measured < 0.87);  // the i.i.d. model overestimates under bursts

  // Phase 2: ARQ sweeps repair what FEC could not; every segment is delivered
  // exactly once and the identity keeps holding through the resend sets.
  for (int round = 0; round < 12; ++round) {
    std::vector<uint32_t> lost;
    for (uint32_t sn = 0; sn < kCount; ++sn) {
      if (sn >= h.hits_b.size() || h.hits_b[sn] == 0) {
        lost.push_back(sn);
      }
    }
    if (lost.empty()) {
      break;
    }
    const int64_t t = 2000 + 100 * round;
    h.now = t;
    for (const uint32_t sn : lost) {
      h.SendA(sn, t);
      h.pump();
    }
    h.a->on_tick(t);
    h.pump();
  }
  for (int64_t t = 3300; t <= 3900; t += fcp::kSessionTickMs) {
    h.TickAt(t);
    CHECK(h.b->settle()->identity_ok());
  }

  CHECK_EQ(h.delivered_b.size(), static_cast<size_t>(kCount));
  for (uint32_t sn = 0; sn < kCount; ++sn) {
    CHECK_EQ(h.hits_b[sn], 1u);
  }
  CHECK_EQ(h.b->rx()->data_delivered(), kCount);
  CHECK_EQ(h.corrupt_b, 0u);
}

}  // namespace

int main() {
  TestT3LosslessKZero();
  TestT7RecoveryRetransmitCollision();
  TestT8AuthFailDoesNotTouchSets();
  TestT10FramedStats();
  TestFuzzLoss20Percent();
  TestBurstLossRepairRate();
  return fcp_test::finish();
}
