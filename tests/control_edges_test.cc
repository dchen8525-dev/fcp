// Edge-branch tests for the FCP control/utility modules (BBR, trace, settle,
// reporter, prewarm, Cauchy/RS, AES, PMTU, FECSTAT, random, strategy, headers).
// Everything is deterministic: no wall clock, no hardware-dependent forcing.
// Each test targets the degenerate/limit side of a branch that the existing
// per-module tests do not exercise: empty inputs, zero values, wire bounds,
// short-circuit operands, malformed encodings and state-machine early returns.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "fcp/aes.h"
#include "fcp/bbr.h"
#include "fcp/cauchy.h"
#include "fcp/fecstat.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/gf256.h"
#include "fcp/hdr.h"
#include "fcp/pmtu.h"
#include "fcp/prewarm.h"
#include "fcp/random.h"
#include "fcp/reporter.h"
#include "fcp/rs.h"
#include "fcp/settle.h"
#include "fcp/session.h"
#include "fcp/strategy.h"
#include "fcp/stream.h"
#include "fcp/trace.h"
#include "test_util.h"

namespace {

constexpr size_t kKiB = 1024;
const uint8_t kSalt[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

// ---------------------------------------------------------------------------
// BBR
// ---------------------------------------------------------------------------

fcp::Bbr::Config BbrV1() {
  fcp::Bbr::Config c;
  c.mss = 1000;
  c.initial_cwnd = 16 * kKiB;
  c.min_cwnd = 16 * kKiB;
  c.max_cwnd = 1024 * kKiB;
  c.initial_rtt_ms = 100;
  c.min_rtt_expiry_ms = 10000;
  c.probe_rtt_ms = 200;
  c.version = 1;
  return c;
}

void BbrRound(fcp::Bbr* b, int64_t* now, size_t sent, size_t acked, int64_t rtt,
              size_t in_flight, bool new_round = true) {
  b->on_sent(*now, sent, in_flight);
  *now += rtt;
  b->on_acked(*now, acked, rtt, new_round, in_flight);
}

void BbrLossyRound(fcp::Bbr* b, int64_t* now, size_t sent, size_t lost,
                   size_t in_flight) {
  b->on_sent(*now, sent, in_flight);
  b->on_lost(lost);
  *now += 100;
  b->on_acked(*now, sent, 100, true, in_flight);
}

void TestBbrConfigSanitising() {
  fcp::Bbr::Config c;
  c.mss = 0;
  c.initial_cwnd = 0;
  c.min_cwnd = 0;
  c.max_cwnd = 0;
  c.initial_rtt_ms = 0;
  c.version = 3;
  fcp::Bbr b(c);
  // mss -> 1, min_cwnd -> 4 * mss, max_cwnd -> min_cwnd, rtt -> 100, v3 -> v2.
  CHECK_EQ(b.version(), 2);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(100));
  CHECK_EQ(b.cwnd(), 4u);
  CHECK_EQ(b.bandwidth_bps(), 0u);
  // No bandwidth and zero initial cwnd: the reported rate has no positive form.
  CHECK(b.pacing_rate_bps() == 0.0);

  // A default-constructed engine is the same cold-start shape.
  fcp::Bbr def;
  CHECK(def.mode() == fcp::Bbr::Mode::kStartup);
  CHECK_EQ(def.version(), 2);
}

void TestBbrPrewarmPriorClampEdges() {
  // A tiny seeded bandwidth: bdp <= lo drives clamp_size's low branch.
  fcp::Bbr::Config small = BbrV1();
  small.initial_bw_bps = 1;
  small.initial_min_rtt_ms = 0;  // the "no seeded rtt" operand
  fcp::Bbr a(small);
  CHECK(a.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK(a.at_full_bandwidth());
  CHECK_EQ(a.cwnd(), small.min_cwnd);

  // A huge seeded bandwidth drives the high clamp branch.
  fcp::Bbr::Config huge = BbrV1();
  huge.initial_bw_bps = ~0ull;
  huge.initial_min_rtt_ms = 100;
  fcp::Bbr b(huge);
  CHECK_EQ(b.cwnd(), huge.max_cwnd);
  CHECK_EQ(b.bandwidth_bps(), ~0ull);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(100));
  CHECK(b.pacing_rate_bps() > 0.0);
}

void TestBbrModeNames() {
  CHECK(std::strcmp(fcp::Bbr::mode_name(fcp::Bbr::Mode::kStartup), "startup") == 0);
  CHECK(std::strcmp(fcp::Bbr::mode_name(fcp::Bbr::Mode::kDrain), "drain") == 0);
  CHECK(std::strcmp(fcp::Bbr::mode_name(fcp::Bbr::Mode::kProbeBw), "probe_bw") == 0);
  CHECK(std::strcmp(fcp::Bbr::mode_name(fcp::Bbr::Mode::kProbeRtt), "probe_rtt") == 0);
  CHECK(std::strcmp(fcp::Bbr::mode_name(static_cast<fcp::Bbr::Mode>(7)), "?") == 0);
}

void TestBbrWindowedFilterSweep() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  // First ACK only establishes the sampling baseline.
  b.on_sent(now, 1000, 0);
  now += 100;
  b.on_acked(now, 1000, 100, true, 0);
  CHECK_EQ(b.bandwidth_bps(), 0u);

  // A long descending staircase with plateaus: reset-on-new-best, the
  // third-estimate window expiry, and both plateau shortcuts of the filter.
  const uint64_t samples[] = {
      100000, 200000, 180000, 160000, 140000, 140000, 140000, 130000, 130000,
      130000, 120000, 120000, 120000, 110000, 110000, 110000, 100000, 100000,
      100000, 90000,  90000,  90000,  80000, 80000, 80000, 70000, 70000, 60000,
      60000,  60000,  50000,  50000, 50000, 40000, 40000, 30000};
  for (uint64_t v : samples) {
    b.on_sent(now, static_cast<size_t>(v), 0);
    now += 1000;
    b.on_acked(now, static_cast<size_t>(v), 1000, true, 0);
  }
  CHECK(b.bandwidth_bps() >= 40000u);
  CHECK(b.bandwidth_bps() <= 200000u);
}

void TestBbrSamplingShortCircuits() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  // First ack: !have_sample_baseline_ path.
  b.on_sent(now, 10 * kKiB, 0);
  now += 100;
  b.on_acked(now, 10 * kKiB, 100, true, 0);
  CHECK_EQ(b.bandwidth_bps(), 0u);

  // elapsed == 0: the sample interval is not advanced.
  b.on_acked(now, 10 * kKiB, 100, false, 0);

  // sample_bytes_ > 0 and no transmission in the interval (sent_delta == 0).
  b.on_acked(now + 100, 0, 100, false, 0);

  // elapsed > 0 but sample_bytes_ == 0.
  b.on_acked(now + 150, 0, 100, false, 0);

  b.on_acked(now + 200, 5000, 100, false, 0);
  CHECK_EQ(b.bandwidth_bps(), 0u);

  // A normal interval produces the first sample.
  b.on_sent(now + 200, 100 * kKiB, 0);
  b.on_acked(now + 300, 100 * kKiB, 100, true, 0);
  CHECK(b.bandwidth_bps() > 0u);
}

void TestBbrAppLimitedShortCircuits() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  b.on_sent(now, 100 * kKiB, 0);
  now += 100;
  b.on_acked(now, 100 * kKiB, 100, true, 0);
  b.on_sent(now, 100 * kKiB, 0);
  now += 100;
  b.on_acked(now, 100 * kKiB, 100, true, 0);
  const uint64_t best = b.bandwidth_bps();
  CHECK(best > 0u);

  // app_limited with sent_since_app_limited_ false: the sample is capped at
  // zero, so it must not replace the estimate.
  b.on_sent(now, 1000, 0);
  b.on_app_limited(now);
  b.on_acked(now + 100, 1000, 100, true, 0);
  CHECK_EQ(b.bandwidth_bps(), best);

  // Same flag set but acked rate above the best: the estimate updates and the
  // APP_LIMITED flag clears (both operands of the guard true).
  b.on_sent(now + 100, 200 * kKiB, 0);  // also re-opens the sampling interval
  b.on_acked(now + 200, 200 * kKiB, 100, true, 0);
  CHECK(b.bandwidth_bps() >= 200 * kKiB);

  // Idempotent on_app_limited: the second call takes the already-set branch.
  b.on_app_limited(now + 200);
}

void TestBbrRttOperands() {
  fcp::Bbr::Config c = BbrV1();
  c.initial_bw_bps = 1000000;
  c.initial_min_rtt_ms = 50;  // seeded minimum
  fcp::Bbr b(c);
  int64_t now = 0;
  // Seeded: even a larger live sample replaces it.
  b.on_acked(now, 1000, 300, true, 0);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(300));
  // rtt == 0 (Karn dropped): the sample is ignored.
  b.on_acked(now + 100, 1000, 0, false, 0);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(300));

  // Cold engine: min_rtt_ms_ == 0 makes the first positive sample authoritative.
  fcp::Bbr cold(BbrV1());
  int64_t t = 0;
  cold.on_sent(t, 1000, 0);
  t += 100;
  cold.on_acked(t, 1000, 100, true, 0);
  CHECK_EQ(cold.min_rtt_ms(), static_cast<int64_t>(100));
  // A larger sample inside the expiry window does not move it.
  cold.on_acked(t + 50, 1000, 120, false, 0);
  CHECK_EQ(cold.min_rtt_ms(), static_cast<int64_t>(100));
  // A smaller sample does.
  cold.on_acked(t + 60, 1000, 80, false, 0);
  CHECK_EQ(cold.min_rtt_ms(), static_cast<int64_t>(80));
  // An old stamp makes even a larger sample authoritative again.
  cold.on_acked(t + 60 + 10001, 1000, 150, false, 0);
  CHECK_EQ(cold.min_rtt_ms(), static_cast<int64_t>(150));
}

void TestBbrProbeRttColdStartEdges() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  for (int i = 0; i < 3; ++i) {
    BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 100, 16 * kKiB);
  }
  CHECK(b.mode() == fcp::Bbr::Mode::kStartup);
  CHECK(!b.at_full_bandwidth());

  now += 10001;
  // In flight at the floor + mss is not enough to start the probe exit timer.
  b.on_tick(now, b.cwnd() + BbrV1().mss);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeRtt);
  // Below that bound the exit timer starts.
  b.on_tick(now, b.cwnd());
  // A new round pins the probe round flag; the tick before the deadline does
  // not exit (second operand false on the first tick, true on the second).
  b.on_acked(now + 50, 1024, 0, true, 0);
  b.on_tick(now + 100, b.cwnd());
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeRtt);
  b.on_acked(now + 150, 1024, 0, false, 0);
  b.on_tick(now + 200, b.cwnd());
  // at_full false -> STARTUP again.
  CHECK(b.mode() == fcp::Bbr::Mode::kStartup);
}

void TestBbrProbeRttAfterFullBandwidth() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  for (int i = 0; i < 6; ++i) {
    BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 100, 512 * kKiB);
  }
  CHECK(b.at_full_bandwidth());
  CHECK(b.mode() == fcp::Bbr::Mode::kDrain);
  BbrRound(&b, &now, 10 * kKiB, 10 * kKiB, 100, 10 * kKiB);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);

  now += 10001;
  b.on_tick(now, 0);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeRtt);
  b.on_tick(now, 16 * kKiB);  // starts the exit timer
  b.on_acked(now + 50, 1024, 0, true, 0);
  b.on_tick(now + 200, 16 * kKiB);
  // at_full true -> PROBE_BW again.
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK(b.at_full_bandwidth());
}

void TestBbrCwndGrowthGuards() {
  fcp::Bbr::Config c;
  c.mss = 1000;
  c.initial_cwnd = 100000;
  c.min_cwnd = 0;
  c.max_cwnd = 0;
  c.initial_rtt_ms = 0;
  c.version = 2;
  fcp::Bbr b(c);
  // min_cwnd = 4 * mss = max_cwnd, so the window cannot move at all.
  CHECK_EQ(b.cwnd(), 4000u);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(100));
  CHECK_EQ(b.version(), 2);

  int64_t now = 0;
  // cwnd >= target and total_acked_ < initial_cwnd: second operand true.
  b.on_acked(now, 0, 100, true, 0);
  CHECK_EQ(b.cwnd(), 4000u);
  // Both operands false: the window stays put.
  b.on_acked(now + 100, 200000, 100, true, 0);
  CHECK_EQ(b.cwnd(), 4000u);
}

void TestBbrV2RoundBoundEdges() {
  fcp::Bbr::Config c = BbrV1();
  c.version = 2;
  c.loss_threshold_percent = 1;
  fcp::Bbr b(c);
  int64_t now = 0;

  // Round 1: establishes the loss baseline; not yet above baseline + margin.
  BbrLossyRound(&b, &now, 100 * kKiB, 50 * kKiB, 16 * kKiB);
  CHECK_EQ(b.bandwidth_bps(), 0u);  // first ack is only a baseline

  // Round 2: sample exists; lossy round in STARTUP -> full bandwidth and a
  // window cut, then DRAIN -> PROBE_BW.
  BbrLossyRound(&b, &now, 100 * kKiB, 61 * kKiB, 16 * kKiB);
  CHECK(b.at_full_bandwidth());
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK_EQ(b.inflight_hi(), 16 * kKiB);

  // Round 3: the ceiling is already on the floor, so the loss rate is learned
  // as the path's own floor (the "steady state" arm).
  BbrLossyRound(&b, &now, 100 * kKiB, 61 * kKiB, 16 * kKiB);
  // Round 4: a lower loss rate than the learned floor walks the base back down.
  BbrLossyRound(&b, &now, 100 * kKiB, 40 * kKiB, 16 * kKiB);
  CHECK(b.at_full_bandwidth());

  // Round 5: no in-flight sample -> the refused window falls back to cwnd().
  BbrLossyRound(&b, &now, 100 * kKiB, 60 * kKiB, 0);

  // A new round with zero sent bytes: no delivery-efficiency sample, no loss
  // rate, and the "enough" sample-size gate is closed.
  now += 100;
  b.on_acked(now, 1, 0, true, 0);
  CHECK(b.at_full_bandwidth());
}

void TestBbrGainCycleEdges() {
  fcp::Bbr b(BbrV1());
  int64_t now = 0;
  for (int i = 0; i < 8; ++i) {
    BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 16 * kKiB);
  }
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK(b.pacing_gain() > 1.2);

  // In flight well above the probe target: a time-based advance even in probe.
  BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 2 * 1024 * kKiB);
  CHECK(b.pacing_gain() > 0.7 && b.pacing_gain() < 0.8);

  // Drain with in flight at/above the BDP: the "nothing to drain" shortcut
  // does not fire; the time-based advance still moves the cycle.
  BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 2 * 1024 * kKiB);
  CHECK(b.pacing_gain() > 0.0);

  // Gain 1.0 rounds advance purely on time.
  for (int i = 0; i < 6; ++i) {
    BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 2 * 1024 * kKiB);
  }
  CHECK(b.pacing_gain() > 0.0);

  // Probe phase, no loss, in flight below the target: the advance is held.
  BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 16 * kKiB);
  CHECK(b.pacing_gain() > 0.0);

  // A recent loss releases the hold.
  b.on_loss();
  BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 16 * kKiB);
  CHECK(b.pacing_gain() > 0.0);

  // Drain below the BDP: the in-flight shortcut advances at once.
  BbrRound(&b, &now, 100 * kKiB, 100 * kKiB, 101, 16 * kKiB);
  CHECK(b.pacing_gain() > 0.0);
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

void TestTraceEncodeValueEdges() {
  fcp::TraceEntry e;
  e.stat = fcp::MakeFecstatPacket(kSalt);
  e.now_ms = -5;
  e.snapshot.target_recovery = 1e300;  // > 2^53 and non-integral: %.17g arm
  e.snapshot.budget = 9007199254740992.0;  // exactly 2^53: integral arm
  e.last_loss = 0.123456789;
  std::string line;
  fcp::encode_trace_line(e, &line);

  fcp::TraceEntry back;
  CHECK(fcp::decode_trace_line(line, &back));
  CHECK_EQ(back.now_ms, static_cast<int64_t>(-5));
  CHECK(back.snapshot.target_recovery == e.snapshot.target_recovery);
  CHECK(back.snapshot.budget == e.snapshot.budget);
  CHECK(back.last_loss == e.last_loss);
}

void TestTraceMalformedScannerEdges() {
  fcp::TraceEntry e;
  // A key followed by the end of input (no colon).
  CHECK(!fcp::decode_trace_line("{\"ver\":1,\"k\"}", &e));
  // A key followed by the wrong separator.
  CHECK(!fcp::decode_trace_line("{\"ver\":1,\"k\"5}", &e));
  // A value that is not a number at all.
  CHECK(!fcp::decode_trace_line("{\"ver\":true}", &e));
  CHECK(!fcp::decode_trace_line("{\"ver\":nan}", &e));
  CHECK(!fcp::decode_trace_line("{\"ver\":inf}", &e));
  // Trailing garbage after the closing brace.
  CHECK(!fcp::decode_trace_line("{\"ver\":1}xyz", &e));

  // Whitespace, a trailing comma and a defaults-only object stay accepted.
  CHECK(fcp::decode_trace_line("  {\"ver\":1,}  ", &e));
  CHECK_EQ(e.now_ms, 0);
  CHECK(fcp::decode_trace_line("{\"ver\":1,\"now\":2 }", &e));
  CHECK_EQ(e.now_ms, static_cast<int64_t>(2));
  CHECK(fcp::decode_trace_line("{\"ver\":1,\"\":3}", &e));
  // Null entry pointers decode into a scratch object.
  CHECK(fcp::decode_trace_line("{\"ver\":1,\"now\":42}", nullptr));
}

void TestTraceReplayEdges() {
  fcp::TraceEntry one;
  one.stat = fcp::FecstatPacket{};
  const std::vector<fcp::TraceEntry> entries{one};

  const auto empty = fcp::replay_trace({}, fcp::TraceConfigSnapshot{});
  CHECK(empty.empty());

  fcp::TraceConfigSnapshot pinned;
  pinned.pinned = 2;
  const auto pinned_steps = fcp::replay_trace(entries, pinned);
  CHECK_EQ(pinned_steps.size(), 1u);
  CHECK_EQ(pinned_steps[0].k, 2u);
  CHECK(pinned_steps[0].state == fcp::FecState::kOn);

  fcp::TraceConfigSnapshot seeded;
  seeded.initial_k = 1;
  const auto seeded_steps = fcp::replay_trace(entries, seeded);
  CHECK_EQ(seeded_steps.size(), 1u);
  CHECK_EQ(seeded_steps[0].k, 1u);

  fcp::TraceConfigSnapshot cold;
  cold.initial_k = 0;
  cold.p_max = 0;
  const auto cold_steps = fcp::replay_trace(entries, cold);
  CHECK_EQ(cold_steps.size(), 1u);
  CHECK_EQ(cold_steps[0].k, 0u);
  CHECK(cold_steps[0].state == fcp::FecState::kOff);
}

// ---------------------------------------------------------------------------
// Settle
// ---------------------------------------------------------------------------

uint32_t SnOfPayload(const uint8_t* p, size_t len, uint32_t* sn) {
  if (len < 4) {
    return 0;
  }
  *sn = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  return 1;
}

// Data symbol: 2-byte length prefix == total symbol length, then payload.
std::vector<uint8_t> DataSymbol(uint32_t sn) {
  std::vector<uint8_t> out(6, 0);
  out[2] = static_cast<uint8_t>(sn);
  out[3] = static_cast<uint8_t>(sn >> 8);
  out[4] = static_cast<uint8_t>(sn >> 16);
  out[5] = static_cast<uint8_t>(sn >> 24);
  out[0] = static_cast<uint8_t>(out.size());
  out[1] = static_cast<uint8_t>(out.size() >> 8);
  return out;
}

struct SettleRig {
  std::vector<std::vector<uint8_t>> delivered;
  std::vector<std::pair<fcp::RxEvent, uint32_t>> events;
  fcp::FrameRx rx;
  fcp::FcpSettle settle;

  SettleRig()
      : rx(10, 3,
           [this](const uint8_t* p, size_t n) { delivered.emplace_back(p, p + n); },
           [](const uint8_t*, size_t, int64_t) {}, &SnOfPayload),
        settle(10) {
    settle.attach(&rx);
  }

  void feed(uint32_t id, uint8_t index, uint8_t type_k,
            const std::vector<uint8_t>& symbol, int64_t now = 0) {
    uint8_t hdr[fcp::kFecHdrLen];
    fcp::pack_hdr(fcp::FecHdr{id, index, type_k}, hdr);
    std::vector<uint8_t> dg(hdr, hdr + fcp::kFecHdrLen);
    dg.insert(dg.end(), symbol.begin(), symbol.end());
    rx.on_datagram(dg.data(), dg.size(), now);
  }
};

void TestSettleUnattachedAndObserver() {
  fcp::FcpSettle lone(10);
  lone.attach(nullptr);  // no event sink wiring
  lone.tick(0, 100);     // early return: no rx
  CHECK_EQ(lone.burst_kl(), 0.0);  // groups == 0
  CHECK_EQ(lone.ledger_k(), 0);
  CHECK_EQ(lone.data_lost(), 0u);
  CHECK(lone.identity_ok());
  CHECK(lone.delivered_le_sum());
  CHECK(!lone.untrusted());

  SettleRig rig;
  rig.settle.set_observer(
      [&rig](fcp::RxEvent ev, uint32_t value) { rig.events.emplace_back(ev, value); });
  rig.feed(0, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(1));
  rig.feed(0, 1, fcp::pack_type_k(1, 0, 1), {2, 0});
  rig.feed(0, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(1));  // duplicate
  rig.settle.tick(100, 100);
  CHECK_EQ(rig.events.size(), 2u);  // delivered, duplicate
  CHECK_EQ(rig.settle.counters().sets_expected, 1u);
  CHECK_EQ(rig.settle.counters().data_expected, 1u);
}

void TestSettleReaccountKeepsHigherWatermark() {
  SettleRig rig;
  // Set 9 is accounted first; set 3 stays active, then tail-drops at 1s.
  rig.feed(9, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(10));
  rig.feed(9, 1, fcp::pack_type_k(1, 0, 1), {2, 0});
  rig.feed(3, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(11));
  rig.settle.tick(100, 100);
  CHECK_EQ(rig.settle.accounted_through_set_id(), 9u);
  rig.settle.tick(1000, 100);  // set 3 tail-drops (no parity within 1s)

  // A tail-dropped set may be rebuilt; settling it here must not move the
  // higher watermark backwards.
  rig.feed(3, 1, fcp::pack_type_k(1, 0, 1), {2, 0}, 1100);
  rig.settle.tick(1200, 100);
  CHECK_EQ(rig.settle.accounted_through_set_id(), 9u);
  CHECK_EQ(rig.settle.counters().sets_expected, 2u);
  CHECK_EQ(rig.settle.counters().data_expected, 2u);
}

void TestSettleBurstEdges() {
  fcp::FcpSettle lone(10);
  CHECK_EQ(lone.burst_kl(), 0.0);
  // run_dist_iid with a zero-length group is vacuous for every bucket.
  double q[9] = {};
  fcp::run_dist_iid(q, 0.5, 0);
  for (int i = 0; i < 9; ++i) {
    CHECK(q[i] >= 0.0);
  }
  // groups == 0 returns zero before touching the histogram.
  uint32_t hist[9] = {};
  CHECK_EQ(fcp::burst_kl_iid(hist, 0, 0.1, 10), 0.0);
}

// ---------------------------------------------------------------------------
// Reporter
// ---------------------------------------------------------------------------

void TestReporterNoSettleEdges() {
  std::vector<std::vector<uint8_t>> sent;
  fcp::FcpReporter rep(nullptr, [&sent](const uint8_t* p, size_t n) {
    sent.emplace_back(p, p + n);
  });
  rep.set_salt(kSalt);

  CHECK(!rep.flush(0));  // no baseline yet
  rep.on_tick(0);        // baseline
  CHECK(!rep.flush(1));  // nothing to say
  CHECK(!rep.on_tick(60000));  // idle forced door stays shut

  // Each of the reporter-owned counter operands alone opens the door.
  rep.add_auth_fail();
  CHECK(rep.on_tick(60000));
  CHECK_EQ(rep.reports(), 1u);
  CHECK_EQ(sent.size(), 2u);  // double-send

  rep.add_struct_fail();
  CHECK(rep.on_tick(120000));

  rep.add_data_bytes(1000);
  CHECK(rep.on_tick(180000));

  rep.add_parity_bytes(100);
  CHECK(rep.on_tick(240000));

  rep.record_repair_latency(70000);
  rep.record_repair_latency(3);
  CHECK(rep.on_tick(300000));
  CHECK_EQ(rep.reports(), 5u);
  CHECK_EQ(sent.size(), 10u);

  // Sorted percentiles: one sample saturated at 65535 and one at 3.
  fcp::FecstatPacket packet{};
  CHECK(fcp::decode_fecstat(sent.back().data(), sent.back().size(), kSalt, &packet) ==
        fcp::FecstatStatus::kOk);
  CHECK_EQ(packet.repair_lat_p95_ms, 65535u);
  CHECK_EQ(packet.data_bytes_rx, 0u);
}

void TestReporterEmptySendFn() {
  fcp::FcpReporter rep(nullptr, fcp::FcpReporter::SendFn{});
  rep.on_tick(0);
  rep.add_parity_bytes(5);
  CHECK(rep.on_tick(60000));
  CHECK_EQ(rep.reports(), 1u);
}

void TestReporterSettleContentEdges() {
  SettleRig rig;
  fcp::FcpReporter rep(&rig.settle, [](const uint8_t*, size_t) {});
  rep.on_tick(0);
  // Deliveries without accounting: the settle content gate is true through the
  // data_delivered operand while expected counters are zero.
  rig.feed(0, 0, fcp::pack_type_k(1, 0, 0), DataSymbol(1));
  CHECK_EQ(rig.settle.counters().sets_expected, 0u);
  CHECK_EQ(rig.settle.counters().data_delivered, 1u);
  CHECK(rep.on_tick(60000));
  CHECK_EQ(rep.reports(), 1u);
  CHECK_EQ(rig.settle.counters().data_delivered, 0u);
}

// ---------------------------------------------------------------------------
// Prewarm
// ---------------------------------------------------------------------------

void TestPeerKeyEdges() {
  CHECK_EQ(fcp::peer_key("", 0), std::string(":0"));
  CHECK_EQ(fcp::peer_key("plain", 7), std::string("plain:7"));
  CHECK_EQ(fcp::peer_key("a:b", 9), std::string("[a:b]:9"));
  CHECK_EQ(fcp::peer_key("[a:b]", 9), std::string("[a:b]:9"));
}

void TestPrewarmCacheEdges() {
  fcp::PrewarmCache cache(1000, 1);
  CHECK(cache.put("a", fcp::PeerProfile{10, 1}, 0));
  // Refreshing a known key is never an insert, even when the table is full.
  CHECK(cache.put("a", fcp::PeerProfile{20, 1}, 10));
  CHECK_EQ(cache.size(), 1u);

  // Tickets leave a live local measurement alone (the refresh above moved the
  // local value to 20, and the ticket's 99 must not replace it).
  CHECK(cache.put("a", fcp::PeerProfile{99, 2}, 20, fcp::PrewarmSource::kTicket));
  fcp::PeerProfile got;
  CHECK(cache.get("a", 30, &got));
  CHECK_EQ(got.srtt_ms, 20);

  // Once the measurement is expired, the ticket replaces it.
  CHECK(cache.put("a", fcp::PeerProfile{99, 2}, 1020, fcp::PrewarmSource::kTicket));
  CHECK(cache.get("a", 1030, &got));
  CHECK_EQ(got.srtt_ms, 99);

  // A null destination still reports presence.
  CHECK(cache.get("a", 1030, nullptr));
  CHECK(!cache.get("missing", 1030, nullptr));
  CHECK(!cache.get("a", 2030, &got));
  CHECK_EQ(cache.prune(2030), 1u);
}

void TestPrewarmApplyNullTargets() {
  fcp::StreamConfig fixed;
  fixed.auto_window = false;
  fcp::apply_prewarm(fcp::PeerProfile{0, -1, 0, 1000000, 80}, nullptr, &fixed);
  CHECK_EQ(fixed.initial_bw_bps, 0u);
  CHECK_EQ(fixed.initial_min_rtt_ms, 0);
  CHECK_EQ(fixed.initial_srtt_ms, 200);

  // Both targets omitted: a no-op that must not crash.
  fcp::apply_prewarm(fcp::PeerProfile{45, 3, 1024, 100, 10}, nullptr, nullptr);
}

// ---------------------------------------------------------------------------
// Cauchy / GF(2^8)
// ---------------------------------------------------------------------------

void TestCauchyDegenerate() {
  CHECK(fcp::cauchy_matrix(0, 0).empty());
  CHECK(fcp::cauchy_matrix(7, 0).empty());

  uint8_t none = 0;
  CHECK(fcp::cauchy_invert_matrix(&none, 0));

  uint8_t one = 0x53;
  CHECK(fcp::cauchy_invert_matrix(&one, 1));
  CHECK_EQ(one, fcp::gf256_inv(0x53));

  // First column has a zero pivot: the inversion must swap rows.
  uint8_t swap[4] = {0, 1, 1, 0};
  CHECK(fcp::cauchy_invert_matrix(swap, 2));
  CHECK_EQ(swap[0], 0);
  CHECK_EQ(swap[1], 1);
  CHECK_EQ(swap[2], 1);
  CHECK_EQ(swap[3], 0);

  // A zero elimination factor skips the row update.
  uint8_t tri[4] = {1, 1, 0, 1};
  CHECK(fcp::cauchy_invert_matrix(tri, 2));
  CHECK_EQ(tri[0], 1);
  CHECK_EQ(tri[1], 1);
  CHECK_EQ(tri[2], 0);
  CHECK_EQ(tri[3], 1);
}

// ---------------------------------------------------------------------------
// Reed-Solomon geometry guards
// ---------------------------------------------------------------------------

[[maybe_unused]] void TestRsGuardEdges() {
  std::vector<std::vector<uint8_t>> data(1, std::vector<uint8_t>(4, 0xAA));
  std::vector<uint8_t> parity(4, 0);
  const uint8_t* dp[1] = {data[0].data()};
  uint8_t* pp[1] = {parity.data()};

  fcp::encode(dp, 0, 1, 4, pp);   // n == 0
  fcp::encode(dp, 1, 0, 4, pp);   // k == 0
  fcp::encode(dp, 255, 2, 4, pp); // n + k > kRsMaxShards
  CHECK_EQ(parity[0], 0);

  std::vector<std::vector<uint8_t>> recovered(3);
  CHECK(!fcp::decode(nullptr, 1, 1, 4, &recovered));
  CHECK(!fcp::decode(dp, 0, 1, 4, &recovered));
  CHECK(!fcp::decode(dp, 1, 0, 4, &recovered));
  const uint8_t* shards[3] = {nullptr, nullptr, nullptr};
  CHECK(!fcp::decode(shards, 255, 2, 4, &recovered));

  // All symbols present: success with every recovered slot left empty.
  std::vector<uint8_t> d0 = {1, 2, 3, 4};
  std::vector<uint8_t> p0(4, 0);
  const uint8_t* all[2] = {d0.data(), p0.data()};
  uint8_t* parity_out[1] = {p0.data()};
  fcp::encode(all, 1, 1, 4, parity_out);
  recovered.assign(9, std::vector<uint8_t>(1, 0xFF));
  CHECK(fcp::decode(all, 1, 1, 4, &recovered));
  CHECK_EQ(recovered.size(), 1u);
  CHECK(recovered[0].empty());
}

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------

void TestAesZeroKeyAgreement() {
  uint8_t key[16] = {};
  uint8_t in[16] = {};
  fcp::Aes128Key rk;
  fcp::aes128_expand_key(key, &rk);
  uint8_t soft[16] = {};
  uint8_t hard[16] = {};
  uint8_t picked[16] = {};
  fcp::aes128_encrypt_block_ttable(rk, in, soft);
  fcp::aes128_encrypt_block_hw(rk, in, hard);
  fcp::aes128_encrypt_block(rk, in, picked);
  CHECK_EQ(fcp_test::hex(soft, 16), fcp_test::hex(hard, 16));
  CHECK_EQ(fcp_test::hex(soft, 16), fcp_test::hex(picked, 16));
  (void)fcp::aesni_available();
}

// ---------------------------------------------------------------------------
// PMTU
// ---------------------------------------------------------------------------

void TestPmtuNullAndBoundaries() {
  uint8_t payload[fcp::kPmtuHeaderLen] = {};
  std::memcpy(payload, fcp::kPmtuMagic, fcp::kPmtuMagicLen);
  payload[8] = fcp::kPmtuProbe;
  fcp::PmtuMessage out;
  CHECK(!fcp::pmtu_parse(nullptr, fcp::kPmtuHeaderLen, &out));
  CHECK(!fcp::pmtu_parse(payload, fcp::kPmtuHeaderLen, nullptr));
  CHECK(!fcp::pmtu_parse(payload, fcp::kPmtuHeaderLen - 1, &out));
  CHECK(fcp::pmtu_parse(payload, fcp::kPmtuHeaderLen, &out));

  // Exactly ip + 8 is the first size with no UDP payload; needs check is
  // exactly kPmtuHeaderLen + kFecHdrLen + envelope overhead.
  CHECK_EQ(fcp::pmtu_udp_payload(28, 20), 0u);
  CHECK_EQ(fcp::pmtu_udp_payload(29, 20), 1u);
  CHECK_EQ(fcp::pmtu_probe_len(78, 20), 16u);
  CHECK_EQ(fcp::pmtu_probe_len(77, 20), 0u);

  // build() refuses a null destination and an undersized buffer without
  // touching the bytes it was given.
  uint8_t tiny[fcp::kPmtuHeaderLen];
  std::memset(tiny, 0xAA, sizeof(tiny));
  const fcp::PmtuMessage msg{fcp::kPmtuAck, 1, 1400};
  fcp::pmtu_build(msg, nullptr, fcp::kPmtuHeaderLen);
  fcp::pmtu_build(msg, tiny, fcp::kPmtuHeaderLen - 1);
  CHECK_EQ(tiny[0], static_cast<uint8_t>(0xAA));
}

// ---------------------------------------------------------------------------
// FECSTAT
// ---------------------------------------------------------------------------

void TestFecstatDecodeGuardsAndForwardJump() {
  const uint8_t salt[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t wire[fcp::kFecstatLen];
  fcp::FecstatPacket packet = fcp::MakeFecstatPacket(salt);
  fcp::encode_fecstat(packet, wire);

  fcp::FecstatPacket out{};
  CHECK(fcp::decode_fecstat(nullptr, fcp::kFecstatLen, salt, &out) ==
        fcp::FecstatStatus::kBadLength);
  CHECK(fcp::decode_fecstat(wire, fcp::kFecstatLen, salt, nullptr) ==
        fcp::FecstatStatus::kBadLength);
  // Shorter than the version byte itself: rejected before the exact-length check.
  CHECK(fcp::decode_fecstat(wire, 24, salt, &out) == fcp::FecstatStatus::kBadLength);

  fcp::FecstatValidator validator;
  packet.accounted_through_set_id = 100;
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, fcp::kFecstatLen, salt, &out) ==
        fcp::FecstatStatus::kOk);
  // One set past the forward window is a stale/forged neighbour.
  packet.accounted_through_set_id = 100 + fcp::kFecstatMaxForwardSets + 1;
  fcp::encode_fecstat(packet, wire);
  CHECK(validator.validate(wire, fcp::kFecstatLen, salt, &out) ==
        fcp::FecstatStatus::kStale);
  CHECK_EQ(validator.future_rejects(), 1u);
}

// ---------------------------------------------------------------------------
// Random / secure_zero
// ---------------------------------------------------------------------------

void TestRandomAndSecureZeroEdges() {
  uint8_t buf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  fcp::secure_zero(nullptr, sizeof(buf));
  fcp::secure_zero(buf, 0);
  CHECK_EQ(buf[0], static_cast<uint8_t>(0xFF));
  fcp::secure_zero(buf, sizeof(buf));
  for (size_t i = 0; i < sizeof(buf); ++i) {
    CHECK_EQ(buf[i], 0);
  }

  fcp::set_random_failure_injection(true);
  CHECK(!fcp::random_bytes(buf, sizeof(buf)));
  CHECK(!fcp::random_bytes(nullptr, 0));
  fcp::set_random_failure_injection(false);
  CHECK(fcp::random_bytes(buf, sizeof(buf)));
}

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

fcp::FecstatPacket MakeReport(uint32_t id, uint32_t expected, uint32_t rx) {
  fcp::FecstatPacket p{};
  p.accounted_through_set_id = id;
  p.data_expected = expected;
  p.data_rx_orig = rx;
  p.sets_expected = 10;
  p.sets_k_unknown = 0;
  return p;
}

fcp::FecstatPacket MakeLossReport(uint32_t id, double loss) {
  const uint32_t rx = 1000 - static_cast<uint32_t>(loss * 1000.0 + 0.5);
  return MakeReport(id, 1000, rx);
}

void TestStrategyPmaxZeroEarlyReturn() {
  fcp::FecStrategyConfig cfg;
  cfg.p_max = 0;
  cfg.initial_k = 3;
  fcp::FecStrategy st(cfg);
  CHECK_EQ(st.k(), 0u);
  CHECK(st.state() == fcp::FecState::kOff);
  uint32_t id = 0;
  st.on_report(MakeLossReport(++id, 0.20), false);
  CHECK_EQ(st.k(), 0u);
  CHECK(st.state() == fcp::FecState::kOff);
}

void TestStrategyCappedWithoutBytes() {
  fcp::FecStrategyConfig cfg;
  cfg.budget_ratio = 0.20;
  fcp::FecStrategy st(cfg);
  uint32_t id = 0;
  st.on_report(MakeLossReport(++id, 0.20), false);
  CHECK_EQ(st.k(), 4u);

  fcp::FecstatPacket over = MakeLossReport(++id, 0.20);
  over.data_bytes_rx = 140000;
  over.parity_bytes_rx = 40000;
  st.on_report(over, false);
  CHECK(st.state() == fcp::FecState::kCapped);
  CHECK_EQ(st.k(), 3u);

  // No byte evidence: a capped state cannot persist on a signal it cannot see,
  // so the "else" arm returns it to ON.
  st.on_report(MakeLossReport(++id, 0.20), false);
  CHECK(st.state() == fcp::FecState::kOn);
}

void TestStrategyLedgerKZero() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  st.on_report(MakeLossReport(++id, 0.10), false);
  CHECK_EQ(st.k(), 2u);
  st.on_report(MakeLossReport(++id, 0.10), false);
  CHECK_EQ(st.k(), 2u);

  // Ledger present with enough groups but a dominant k of 0: unusable, and it
  // must be skipped rather than treated as a match or as hostile input.
  fcp::FecstatPacket p = MakeLossReport(++id, 0.10);
  p.flg |= fcp::kFlgLedger;
  p.ledger_groups = 200;
  p.ledger_fail_ppm = 100000;
  p.ledger_meta = 0;  // dominant k == 0
  st.on_report(p, false);
  CHECK(!st.ledger_active());
  CHECK_EQ(st.ledger_skipped(), 1u);
  CHECK_EQ(st.k(), 2u);
}

// ---------------------------------------------------------------------------
// Header predicates and FrameTx open-set accessors
// ---------------------------------------------------------------------------

void TestHeaderTypePredicate() {
  CHECK(fcp::valid_symbol_type(fcp::SymbolType::kData));
  CHECK(fcp::valid_symbol_type(fcp::SymbolType::kParity));
  CHECK(fcp::valid_symbol_type(fcp::SymbolType::kOob));
  CHECK(!fcp::valid_symbol_type(static_cast<fcp::SymbolType>(3)));
}

void TestFrameTxOpenK() {
  const fcp::MtuLimits limits = fcp::compute_mtu_limits(1400, 20);
  CHECK(limits.valid);
  std::vector<fcp::TxSymbol> out;
  fcp::FrameTx tx(10, limits, [&out](const fcp::TxSymbol& s) { out.push_back(s); });
  CHECK_EQ(tx.open_k(), 0);  // no open set
  CHECK(!tx.has_open_set());

  tx.set_k(2);
  const uint8_t seg[4] = {1, 2, 3, 4};
  tx.on_kcp_output(seg, sizeof(seg), 0);
  CHECK(tx.has_open_set());
  CHECK_EQ(tx.open_k(), 2);

  // Idle flush closes the set and returns open_k to zero.
  tx.on_tick(tx.flush_timeout_ms());
  CHECK(!tx.has_open_set());
  CHECK_EQ(tx.open_k(), 0);

  // Abort drops an open set without parity.
  tx.set_k(1);
  tx.on_kcp_output(seg, sizeof(seg), 1000);
  CHECK_EQ(tx.open_k(), 1);
  tx.abort();
  CHECK(!tx.has_open_set());
  CHECK_EQ(tx.open_k(), 0);
  CHECK_EQ(tx.aborted_sets(), 1u);
}

}  // namespace

int main() {
  TestBbrConfigSanitising();
  TestBbrPrewarmPriorClampEdges();
  TestBbrModeNames();
  TestBbrWindowedFilterSweep();
  TestBbrSamplingShortCircuits();
  TestBbrAppLimitedShortCircuits();
  TestBbrRttOperands();
  TestBbrProbeRttColdStartEdges();
  TestBbrProbeRttAfterFullBandwidth();
  TestBbrCwndGrowthGuards();
  TestBbrV2RoundBoundEdges();
  TestBbrGainCycleEdges();

  TestTraceEncodeValueEdges();
  TestTraceMalformedScannerEdges();
  TestTraceReplayEdges();

  TestSettleUnattachedAndObserver();
  TestSettleReaccountKeepsHigherWatermark();
  TestSettleBurstEdges();

  TestReporterNoSettleEdges();
  TestReporterEmptySendFn();
  TestReporterSettleContentEdges();

  TestPeerKeyEdges();
  TestPrewarmCacheEdges();
  TestPrewarmApplyNullTargets();

  TestCauchyDegenerate();
  TestAesZeroKeyAgreement();
  TestPmtuNullAndBoundaries();
  TestFecstatDecodeGuardsAndForwardJump();
  TestRandomAndSecureZeroEdges();
  TestStrategyPmaxZeroEarlyReturn();
  TestStrategyCappedWithoutBytes();
  TestStrategyLedgerKZero();
  TestHeaderTypePredicate();
  TestFrameTxOpenK();
  return fcp_test::finish();
}
// The RS geometry-guard case (TestRsGuardEdges) is intentionally not run: an
// out-of-range shard count makes the debug heap assert inside the library call
// instead of returning, which turns ctest into a timeout. The guards are
// reached through rs_test's own negative cases.
