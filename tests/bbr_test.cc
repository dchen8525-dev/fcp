// BBR model tests (src/fcp/bbr.*). The stream-level wiring (pacing, round
// boundary, ACK feeding) is covered by stream_test's BBR cases.

#include "fcp/bbr.h"

#include "test_util.h"

namespace {

fcp::Bbr::Config TestCfg() {
  fcp::Bbr::Config c;
  c.mss = 1000;
  c.initial_cwnd = 16 * 1024;
  c.min_cwnd = 16 * 1024;
  c.max_cwnd = 1024 * 1024;
  c.initial_rtt_ms = 100;
  c.min_rtt_expiry_ms = 10000;
  c.probe_rtt_ms = 200;
  c.version = 1;
  return c;
}

fcp::Bbr::Config V2Cfg() {
  fcp::Bbr::Config c = TestCfg();
  c.version = 2;
  return c;
}

// Feed one round at a constant 1 MB/s: 100 KB acknowledged every 100ms, with
// the same amount handed to on_sent so the send-rate cap never binds.
void OneRound(fcp::Bbr* b, int64_t* now_ms, size_t bytes = 100 * 1024,
              int64_t rtt = 100, size_t in_flight = 0, bool new_round = true) {
  b->on_sent(*now_ms, bytes, in_flight);
  *now_ms += rtt;
  b->on_acked(*now_ms, bytes, rtt, new_round, in_flight);
}

void TestStartupGrowsAndExits() {
  fcp::Bbr b(TestCfg());
  int64_t now = 0;
  // The first ACK only establishes the sampling baseline; the second produces
  // the first bandwidth sample.
  b.on_sent(now, 100 * 1024, 16384);
  now += 100;
  b.on_acked(now, 100 * 1024, 100, true, 16384);
  CHECK(b.bandwidth_bps() == 0u);

  for (int i = 0; i < 2; ++i) {
    OneRound(&b, &now, 100 * 1024, 100, 16384);
  }
  const uint64_t bw = b.bandwidth_bps();
  CHECK(bw >= 900 * 1024u && bw <= 1000 * 1024u);
  CHECK(b.cwnd() > 16 * 1024u);  // startup grows by acked bytes

  // A constant path cannot grow the estimate by 25% for three rounds, so
  // startup has to hand over. Keep in flight high so DRAIN does not finish
  // sooner than the mode check we are making.
  for (int i = 0; i < 3; ++i) {
    OneRound(&b, &now, 100 * 1024, 100, 512 * 1024);
  }
  CHECK(b.at_full_bandwidth());
  CHECK(b.mode() == fcp::Bbr::Mode::kDrain);

  // DRAIN ends once in flight has fallen to the BDP (100 KB here).
  OneRound(&b, &now, 10 * 1024, 100, 50 * 1024);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK(b.pacing_gain() > 1.2 && b.pacing_gain() < 1.3);
}

void TestBandwidthSampleIsCappedBySendRate() {
  fcp::Bbr b(TestCfg());
  int64_t now = 0;
  b.on_sent(now, 10 * 1024, 16384);  // baseline interval
  now += 100;
  b.on_acked(now, 10 * 1024, 100, true, 16384);
  // ACK says 100 KB arrived in the next 100ms, but only 10 KB went on the
  // wire in that interval: ACK compression must not inflate the estimate.
  b.on_sent(now, 10 * 1024, 16384);
  now += 100;
  b.on_acked(now, 100 * 1024, 100, true, 16384);
  CHECK_EQ(b.bandwidth_bps(), 100u * 1024u);
}

void TestMinRttExpiryEntersProbeRtt() {
  fcp::Bbr b(TestCfg());
  int64_t now = 0;
  for (int i = 0; i < 4; ++i) {
    OneRound(&b, &now, 100 * 1024, 100, 16384);
  }
  CHECK(b.min_rtt_ms() == 100);

  // No new min-RTT sample for the whole expiry window: the path may have
  // changed, so BBR drains and re-measures.
  now += 10001;
  b.on_tick(now, 0);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeRtt);
  CHECK_EQ(b.cwnd(), 16 * 1024u);  // the minimum window while probing

  // The probe needs 200ms plus one round to observe an empty pipe.
  b.on_acked(now + 200, 1024, 0, true, 0);
  b.on_tick(now + 500, 0);
  CHECK(b.mode() != fcp::Bbr::Mode::kProbeRtt);
}

void TestProbeBwCyclesPacingGain() {
  fcp::Bbr::Config c = TestCfg();
  fcp::Bbr b(c);
  int64_t now = 0;
  // Keep in flight at the minimum so STARTUP exits and DRAIN finishes at once.
  for (int i = 0; i < 8; ++i) {
    OneRound(&b, &now, 100 * 1024, 101, 16 * 1024);
  }
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK(b.pacing_gain() > 1.2);  // cycle starts at 1.25

  // A probe holds until in flight reaches 1.25 x BDP, then advances to 0.75.
  OneRound(&b, &now, 100 * 1024, 101, 2 * 1024 * 1024);
  CHECK(b.pacing_gain() < 0.8);
  CHECK(b.pacing_gain() > 0.7);

  // The drain phase advances as soon as in flight falls to the BDP.
  OneRound(&b, &now, 10 * 1024, 101, 10 * 1024);
  CHECK(b.pacing_gain() > 0.9 && b.pacing_gain() < 1.1);
}

void TestPacingRateUsesCurrentBandwidth() {
  fcp::Bbr b(TestCfg());
  // Before any sample the rate is the high-gain start rate.
  const double expected0 =
      2.885 * static_cast<double>(16 * 1024) * 1000.0 / 100.0;
  CHECK(b.pacing_rate_bps() > expected0 * 0.99);
  CHECK(b.pacing_rate_bps() < expected0 * 1.01);

  int64_t now = 0;
  for (int i = 0; i < 3; ++i) {
    OneRound(&b, &now, 100 * 1024, 100, 16384);
  }
  CHECK(b.bandwidth_bps() > 0);
  CHECK(b.pacing_rate_bps() > static_cast<double>(b.bandwidth_bps()));
}

void TestV2LossShrinksInflightBounds() {
  fcp::Bbr b(V2Cfg());
  int64_t now = 0;
  for (int i = 0; i < 6; ++i) {
    OneRound(&b, &now, 100 * 1024, 101, 16 * 1024);
  }
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);
  CHECK_EQ(b.version(), 2);
  const size_t hi_before = b.inflight_hi();

  // A round that retransmitted 20% of what it sent is lossy at the 2%
  // threshold: the upper bound lands just under the in-flight that lost.
  b.on_sent(now, 100 * 1024, 200 * 1024);
  b.on_lost(20 * 1024);
  now += 101;
  b.on_acked(now, 100 * 1024, 101, true, 200 * 1024);
  CHECK(b.inflight_hi() < hi_before);
  CHECK(b.inflight_hi() <= 175u * 1024u);
  CHECK(b.cwnd() <= b.inflight_hi());
  CHECK(b.inflight_lo() > 0u);
  CHECK(b.at_full_bandwidth());
}

void TestV2ProbeUpRaisesInflightHiAfterLoss() {
  fcp::Bbr b(V2Cfg());
  int64_t now = 0;
  for (int i = 0; i < 6; ++i) {
    OneRound(&b, &now, 100 * 1024, 101, 16 * 1024);
  }
  b.on_sent(now, 100 * 1024, 200 * 1024);
  b.on_lost(20 * 1024);
  now += 101;
  b.on_acked(now, 100 * 1024, 101, true, 200 * 1024);
  const size_t hi_low = b.inflight_hi();
  CHECK(hi_low < 1024u * 1024u);

  // Clean rounds in the 1.25 probe phase may raise it again; the model must
  // let a loss-limited path recover instead of staying pinned forever.
  for (int i = 0; i < 4; ++i) {
    OneRound(&b, &now, 100 * 1024, 101, hi_low);
  }
  CHECK(b.inflight_hi() > hi_low);
}

// The WAN path this was measured on loses ~2% of segments after FEC, and
// speculative SACK fills used to be counted as loss on top of that. v2 learns
// the path's own loss rate and only cuts inflight_hi for loss above it, so a
// lossy-but-healthy path is not ratcheted down to the minimum window.
void TestV2InherentLossDoesNotCollapseInflightHi() {
  fcp::Bbr b(V2Cfg());
  int64_t now = 0;
  for (int i = 0; i < 6; ++i) {
    OneRound(&b, &now, 100 * 1024, 101, 16 * 1024);
  }
  for (int i = 0; i < 12; ++i) {
    b.on_sent(now, 100 * 1024, 200 * 1024);
    b.on_lost(15 * 1024);
    now += 101;
    b.on_acked(now, 100 * 1024, 101, true, 200 * 1024);
  }
  const size_t hi_steady = b.inflight_hi();
  CHECK(hi_steady > 64 * 1024u);  // learned as inherent, not congestion

  // A round well above the path's floor is still congestion evidence: the
  // bound moves below the in-flight that produced the loss.
  b.on_sent(now, 100 * 1024, 100 * 1024);
  b.on_lost(45 * 1024);
  now += 101;
  b.on_acked(now, 100 * 1024, 101, true, 100 * 1024);
  CHECK(b.inflight_hi() < hi_steady);
  CHECK(b.inflight_lo() > 0u);
}

void TestAppLimitedSamplesDoNotRaiseTheEstimate() {
  fcp::Bbr b(TestCfg());
  int64_t now = 0;
  for (int i = 0; i < 4; ++i) {
    OneRound(&b, &now, 100 * 1024, 100, 16384);
  }
  const uint64_t before = b.bandwidth_bps();
  CHECK(before > 0);

  // Nothing to send: the next interval's rate says more about the application
  // than about the path, so a low sample must not replace the estimate.
  b.on_app_limited(now);
  b.on_sent(now, 10 * 1024, 0);
  now += 100;
  b.on_acked(now, 10 * 1024, 100, true, 0);
  CHECK_EQ(b.bandwidth_bps(), before);
}

}  // namespace

// Prewarm prior: a new connection to a peer we already measured starts in
// PROBE_BW at the proven operating point instead of re-running STARTUP from the
// default window. The seeded minimum RTT is provisional -- the first live
// sample replaces it even when it is larger, because the path may have changed.
void TestPrewarmPriorStartsAtTheProvenPoint() {
  fcp::Bbr::Config c = TestCfg();
  c.max_cwnd = 4 * 1024 * 1024;
  c.min_cwnd = 64 * 1024;
  c.initial_bw_bps = 20u * 1000u * 1000u;  // 20 MB/s
  c.initial_min_rtt_ms = 100;              // -> 2 MB BDP
  fcp::Bbr b(c);
  CHECK(b.mode() == fcp::Bbr::Mode::kProbeBw);  // no STARTUP re-run
  CHECK_EQ(b.bandwidth_bps(), 20u * 1000u * 1000u);
  CHECK(b.cwnd() >= 2u * 1000u * 1000u);
  CHECK(b.cwnd() <= c.max_cwnd);

  // Provisional minimum: the first sample wins even though it is slower.
  b.on_acked(1000, 1000, 300, true, 0);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(300));
}

// No prior means the old cold start: STARTUP from the initial window, with the
// model's own minimum still unset.
void TestColdStartStillRunsStartup() {
  fcp::Bbr b(TestCfg());
  CHECK(b.mode() == fcp::Bbr::Mode::kStartup);
  CHECK_EQ(b.bandwidth_bps(), 0u);
  CHECK_EQ(b.min_rtt_ms(), static_cast<int64_t>(100));  // initial_rtt_ms
}

int main() {
  TestStartupGrowsAndExits();
  TestBandwidthSampleIsCappedBySendRate();
  TestMinRttExpiryEntersProbeRtt();
  TestProbeBwCyclesPacingGain();
  TestPacingRateUsesCurrentBandwidth();
  TestV2LossShrinksInflightBounds();
  TestV2ProbeUpRaisesInflightHiAfterLoss();
  TestV2InherentLossDoesNotCollapseInflightHi();
  TestAppLimitedSamplesDoNotRaiseTheEstimate();
  TestPrewarmPriorStartsAtTheProvenPoint();
  TestColdStartStillRunsStartup();
  return fcp_test::finish();
}
