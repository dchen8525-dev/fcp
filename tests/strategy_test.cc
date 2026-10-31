#include "fcp/strategy.h"

#include "test_util.h"

namespace {

fcp::FecstatPacket Report(uint32_t set_id, uint32_t expected, uint32_t rx_orig,
                          uint32_t sets_expected = 10, uint32_t k_unknown = 0) {
  fcp::FecstatPacket p{};
  p.accounted_through_set_id = set_id;
  p.data_expected = expected;
  p.data_rx_orig = rx_orig;
  p.sets_expected = sets_expected;
  p.sets_k_unknown = k_unknown;
  return p;
}

// A 1000-packet interval with the given loss.
fcp::FecstatPacket LossReport(uint32_t set_id, double loss) {
  const uint32_t rx = 1000 - static_cast<uint32_t>(loss * 1000.0 + 0.5);
  return Report(set_id, 1000, rx);
}

void Feed(fcp::FecStrategy* st, uint32_t* set_id, double loss, bool queued = false) {
  st->on_report(LossReport(++*set_id, loss), queued);
}

// ON at 20% (k = 4) then five clean reports -> OFF.
void DriveToOff(fcp::FecStrategy* st, uint32_t* set_id) {
  Feed(st, set_id, 0.20);
  for (int i = 0; i < 5; ++i) {
    Feed(st, set_id, 0.002);
  }
  CHECK(st->state() == fcp::FecState::kOff);
  CHECK_EQ(st->k(), 0);
}

void TestOffToOn() {
  fcp::FecStrategy st;
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.k(), 0);

  uint32_t id = 0;
  Feed(&st, &id, 0.02);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 1);

  fcp::FecStrategy st2;
  id = 0;
  Feed(&st2, &id, 0.20);
  CHECK(st2.state() == fcp::FecState::kOn);
  CHECK_EQ(st2.k(), 4);  // no per-report step limit on entry

  fcp::FecStrategy st3;
  id = 0;
  Feed(&st3, &id, 0.10);
  CHECK_EQ(st3.k(), 2);
}

void TestTwoReportEntry() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  Feed(&st, &id, 0.009);
  CHECK(st.state() == fcp::FecState::kOff);
  Feed(&st, &id, 0.009);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 1);

  // A dip below 0.8% restarts the count.
  fcp::FecStrategy st2;
  id = 0;
  Feed(&st2, &id, 0.009);
  Feed(&st2, &id, 0.007);
  Feed(&st2, &id, 0.009);
  CHECK(st2.state() == fcp::FecState::kOff);
  Feed(&st2, &id, 0.009);
  CHECK(st2.state() == fcp::FecState::kOn);
}

void TestPerReportStep() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  Feed(&st, &id, 0.20);  // k = 4
  CHECK_EQ(st.k(), 4);
  Feed(&st, &id, 0.02);
  CHECK_EQ(st.k(), 3);
  Feed(&st, &id, 0.02);
  CHECK_EQ(st.k(), 2);
  Feed(&st, &id, 0.02);
  CHECK_EQ(st.k(), 1);
  Feed(&st, &id, 0.02);
  CHECK_EQ(st.k(), 1);

  // Increase is also capped at one per report.
  fcp::FecStrategy st2;
  id = 0;
  Feed(&st2, &id, 0.02);  // k = 1
  Feed(&st2, &id, 0.20);
  CHECK_EQ(st2.k(), 2);
  Feed(&st2, &id, 0.20);
  CHECK_EQ(st2.k(), 3);
}

void TestQueuedGuard() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  Feed(&st, &id, 0.20);  // k = 4
  Feed(&st, &id, 0.20, true);
  CHECK_EQ(st.k(), 4);  // 1 queued report: no grow, target equal
  Feed(&st, &id, 0.20, true);
  CHECK_EQ(st.k(), 4);
  Feed(&st, &id, 0.20, true);
  CHECK_EQ(st.k(), 3);  // 3 queued reports: forced k - 1

  // A report without queueing resets the streak.
  Feed(&st, &id, 0.20);
  CHECK_EQ(st.k(), 4);
  Feed(&st, &id, 0.20, true);
  Feed(&st, &id, 0.20, true);
  CHECK_EQ(st.k(), 4);
  Feed(&st, &id, 0.20, true);
  CHECK_EQ(st.k(), 3);

  // Decreasing while queued is allowed (only growth is blocked).
  fcp::FecStrategy st2;
  id = 0;
  Feed(&st2, &id, 0.20);  // k = 4
  Feed(&st2, &id, 0.02, true);
  CHECK_EQ(st2.k(), 3);

  // The floor is 1.
  fcp::FecStrategy st3;
  id = 0;
  Feed(&st3, &id, 0.02);  // k = 1
  for (int i = 0; i < 5; ++i) {
    Feed(&st3, &id, 0.02, true);
  }
  CHECK_EQ(st3.k(), 1);
  CHECK(st3.state() == fcp::FecState::kOn);
}

void TestCleanStreak() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  Feed(&st, &id, 0.10);  // k = 2
  for (int i = 0; i < 4; ++i) {
    Feed(&st, &id, 0.002);
  }
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 1);
  Feed(&st, &id, 0.002);
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.k(), 0);

  // A non-clean report resets the streak.
  fcp::FecStrategy st2;
  id = 0;
  Feed(&st2, &id, 0.10);
  for (int i = 0; i < 4; ++i) {
    Feed(&st2, &id, 0.002);
  }
  Feed(&st2, &id, 0.010);
  for (int i = 0; i < 4; ++i) {
    Feed(&st2, &id, 0.002);
  }
  CHECK(st2.state() == fcp::FecState::kOn);
  Feed(&st2, &id, 0.002);
  CHECK(st2.state() == fcp::FecState::kOff);
}

void TestCooldown() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  DriveToOff(&st, &id);
  for (int i = 0; i < 3; ++i) {
    Feed(&st, &id, 0.02);
    CHECK(st.state() == fcp::FecState::kOff);
  }
  Feed(&st, &id, 0.02);
  CHECK(st.state() == fcp::FecState::kOn);

  // >= 4.5% bypasses the cooldown.
  fcp::FecStrategy st2;
  id = 0;
  DriveToOff(&st2, &id);
  Feed(&st2, &id, 0.05);
  CHECK(st2.state() == fcp::FecState::kOn);
  CHECK_EQ(st2.k(), 1);

  // The 0.8% two-report path also waits out the cooldown.
  fcp::FecStrategy st3;
  id = 0;
  DriveToOff(&st3, &id);
  Feed(&st3, &id, 0.009);
  Feed(&st3, &id, 0.009);
  Feed(&st3, &id, 0.009);
  CHECK(st3.state() == fcp::FecState::kOff);
  Feed(&st3, &id, 0.009);
  CHECK(st3.state() == fcp::FecState::kOff);  // first report after cooldown
  Feed(&st3, &id, 0.009);
  CHECK(st3.state() == fcp::FecState::kOn);
}

void TestUntrustedSample() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  // 31/300 > 10%: gate closed, even at 20% loss.
  st.on_report(Report(++id, 1000, 800, 300, 31), false);
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.untrusted_reports(), 1u);
  CHECK(st.last_loss() == 0.0);

  // Exactly 10% is still trusted.
  st.on_report(Report(++id, 1000, 800, 300, 30), false);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 4);

  // sets_expected = 0 with any unknown set is untrusted (denominator floor 1).
  fcp::FecStrategy st2;
  id = 0;
  st2.on_report(Report(++id, 1000, 800, 0, 1), false);
  CHECK(st2.state() == fcp::FecState::kOff);
  CHECK_EQ(st2.untrusted_reports(), 1u);
}

void TestSmallSample() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  st.on_report(Report(++id, 255, 100), false);
  CHECK(st.state() == fcp::FecState::kOff);
  CHECK_EQ(st.small_sample_reports(), 1u);
  st.on_report(Report(++id, 256, 200), false);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 4);
}

void TestStaleReport() {
  fcp::FecStrategy st;
  // accounted_through_set_id starts at 0 and is valid.
  st.on_report(Report(0, 1000, 980, 10, 0), false);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 1);

  // Same key: ignored, even though the payload says 0% loss.
  st.on_report(Report(0, 1000, 1000, 10, 0), false);
  CHECK_EQ(st.stale_reports(), 1u);
  CHECK_EQ(st.k(), 1);
  CHECK(st.state() == fcp::FecState::kOn);

  // Smaller key: ignored as well.
  st.on_report(Report(0, 1000, 500, 10, 0), false);
  CHECK_EQ(st.stale_reports(), 2u);
  CHECK_EQ(st.k(), 1);

  // Newer key: processed (0% loss counts toward the clean streak).
  st.on_report(Report(1, 1000, 1000, 10, 0), false);
  CHECK_EQ(st.state(), fcp::FecState::kOn);
  CHECK_EQ(st.k(), 1);
}

void TestPinned() {
  fcp::FecStrategyConfig cfg;
  cfg.pinned_k = 2;
  fcp::FecStrategy st(cfg);
  CHECK(st.pinned());
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 2);

  uint32_t id = 0;
  for (int i = 0; i < 10; ++i) {
    Feed(&st, &id, 0.50);
  }
  CHECK_EQ(st.k(), 2);
  CHECK(st.state() == fcp::FecState::kOn);
  for (int i = 0; i < 10; ++i) {
    Feed(&st, &id, 0.0);
  }
  CHECK_EQ(st.k(), 2);
  CHECK(st.state() == fcp::FecState::kOn);

  fcp::FecStrategyConfig off_cfg;
  off_cfg.pinned_k = 0;
  fcp::FecStrategy st2(off_cfg);
  CHECK(st2.pinned());
  CHECK_EQ(st2.k(), 0);
  id = 0;
  Feed(&st2, &id, 0.20);
  CHECK_EQ(st2.k(), 0);
  CHECK(st2.state() == fcp::FecState::kOff);

  fcp::FecStrategyConfig big_cfg;
  big_cfg.pinned_k = 9;
  fcp::FecStrategy st3(big_cfg);
  CHECK_EQ(st3.k(), fcp::kDefaultPmax);  // clamped to p_max, not just 3 bits

  fcp::FecStrategyConfig six_cfg;
  six_cfg.p_max = 6;
  six_cfg.pinned_k = 9;
  fcp::FecStrategy st4(six_cfg);
  CHECK_EQ(st4.k(), 6);
}

void TestKInvariant() {
  // While ON, k never leaves 1..Pmax.
  fcp::FecStrategy st;
  uint32_t id = 0;
  Feed(&st, &id, 0.30);
  for (int i = 0; i < 200; ++i) {
    const double loss = (i % 7 == 0) ? 0.0005 : ((i * 37) % 1000) / 4000.0;
    // Cycle queued/unqueue to exercise both branches.
    st.on_report(LossReport(++id, loss), (i % 5) == 0);
    if (st.state() == fcp::FecState::kOn) {
      CHECK(st.k() >= 1);
      CHECK(st.k() <= fcp::kDefaultPmax);
    } else {
      CHECK_EQ(st.k(), 0);
    }
  }
}

}  // namespace

// A report carrying the M3 ledger (FCP_M3_CONTROL.md §1.2). fail_rate is the
// empirical share of full-size groups with >= 1 unrecovered data.
fcp::FecstatPacket LedgerReport(uint32_t set_id, double loss, uint32_t groups,
                                double fail_rate, uint8_t ledger_k,
                                bool with_flag = true) {
  fcp::FecstatPacket p = LossReport(set_id, loss);
  if (with_flag) {
    p.flg |= fcp::kFlgLedger;
  }
  p.ledger_groups = groups;
  p.ledger_fail_ppm = static_cast<uint32_t>(fail_rate * 1000000.0 + 0.5);
  p.ledger_meta = ledger_k;
  return p;
}

// ON at k = 2 (loss 10%), then one plain report so the steady state is
// established with the entry report out of the way.
void DriveToK2(fcp::FecStrategy* st, uint32_t* id) {
  Feed(st, id, 0.10);
  CHECK(st->state() == fcp::FecState::kOn);
  CHECK_EQ(st->k(), 2);
  Feed(st, id, 0.10);
  CHECK_EQ(st->k(), 2);
}

// Empirical failure worse than the i.i.d. prediction must lift k: the ledger
// maps to p_eff > p_observed, and k_for acts on the larger input.
void TestLedgerLiftsK() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  DriveToK2(&st, &id);
  // Bursty link: 26.4% of k=2 groups keep a hole where i.i.d. 15% loss would
  // produce the same failure rate.
  const double bursty_fail = 1.0 - fcp::binom_cdf(2, 12, 0.15);
  st.on_report(LedgerReport(++id, 0.10, 200, bursty_fail, 2), false);
  CHECK(st.ledger_active());
  CHECK(st.last_p_eff() > 0.149 && st.last_p_eff() < 0.151);
  CHECK_EQ(st.k(), 3);  // k_for(0.15) = 3, one step up
}

// Better-than-i.i.d. ledger must not push k down: the correction is
// one-sided, a good interval is treated as luck (§1.2).
void TestLedgerOneSided() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  DriveToK2(&st, &id);
  const double lucky_fail = 1.0 - fcp::binom_cdf(2, 12, 0.05);
  st.on_report(LedgerReport(++id, 0.10, 200, lucky_fail, 2), false);
  CHECK(st.ledger_active());
  CHECK(st.last_p_eff() < 0.10);
  CHECK_EQ(st.k(), 2);  // p_use stays at the observed 10%
}

// i.i.d. link: the ledger's own answer reproduces the observed loss, so k
// holds steady — the correction degenerates to identity.
void TestLedgerIidStable() {
  fcp::FecStrategy st;
  uint32_t id = 0;
  DriveToK2(&st, &id);
  const double iid_fail = 1.0 - fcp::binom_cdf(2, 12, 0.10);
  for (int i = 0; i < 5; ++i) {
    st.on_report(LedgerReport(++id, 0.10, 200, iid_fail, 2), false);
    CHECK(st.ledger_active());
    CHECK(st.last_p_eff() > 0.099 && st.last_p_eff() < 0.101);
    CHECK_EQ(st.k(), 2);
  }
}

void TestLedgerGates() {
  // Too few groups: the failure rate carries no signal.
  fcp::FecStrategy st;
  uint32_t id = 0;
  DriveToK2(&st, &id);
  const double bursty_fail = 1.0 - fcp::binom_cdf(2, 12, 0.20);
  st.on_report(LedgerReport(++id, 0.10, fcp::kMinLedgerGroups - 1, bursty_fail, 2),
               false);
  CHECK(!st.ledger_active());
  CHECK_EQ(st.ledger_skipped(), 1u);
  CHECK_EQ(st.k(), 2);

  // Dominant k does not match the k we run: unusable, not hostile.
  st.on_report(LedgerReport(++id, 0.10, 200, bursty_fail, 3), false);
  CHECK(!st.ledger_active());
  CHECK_EQ(st.ledger_skipped(), 2u);
  CHECK_EQ(st.k(), 2);

  // No bit3 (pre-M3 peer): ignored entirely, not a skip.
  const uint32_t skipped_before = st.ledger_skipped();
  st.on_report(LedgerReport(++id, 0.10, 200, bursty_fail, 2, false), false);
  CHECK(!st.ledger_active());
  CHECK_EQ(st.ledger_skipped(), skipped_before);
  CHECK_EQ(st.ledger_reports(), 0u);
  CHECK_EQ(st.k(), 2);
}

// --- M3 byte budget / kCapped (FCP_M3_CONTROL.md §2) ---

constexpr uint32_t kDataBytes = 140000;  // ~1000 full-size data packets
constexpr uint32_t kParityAtK4 = 40000;  // ratio 2/7 ≈ 28.6% > 20% budget

fcp::FecStrategyConfig BudgetConfig(double ratio) {
  fcp::FecStrategyConfig c;
  c.budget_ratio = ratio;
  return c;
}

// A fresh report per feed — the monotonic key rejects a repeated set_id.
fcp::FecstatPacket BudgetReport(uint32_t set_id, double loss, uint32_t parity_bytes) {
  fcp::FecstatPacket p = LossReport(set_id, loss);
  p.data_bytes_rx = kDataBytes;
  p.parity_bytes_rx = parity_bytes;
  return p;
}

// Over the ceiling the state enters CAPPED and sheds one parity per report
// regardless of k_target, until a report measures back under.
void TestBudgetEntersCapped() {
  fcp::FecStrategy st(BudgetConfig(0.20));
  uint32_t id = 0;
  Feed(&st, &id, 0.20);  // k = 4, no byte signal on the entry report
  CHECK_EQ(st.k(), 4);

  st.on_report(BudgetReport(++id, 0.20, kParityAtK4), false);
  CHECK(st.state() == fcp::FecState::kCapped);
  CHECK_EQ(st.k(), 3);  // budget wins over k_target (= 4 at 20% loss)

  st.on_report(BudgetReport(++id, 0.20, kParityAtK4), false);
  CHECK_EQ(st.k(), 2);
  st.on_report(BudgetReport(++id, 0.20, kParityAtK4), false);
  CHECK_EQ(st.k(), 1);
  // Floor: §14.11 — congestion pressure never returns k to 0.
  st.on_report(BudgetReport(++id, 0.20, kParityAtK4), false);
  CHECK(st.state() == fcp::FecState::kCapped);
  CHECK_EQ(st.k(), 1);
}

// One report under the ceiling returns to ON without stepping; the next
// report resumes normal ±1 movement (k may rise again).
void TestBudgetRecoveryHysteresis() {
  fcp::FecStrategy st(BudgetConfig(0.20));
  uint32_t id = 0;
  Feed(&st, &id, 0.20);
  st.on_report(BudgetReport(++id, 0.20, kParityAtK4), false);
  CHECK(st.state() == fcp::FecState::kCapped);
  CHECK_EQ(st.k(), 3);

  st.on_report(BudgetReport(++id, 0.20, 28000), false);  // ratio 20% — not over
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 3);  // hysteresis report moves nothing

  st.on_report(BudgetReport(++id, 0.20, 28000), false);
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 4);  // k_for(0.20) = 4, normal stepping restored
}

// The red line: after convergence the measured ratio respects the budget.
// R = 0.10 admits at most k = 1 (1/11 ≈ 9.1%); the walk-down is monotone.
void TestBudgetConvergesUnderCeiling() {
  fcp::FecStrategy st(BudgetConfig(0.10));
  uint32_t id = 0;
  Feed(&st, &id, 0.20);  // k = 4
  for (int round = 0; round < 10; ++round) {
    // The peer reports the traffic actually sent at the current k: ratio ≈ k/10.
    st.on_report(BudgetReport(++id, 0.20, static_cast<uint32_t>(st.k()) * 14000), false);
    if (st.state() == fcp::FecState::kOn) {
      CHECK(static_cast<double>(st.k()) / 10.0 <= 0.10 + 1e-9);
      return;
    }
    CHECK(st.state() == fcp::FecState::kCapped);
    CHECK(st.k() >= 1);
  }
  CHECK(false);  // never converged
}

// Budget 0 disables the ceiling entirely, even with absurd ratio evidence.
void TestBudgetZeroDisables() {
  fcp::FecStrategy st(BudgetConfig(0.0));
  uint32_t id = 0;
  Feed(&st, &id, 0.20);
  st.on_report(BudgetReport(++id, 0.20, 100000000), false);  // ratio 700x
  CHECK(st.state() == fcp::FecState::kOn);
  CHECK_EQ(st.k(), 4);
}

// Degenerate budget below the k=1 floor's own ratio: k stays 1, no underflow,
// state stays CAPPED — documented boundary (§7 of the M3 doc), not a hang.
void TestBudgetFloorStaysOne() {
  fcp::FecStrategy st(BudgetConfig(0.05));
  uint32_t id = 0;
  Feed(&st, &id, 0.20);
  for (int i = 0; i < 5; ++i) {
    st.on_report(BudgetReport(++id, 0.20, 1400000), false);  // ratio 10x > 5%
    CHECK_EQ(st.k(), 1);
    CHECK(st.state() == fcp::FecState::kCapped);
  }
}

int main() {
  TestOffToOn();
  TestTwoReportEntry();
  TestPerReportStep();
  TestQueuedGuard();
  TestCleanStreak();
  TestCooldown();
  TestUntrustedSample();
  TestSmallSample();
  TestStaleReport();
  TestPinned();
  TestKInvariant();
  TestLedgerLiftsK();
  TestLedgerOneSided();
  TestLedgerIidStable();
  TestLedgerGates();
  return fcp_test::finish();
}
