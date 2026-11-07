// Redundancy strategy (协议规格.md §8).
//
// B1: binom_cdf / k_for, the pure part.
// B2: FecStrategy, the OFF/ON state machine driven by inbound FECSTAT reports.
// The strategy only chooses k for the next set; it never touches pacing.

#ifndef FCP_STRATEGY_H_
#define FCP_STRATEGY_H_

#include <cstdint>

#include "fcp/defaults.h"
#include "fcp/fecstat.h"
#include "fcp/limits.h"

namespace fcp {

// Hard bounds from the wire format: k occupies 3 bits, so 7 is absolute —
// the value's definition moved to limits.h (单一 home，rs.h 的 assert 钉着).
// WAN calibration 2026-11-07 (see docs/决策记录.md): the international path
// runs a constant ~12% loss with evening bursts to 50%+; k=1..3 parity could
// not cover it and the ceiling capped the controller below the binomial
// target. 6 lets the adaptive machine reach k_for(15%, d=10) without --p-max.
constexpr uint8_t kDefaultPmax = 6;
// Target probability that a group needs no KCP retransmission (§8).
constexpr double kTargetRecovery = 0.80;
// P(X <= max_losses) for X ~ Binomial(trials, p).
// p is clamped to [0, 1]; trials == 0 returns 1.
double binom_cdf(unsigned max_losses, unsigned trials, double p);

// Smallest k in 1..p_max with binom_cdf(k, d + k, loss) >= target.
// Returns p_max when no k reaches the target (including loss >= 1).
uint8_t k_for(double loss, uint8_t d, uint8_t p_max, double target = kTargetRecovery);

// Inverse of binom_cdf along its (monotonically decreasing) loss argument:
// the p with binom_cdf(max_losses, trials, p) == q. Bisection; q >= 1 -> 0,
// q <= 0 -> 1. M3's R(k) correction uses it to map an empirical group-failure
// rate back to the i.i.d. loss rate that would predict it (§1.2).
double binom_p_for_cdf(unsigned max_losses, unsigned trials, double q);

// The ledger correction only fires when the interval accounted enough
// full-size groups for the failure rate to beat binomial noise: 64 groups
// keep the estimate's resolution below the k_for step granularity.
constexpr uint32_t kMinLedgerGroups = 64;

enum class FecState : uint8_t {
  kOff = 0,
  kOn = 1,
  // M3 third state (M3控制设计.md §2): the measured redundancy ratio
  // parity_bytes/data_bytes exceeded the byte budget. k only declines here
  // (one parity per report, floor 1); one report back under the ceiling
  // returns to ON. Entered from and exited to ON only.
  kCapped = 2,
};

// §10-style log name; keeps session.cc free of a per-state switch.
const char* fec_state_name(FecState state);

struct FecStrategyConfig {
  uint8_t d = kDefaultD;  // 对抗分析第九轮：与 SessionConfig 的 d 同一处定义
  uint8_t p_max = kDefaultPmax;
  double target_recovery = kTargetRecovery;
  int pinned_k = -1;  // --fec-parity-pinned; >= 0 bypasses the state machine
  // Link warm-up (M2代理设计.md §5): -1 starts OFF like every M1 session,
  // >= 1 starts ON at that k. Reports still drive the machine, so a warmed
  // value only buys the first few seconds and converges away if the link lost
  // its habit.
  int initial_k = -1;
  // M3 byte budget (M3控制设计.md §2): ceiling on the interval's
  // parity_bytes/data_bytes ratio; 0 disables. On the wire that ratio is k/D
  // (parity and data packets cost the same bytes), so the 0.50 default
  // leaves k <= 5 untouched at D = 10 and only constrains the k = 6..7
  // extremes — the #28 replay test caught the original 0.40 default binding
  // exactly at k = 4, the 20%-loss operating point.
  double budget_ratio = kDefaultFecBudget;
};

class FecStrategy {
 public:
  explicit FecStrategy(const FecStrategyConfig& config = FecStrategyConfig());

  // One accepted FECSTAT report. window_queued is
  // (srtt - min_rtt >= 40ms) from the window strategy on this report's tick.
  void on_report(const FecstatPacket& stat, bool window_queued);

  uint8_t k() const { return k_; }
  FecState state() const { return state_; }
  bool pinned() const { return pinned_k_ >= 0; }

  // The k the machine was seeded with, or -1 for a cold OFF start. Diagnostics
  // only: nothing reads it after construction.
  int initial_k() const { return initial_k_; }

  // Diagnostics for the §11 log line.
  double last_loss() const { return last_loss_; }
  double target_recovery() const { return target_recovery_; }
  uint32_t untrusted_reports() const { return untrusted_reports_; }
  uint32_t stale_reports() const { return stale_reports_; }
  uint32_t small_sample_reports() const { return small_sample_reports_; }

  // M3 R(k) correction diagnostics: whether the last ON-state report carried
  // a usable ledger (and the p_eff it produced), plus how many reports were
  // applied vs gated out. `skipped` counts only bit3-bearing reports that
  // failed a gate — a pre-M3 peer without the bit is normal, not a skip.
  bool ledger_active() const { return have_p_eff_; }
  double last_p_eff() const { return last_p_eff_; }
  uint32_t ledger_reports() const { return ledger_reports_; }
  uint32_t ledger_skipped() const { return ledger_skipped_; }

 private:
  void enter_on(double loss);
  void enter_off();
  void update_p_eff(const FecstatPacket& stat);

  uint8_t d_;
  uint8_t p_max_;
  double target_recovery_;
  int pinned_k_;
  int initial_k_;
  double budget_ratio_;  // clamped at construction; <= 0 means off

  FecState state_ = FecState::kOff;
  uint8_t k_ = 0;

  bool have_last_ = false;
  uint32_t last_set_id_ = 0;
  double last_loss_ = 0.0;

  unsigned consec_ge_08_ = 0;
  unsigned clean_streak_ = 0;
  unsigned queued_streak_ = 0;
  unsigned cooldown_reports_ = 0;

  uint32_t untrusted_reports_ = 0;
  uint32_t stale_reports_ = 0;
  uint32_t small_sample_reports_ = 0;

  // R(k) correction state (one report of memory; the ±1 rate limiter does the
  // smoothing, so no EWMA on top).
  bool have_p_eff_ = false;
  double last_p_eff_ = 0.0;
  uint32_t ledger_reports_ = 0;
  uint32_t ledger_skipped_ = 0;
};

}  // namespace fcp

#endif  // FCP_STRATEGY_H_
