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
// target. 6 keeps direct EngineConfig users (no --fec) at the historical
// ceiling; the CLI mirrors p_max to --fec's P, so P is the only ceiling there.
constexpr uint8_t kDefaultPmax = 6;
// The controller's target: k must cover the expected number of lost shards per
// group with this much headroom, i.e. k = ceil(headroom x d x loss).
//
// This replaced the binomial rule (smallest k with P(group needs no KCP
// retransmission) >= target) for two reasons, both measured rather than
// argued. First, the binomial answer has a dead band: on a path losing 16.5%
// of datagrams the sampled loss lands on the same step repeatedly, and
// whichever side of the target it falls on, k does not move -- the controller
// becomes decorative for the whole session. Second, the binomial rule is
// worst-case-shaped: it buys coverage of the full distribution, so at 20% loss
// it asks for k=4 where the mean-plus-variance answer is k=3, paying 40%
// redundancy for failure modes FEC cannot fix anyway (a group that loses more
// than k shards is lost regardless).
//
// 1.5 x the mean is the multiplier that covers bursty loss without paying for
// the worst case every group: at d=10 that is k=1/2/3/3 for 2/10/20/30% loss.
constexpr double kFecHeadroom = 1.5;
// Consecutive low-loss reports before k steps down. A FECSTAT is 2 s, so four
// samples is 8 s of evidence against one loss event -- enough that a path
// sitting on a step boundary does not flap k every report.
constexpr uint32_t kFecDropStreak = 4;
// P(X <= max_losses) for X ~ Binomial(trials, p).
// p is clamped to [0, 1]; trials == 0 returns 1.
double binom_cdf(unsigned max_losses, unsigned trials, double p);

// k the controller asks for at a measured shard-loss rate: ceil(d x loss x
// kFecHeadroom), floored at 1 and capped at p_max. One formula, no dead band:
// every sample maps to a target, so the controller always has an opinion.
uint8_t k_for(double loss, uint8_t d, uint8_t p_max);

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
  // Consecutive reports whose k target sits below the current k (see
  // kFecDropStreak). Counted separately from clean_streak_ (which measures
  // going OFF) because a step down and a full stop are different evidence.
  unsigned low_streak_ = 0;
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
