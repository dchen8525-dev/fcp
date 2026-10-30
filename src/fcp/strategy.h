// Redundancy strategy (FCP_PROTOCOL_V6.md §8).
//
// B1: binom_cdf / k_for, the pure part.
// B2: FecStrategy, the OFF/ON state machine driven by inbound FECSTAT reports.
// The strategy only chooses k for the next set; it never touches pacing.

#ifndef FCP_STRATEGY_H_
#define FCP_STRATEGY_H_

#include <cstddef>
#include <cstdint>

#include "fcp/fecstat.h"

namespace fcp {

// Hard bounds from the wire format: k occupies 3 bits, so 7 is absolute.
constexpr uint8_t kMaxParity = 7;
// M1 default; raising it to 5..7 is a config change, not a protocol change.
constexpr uint8_t kDefaultPmax = 4;
// Target probability that a group needs no KCP retransmission (§8).
constexpr double kTargetRecovery = 0.80;
// Reports with fewer accounted data packets only refresh logs (spec §8 "样本").
constexpr uint32_t kMinSamplePackets = 256;

// P(X <= max_losses) for X ~ Binomial(trials, p).
// p is clamped to [0, 1]; trials == 0 returns 1.
double binom_cdf(unsigned max_losses, unsigned trials, double p);

// Smallest k in 1..p_max with binom_cdf(k, d + k, loss) >= target.
// Returns p_max when no k reaches the target (including loss >= 1).
uint8_t k_for(double loss, uint8_t d, uint8_t p_max, double target = kTargetRecovery);

enum class FecState : uint8_t {
  kOff = 0,
  kOn = 1,
};

struct FecStrategyConfig {
  uint8_t d = 10;
  uint8_t p_max = kDefaultPmax;
  double target_recovery = kTargetRecovery;
  int pinned_k = -1;  // --fec-parity-pinned; >= 0 bypasses the state machine
  // Link warm-up (FCP_M2_PROXY.md §5): -1 starts OFF like every M1 session,
  // >= 1 starts ON at that k. Reports still drive the machine, so a warmed
  // value only buys the first few seconds and converges away if the link lost
  // its habit.
  int initial_k = -1;
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

 private:
  void enter_on(double loss);
  void enter_off();

  uint8_t d_;
  uint8_t p_max_;
  double target_recovery_;
  int pinned_k_;
  int initial_k_;

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
};

}  // namespace fcp

#endif  // FCP_STRATEGY_H_
