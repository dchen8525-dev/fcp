#include "fcp/strategy.h"

#include <algorithm>
#include <cmath>

#include "fcp/hdr.h"

namespace fcp {

double binom_cdf(unsigned max_losses, unsigned trials, double p) {
  if (max_losses >= trials) {
    return 1.0;
  }
  p = std::clamp(p, 0.0, 1.0);
  if (p == 0.0) {
    return 1.0;
  }
  if (p == 1.0) {
    return 0.0;  // max_losses < trials at this point
  }

  const double q = 1.0 - p;
  double term = std::pow(q, static_cast<double>(trials));
  double sum = term;
  for (unsigned i = 1; i <= max_losses; ++i) {
    term *= (static_cast<double>(trials - i + 1) / static_cast<double>(i)) * (p / q);
    sum += term;
  }
  return std::min(sum, 1.0);
}

uint8_t k_for(double loss, uint8_t d, uint8_t p_max, double target) {
  p_max = std::min(p_max, kMaxParity);
  for (uint8_t k = 1; k <= p_max; ++k) {
    if (binom_cdf(k, static_cast<unsigned>(d) + k, loss) >= target) {
      return k;
    }
  }
  return p_max;
}

const char* fec_state_name(FecState state) {
  switch (state) {
    case FecState::kOff:
      return "OFF";
    case FecState::kOn:
      return "ON";
    case FecState::kCapped:
      return "CAPPED";
  }
  return "?";
}

double binom_p_for_cdf(unsigned max_losses, unsigned trials, double q) {
  if (q >= 1.0) {
    return 0.0;
  }
  if (q <= 0.0) {
    return 1.0;
  }
  double lo = 0.0;
  double hi = 1.0;
  // 60 halvings put the interval far below double resolution; each step is a
  // <=7-term CDF evaluation at report cadence, so cost is a non-issue.
  for (int i = 0; i < 60; ++i) {
    const double mid = 0.5 * (lo + hi);
    if (binom_cdf(max_losses, trials, mid) >= q) {
      lo = mid;
    } else {
      hi = mid;
    }
  }
  return 0.5 * (lo + hi);
}

FecStrategy::FecStrategy(const FecStrategyConfig& config)
    : d_(config.d),
      p_max_(std::min(config.p_max, kMaxParity)),
      target_recovery_(config.target_recovery),
      // A pinned k above P' would ask FrameTx for more parity than negotiated.
      pinned_k_(config.pinned_k < 0
                    ? -1
                    : std::min(config.pinned_k, static_cast<int>(p_max_))),
      // A pinned k owns the machine, so nothing gets seeded alongside it; a
      // warm-up value is only the starting point and keeps the same P' clamp.
      initial_k_(config.pinned_k >= 0 || config.initial_k < 0
                     ? -1
                     : std::min(config.initial_k, static_cast<int>(p_max_))),
      // Negative budgets are config noise, not "more off than off".
      budget_ratio_(std::max(0.0, config.budget_ratio)) {
  if (pinned_k_ > 0) {
    state_ = FecState::kOn;
    k_ = static_cast<uint8_t>(pinned_k_);
  } else if (initial_k_ > 0) {
    // Same clamp as pinned_k_, but the reports keep driving: a warmed k that
    // the link no longer needs walks back down, so prewarm cannot strand k.
    state_ = FecState::kOn;
    k_ = static_cast<uint8_t>(initial_k_);
  }
}

void FecStrategy::on_report(const FecstatPacket& stat, bool window_queued) {
  if (pinned_k_ >= 0 || p_max_ == 0) {
    return;
  }
  if (have_last_ && !set_id_after(last_set_id_, stat.accounted_through_set_id)) {
    ++stale_reports_;
    return;
  }
  have_last_ = true;
  last_set_id_ = stat.accounted_through_set_id;

  // Sample gate 1: a group whose k never arrived cannot be accounted (§5.2).
  const uint64_t sets = std::max<uint32_t>(1, stat.sets_expected);
  if (static_cast<uint64_t>(stat.sets_k_unknown) * 10 > sets) {
    ++untrusted_reports_;
    return;
  }
  // Sample gate 2: the 60s forced report may carry too little traffic.
  if (stat.data_expected < kMinSamplePackets) {
    ++small_sample_reports_;
    return;
  }

  const int64_t lost = std::max<int64_t>(
      0, static_cast<int64_t>(stat.data_expected) - static_cast<int64_t>(stat.data_rx_orig));
  const double loss = static_cast<double>(lost) / static_cast<double>(stat.data_expected);
  last_loss_ = loss;

  if (state_ == FecState::kOff) {
    if (cooldown_reports_ > 0) {
      --cooldown_reports_;
      consec_ge_08_ = 0;
      if (loss >= 0.045) {
        enter_on(loss);
      }
      return;
    }
    if (loss >= 0.015) {
      enter_on(loss);
    } else if (loss >= 0.008) {
      if (++consec_ge_08_ >= 2) {
        enter_on(loss);
      }
    } else {
      consec_ge_08_ = 0;
    }
    return;
  }

  // M3 byte budget (FCP_M3_CONTROL.md §2): the peer's bytes are the real
  // measure of our redundancy. Over the ceiling we drop one parity per report
  // unconditionally (k_target is irrelevant — the budget wins over the
  // recovery target), floored at 1 per §14.11 (congestion never returns k to
  // 0). One report under the ceiling returns to ON without stepping.
  if (budget_ratio_ > 0.0 && stat.data_bytes_rx > 0) {
    const double ratio =
        static_cast<double>(stat.parity_bytes_rx) / static_cast<double>(stat.data_bytes_rx);
    if (ratio > budget_ratio_) {
      state_ = FecState::kCapped;
      k_ = std::max<uint8_t>(1, static_cast<uint8_t>(k_ - 1));
      clean_streak_ = 0;
      return;
    }
    if (state_ == FecState::kCapped) {
      state_ = FecState::kOn;
      return;
    }
  } else {
    // No bytes to measure (or budget off): a capped state cannot persist on
    // evidence it cannot see — fall back to ON.
    if (state_ == FecState::kCapped) {
      state_ = FecState::kOn;
    }
  }

  // M3 R(k) correction (FCP_M3_CONTROL.md §1.2): a usable ledger from the
  // peer upgrades the loss input from the observed mean to the i.i.d.-equivalent
  // rate that reproduces the empirical group-failure rate. One-sided: only
  // inflation is allowed, a ledger better than i.i.d. is treated as luck.
  double p_use = loss;
  update_p_eff(stat);
  if (have_p_eff_ && last_p_eff_ > p_use) {
    p_use = last_p_eff_;
  }
  const uint8_t k_target = k_for(p_use, d_, p_max_, target_recovery_);
  if (window_queued) {
    ++queued_streak_;
    if (queued_streak_ >= 3) {
      k_ = std::max<uint8_t>(1, static_cast<uint8_t>(k_ - 1));
    } else if (k_target < k_) {
      --k_;
    }
  } else {
    queued_streak_ = 0;
    if (k_target > k_) {
      ++k_;
    } else if (k_target < k_) {
      --k_;
    }
  }

  if (loss < 0.003) {
    if (++clean_streak_ >= 5) {
      enter_off();
    }
  } else {
    clean_streak_ = 0;
  }
}

void FecStrategy::enter_on(double loss) {
  state_ = FecState::kOn;
  k_ = k_for(loss, d_, p_max_, target_recovery_);
  clean_streak_ = 0;
  queued_streak_ = 0;
  consec_ge_08_ = 0;
  cooldown_reports_ = 0;
}

void FecStrategy::enter_off() {
  state_ = FecState::kOff;
  k_ = 0;
  clean_streak_ = 0;
  queued_streak_ = 0;
  consec_ge_08_ = 0;
  cooldown_reports_ = 3;
}

void FecStrategy::update_p_eff(const FecstatPacket& stat) {
  if ((stat.flg & kFlgLedger) == 0) {
    return;  // pre-M3 peer; normal, not counted as a skip
  }
  have_p_eff_ = false;
  if (stat.ledger_groups < kMinLedgerGroups) {
    ++ledger_skipped_;
    return;
  }
  const uint8_t lk = ledger_k(stat);
  // The ledger measures the k we actually ran. A mismatched mode (our step
  // lags the peer's report, or vice versa) is unusable, not hostile.
  if (lk == 0 || lk != k_) {
    ++ledger_skipped_;
    return;
  }
  const double fail = std::clamp(stat.ledger_fail_ppm / 1000000.0, 0.0, 1.0);
  last_p_eff_ = binom_p_for_cdf(k_, static_cast<unsigned>(d_) + k_, 1.0 - fail);
  have_p_eff_ = true;
  ++ledger_reports_;
}

}  // namespace fcp
