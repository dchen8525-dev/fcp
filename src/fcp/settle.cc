#include "fcp/settle.h"

#include <algorithm>
#include <cmath>
#include <utility>

#include "fcp/hdr.h"

namespace fcp {

void run_dist_iid(double out[9], double p, uint8_t d) {
  p = std::clamp(p, 0.0, 1.0);
  const auto n = static_cast<int>(d);
  // P(M >= m) = 1 - g_m(d), where g_m is the probability that no loss run
  // reaches length m within d slots. g_m is a DP over the trailing run
  // length r in 0..m-1: a lost slot extends it (r == m-1 dies), an arrived
  // slot resets it. m = 0 is vacuous (P >= 0 = 1).
  double tail[9];  // tail[m] = P(M >= m), m = 0..8
  tail[0] = 1.0;
  for (int m = 1; m <= 8; ++m) {
    if (m > n) {
      tail[m] = 0.0;  // a run cannot exceed the group size
      continue;
    }
    double g[9] = {};  // g[r] = P(trailing run = r, no run >= m yet)
    g[0] = 1.0;
    for (int i = 0; i < n; ++i) {
      double next[9] = {};
      for (int r = 0; r < m; ++r) {
        if (g[r] == 0.0) {
          continue;
        }
        next[0] += g[r] * (1.0 - p);
        if (r + 1 < m) {
          next[r + 1] += g[r] * p;
        }
        // r + 1 == m: the run hits the bound, excluded from g_m.
      }
      std::copy(next, next + m, g);
    }
    double alive = 0.0;
    for (int r = 0; r < m; ++r) {
      alive += g[r];
    }
    tail[m] = 1.0 - alive;
  }
  for (int l = 0; l < 8; ++l) {
    out[l] = tail[l] - tail[l + 1];
  }
  out[8] = tail[8];
}

double burst_kl_iid(const uint32_t run_hist[9], uint32_t groups, double p, uint8_t d) {
  if (groups == 0) {
    return 0.0;
  }
  double q[9];
  run_dist_iid(q, p, d);
  double kl = 0.0;
  for (int l = 0; l < 9; ++l) {
    const double e = static_cast<double>(run_hist[l]) / static_cast<double>(groups);
    if (e > 0.0) {
      kl += e * std::log(e / std::max(q[l], 1e-12));
    }
  }
  return kl;
}

FcpSettle::FcpSettle(uint8_t d) : d_(d) {}

void FcpSettle::attach(FrameRx* rx) {
  rx_ = rx;
  if (rx_ != nullptr) {
    rx_->set_event_sink([this](RxEvent event, uint32_t value) { on_event(event, value); });
  }
}

void FcpSettle::set_observer(EventObserver fn) { observer_ = std::move(fn); }

int64_t FcpSettle::late_guard_ms(int64_t rtt_ms) {
  return std::clamp<int64_t>(rtt_ms, kLateGuardMinMs, kLateGuardMaxMs);
}

int64_t FcpSettle::tombstone_ms(int64_t rtt_ms) {
  return std::clamp<int64_t>(2 * rtt_ms, kTombstoneMinMs, kTombstoneMaxMs);
}

void FcpSettle::tick(int64_t now_ms, int64_t rtt_ms) {
  if (rx_ == nullptr) {
    return;
  }
  const int64_t guard = late_guard_ms(rtt_ms);
  const int64_t tomb = tombstone_ms(rtt_ms);

  rx_->active_set_ids(&tick_ids_);
  for (const uint32_t id : tick_ids_) {
    RxSetView view;
    if (!rx_->view(id, &view)) {
      continue;
    }
    if (view.phase == SetPhase::kActive) {
      const bool eligible = view.saw_parity || set_id_after(id, rx_->anchor());
      if (eligible) {
        rx_->mark_eligible(id);
        view.phase = SetPhase::kEligible;
      } else if (now_ms - view.t_first_ms >= kTailDropMs) {
        ++counters_.sets_tail_dropped;
        // Its data was already delivered to KCP: keep the delivered-vs-
        // accounted invariant closed by remembering how much that is.
        counters_.tail_delivered +=
            static_cast<uint32_t>((view.orig_mask | view.recov_mask).count());
        rx_->release_set(id);
        continue;
      }
    }
    if (view.phase == SetPhase::kEligible && now_ms - view.t_first_ms >= guard) {
      account(view);
      rx_->mark_accounted(id, now_ms + tomb);
    } else if (view.phase == SetPhase::kAccounted && now_ms >= view.tombstone_until_ms) {
      rx_->release_set(id);
    }
  }
}

void FcpSettle::account(const RxSetView& view) {
  if (!view.has_any_symbol) {
    // Completely lost set seen only as an id jump (erratum #3).
    ++counters_.sets_k_unknown;
  } else {
    const uint32_t n_used =
        view.n_known ? view.n : static_cast<uint32_t>(view.max_data_index) + 1;
    ++counters_.sets_expected;
    counters_.data_expected += n_used;
    size_t orig = 0;
    size_t recov = 0;
    for (size_t i = 0; i < n_used; ++i) {
      orig += view.orig_mask.test(i) ? 1 : 0;
      recov += view.recov_mask.test(i) ? 1 : 0;
    }
    counters_.data_rx_orig += static_cast<uint32_t>(orig);
    counters_.data_recovered_dl += static_cast<uint32_t>(recov);
    counters_.parity_rx += static_cast<uint32_t>(view.parity_mask.count());
    if (orig + recov == n_used) {
      ++counters_.sets_full;
    }
    if (n_used < d_) {
      ++counters_.sets_partial;
    }
    if (view.k_known && view.k > 0) {
      counters_.parity_expected += view.k;  // planned k, an upper bound
    }
    // M3 R(k) ledger: only full-size groups with known k >= 1 match the
    // binomial model k_for solves against (M3控制设计.md §1.2).
    if (view.k_known && view.k > 0 && view.k <= 7 && n_used == static_cast<uint32_t>(d_)) {
      ++counters_.ledger_groups;
      ++counters_.ledger_k_hist[view.k];
      counters_.ledger_data += n_used;
      counters_.ledger_data_lost += static_cast<uint32_t>(n_used - orig);
      if (orig + recov < n_used) {
        ++counters_.ledger_groups_failed;
      }
      // Raw-loss run (see run_hist comment): recovery must not bleed into the
      // burst signal.
      unsigned run = 0;
      unsigned best = 0;
      for (uint32_t i = 0; i < n_used; ++i) {
        if (!view.orig_mask.test(i)) {
          ++run;
          best = std::max(best, run);
        } else {
          run = 0;
        }
      }
      ++counters_.run_hist[std::min<unsigned>(best, 8)];
    }
  }
  if (!have_accounted_ || set_id_after(accounted_through_, view.set_id)) {
    accounted_through_ = view.set_id;
  }
  have_accounted_ = true;
}

void FcpSettle::on_event(RxEvent event, uint32_t value) {
  switch (event) {
    case RxEvent::kDataDelivered:
      ++counters_.data_delivered;
      break;
    case RxEvent::kDataLate:
      ++counters_.data_delivered;
      ++counters_.data_late_rx;
      break;
    case RxEvent::kDataLateUnexpected:
      // Never part of data_expected (k-unknown set or an index past the
      // accounted code length), so it must not enter data_late_rx: the
      // identity would then exceed expected by one per such delivery.
      ++counters_.data_delivered;
      ++counters_.data_late_unexpected;
      break;
    case RxEvent::kDataDuplicate:
      ++counters_.late_dup;
      break;
    case RxEvent::kRecovered:
      ++counters_.data_delivered;
      break;
    case RxEvent::kRecoveredLate:
      ++counters_.data_delivered;
      ++counters_.data_recovered_late;
      break;
    case RxEvent::kSetTailDropped:
      // Capacity eviction dropped an unaccounted set. Mirror the 1s tail drop:
      // the set never enters expected, and its already-delivered symbols are
      // added back so delivered_le_sum keeps holding. value = delivered count.
      ++counters_.sets_tail_dropped;
      counters_.tail_delivered += value;
      break;
  }
  if (observer_) {
    observer_(event, value);
  }
}

void FcpSettle::reset_interval() { counters_ = SettleCounters{}; }

bool FcpSettle::untrusted() const {
  return k_unknown_untrusted(counters_.sets_expected, counters_.sets_k_unknown);
}

uint32_t FcpSettle::data_lost() const {
  // Post-repair loss: nothing the application did not receive. FecStrategy's
  // loss is the raw wire loss on purpose (it sizes parity for the path), so the
  // two figures legitimately differ whenever FEC or late delivery recovered
  // anything -- see the comment at the strategy calculation.
  const int64_t lost = static_cast<int64_t>(counters_.data_expected) -
                       counters_.data_rx_orig - counters_.data_recovered_dl -
                       counters_.data_late_rx;
  return lost > 0 ? static_cast<uint32_t>(lost) : 0;
}

uint8_t FcpSettle::ledger_k() const {
  uint8_t best_k = 0;
  uint32_t best_n = 0;
  for (uint8_t k = 1; k < 8; ++k) {
    if (counters_.ledger_k_hist[k] > best_n) {
      best_n = counters_.ledger_k_hist[k];
      best_k = k;
    }
  }
  return best_k;
}

double FcpSettle::burst_kl() const {
  if (counters_.ledger_groups == 0 || counters_.ledger_data == 0) {
    return 0.0;
  }
  const double p = static_cast<double>(counters_.ledger_data_lost) /
                   static_cast<double>(counters_.ledger_data);
  return burst_kl_iid(counters_.run_hist, counters_.ledger_groups, p, d_);
}

bool FcpSettle::identity_ok() const {
  const int64_t sum = static_cast<int64_t>(counters_.data_rx_orig) +
                      counters_.data_recovered_dl + data_lost() +
                      counters_.data_late_rx;
  return sum == static_cast<int64_t>(counters_.data_expected);
}

bool FcpSettle::delivered_le_sum() const {
  const int64_t sum = static_cast<int64_t>(counters_.data_rx_orig) +
                      counters_.data_recovered_dl + counters_.data_recovered_late +
                      counters_.data_late_rx + counters_.data_late_unexpected +
                      counters_.tail_delivered;
  return static_cast<int64_t>(counters_.data_delivered) <= sum;
}

}  // namespace fcp
