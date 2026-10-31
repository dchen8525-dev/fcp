#include "fcp/settle.h"

#include <algorithm>
#include <utility>

#include "fcp/hdr.h"

namespace fcp {

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

  for (const uint32_t id : rx_->active_set_ids()) {
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
    // binomial model k_for solves against (FCP_M3_CONTROL.md §1.2).
    if (view.k_known && view.k > 0 && view.k <= 7 && n_used == static_cast<uint32_t>(d_)) {
      ++counters_.ledger_groups;
      ++counters_.ledger_k_hist[view.k];
      if (orig + recov < n_used) {
        ++counters_.ledger_groups_failed;
      }
      unsigned run = 0;
      unsigned best = 0;
      for (uint32_t i = 0; i < n_used; ++i) {
        if (!view.orig_mask.test(i) && !view.recov_mask.test(i)) {
          ++run;
          best = std::max(best, run);
        } else {
          run = 0;
        }
      }
      ++counters_.run_hist[std::min<unsigned>(best, 8)];
    }
  }
  if (accounted_through_ == 0 || set_id_after(accounted_through_, view.set_id)) {
    accounted_through_ = view.set_id;
  }
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
  const uint32_t denom = std::max<uint32_t>(1, counters_.sets_expected);
  return static_cast<double>(counters_.sets_k_unknown) / denom >
         kUntrustedKUnknownRatio;
}

uint32_t FcpSettle::data_lost() const {
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

bool FcpSettle::identity_ok() const {
  const int64_t sum = static_cast<int64_t>(counters_.data_rx_orig) +
                      counters_.data_recovered_dl + data_lost() +
                      counters_.data_late_rx;
  return sum == static_cast<int64_t>(counters_.data_expected);
}

bool FcpSettle::delivered_le_sum() const {
  const int64_t sum = static_cast<int64_t>(counters_.data_rx_orig) +
                      counters_.data_recovered_dl + counters_.data_recovered_late +
                      counters_.data_late_rx + counters_.tail_delivered;
  return static_cast<int64_t>(counters_.data_delivered) <= sum;
}

}  // namespace fcp
