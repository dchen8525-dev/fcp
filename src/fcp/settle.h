// Set settlement (design doc §7, FCP_PROTOCOL_V6.md §5.2/§5.3).
//
// Drives the per-set phase machine on top of FrameRx:
//   Active -> Eligible : saw_parity OR a fragment of a higher set_id was seen
//   Eligible -> Accounted : now - t_first >= late_guard = clamp(RTT,100ms,500ms)
//   Accounted -> released : now >= tombstone_until = clamp(2*RTT,200ms,1s)
// A set that never becomes eligible after 1s is dropped as tail_dropped and is
// never part of data_expected.
//
// Sets that were completely lost are observed as a set_id jump; FrameRx inserts
// fragment-less placeholders for the skipped ids and they account as
// sets_k_unknown only (erratum #3). When those exceed 10% of the accounted sets
// the interval sample is untrusted and the strategy must hold k.
//
// All counters are per-report-interval; reset_interval() clears them and keeps
// the session-level monotonic accounted_through_set_id key.

#ifndef FCP_SETTLE_H_
#define FCP_SETTLE_H_

#include <cstdint>
#include <functional>

#include "fcp/frame_rx.h"

namespace fcp {

constexpr int64_t kSettleTickMs = 25;
constexpr int64_t kTailDropMs = 1000;
constexpr int64_t kLateGuardMinMs = 100;
constexpr int64_t kLateGuardMaxMs = 500;
constexpr int64_t kTombstoneMinMs = 200;
constexpr int64_t kTombstoneMaxMs = 1000;
constexpr double kUntrustedKUnknownRatio = 0.10;

struct SettleCounters {
  uint32_t sets_expected = 0;
  uint32_t data_expected = 0;
  uint32_t data_rx_orig = 0;
  uint32_t data_recovered_dl = 0;
  uint32_t data_recovered_late = 0;
  uint32_t data_late_rx = 0;
  uint32_t data_delivered = 0;
  uint32_t parity_rx = 0;
  uint32_t parity_expected = 0;
  uint32_t sets_k_unknown = 0;
  uint32_t sets_full = 0;
  uint32_t sets_partial = 0;
  uint32_t sets_tail_dropped = 0;
  // Deliveries made by sets that later tail-dropped (k = 0 tail sets, sender
  // abort, or capacity eviction before settlement). They are deliberately
  // outside data_expected, so the data_delivered invariant only holds once
  // they are added back in.
  uint32_t tail_delivered = 0;
  uint32_t late_dup = 0;
  // M3 R(k) ledger (FCP_M3_CONTROL.md §1.2): full-size (n_used == d) settled
  // sets whose k is known and >= 1. Whole-set losses cannot know their k and
  // stay outside, so extreme bursts make the ledger optimistic (§1.3);
  // partial sets stay out because their code length breaks the binomial
  // model's D+k assumption.
  uint32_t ledger_groups = 0;
  uint32_t ledger_groups_failed = 0;
  uint32_t ledger_k_hist[8] = {};  // index = k (1..7 used); [0] unused
  // Max consecutive missing run within the set (recovered slots do not
  // count); bucket 8 absorbs ">= 8". Input for the §3 burst detector (#26).
  uint32_t run_hist[9] = {};
};

class FcpSettle {
 public:
  // Mirrors every delivery event; repair events carry the repair latency.
  using EventObserver = std::function<void(RxEvent, uint32_t)>;

  explicit FcpSettle(uint8_t d);

  // Wires delivery events and drives rx's phase machine from then on.
  void attach(FrameRx* rx);
  void set_observer(EventObserver fn);

  void tick(int64_t now_ms, int64_t rtt_ms);

  void reset_interval();
  const SettleCounters& counters() const { return counters_; }
  uint32_t accounted_through_set_id() const { return accounted_through_; }

  bool untrusted() const;
  bool delivered_le_sum() const;
  bool identity_ok() const;
  uint32_t data_lost() const;

  // Dominant k over the interval's ledger (mode of ledger_k_hist; ties go to
  // the lower k). 0 when the ledger is empty.
  uint8_t ledger_k() const;

  static int64_t late_guard_ms(int64_t rtt_ms);
  static int64_t tombstone_ms(int64_t rtt_ms);

 private:
  void account(const RxSetView& view);
  void on_event(RxEvent event, uint32_t value);

  uint8_t d_;
  FrameRx* rx_ = nullptr;
  EventObserver observer_;
  SettleCounters counters_{};
  uint32_t accounted_through_ = 0;
};

}  // namespace fcp

#endif  // FCP_SETTLE_H_
