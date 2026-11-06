// Set settlement (design doc §7, 协议规格.md §5.2/§5.3).
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
#include <vector>

#include "fcp/frame_rx.h"

namespace fcp {

constexpr int64_t kTailDropMs = 1000;
constexpr int64_t kLateGuardMinMs = 100;
// #29a (§14.14): raised to match the handshake backoff's RTT <= ~700ms door
// (decision #27); the old 500/1000 caps misjudged in-flight fragments as lost
// on high-RTT links. Direction-safe: the guard only decides when to settle.
constexpr int64_t kLateGuardMaxMs = 700;
constexpr int64_t kTombstoneMinMs = 200;
constexpr int64_t kTombstoneMaxMs = 1400;
// "k-unknown 集占比超 10% 则本区段不可信" —— 同一条规则现在只有这一处定义：
// FcpSettle::untrusted()、strategy 的样本门 1、session 的日志门、以及日志
// 文本里的百分比都读它（对抗分析第九轮：原先四处 0.10 独立拼写，改门槛会
// 静默只改到其中一处）。
constexpr uint32_t kUntrustedKUnknownPct = 10;

// 判据本身也只有这一处实现。原先三个调用点（settle / strategy / session）
// 各写一遍 `k_unknown * 100 > max(1, expected) * pct`，其中 session 那处把
// 右侧留在了 uint32：对端给 sets_expected = 0x80000000 时该乘积在 2^32 上
// 回绕成 0，于是一份合法的 k-unknown 报告被判成不可信、日志行被静默顶掉。
// 两侧都提升到 uint64 后宽度漂移不再可能，因为宽度只在这一行决定。
constexpr bool k_unknown_untrusted(uint32_t sets_expected, uint32_t sets_k_unknown) {
  const uint64_t denom = sets_expected != 0 ? sets_expected : 1;
  return static_cast<uint64_t>(sets_k_unknown) * 100 >
         denom * static_cast<uint64_t>(kUntrustedKUnknownPct);
}

// Burst detection (M3控制设计.md §3, #26). The reference is the exact
// i.i.d. law of the max raw-loss run M over one full-size group of `d` slots
// at per-slot loss `p`: out[l] = P(M = l) for l = 0..7, out[8] = P(M >= 8).
// Solved exactly by a run-length DP (no geometric approximation, no edge
// fudge), sum == 1. `p` outside [0, 1] is clamped.
void run_dist_iid(double out[9], double p, uint8_t d);

// KL(P_emp ‖ Q_iid) in nats over the 9 run buckets, where P_emp is
// run_hist/groups and Q_iid = run_dist_iid(p, d). Buckets with no empirical
// mass contribute 0; Q is clamped at 1e-12 so an impossible-under-i.i.d.
// empirical run stays finite (huge, which is the point). groups == 0 -> 0.
double burst_kl_iid(const uint32_t run_hist[9], uint32_t groups, double p, uint8_t d);

struct SettleCounters {
  uint32_t sets_expected = 0;
  uint32_t data_expected = 0;
  uint32_t data_rx_orig = 0;
  uint32_t data_recovered_dl = 0;
  uint32_t data_recovered_late = 0;
  uint32_t data_late_rx = 0;
  // Late originals that were never part of data_expected: the set accounted
  // with no symbols (k unknown) or the index was beyond its accounted code
  // length. Real deliveries, but counted like tail deliveries: they enter
  // delivered_le_sum, never the expected/delivered identity.
  uint32_t data_late_unexpected = 0;
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
  // M3 R(k) ledger (M3控制设计.md §1.2): full-size (n_used == d) settled
  // sets whose k is known and >= 1. Whole-set losses cannot know their k and
  // stay outside, so extreme bursts make the ledger optimistic (§1.3);
  // partial sets stay out because their code length breaks the binomial
  // model's D+k assumption.
  uint32_t ledger_groups = 0;
  uint32_t ledger_groups_failed = 0;
  uint32_t ledger_k_hist[8] = {};  // index = k (1..7 used); [0] unused
  // Ledger data slots and how many arrived without their original copy (raw
  // loss, recovery-independent). Gives the burst detector a loss rate over
  // the exact population the run histogram was taken from.
  uint32_t ledger_data = 0;
  uint32_t ledger_data_lost = 0;
  // Max consecutive RAW-loss run within the set (original copies that never
  // arrived; recovered slots still count as lost here). Bucket 8 absorbs
  // ">= 8". Raw, not post-recovery, because RS fixes holes all-or-nothing:
  // a group with holes > k shows every hole as unrecovered, which would
  // fake burstiness on a perfectly i.i.d. link. Input for the §3 burst
  // detector (#26).
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

  // burst_kl_iid over this interval's ledger, with p taken from the ledger's
  // own raw-loss rate (same population as run_hist). 0 when the ledger is
  // empty.
  double burst_kl() const;

  static int64_t late_guard_ms(int64_t rtt_ms);
  static int64_t tombstone_ms(int64_t rtt_ms);

 private:
  void account(const RxSetView& view);
  void on_event(RxEvent event, uint32_t value);

  uint8_t d_;
  FrameRx* rx_ = nullptr;
  EventObserver observer_;
  SettleCounters counters_{};
  // The report key: the lowest set id accounted so far, i.e. the contiguous
  // watermark. set id 0 is a legal id, so "nothing accounted yet" needs a flag
  // of its own -- the ==0 sentinel it used to carry made the first account's
  // value indistinguishable from "unset" and let the key jump forward past sets
  // that had not been accounted.
  uint32_t accounted_through_ = 0;
  bool have_accounted_ = false;
  // Reused by tick() for the active set ids; see FrameRx::active_set_ids().
  std::vector<uint32_t> tick_ids_;
};

}  // namespace fcp

#endif  // FCP_SETTLE_H_
