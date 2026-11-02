#include "fcp/reporter.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "fcp/settle.h"

namespace fcp {
namespace {

uint16_t percentile(const std::vector<uint16_t>& sorted, unsigned pct) {
  if (sorted.empty()) {
    return 0;
  }
  // Nearest rank: ceil(pct * n / 100), clamped to [1, n].
  size_t rank = (static_cast<size_t>(pct) * sorted.size() + 99) / 100;
  rank = std::clamp<size_t>(rank, 1, sorted.size());
  return sorted[rank - 1];
}

// The mechanical part of SettleCounters -> FecstatPacket: every field whose
// name the two structs share, so a new interval counter is wired in one place
// instead of two that can silently drift apart. Not template metaprogramming:
// the packet also carries non-counter fields (magic, flags, derived ppm/KL
// values) and only a handful of counters, so a plain function is clearer.
void copy_settle_counters(const SettleCounters& c, FecstatPacket* p) {
  p->sets_expected = c.sets_expected;
  p->data_expected = c.data_expected;
  p->data_rx_orig = c.data_rx_orig;
  p->data_recovered_dl = c.data_recovered_dl;
  p->data_recovered_late = c.data_recovered_late;
  p->data_delivered = c.data_delivered;
  p->parity_rx = c.parity_rx;
  p->parity_expected = c.parity_expected;
  p->sets_k_unknown = c.sets_k_unknown;
  p->sets_full = c.sets_full;
  p->late_dup = c.late_dup;
  p->sets_tail_dropped = c.sets_tail_dropped;
  p->data_late_rx = c.data_late_rx;
  p->sets_partial = c.sets_partial;
}

}  // namespace

FcpReporter::FcpReporter(FcpSettle* settle, SendFn send)
    : settle_(settle), send_(std::move(send)) {}

void FcpReporter::set_salt(const uint8_t salt[8]) {
  std::memcpy(salt_, salt, sizeof(salt_));
}

void FcpReporter::add_auth_fail(uint32_t count) { auth_fail_ += count; }
void FcpReporter::add_struct_fail(uint32_t count) { struct_fail_ += count; }
void FcpReporter::add_data_bytes(uint32_t bytes) { data_bytes_ += bytes; }
void FcpReporter::add_parity_bytes(uint32_t bytes) { parity_bytes_ += bytes; }

void FcpReporter::record_repair_latency(uint32_t ms) {
  repair_lat_.push_back(static_cast<uint16_t>(std::min<uint32_t>(ms, 0xFFFF)));
}

bool FcpReporter::has_content() const {
  if (auth_fail_ != 0 || struct_fail_ != 0 || data_bytes_ != 0 || parity_bytes_ != 0 ||
      !repair_lat_.empty()) {
    return true;
  }
  if (settle_ == nullptr) {
    return false;
  }
  const SettleCounters& c = settle_->counters();
  return c.sets_expected != 0 || c.data_expected != 0 || c.data_delivered != 0 ||
         c.parity_rx != 0 || c.sets_k_unknown != 0 || c.sets_tail_dropped != 0 ||
         c.late_dup != 0 || c.data_late_rx != 0 || c.data_recovered_late != 0;
}

bool FcpReporter::on_tick(int64_t now_ms) {
  if (!have_last_) {
    last_report_ms_ = now_ms;
    have_last_ = true;
    return false;
  }
  const int64_t elapsed = now_ms - last_report_ms_;

  const uint32_t expected =
      settle_ != nullptr ? settle_->counters().data_expected : 0;
  const bool due = elapsed >= kFecstatMinIntervalMs && expected >= kFecstatMinSamples;
  if (due) {
    last_forced_ = false;
    report(now_ms, elapsed);
    return true;
  }
  if (elapsed >= kFecstatMaxIntervalMs && has_content()) {
    last_forced_ = true;
    report(now_ms, elapsed);
    return true;
  }
  return false;
}

bool FcpReporter::flush(int64_t now_ms) {
  // §14.6 (#30): a teardown with any accounted traffic sends its last report
  // immediately; the monotonic key on the peer makes it an ordinary report.
  if (!have_last_ || !has_content()) {
    return false;
  }
  const int64_t elapsed = now_ms - last_report_ms_;
  report(now_ms, elapsed > 0 ? elapsed : 1);
  return true;
}

void FcpReporter::report(int64_t now_ms, int64_t elapsed_ms) {
  FecstatPacket packet = MakeFecstatPacket(salt_);
  packet.flg = kFlgDirection;
  packet.interval_ms =
      static_cast<uint16_t>(std::min<int64_t>(elapsed_ms, kFecstatMaxIntervalMs));

  std::vector<uint16_t> sorted;
  if (!repair_lat_.empty()) {
    sorted = repair_lat_;
    std::sort(sorted.begin(), sorted.end());
  }
  packet.repair_lat_p50_ms = percentile(sorted, 50);
  packet.repair_lat_p95_ms = percentile(sorted, 95);

  packet.auth_fail = auth_fail_;
  packet.struct_fail = struct_fail_;
  packet.data_bytes_rx = data_bytes_;
  packet.parity_bytes_rx = parity_bytes_;

  if (settle_ != nullptr) {
    const SettleCounters& c = settle_->counters();
    if (c.sets_tail_dropped > 0) {
      packet.flg |= kFlgTailDropped;
    }
    if (c.data_recovered_late > 0) {
      packet.flg |= kFlgLateRecovery;
    }
    packet.accounted_through_set_id = settle_->accounted_through_set_id();
    copy_settle_counters(c, &packet);
    // M3 R(k) ledger (M3控制设计.md §1.2) with the #26 burst metric in
    // the ledger_meta high half (0.01 nat, saturating).
    if (c.ledger_groups > 0) {
      packet.flg |= kFlgLedger;
      packet.ledger_groups = c.ledger_groups;
      packet.ledger_fail_ppm = static_cast<uint32_t>(
          (static_cast<uint64_t>(c.ledger_groups_failed) * 1000000ull +
           c.ledger_groups / 2) /
          c.ledger_groups);
      const uint16_t kl =
          static_cast<uint16_t>(std::min<uint64_t>(
              65535, static_cast<uint64_t>(settle_->burst_kl() * 100.0 + 0.5)));
      packet.ledger_meta =
          static_cast<uint32_t>(settle_->ledger_k()) | (static_cast<uint32_t>(kl) << 16);
    }
  }

  uint8_t wire[kFecstatLen];
  encode_fecstat(packet, wire);
  if (send_) {
    // #28⑤ (F3): FECSTAT travels over an oob datagram that is never
    // retransmitted, so one lost copy would blind the peer's strategy for a
    // full report period ("no FECSTAT for 3 periods" -> keep k). The 128-byte
    // report is sent twice; the receiver's monotonic key classifies the copy
    // as kDuplicate and ignores it (spec §14.15).
    send_(wire, sizeof(wire));
    send_(wire, sizeof(wire));
  }
  ++reports_;
  last_report_ms_ = now_ms;
  reset_interval();
}

void FcpReporter::reset_interval() {
  auth_fail_ = 0;
  struct_fail_ = 0;
  data_bytes_ = 0;
  parity_bytes_ = 0;
  repair_lat_.clear();
  if (settle_ != nullptr) {
    settle_->reset_interval();
  }
}

}  // namespace fcp
