// FECSTAT reporting cadence and packet assembly (design doc §8).
//
// A report is sent when, since the last one, at least 2s elapsed AND the
// interval accounted for >= 256 data packets; otherwise counters accumulate up
// to a hard 60s cap (interval_ms reflects the real span). An idle direction
// never reports.
//
// flg bit0 is always set: the packet describes inbound traffic ("you -> me").
// bit1 = this interval had tail-dropped sets, bit2 = late recovery happened.
// Repair latency percentiles are nearest-rank over the interval samples.
// Every report clears the interval counters (settlement included); only
// accounted_through_set_id stays session-level.

#ifndef FCP_REPORTER_H_
#define FCP_REPORTER_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "fcp/fecstat.h"

namespace fcp {

// Only used through a pointer: callers that merely hold an FcpReporter
// (session.h by value) need not pull in settle.h.
class FcpSettle;

constexpr int64_t kFecstatMinIntervalMs = 2000;
constexpr int64_t kFecstatMaxIntervalMs = 60000;
// The report cadence and the strategy's decision gate are the same §8
// threshold; see kMinSamplePackets in fecstat.h.
constexpr uint32_t kFecstatMinSamples = kMinSamplePackets;

class FcpReporter {
 public:
  using SendFn = std::function<void(const uint8_t* packet, size_t len)>;

  FcpReporter(FcpSettle* settle, SendFn send);

  void set_salt(const uint8_t salt[8]);

  // Extra interval counters owned outside the settle module.
  void add_auth_fail(uint32_t count = 1);
  void add_struct_fail(uint32_t count = 1);
  void add_data_bytes(uint32_t bytes);
  void add_parity_bytes(uint32_t bytes);
  void record_repair_latency(uint32_t ms);

  // Call on every timer tick. The first call only establishes the baseline.
  // Returns true when a report was emitted.
  bool on_tick(int64_t now_ms);

  // §14.6 (#30): emit the interval now if it holds anything. Called on
  // session teardown so the peer's controller sees the last stretch of
  // traffic instead of losing it to the < 60s tail that never hit the
  // cadence doors. Idle directions stay silent.
  bool flush(int64_t now_ms);

  bool last_forced() const { return last_forced_; }
  uint32_t reports() const { return reports_; }
  int64_t last_report_ms() const { return last_report_ms_; }

 private:
  bool has_content() const;
  void report(int64_t now_ms, int64_t elapsed_ms);
  void reset_interval();

  FcpSettle* settle_;
  SendFn send_;
  uint8_t salt_[8] = {};

  uint32_t auth_fail_ = 0;
  uint32_t struct_fail_ = 0;
  uint32_t data_bytes_ = 0;
  uint32_t parity_bytes_ = 0;
  std::vector<uint16_t> repair_lat_;

  int64_t last_report_ms_ = 0;
  bool have_last_ = false;
  bool last_forced_ = false;
  uint32_t reports_ = 0;
};

}  // namespace fcp

#endif  // FCP_REPORTER_H_
