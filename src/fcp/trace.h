// Controller trace recording and offline replay (FCP_M3_CONTROL.md §5, #28).
//
// A trace is one JSONL line per accepted FECSTAT report: the report's numeric
// fields (flattened with an s_ prefix), the strategy config snapshot the
// recording session ran, and the decision it made. Lines are self-contained —
// truncation loses whole reports, never the file — and the format carries no
// strings, so the decoder is a strict flat scanner with no escape handling.
//
// Offline replay feeds the recorded reports through a fresh FecStrategy built
// from the (possibly overridden) snapshot. Identical entries and config give
// identical steps, which is what makes candidate comparison a diff of two
// replay runs — the threshold-calibration loop of spec §14.1 without touching
// a live link.
//
// Byte-evidence caveat: the parity/data byte ratios in a trace are the
// recording session's traffic. A replayed budget what-if therefore sees the
// ratios frozen at the recording k, not re-simulated at the candidate k —
// fine for controller-parameter calibration, wrong for budget sizing.

#ifndef FCP_TRACE_H_
#define FCP_TRACE_H_

#include <cstdint>
#include <string>
#include <vector>

#include "fcp/fecstat.h"
#include "fcp/strategy.h"

namespace fcp {

constexpr int kTraceVersion = 1;

// The strategy-relevant slice of the recording session's controller config.
struct TraceConfigSnapshot {
  uint8_t d = 10;
  uint8_t p_max = kDefaultPmax;
  double target_recovery = kTargetRecovery;
  double budget = 0.50;
  int initial_k = -1;
  int pinned = -1;
};

// One recorded report plus the decision the recording controller made. The
// snapshot is the session's *effective* controller config (negotiated D and
// P' included), captured once at strategy construction.
struct TraceEntry {
  int64_t now_ms = 0;
  bool window_queued = false;
  FecstatPacket stat{};
  TraceConfigSnapshot snapshot{};
  // Reference decision; replay recomputes it from the snapshot.
  uint8_t k_after = 0;
  FecState state_after = FecState::kOff;
  double last_loss = 0.0;
};

// Strict single-line serialization: `{"key":value,...}` with numeric values
// only. decode accepts exactly the grammar encode produces (plus unknown
// keys, which are skipped for forward compatibility). Integer fields outside
// their wire width, non-finite numbers and trailing bytes reject the line, so
// no decoded value can drive an out-of-range cast. Doubles are written with
// %.17g, the shortest width that round-trips a double exactly: replaying a
// trace with its own snapshot reproduces the recording's decision even when a
// threshold sits between two adjacent doubles.
void encode_trace_line(const TraceEntry& entry, std::string* out);
bool decode_trace_line(const std::string& line, TraceEntry* entry);

struct ReplayStep {
  uint8_t k = 0;
  FecState state = FecState::kOff;
};

// Deterministic candidate evaluation: a fresh FecStrategy per call.
std::vector<ReplayStep> replay_trace(const std::vector<TraceEntry>& entries,
                                     const TraceConfigSnapshot& cfg);

}  // namespace fcp

#endif  // FCP_TRACE_H_
