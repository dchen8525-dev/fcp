// Values a connection starts from, in one place.
//
// These are defaults, not protocol constants: nothing on the wire depends on
// them, and every one can be overridden by the operator. They are collected
// here because the same number used to be spelled out in SessionConfig,
// EngineConfig, FecStrategyConfig and TraceConfigSnapshot — four headers plus
// the replay decoder — so raising the default in one place silently left the
// others behind.
//
// This header must stay dependency-free: it is included by configuration
// structs that everything else includes.

#ifndef FCP_DEFAULTS_H_
#define FCP_DEFAULTS_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

// Codec the session opens with. Both ends negotiate, so a mismatch between
// the two ends' configured defaults is legal; what is not legal is the two
// ends of *one* binary disagreeing, which is what this header prevents.
constexpr uint8_t kDefaultD = 10;
constexpr uint8_t kDefaultP = 3;
// Largest P the codec may be negotiated up to before the strategy's pmax cap
// applies (see strategy.h, kDefaultPmax for the controller side).
constexpr uint16_t kDefaultMtu = 1400;
constexpr size_t kDefaultIpHeaderLen = 20;

// M3 byte budget (M3控制设计.md §2): parity/data bytes for one interval.
constexpr double kDefaultFecBudget = 0.50;

// Stream buffers and window bounds (StreamConfig / EngineConfig).
constexpr size_t kDefaultSendWindowBytes = 256 * 1024;
constexpr size_t kDefaultRcvBufBytes = 256 * 1024;
constexpr size_t kDefaultWindowMinBytes = 64 * 1024;
constexpr size_t kDefaultWindowMaxBytes = 1024 * 1024;
constexpr int64_t kDefaultIdleTimeoutMs = 300000;

}  // namespace fcp

#endif  // FCP_DEFAULTS_H_
