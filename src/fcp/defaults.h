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
// PMTUD ceiling (pmtu.h): the largest IP packet a probe will try. 1500 is the
// Ethernet path every deployment can be expected to have; there is no operator
// knob for it (quic-go hard-codes its equivalent as MaxPacketBufferSize too),
// and ApplyInterfaceMtu may still lower it below 1500 when the interface says
// so. Nothing configures it above 1500.
constexpr uint16_t kDefaultPmtuMaxMtu = 1500;

// M3 byte budget (M3控制设计.md §2): parity/data bytes for one interval.
// 0.80 pairs with kDefaultPmax=6 (WAN calibration 2026-11-07): k=6 on d=10
// is a 0.6 wire ratio, and the ceiling must not clamp the recovery target
// the controller just proved it needs.
constexpr double kDefaultFecBudget = 0.80;

// RTT / flush timing defaults. srtt seeds every engine until the first sample
// arrives; T_flush is the frame layer's flush retransmit deadline. Same number
// by coincidence, not by coupling: raise one and leave the other alone.
constexpr int64_t kDefaultSrttMs = 200;
constexpr int64_t kDefaultFlushMs = 200;

// §8 queue guardrail (session → FEC strategy): this much srtt inflation over
// the observed minimum means our own queue is standing and k shrinks. Stream's
// delay brake is sized as half of this (StreamConfig::window_queue_ms) so the
// two controllers never trim (k 和窗口) on the same evidence at the same time;
// raising it past 2x window_queue_ms or shrinking it below that would have the
// session poke the queue the stream is already braking against.
constexpr int64_t kQueueGuardrailGapMs = 40;

// Stream buffers and window bounds (StreamConfig / EngineConfig).
//
// One window knob: --window-min is the floor BBR never goes below; the ceiling
// is twice that floor (2026-11-15 CN-VPS 实测定标). The old start/ceiling pair
// (256 KiB start, 1 MiB MAX, optional 4 MiB BDP ceiling) measured as three
// values that fought each other: a 1 MiB cap held the 268 ms path to
// window/RTT ~= 3.9 MB/s, while 4 MiB on a thin-BDP stretch ran at 4.5x BDP,
// queued, and dropped throughput to 0.6 MB/s. A floor of 2 MiB with a 2x
// ceiling keeps the BBR working point inside [BDP, 2xBD P] across the
// 25-70 Mbps x ~270 ms envelope this link swings through without an operator
// chasing it, and bounds one connection's worst-case memory at 2 x 4 MiB.
constexpr size_t kDefaultSendWindowBytes = 2 * 1024 * 1024;  // == window floor
constexpr size_t kDefaultRcvBufBytes = 256 * 1024;
constexpr size_t kDefaultWindowMinBytes = 2 * 1024 * 1024;
constexpr int64_t kDefaultIdleTimeoutMs = 300000;

}  // namespace fcp

#endif  // FCP_DEFAULTS_H_
