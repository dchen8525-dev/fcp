// Small helpers shared by the stream's translation units (stream.cc,
// stream_recv.cc, stream_send.cc, stream_window.cc).
//
// The stream is one class split across six .cc files by responsibility, so
// anything two of them need has to live in a header rather than in a
// per-file anonymous namespace. Nothing here is protocol-specific; the
// wrap-safe comparisons live in seq.h.

#ifndef FCP_STREAM_UTIL_H_
#define FCP_STREAM_UTIL_H_

#include <algorithm>
#include <cstdint>
#include <string>

namespace fcp {
namespace stream_detail {

// clamp_ms(name kept for the call sites that read like timers).
constexpr int64_t clamp_ms(int64_t v, int64_t lo, int64_t hi) {
  return v < lo ? lo : (v > hi ? hi : v);
}

// An epoch only says something about the path if enough rounds were measured in
// it. The minimum of one or two samples on a jittery path sits far above the
// path's real floor -- during an ACK backlog, when the stream sends almost
// nothing -- and reading that as bufferbloat would shrink a window the path can
// still carry, just as its near-zero goodput would report a capacity it does not
// have. A window too small to produce this many segments per RTT cannot build a
// queue worth braking on either.
constexpr int kQueueMinSamples = 8;

}  // namespace stream_detail
}  // namespace fcp

#endif  // FCP_STREAM_UTIL_H_
