// Stream, window control (M2/M3: #32/#33). Everything that decides how large
// send_window_ may be lives here -- slow start, ssthresh, the delivery-rate
// reference, the standing-queue brake and the loss floor -- so a window policy
// change never has to be read past ARQ code.

#include <algorithm>

#include "fcp/stream.h"
#include "fcp/stream_util.h"

namespace fcp {

void Stream::update_srtt(int64_t sample_ms, int64_t now_ms) {
  srtt_ms_ = srtt_ms_ + (sample_ms - srtt_ms_) / 8;
  if (srtt_ms_ < 1) {
    srtt_ms_ = 1;
  }
  // The BDP estimate uses the minimum observed RTT, not the smoothed one: a
  // window sized from an inflated (queued) RTT would keep the queue standing.
  // The floor has to expire, though: after a route change the path is slower,
  // and a minimum from the faster path keeps epoch_min_rtt - min_rtt above the
  // queue allowance forever, so the window brakes and never recovers.
  const bool expired =
      min_rtt_ms_ > 0 && now_ms - min_rtt_stamp_ms_ >= kMinRttExpiryMs;
  if (min_rtt_ms_ <= 0 || sample_ms < min_rtt_ms_ || expired) {
    min_rtt_ms_ = sample_ms;
    min_rtt_stamp_ms_ = now_ms;
  }
  // A clean round trip proves the peer is alive and the path is delivering:
  // the timeout episode is over, so the next one starts from the base RTO.
  rto_backoff_ = 1;
  rto_ms_ = stream_detail::clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);
  if (rtt_) {
    rtt_(srtt_ms_);
  }
}

void Stream::update_window(int64_t now_ms) {
  if (state_ == StreamState::kClosed) {
    return;
  }
  // BBR owns the window. The model advances on ACK/send events; the tick only
  // polls PROBE_RTT entry/exit and keeps send_window_ in sync.
  bbr_.on_tick(now_ms, in_flight_);
  send_window_ = std::clamp(bbr_.cwnd(), window_min_, window_max_);
}

int64_t Stream::next_wake_ms(int64_t now_ms) const {
  int64_t next = 0;
  if (ack_pending_ && now_ms < last_ack_ms_ + kAckDelayMs) {
    next = last_ack_ms_ + kAckDelayMs;
  }
  // The tail probe has its own deadline; without it the host only discovers
  // the probe on its next 25 ms tick, which is fine on a WAN but eats most of
  // the gain on a short path.
  const int64_t tlp_due = tlp_due_ms(now_ms);
  if (tlp_due > now_ms) {
    next = next == 0 ? tlp_due : std::min(next, tlp_due);
  }
  // The pacer only matters when it -- not the window -- is what holds the next
  // segment back: if the window admits nothing, waiting for tokens is useless
  // and the ACK that opens the window will wake us anyway.
  if (!using_bbr() || state_ == StreamState::kClosed) {
    return next;
  }
  size_t need = 0;
  for (const PendingSeg& seg : tx_) {
    if (!seg.sent) {
      need = seg.wire_len();
      break;
    }
  }
  if (need == 0) {
    return next;  // nothing unsent is waiting on the pacer
  }
  const size_t allowed = std::min(send_window_, peer_rwnd_);
  if (!probe_credit_ && in_flight_ + need > allowed) {
    return next;
  }
  const double rate = bbr_.pacing_rate_bps();
  if (rate <= 0.0) {
    return next;
  }
  const size_t seg = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  double tokens = pace_tokens_;
  if (pace_ms_ > 0 && now_ms > pace_ms_) {
    tokens += rate * static_cast<double>(now_ms - pace_ms_) / 1000.0;
  }
  // Mirror pace_allow's cap without mutating the bucket: this is a prediction,
  // the actual accounting happens when the segment is released.
  tokens = std::min(tokens, std::max<double>(static_cast<double>(2 * seg),
                                             rate * kPaceBurstMs / 1000.0));
  if (tokens >= static_cast<double>(need)) {
    return next;  // it can go right now; the host's own tick covers that
  }
  const int64_t wait_ms =
      static_cast<int64_t>((static_cast<double>(need) - tokens) * 1000.0 / rate);
  const int64_t due = now_ms + std::max<int64_t>(1, wait_ms);
  return next == 0 ? due : std::min(next, due);
}

bool Stream::pace_allow(size_t bytes, int64_t now_ms) {
  if (!using_bbr()) {
    return true;
  }
  const double rate = bbr_.pacing_rate_bps();
  if (rate <= 0.0) {
    return true;
  }
  const size_t seg = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  if (pace_ms_ == 0) {
    pace_ms_ = now_ms;
  }
  const int64_t elapsed = now_ms - pace_ms_;
  if (elapsed > 0) {
    pace_tokens_ += rate * static_cast<double>(elapsed) / 1000.0;
    pace_ms_ = now_ms;
  }
  // kPaceBurstMs of credit at most: tokens accumulated while the app was idle
  // must not turn into a burst the path has to absorb all at once, and the
  // host can now wake before its 25 ms tick (next_wake_ms), so the bucket does
  // not have to bank a whole tick's worth to keep the pipe full. (#81: this
  // bucket also bounds the SACK-fill repair burst by design — see stream.h.)
  //
  // The opening window is the exception: the app can queue a whole window
  // before the path has said anything, and pacing it at the cold-start rate
  // (which is derived from the initial cwnd, so a 2*seg burst) held every
  // connection to a two-segment trickle until the first ACK. The bucket is
  // pre-charged with the start window for exactly one burst (pace_burst_left_);
  // after that the normal cap applies.
  double cap = std::max<double>(static_cast<double>(2 * seg), rate * kPaceBurstMs / 1000.0);
  if (pace_burst_left_) {
    cap = std::max<double>(cap, static_cast<double>(send_window_));
  }
  pace_tokens_ = std::min(pace_tokens_, cap);
  if (pace_tokens_ < static_cast<double>(bytes)) {
    return false;
  }
  pace_tokens_ -= static_cast<double>(bytes);
  // The opening allowance stays in force until it is spent (or the model has a
  // rate to pace against), so one pump can put the whole start window on the
  // wire instead of three segments.
  if (pace_tokens_ <= 0.0) {
    pace_burst_left_ = false;
  }
  return true;
}

}  // namespace fcp
