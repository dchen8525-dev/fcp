// Stream, window control (M2/M3: #32/#33). Everything that decides how large
// send_window_ may be lives here -- slow start, ssthresh, the delivery-rate
// reference, the standing-queue brake and the loss floor -- so a window policy
// change never has to be read past ARQ code.

#include <algorithm>

#include "fcp/stream.h"
#include "fcp/stream_util.h"

namespace fcp {

void Stream::update_srtt(int64_t sample_ms) {
  srtt_ms_ = srtt_ms_ + (sample_ms - srtt_ms_) / 8;
  if (srtt_ms_ < 1) {
    srtt_ms_ = 1;
  }
  // The BDP estimate uses the minimum observed RTT, not the smoothed one: a
  // window sized from an inflated (queued) RTT would keep the queue standing.
  if (min_rtt_ms_ <= 0 || sample_ms < min_rtt_ms_) {
    min_rtt_ms_ = sample_ms;
  }
  if (epoch_min_rtt_ms_ <= 0 || sample_ms < epoch_min_rtt_ms_) {
    epoch_min_rtt_ms_ = sample_ms;
  }
  ++epoch_samples_;
  // A clean round trip proves the peer is alive and the path is delivering:
  // the timeout episode is over, so the next one starts from the base RTO.
  rto_backoff_ = 1;
  rto_ms_ = stream_detail::clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);
  if (rtt_) {
    rtt_(srtt_ms_);
  }
}

void Stream::update_window(int64_t now_ms) {
  if (!cfg_.auto_window || state_ == StreamState::kClosed) {
    return;
  }
  if (win_epoch_ms_ == 0) {
    win_epoch_ms_ = now_ms;
    epoch_acked_ = bytes_acked_;
    epoch_min_rtt_ms_ = 0;
    epoch_samples_ = 0;
    return;
  }
  // One sample per RTT (at least 50ms so a loopback RTT of ~1ms does not turn
  // the delivery-rate estimate into noise). The window moves at most once per
  // epoch, so several RTO passes inside one epoch cost a single decrease; a
  // blackout that outlives the backoff is repeated loss and decreases again.
  const int64_t rtt = min_rtt_ms_ > 0 ? min_rtt_ms_ : std::max<int64_t>(srtt_ms_, 50);
  const int64_t epoch_ms = std::max<int64_t>(rtt, 50);
  const int64_t elapsed = now_ms - win_epoch_ms_;
  if (elapsed < epoch_ms) {
    return;
  }
  const uint64_t acked = bytes_acked_ - epoch_acked_;
  const size_t seg = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  if (loss_epoch_) {
    // AIMD backoff -- bounded by the window we started with. FEC already
    // repaired what it could, so a stream-level hole is contention *or* random
    // loss the parity missed, and the two are not separable here. Cutting below
    // the configured start on that ambiguity is what a lossy WAN path punishes:
    // the window reaches the 64 KiB floor in half a second, ARQ recovery then
    // costs more than it delivers, and nothing pulls it back up because every
    // epoch still has a hole in it. Queue evidence (below) owns the deeper cuts.
    // ssthresh keeps the pre-loss target as a recovery reference: setting it to
    // the just-cut window made every later round additive from the floor (~40s
    // to climb back at one segment/RTT).
    const size_t cut = send_window_ - send_window_ * 3 / 10;
    send_window_ = std::min(send_window_, std::max(loss_floor_, cut));
    ssthresh_ = std::max(send_window_, last_target_);
    queue_over_ = 0;
  } else if (limited_epoch_ && acked > 0) {
    // Our own window is the binding constraint. First look for a standing queue
    // of our own making: the epoch's lowest RTT against the historical minimum.
    // A rate-limited path with a full buffer pushes this up; a jittery one does
    // too when the epoch is sample-poor, so the reading needs a crowd of rounds.
    const bool credible = epoch_samples_ >= stream_detail::kQueueMinSamples;
    const int64_t queue_ms =
        (cfg_.window_queue_ms > 0 && credible && min_rtt_ms_ > 0 && epoch_min_rtt_ms_ > 0)
            ? epoch_min_rtt_ms_ - min_rtt_ms_
            : 0;
    if (queue_ms >= 2 * cfg_.window_queue_ms) {
      // One epoch is not evidence: two consecutive ones over twice the allowance
      // is a queue that is not draining, and only then does the window come down.
      if (++queue_over_ >= 2) {
        send_window_ = std::max(window_min_, send_window_ - send_window_ / 8);
        ssthresh_ = send_window_;
        queue_over_ = 0;
      }
    } else if (queue_ms >= cfg_.window_queue_ms) {
      // At the allowance: hold, and leave slow start behind so the next quiet
      // epoch does not double the window straight back into a queue.
      ssthresh_ = send_window_;
      queue_over_ = 0;
    } else {
      // Delivery rate x min RTT is a capacity reading, not a law: goodput omits
      // retransmitted bytes and a sparse epoch reports a path that is not there.
      // It therefore sets where slow start hands over to additive growth, and
      // never a ceiling on the window -- the current window always stays allowed
      // and additive growth keeps climbing past it. Using it as that ceiling is
      // what froze the window permanently after the first loss.
      if (credible) {
        const uint64_t bdp =
            acked * static_cast<uint64_t>(rtt) / static_cast<uint64_t>(elapsed);
        last_target_ = static_cast<size_t>(std::min<uint64_t>(
            std::max<uint64_t>(2 * bdp, window_min_), window_max_));
        ssthresh_ = std::max(last_target_, send_window_);
      }
      if (send_window_ < ssthresh_) {
        send_window_ = std::min(send_window_ * 2, window_max_);
      } else {
        send_window_ = std::min(send_window_ + seg, window_max_);
      }
    }
    send_window_ = std::clamp(send_window_, window_min_, window_max_);
  }
  win_epoch_ms_ = now_ms;
  epoch_acked_ = bytes_acked_;
  epoch_min_rtt_ms_ = 0;
  epoch_samples_ = 0;
  loss_epoch_ = false;
  limited_epoch_ = false;
}

}  // namespace fcp
