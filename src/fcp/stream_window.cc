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
  if (cfg_.bbr) {
    // BBR owns the window. The model advances on ACK/send events; the tick
    // only polls PROBE_RTT entry/exit and keeps send_window_ in sync.
    bbr_.on_tick(now_ms, in_flight_);
    refresh_window_ceiling();
    send_window_ = std::clamp(bbr_.cwnd(), window_min_, window_max_);
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
  // Credible queue reading: an epoch's minimum RTT against the historical
  // minimum. Sample-poor epochs say nothing (jitter can look like a queue), so
  // both the delay brake and the loss probe require a crowd of rounds.
  const bool credible = epoch_samples_ >= stream_detail::kQueueMinSamples;
  const int64_t queue_ms =
      (cfg_.window_queue_ms > 0 && credible && min_rtt_ms_ > 0 && epoch_min_rtt_ms_ > 0)
          ? epoch_min_rtt_ms_ - min_rtt_ms_
          : 0;
  // Delivery rate of this epoch (bytes/s). The probe uses it as its evidence:
  // growing the window is worth it only while the path delivers more.
  const uint64_t rate_bps =
      elapsed > 0 ? acked * 1000 / static_cast<uint64_t>(elapsed) : 0;
  if (loss_epoch_) {
    // Rate probe (auto mode): a stream-level hole is not clean congestion
    // evidence on a FEC-protected path -- the parity already absorbed what it
    // could, and the residue is a mix of contention and random loss. When the
    // evidence is a dup-ACK hole (the peer is still acknowledging, so data is
    // flowing) and there is no standing queue, treat the epoch as grow-capable:
    // probe 25% per epoch up to the ceiling, where the delay brake and the
    // operator's MAX bound it. Without this, a path whose loss falls in nearly
    // every epoch never sees the clean epoch that used to be the only way to
    // grow, and the window freezes at its start (the 2026-11-03 205 ms / 14%
    // WAN measurement: 256 KiB held forever, 4 MiB was optimal). An RTO
    // blackout and a standing queue still cut exactly as before.
    if (cfg_.window_probe && loss_epoch_dup_ && queue_ms < cfg_.window_queue_ms) {
      if (credible) {
        const uint64_t bdp =
            acked * static_cast<uint64_t>(rtt) / static_cast<uint64_t>(elapsed);
        last_target_ = static_cast<size_t>(std::min<uint64_t>(
            std::max<uint64_t>(2 * bdp, window_min_), window_max_));
        ssthresh_ = std::max(last_target_, send_window_);
      }
      const size_t grow = std::max<size_t>(send_window_ / 4, seg);
      send_window_ = std::min(send_window_ + grow, window_max_);
      probe_rate_bps_ = rate_bps;
      queue_over_ = 0;
    } else {
      // AIMD backoff -- bounded by the window we started with. Cutting below
      // the configured start on the ambiguity is what a lossy WAN path
      // punishes: the window reaches the 64 KiB floor in half a second, ARQ
      // recovery then costs more than it delivers, and nothing pulls it back
      // up because every epoch still has a hole in it. Queue evidence (below)
      // owns the deeper cuts. ssthresh keeps the pre-loss target as a recovery
      // reference: setting it to the just-cut window made every later round
      // additive from the floor (~40s to climb back at one segment/RTT).
      const size_t cut = send_window_ - send_window_ * 3 / 10;
      send_window_ = std::min(send_window_, std::max(loss_floor_, cut));
      ssthresh_ = std::max(send_window_, last_target_);
      probe_rate_bps_ = rate_bps;  // judge the next window against the new rate
      queue_over_ = 0;
    }
  } else if (limited_epoch_ && acked > 0) {
    // Our own window is the binding constraint. First look for a standing queue
    // of our own making (the reading is computed above).
    // window_queue_ms == 0 disables the brake; without the explicit > 0 the
    // comparison below is 0 >= 0 and the disabled brake becomes the most
    // aggressive one (a cut every two epochs).
    if (cfg_.window_queue_ms > 0 && queue_ms >= 2 * cfg_.window_queue_ms) {
      // One epoch is not evidence: two consecutive ones over twice the allowance
      // is a queue that is not draining, and only then does the window come down.
      if (++queue_over_ >= 2) {
        send_window_ = std::max(window_min_, send_window_ - send_window_ / 8);
        ssthresh_ = send_window_;
        queue_over_ = 0;
      }
    } else if (cfg_.window_queue_ms > 0 && queue_ms >= cfg_.window_queue_ms) {
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
      // Past ssthresh the old law added one segment per epoch -- on a 200 ms
      // path that is ~6 KB/s, so a transfer that needs a bigger window never
      // reaches it. While the delivery rate is still rising, probe 25% instead;
      // once it plateaus the additive step takes over again.
      const bool rising = probe_rate_bps_ == 0 || rate_bps > probe_rate_bps_ * 105 / 100;
      if (send_window_ < ssthresh_) {
        send_window_ = std::min(send_window_ * 2, window_max_);
        probe_rate_bps_ = rate_bps;
      } else if (cfg_.window_probe && credible && rising) {
        const size_t grow = std::max<size_t>(send_window_ / 4, seg);
        send_window_ = std::min(send_window_ + grow, window_max_);
        probe_rate_bps_ = rate_bps;
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
  loss_epoch_dup_ = false;
  limited_epoch_ = false;
}

void Stream::refresh_window_ceiling() {
  if (window_ceiling_ == 0) {
    return;  // fixed ceiling: the operator's --window MAX is the last word
  }
  // Twice the measured BDP is the window BBR itself targets (cwnd_gain); the
  // BDP is in application bytes, the same unit as every window here. The
  // configured window_max_bytes is the floor of the ceiling, so an operator who
  // asked for at least 1 MiB keeps it even on a short path.
  const size_t bdp = bbr_.bdp_bytes();
  const size_t want = std::min<size_t>(
      window_ceiling_, std::max<size_t>(cfg_.window_max_bytes, 2 * bdp));
  if (want <= window_max_) {
    return;
  }
  window_max_ = want;
  // The receive capacity has to keep up, or our own advertised window clamps
  // the peer's growth at the old ceiling -- the two ends tune against each
  // other and neither moves. The memory is committed lazily, by arrivals.
  if (cfg_.auto_window) {
    rcv_cap_ = std::max(rcv_cap_, window_max_);
  }
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
  const double cap =
      std::max<double>(static_cast<double>(2 * seg), rate * kPaceBurstMs / 1000.0);
  pace_tokens_ = std::min(pace_tokens_, cap);
  if (pace_tokens_ < static_cast<double>(bytes)) {
    return false;
  }
  pace_tokens_ -= static_cast<double>(bytes);
  return true;
}

}  // namespace fcp
