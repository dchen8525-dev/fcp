// BBRv1 for the FCP stream (see bbr.h for the porting notes).

#include "fcp/bbr.h"

#include <algorithm>
#include <cmath>

namespace fcp {
namespace {

// Constants from the reference (quic-go congestion/bbr, itself a port of the
// BBR draft).
constexpr double kHighGain = 2.885;              // 2/ln(2)
constexpr double kDrainGain = 1.0 / kHighGain;
constexpr double kCwndGain = 2.0;
constexpr double kPacingGainCycle[] = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
constexpr int kGainCycleLength = 8;
constexpr uint64_t kBandwidthWindowRounds = kGainCycleLength + 2;
constexpr int kRoundsWithoutGrowthBeforeExit = 3;
constexpr double kStartupGrowthTarget = 1.25;

size_t clamp_size(double v, size_t lo, size_t hi) {
  if (v <= static_cast<double>(lo)) {
    return lo;
  }
  if (v >= static_cast<double>(hi)) {
    return hi;
  }
  return static_cast<size_t>(v);
}

}  // namespace

Bbr::Bbr(const Config& cfg)
    : cfg_(cfg),
      max_bw_(kBandwidthWindowRounds),
      cwnd_(cfg.initial_cwnd),
      pacing_gain_(kHighGain),
      cwnd_gain_(kHighGain) {
  if (cfg_.mss == 0) {
    cfg_.mss = 1;
  }
  cfg_.min_cwnd = std::max(cfg_.min_cwnd, 4 * cfg_.mss);
  cfg_.max_cwnd = std::max(cfg_.max_cwnd, cfg_.min_cwnd);
  if (cfg_.initial_rtt_ms <= 0) {
    cfg_.initial_rtt_ms = 100;
  }
  if (cfg_.version != 1 && cfg_.version != 2) {
    cfg_.version = 2;
  }
  min_cwnd_ = cfg_.min_cwnd;
  max_cwnd_ = cfg_.max_cwnd;
  inflight_hi_ = max_cwnd_;
  inflight_lo_ = 0;
  cwnd_ = std::clamp(cwnd_, min_cwnd_, max_cwnd_);

  // Prewarm prior: start where the previous session to this peer converged.
  // Without it every new connection re-runs STARTUP from initial_cwnd (256 KiB
  // by default), which on a 200 ms path is several RTTs of half-empty pipe per
  // connection -- the dominant cost for bursts of short-lived requests.
  if (cfg_.initial_bw_bps > 0) {
    max_bw_.reset(cfg_.initial_bw_bps, 0);
    bw_at_last_round_ = cfg_.initial_bw_bps;
    at_full_bw_ = true;  // the path's ceiling was already found: no STARTUP
    if (cfg_.initial_min_rtt_ms > 0) {
      min_rtt_ms_ = cfg_.initial_min_rtt_ms;
      min_rtt_seeded_ = true;
    }
    const double bdp = static_cast<double>(cfg_.initial_bw_bps) *
                       static_cast<double>(min_rtt_ms()) / 1000.0;
    if (bdp > 0) {
      cwnd_ = clamp_size(bdp, min_cwnd_, max_cwnd_);
    }
    enter_probe_bw(0);
  }
  recalculate_pacing_rate();
}

const char* Bbr::mode_name(Mode mode) {
  switch (mode) {
    case Mode::kStartup:
      return "startup";
    case Mode::kDrain:
      return "drain";
    case Mode::kProbeBw:
      return "probe_bw";
    case Mode::kProbeRtt:
      return "probe_rtt";
  }
  return "?";
}

void Bbr::WindowedMaxFilter::reset(uint64_t bandwidth, uint64_t round) {
  for (Sample& e : estimates_) {
    e.bandwidth = bandwidth;
    e.round = round;
  }
}

void Bbr::WindowedMaxFilter::update(uint64_t bandwidth, uint64_t round) {
  // Uninitialized, a new best, or the third estimate is older than the window:
  // restart all three from this sample.
  if (estimates_[0].bandwidth == 0 || bandwidth >= estimates_[0].bandwidth ||
      round - estimates_[2].round > window_) {
    reset(bandwidth, round);
    return;
  }
  const Sample sample{bandwidth, round};
  if (bandwidth >= estimates_[1].bandwidth) {
    estimates_[1] = sample;
    estimates_[2] = sample;
  } else if (bandwidth >= estimates_[2].bandwidth) {
    estimates_[2] = sample;
  }

  if (round - estimates_[0].round > window_) {
    estimates_[0] = estimates_[1];
    estimates_[1] = estimates_[2];
    estimates_[2] = sample;
    if (round - estimates_[0].round > window_) {
      estimates_[0] = estimates_[1];
      estimates_[1] = estimates_[2];
    }
    return;
  }
  if (estimates_[1].bandwidth == estimates_[0].bandwidth &&
      round - estimates_[1].round > (window_ >> 2)) {
    estimates_[2] = sample;
    estimates_[1] = sample;
    return;
  }
  if (estimates_[2].bandwidth == estimates_[1].bandwidth &&
      round - estimates_[2].round > (window_ >> 1)) {
    estimates_[2] = sample;
  }
}

void Bbr::on_sent(int64_t now_ms, size_t wire_bytes, size_t in_flight) {
  // The first send after an idle phase opens a fresh sampling interval. The
  // bytes still in flight from before the idle period must not be divided by
  // the idle gap (they would look like an almost-zero rate).
  if (app_limited_ && !sent_since_app_limited_) {
    last_sample_ms_ = now_ms;
    last_sample_sent_ = total_sent_;
    sample_bytes_ = 0;
    have_sample_baseline_ = true;
    sent_since_app_limited_ = true;
    last_sample_app_limited_ = true;
  }
  total_sent_ += wire_bytes;
  round_sent_ += wire_bytes;
  // v2 bounds a lossy round by the in-flight that produced the loss. At the
  // round boundary in-flight has usually drained, so keep the round's peak.
  round_max_inflight_ = std::max(round_max_inflight_, in_flight);
}

void Bbr::on_acked(int64_t now_ms, size_t wire_bytes, int64_t rtt_ms, bool new_round,
                   size_t in_flight) {
  total_acked_ += wire_bytes;
  round_delivered_ += wire_bytes;

  if (new_round) {
    if (cfg_.version == 2) {
      update_bounds_at_round_start(in_flight);
    }
    ++round_;
    if (!at_full_bw_) {
      check_full_bandwidth();
    }
    if (mode_ == Mode::kProbeRtt) {
      probe_rtt_round_ = true;
    }
  }

  const bool min_rtt_expired =
      min_rtt_ms_ > 0 && now_ms - min_rtt_stamp_ms_ >= cfg_.min_rtt_expiry_ms;
  if (rtt_ms > 0) {
    if (min_rtt_seeded_ || min_rtt_ms_ == 0 || rtt_ms < min_rtt_ms_ || min_rtt_expired) {
      min_rtt_ms_ = rtt_ms;
      min_rtt_stamp_ms_ = now_ms;
      min_rtt_seeded_ = false;
    }
  }

  sample_bytes_ += wire_bytes;
  if (!have_sample_baseline_) {
    last_sample_ms_ = now_ms;
    last_sample_sent_ = total_sent_;
    sample_bytes_ = 0;
    have_sample_baseline_ = true;
  } else {
    const int64_t elapsed = now_ms - last_sample_ms_;
    if (elapsed > 0 && sample_bytes_ > 0) {
      // Same slope rule as the reference: ack rate is the delivery evidence,
      // send rate caps it when ACK compression makes the ack side look faster
      // than the path could have delivered. A sample with no transmission in
      // the interval says nothing about capacity (the bytes acked were sent
      // before the baseline), so it is dropped instead of being capped at zero.
      const uint64_t sent_delta = total_sent_ - last_sample_sent_;
      if (sent_delta > 0) {
        const uint64_t ack_rate =
            sample_bytes_ * 1000 / static_cast<uint64_t>(elapsed);
        const uint64_t send_rate =
            sent_delta * 1000 / static_cast<uint64_t>(elapsed);
        const uint64_t bandwidth = std::min(ack_rate, send_rate);
        last_sample_app_limited_ = app_limited_;
        if (!app_limited_ || bandwidth > max_bw_.best()) {
          max_bw_.update(bandwidth, round_);
        }
        if (app_limited_ && sent_since_app_limited_) {
          app_limited_ = false;
        }
      }
      last_sample_ms_ = now_ms;
      last_sample_sent_ = total_sent_;
      sample_bytes_ = 0;
    }
  }

  if (mode_ == Mode::kProbeBw) {
    maybe_advance_gain_cycle(now_ms, in_flight);
  }
  maybe_exit_startup_or_drain(now_ms, in_flight);
  maybe_enter_or_exit_probe_rtt(now_ms, in_flight);

  calculate_congestion_window(wire_bytes);
  recalculate_pacing_rate();
}

void Bbr::on_app_limited(int64_t /*now_ms*/) {
  if (!app_limited_) {
    app_limited_ = true;
    sent_since_app_limited_ = false;
  }
}

void Bbr::on_tick(int64_t now_ms, size_t in_flight) {
  maybe_enter_or_exit_probe_rtt(now_ms, in_flight);
  // The pacing rate is derived from state that only changes on ACKs; refresh it
  // here so a caller that polls the rate between ACKs sees the current gain.
  recalculate_pacing_rate();
}

void Bbr::check_full_bandwidth() {
  if (last_sample_app_limited_) {
    return;  // a quiet round says nothing about the path's ceiling
  }
  const double target = static_cast<double>(bw_at_last_round_) * kStartupGrowthTarget;
  if (static_cast<double>(bandwidth_bps()) >= target) {
    bw_at_last_round_ = bandwidth_bps();
    rounds_without_growth_ = 0;
    return;
  }
  if (++rounds_without_growth_ >= kRoundsWithoutGrowthBeforeExit) {
    at_full_bw_ = true;
  }
}

void Bbr::update_bounds_at_round_start(size_t in_flight) {
  const uint64_t sent = round_sent_;
  const uint64_t lost = round_lost_;
  const uint64_t delivered = round_delivered_;
  const size_t peak = round_max_inflight_;
  round_sent_ = 0;
  round_lost_ = 0;
  round_delivered_ = 0;
  // Start the next round's peak from zero: the losses being judged belong to
  // the transmissions since the previous boundary, and carrying the in-flight
  // at the boundary over would keep citing a window that did not produce them.
  round_max_inflight_ = 0;
  (void)in_flight;
  // A round that had to retransmit part of what it sent delivers less than it
  // spent on the wire. Clamp the ratio so one pathological round cannot inflate
  // the window without bound; 0.25 means "up to four times the BDP".
  if (sent > 0) {
    const double eff = static_cast<double>(delivered) / static_cast<double>(sent);
    delivery_efficiency_ = std::clamp(eff, 0.25, 1.0);
  }
  // Loss that is always present is a property of the path, not a congestion
  // signal. Learn its floor (immediately down, 1/64 per clean round back up)
  // and require a margin above it before inflight_hi moves.
  const uint64_t rate_ppm = sent > 0 ? lost * 1000000 / sent : 0;
  const bool enough = sent >= 4 * cfg_.mss;
  auto loss_base = [&](bool congested) {
    if (!enough) {
      return;
    }
    if (!have_loss_base_) {
      loss_base_ppm_ = rate_ppm;
      have_loss_base_ = true;
    } else if (rate_ppm < loss_base_ppm_) {
      loss_base_ppm_ = rate_ppm;
    } else if (!congested) {
      loss_base_ppm_ += (rate_ppm - loss_base_ppm_) / 64;
    } else if (inflight_hi_ <= min_cwnd_ + min_cwnd_ / 8) {
      // The ceiling is already on the floor: another cut is not available, so
      // this loss rate is the path's steady state, not a response to the
      // window. Learn it now. Without this the base could only rise on a round
      // that was *not* congested, and a path with persistent loss above the
      // 5-point threshold made every round congested -- inflight_hi stayed
      // pinned at the floor for the whole session while the threshold stayed at
      // the old, cleaner baseline.
      loss_base_ppm_ += (rate_ppm - loss_base_ppm_) / 2;
    }
  };
  constexpr uint64_t kMarginPpm = 50000;  // 5 points above the path's own loss
  const uint64_t threshold_ppm = std::max<uint64_t>(
      static_cast<uint64_t>(cfg_.loss_threshold_percent) * 10000u,
      loss_base_ppm_ + kMarginPpm);
  const bool lossy = enough && rate_ppm > threshold_ppm;
  loss_base(lossy);

  if (lossy) {
    // A lossy round is the only signal BBRv2 trusts as "the path (or a
    // buffer) refused this much". The upper bound moves to just below the
    // in-flight that produced the loss, while the lower bound keeps the
    // window from collapsing onto the engine floor.
    const size_t refused = peak > 0 ? peak : cwnd_;
    const size_t hi = refused - refused / 8;
    inflight_hi_ = std::min(inflight_hi_, std::max(min_cwnd_, hi));
    const size_t floor = cwnd_ - cwnd_ / 4;
    inflight_lo_ = std::max(inflight_lo_, std::max(min_cwnd_, floor));
    if (mode_ == Mode::kStartup) {
      // STARTUP overshoots on purpose; a refused round is proof the pipe is
      // full, so hand over even if the delivery rate has not plateaued yet.
      at_full_bw_ = true;
    }
    return;
  }

  // No loss: the lower bound decays (the loss evidence is old) and a probe-up
  // phase may raise the upper bound by a quarter of the current window, which
  // is what gives the next probe room to fill.
  inflight_lo_ -= inflight_lo_ / 8;
  if (mode_ == Mode::kProbeBw && pacing_gain_ > 1.0) {
    const size_t grown = cwnd_ + cwnd_ / 4;
    inflight_hi_ = std::min(max_cwnd_, std::max(inflight_hi_, grown));
  }
}

void Bbr::maybe_advance_gain_cycle(int64_t now_ms, size_t in_flight) {
  if (cycle_start_ms_ == 0) {
    cycle_start_ms_ = now_ms;
  }
  bool advance = now_ms - cycle_start_ms_ > min_rtt_ms();
  // While probing (gain > 1) the reference waits until in flight actually
  // reaches gain x BDP; on a path whose buffers cannot hold that, a loss is the
  // answer, so do not wait for a target that will never be reached.
  if (pacing_gain_ > 1.0 && !recent_loss_ &&
      in_flight < target_window(pacing_gain_)) {
    advance = false;
  }
  // While draining (gain < 1) there is nothing to wait for once in flight has
  // fallen to the BDP: the queue the previous probe built is gone.
  if (pacing_gain_ < 1.0 && in_flight < target_window(1.0)) {
    advance = true;
  }
  if (advance) {
    cycle_offset_ = (cycle_offset_ + 1) % kGainCycleLength;
    cycle_start_ms_ = now_ms;
    pacing_gain_ = kPacingGainCycle[cycle_offset_];
  }
  recent_loss_ = false;
}

void Bbr::maybe_exit_startup_or_drain(int64_t now_ms, size_t in_flight) {
  if (mode_ == Mode::kStartup && at_full_bw_) {
    mode_ = Mode::kDrain;
    pacing_gain_ = kDrainGain;
    cwnd_gain_ = kHighGain;
  }
  if (mode_ == Mode::kDrain && in_flight <= bdp_bytes()) {
    enter_probe_bw(now_ms);
  }
}

void Bbr::maybe_enter_or_exit_probe_rtt(int64_t now_ms, size_t in_flight) {
  if (mode_ != Mode::kProbeRtt && min_rtt_stamp_ms_ > 0 &&
      now_ms - min_rtt_stamp_ms_ >= cfg_.min_rtt_expiry_ms) {
    // The min RTT is old enough that a standing queue could be hiding behind
    // it. Drain the pipe, re-measure, and keep the old min as the reference
    // unless a lower sample arrives.
    mode_ = Mode::kProbeRtt;
    pacing_gain_ = 1.0;
    probe_rtt_exit_ms_ = 0;
    probe_rtt_round_ = false;
  }
  if (mode_ != Mode::kProbeRtt) {
    return;
  }
  if (probe_rtt_exit_ms_ == 0) {
    // The reference allows one packet beyond the minimum window because QUIC
    // checks cwnd before sending; the same slack keeps a lone segment moving.
    if (in_flight < min_cwnd_ + cfg_.mss) {
      probe_rtt_exit_ms_ = now_ms + cfg_.probe_rtt_ms;
    }
    return;
  }
  if (probe_rtt_round_ && now_ms >= probe_rtt_exit_ms_) {
    min_rtt_stamp_ms_ = now_ms;
    if (!at_full_bw_) {
      enter_startup();
    } else {
      enter_probe_bw(now_ms);
    }
  }
}

void Bbr::enter_startup() {
  mode_ = Mode::kStartup;
  pacing_gain_ = kHighGain;
  cwnd_gain_ = kHighGain;
}

void Bbr::enter_probe_bw(int64_t now_ms) {
  mode_ = Mode::kProbeBw;
  cwnd_gain_ = kCwndGain;
  // The reference picks a random offset out of {0, 2..7}; a fixed 0 (the 1.25
  // probe) is deterministic for tests and starts every stream by probing once,
  // which is what the following drain phase is for.
  cycle_offset_ = 0;
  cycle_start_ms_ = now_ms;
  pacing_gain_ = kPacingGainCycle[cycle_offset_];
}

void Bbr::calculate_congestion_window(size_t bytes_acked) {
  if (mode_ == Mode::kProbeRtt) {
    return;  // cwnd() reports the minimum directly; keep the stored value
  }
  const size_t target = target_window(cwnd_gain_);
  if (at_full_bw_) {
    // Grow toward the target by at most what was just acknowledged. BBR does
    // not shrink the cwnd on loss; pacing (not cwnd) is what keeps the path
    // from being overrun.
    cwnd_ = std::min(target, cwnd_ + bytes_acked);
  } else if (cwnd_ < target || total_acked_ < cfg_.initial_cwnd) {
    cwnd_ += bytes_acked;
  }
  if (cfg_.version == 2) {
    const size_t hi = std::clamp(inflight_hi_, min_cwnd_, max_cwnd_);
    const size_t lo = std::min(std::max(inflight_lo_, min_cwnd_), hi);
    cwnd_ = std::clamp(cwnd_, lo, hi);
  } else {
    cwnd_ = std::clamp(cwnd_, min_cwnd_, max_cwnd_);
  }
}

void Bbr::recalculate_pacing_rate() {
  const double base = bandwidth_bps() > 0
                          ? static_cast<double>(bandwidth_bps())
                          : static_cast<double>(cfg_.initial_cwnd) * 1000.0 /
                                static_cast<double>(min_rtt_ms());
  // With no bandwidth sample the reference always uses the high gain, whatever
  // the current phase; once a sample exists the phase's gain applies.
  const double gain = bandwidth_bps() > 0 ? pacing_gain_ : kHighGain;
  pacing_rate_bps_ = gain * base;
}

size_t Bbr::target_window(double gain) const {
  const double bdp = static_cast<double>(bandwidth_bps()) *
                     static_cast<double>(min_rtt_ms()) / 1000.0 /
                     delivery_efficiency_;
  const double target = bdp > 0 ? gain * bdp : gain * static_cast<double>(cfg_.initial_cwnd);
  return clamp_size(target, cfg_.min_cwnd, cfg_.max_cwnd);
}

size_t Bbr::cwnd() const {
  if (mode_ == Mode::kProbeRtt) {
    return min_cwnd_;
  }
  return cwnd_;
}

double Bbr::pacing_rate_bps() const {
  if (pacing_rate_bps_ <= 0.0) {
    return static_cast<double>(cfg_.initial_cwnd) * 1000.0 /
           static_cast<double>(min_rtt_ms());
  }
  return pacing_rate_bps_;
}

int64_t Bbr::min_rtt_ms() const {
  return min_rtt_ms_ > 0 ? min_rtt_ms_ : cfg_.initial_rtt_ms;
}

size_t Bbr::bdp_bytes() const {
  const double bdp = static_cast<double>(bandwidth_bps()) *
                     static_cast<double>(min_rtt_ms()) / 1000.0;
  return clamp_size(bdp, 0, cfg_.max_cwnd);
}

}  // namespace fcp
