// BBRv1 congestion control for the FCP stream layer.
//
// Ported from quic-go's `congestion/bbr` (the `wip-bbr` branch): the delivery
// rate sampler, the windowed max filter, and the STARTUP / DRAIN / PROBE_BW /
// PROBE_RTT state machine. The stream has no packet-number space of its own
// (sequence numbers are byte offsets), so the round counter advances on a
// cumulative ACK that passes the highest offset sent when the round began.
//
// Deviations from the reference, all forced by where this code sits:
//   * Bandwidth is sampled once per cumulative ACK advance, not once per
//     acknowledged packet: one ACK carries a cumulative point plus a single
//     SACK block, so the individual ack times of the covered segments are not
//     observable. The sample is min(send rate, ack rate) over the same
//     interval, which is the reference's slope rule at ACK-batch granularity.
//   * There is no per-packet recovery window: BBR treats loss as a signal to
//     retransmit, not as a reason to cut the rate, and FCP's FEC layer already
//     hides most of the path loss. Cutting on every stream-level hole is what
//     pinned the old autotune to its start window on a lossy WAN path.
//   * Pacing is enforced by the stream host (Stream::pace_allow) against
//     pacing_rate_bps(); the reactor ticks every 25ms, so the token bucket is
//     the granularity limit, not a zero-delay pacer.
//
// The class is deliberately event-driven and clock-free: callers pass now_ms,
// which keeps the unit tests deterministic.

#ifndef FCP_BBR_H_
#define FCP_BBR_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

class Bbr {
 public:
  enum class Mode : uint8_t {
    kStartup = 0,
    kDrain,
    kProbeBw,
    kProbeRtt,
  };

  struct Config {
    size_t mss = 1336;
    size_t initial_cwnd = 256 * 1024;
    size_t min_cwnd = 64 * 1024;
    size_t max_cwnd = 1024 * 1024;
    // RTT used before the first sample (the stream's SRTT, not an optimistic
    // 100ms): an initial rate that is too high turns the first window into a
    // burst the path has to absorb.
    int64_t initial_rtt_ms = 100;
    // How long a minimum-RTT sample stays authoritative before PROBE_RTT.
    int64_t min_rtt_expiry_ms = 10000;
    int64_t probe_rtt_ms = 200;
    // Priors from the previous session to this peer (prewarm). A seeded model
    // starts in PROBE_BW at the proven operating point instead of re-running
    // STARTUP from initial_cwnd: the first connection of a page pays slow
    // start, but the fifth should not. Both are provisional -- the first live
    // RTT sample replaces the seeded minimum, and the bandwidth filter goes on
    // learning normally. 0 = cold start.
    uint64_t initial_bw_bps = 0;
    int64_t initial_min_rtt_ms = 0;
    // 1 = BBRv1 (loss is not congestion evidence); 2 = BBRv2 (learns
    // inflight_hi/inflight_lo from stream-level loss, on top of the v1 model).
    int version = 2;
    // v2: a round whose retransmitted/sent ratio exceeds this is a lossy
    // round. Stream-level loss is already post-FEC, so 2% is the residue, not
    // the raw path loss.
    int loss_threshold_percent = 10;
  };

  Bbr() : Bbr(Config{}) {}
  explicit Bbr(const Config& cfg);
  // Re-seed after the stream has computed its engine clamps (window min/max).
  void configure(const Config& cfg) { *this = Bbr(cfg); }

  // One transmission on the wire, including retransmissions. `in_flight` is
  // the stream's current unacked byte count.
  void on_sent(int64_t now_ms, size_t wire_bytes, size_t in_flight);
  // One cumulative-ACK advance. `wire_bytes` is what the ACK removed from the
  // unacked queue, `rtt_ms` the newest clean RTT sample (0 when Karn dropped
  // it), `new_round` true when this ACK started a new round, and `in_flight`
  // the byte count still outstanding.
  void on_acked(int64_t now_ms, size_t wire_bytes, int64_t rtt_ms, bool new_round,
                size_t in_flight);
  // The stream has nothing left to send. Reference: informs the sampler that a
  // low delivery rate may be the application's fault, not the path's.
  void on_app_limited(int64_t now_ms);
  // A stream-level loss was detected (dup-ACK burst, RTO). BBR does not cut on
  // loss; this only stops a gain-cycle probe from waiting for a target the
  // buffers cannot hold.
  void on_loss() { recent_loss_ = true; }
  // v2: bytes retransmitted since the last round boundary. Loss rate is
  // computed over a round at the next new_round; v1 only ignores it.
  void on_lost(size_t wire_bytes) { round_lost_ += wire_bytes; }
  // Tick-driven upkeep: PROBE_RTT entry/exit when no ACK has arrived.
  void on_tick(int64_t now_ms, size_t in_flight);

  size_t cwnd() const;
  // Bytes per second the caller should use for its token bucket.
  double pacing_rate_bps() const;
  uint64_t bandwidth_bps() const { return max_bw_.best(); }
  int64_t min_rtt_ms() const;
  size_t bdp_bytes() const;
  Mode mode() const { return mode_; }
  double pacing_gain() const { return pacing_gain_; }
  bool at_full_bandwidth() const { return at_full_bw_; }
  size_t inflight_hi() const { return inflight_hi_; }
  size_t inflight_lo() const { return inflight_lo_; }
  // Delivered bytes / sent bytes over the last round. FCP's in-flight includes
  // lost bytes waiting for retransmission, so the window target is divided by
  // this to keep the useful part equal to the BDP.
  double delivery_efficiency() const { return delivery_efficiency_; }
  int version() const { return cfg_.version; }
  uint64_t round() const { return round_; }

  // Small helpers used by the stream's diagnostics.
  static const char* mode_name(Mode mode);

 private:
  // Kathleen Nichols' max filter, as used by the reference: three estimates
  // guarantee the best sample over the window even when the true maximum is
  // monotonically moving.
  class WindowedMaxFilter {
   public:
    explicit WindowedMaxFilter(uint64_t window) : window_(window) {}
    void update(uint64_t bandwidth, uint64_t round);
    uint64_t best() const { return estimates_[0].bandwidth; }
    void reset(uint64_t bandwidth, uint64_t round);

   private:
    struct Sample {
      uint64_t bandwidth = 0;
      uint64_t round = 0;
    };
    uint64_t window_;
    Sample estimates_[3];
  };

  void maybe_advance_gain_cycle(int64_t now_ms, size_t in_flight);
  void maybe_exit_startup_or_drain(int64_t now_ms, size_t in_flight);
  void maybe_enter_or_exit_probe_rtt(int64_t now_ms, size_t in_flight);
  void check_full_bandwidth();
  void update_bounds_at_round_start(size_t in_flight);
  void enter_startup();
  void enter_probe_bw(int64_t now_ms);
  void calculate_congestion_window(size_t bytes_acked);
  void recalculate_pacing_rate();
  size_t target_window(double gain) const;

  Config cfg_;
  Mode mode_ = Mode::kStartup;
  WindowedMaxFilter max_bw_;
  size_t min_cwnd_ = 0;
  size_t max_cwnd_ = 0;

  uint64_t round_ = 0;
  uint64_t total_sent_ = 0;
  uint64_t total_acked_ = 0;
  int64_t last_sample_ms_ = 0;
  uint64_t last_sample_sent_ = 0;
  uint64_t sample_bytes_ = 0;
  bool have_sample_baseline_ = false;
  bool app_limited_ = false;
  bool sent_since_app_limited_ = false;
  bool last_sample_app_limited_ = false;

  int64_t min_rtt_ms_ = 0;
  int64_t min_rtt_stamp_ms_ = 0;

  size_t cwnd_ = 0;
  double pacing_rate_bps_ = 0.0;
  double pacing_gain_ = 0.0;
  double cwnd_gain_ = 0.0;
  int cycle_offset_ = 0;
  int64_t cycle_start_ms_ = 0;

  bool at_full_bw_ = false;
  // The minimum RTT came from a prior session, not from a live sample: the
  // first real sample must replace it even if it is larger (the path may have
  // changed), which the ordinary "only smaller samples move it" rule would
  // refuse. Cleared by that first sample.
  bool min_rtt_seeded_ = false;

  // BBRv2 inflight bounds. v1 leaves inflight_hi_ at max_cwnd_ and ignores
  // inflight_lo_.
  size_t inflight_hi_ = 0;
  size_t inflight_lo_ = 0;
  uint64_t round_sent_ = 0;
  uint64_t round_lost_ = 0;
  uint64_t round_delivered_ = 0;
  size_t round_max_inflight_ = 0;
  // The path's own loss floor (random loss the FEC cannot hide). v2 treats only
  // loss above this as congestion evidence; otherwise a 15%-loss satellite or
  // WAN path would ratchet inflight_hi down to the floor forever.
  uint64_t loss_base_ppm_ = 0;
  bool have_loss_base_ = false;
  double delivery_efficiency_ = 1.0;
  int rounds_without_growth_ = 0;
  uint64_t bw_at_last_round_ = 0;
  bool recent_loss_ = false;

  int64_t probe_rtt_exit_ms_ = 0;
  bool probe_rtt_round_ = false;
};

}  // namespace fcp

#endif  // FCP_BBR_H_
