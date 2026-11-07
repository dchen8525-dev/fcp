// FCP-STREAM v1: a minimal reliable ordered byte stream on top of one Session.
//
// Position in the stack (M2代理设计.md §1-§2): FCP carries opaque
// payloads and recovers erasures; it does NOT retransmit what RS could not
// repair. That ARQ job is this file — the slot KCP would otherwise fill. One
// segment is exactly one data symbol, so segment boundaries survive the wire
// and no length prefixing is needed here.
//
// Sequence numbers are BYTE offsets into the stream (not packet ids), so a
// cumulative ack is "bytes delivered" and retransmission may re-chunk freely.
// Each direction numbers its own bytes from 0: cross-connection injection is
// already blocked by the per-session salt and key, so a random initial
// sequence number would only add a second numbering space to keep in sync.
// A fin is carried by a dedicated zero-length segment and occupies one
// sequence number past the last data byte, exactly like TCP's FIN.
//
// No clocks and no sockets: the host passes now_ms in and handles the emitted
// segments, so the same code runs under the CLI select loop and the Qt timer.

#ifndef FCP_STREAM_H_
#define FCP_STREAM_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "fcp/bbr.h"
#include "fcp/defaults.h"

namespace fcp {

constexpr uint8_t kStreamTypeData = 1;
constexpr uint8_t kStreamTypeAck = 2;
constexpr uint8_t kStreamTypeRst = 3;

constexpr size_t kStreamDataHdrLen = 6;  // type | seq(4) | flags
constexpr size_t kStreamAckLen = 17;     // type | cum | rwnd | sack_start | sack_end
constexpr size_t kStreamRstLen = 2;      // type | code
constexpr uint8_t kStreamFlagFin = 1u << 0;

// M3 fast retransmit (M3控制设计.md §4, #27): duplicate ACKs of the same
// cumulative point are proof the peer is buffering past a hole; the third one
// force-retransmits the first unacked segment without waiting for the RTO or
// the SACK-fill bookkeeping. The receiver rotates the single SACK block per
// dup-ACK so every buffered hole gets reported within a few duplicates.
constexpr uint32_t kDupAckThresh = 3;

// Bound on the *number* of chunks in the out-of-order buffer, not just their
// bytes. A chunk costs ~32 B of bookkeeping whatever it carries, so a peer that
// fills the receive window with 1-byte segments would otherwise turn a 1 MiB
// window into tens of MB (and one sort+rebuild per packet once the arrival
// order dips behind the tail). One chunk per 512 bytes of capacity leaves the
// legitimate case -- segments of ~1.3 KiB, so ~800 chunks in 1 MiB -- untouched.
constexpr size_t kMinOobChunks = 1024;
constexpr size_t kMaxOobChunks = 8192;

// How long the historical min RTT stays valid. Mirrors Bbr's
// min_rtt_expiry_ms: after a route change the path is slower, and a floor that
// never rises turns every epoch into a standing queue (the delay brake reads
// epoch_min - min as queueing) so the window brakes forever.
constexpr int64_t kMinRttExpiryMs = 10000;

// Delayed-ACK deadline for a coalesced ACK (StreamConfig::ack_every > 1). A
// single-segment request must not wait for the reactor's 25 ms tick -- that
// would add a tick of latency to every short exchange -- so the pending ACK
// carries its own deadline and the host wakes for it (next_wake_ms). 4 ms keeps
// the coalescing effective on a burst while staying well under the tick.
constexpr int64_t kAckDelayMs = 4;

// Largest slice of the pacing rate the token bucket may bank. It used to be one
// reactor tick (30 ms), which turned the pacer into a burst emitter: at 20 Mbps
// every tick released ~62 KB back-to-back, exactly the micro-burst a shallow
// queue drops. With next_wake_ms() the host can wake mid-tick, so the allowance
// only has to cover scheduling jitter, not a whole tick.
constexpr double kPaceBurstMs = 6.0;

// Tail loss probe (RFC 8985 in shape, simplified here). With data outstanding
// and neither cumulative progress nor a probe for about one and a half RTTs,
// resend the newest segment the peer has not SACKed. The ACK it provokes either
// repairs the lost tail itself or tells us the tail arrived and only its ACK
// was lost, so a tail loss costs one RTT instead of the RTO's two (plus the
// exponential backoff the RTO would arm). It is a probe, not congestion
// evidence: BBR hears about the send, never about a loss. Two probes per stall
// at most -- after that the RTO is the backstop.
//
// The floor keeps the probe off the host's tick grid: delivery is quantized to
// the 25 ms tick, so a lossless round trip can look like a tick and a half, and
// probing every tick would turn the feature into a retransmission storm on fast
// paths. The ceiling keeps it strictly before the base RTO, which owns the case
// where the probe itself is lost.
constexpr int64_t kTlpMinPtoMs = 60;
constexpr int64_t kTlpSlackMs = 10;
constexpr uint32_t kTlpMaxProbes = 2;

constexpr uint8_t kStreamRstAbort = 1;

enum class StreamState : uint8_t {
  kOpen = 0,
  kSendingFin,   // local side closed, waiting for the fin to be acked
  kPeerClosed,   // peer's fin fully received
  kClosed,
};

enum class CloseReason : uint8_t {
  kNone = 0,
  kLocalEof,     // our fin was acked
  kPeerClose,    // peer fin received and we are done
  kReset,        // RST either way, including host-given aborts
  kIdle,         // idle_timeout_ms of silence
};

struct StreamConfig {
  // Largest segment payload the session can carry: Session::mtu_limits().payload_max.
  // Follows that bound both ways at run time (set_max_segment): up on PMTUD
  // growth, down on a PMTUD black-hole fallback. A downward move re-cuts the
  // in-flight segments, so the byte offsets the ARQ works in never change.
  size_t max_segment = 1336;
  // Send window. With auto_window off this is the constant window; with it on
  // it is only the starting value -- see below.
  size_t send_window_bytes = kDefaultSendWindowBytes;
  // Set when send_window_bytes came from an explicit choice (a CLI --window or
  // the GUI spinbox) rather than the default. The prewarm cache may replace a
  // default start with the peer's converged window; it never overrides an
  // explicit one.
  bool send_window_explicit = false;
  // Floor for the loss-driven decrease in auto mode (decision #33). Normally
  // the operator's --window, which is not necessarily the window the stream
  // starts at: the prewarm prior may raise the start above it. Without this
  // field the floor would be the seeded start, so a warm connection could
  // never shrink back to the value the operator asked for. 0 means "use the
  // start window", which is the behaviour when no prior was applied.
  size_t loss_floor_bytes = 0;
  size_t rcv_buf_bytes = kDefaultRcvBufBytes;
  // Window autotune. The send window starts at send_window_bytes and grows
  // while the stream is its own bottleneck: doubling per RTT until ssthresh, then
  // one segment per RTT after that. A credible epoch (enough samples to say
  // something) refreshes ssthresh to twice the delivery-rate x min_rtt estimate,
  // so slow start exits where the path appears to saturate -- but never below the
  // window already in force, and additive growth continues past the estimate.
  // Goodput on a lossy path underestimates capacity (retransmitted bytes are not
  // "delivered"), and using the estimate as a ceiling froze the window
  // permanently after the first loss. It is also the recovery reference: a loss
  // sets ssthresh to it, so the window doubles back to what it had proven before
  // going additive.
  //
  // The downward signals are loss and self-induced delay. When the minimum RTT
  // of an epoch sits window_queue_ms above the historical minimum, our own queue
  // is standing, so the window holds; two consecutive epochs over twice that cut
  // it by an eighth. Both readings need enough samples in the epoch, because the
  // minimum of one or two rounds on a jittery path says nothing about a queue.
  // Loss costs one 30% decrease per epoch.
  //
  // window_max_bytes is the hard ceiling. In auto mode the receive capacity is
  // raised to the same value so the peer's growth is not clamped by a buffer
  // smaller than the window it is allowed to reach. This is NOT negotiated on
  // the wire: auto/fixed mixes are safe (a fixed peer simply advertises its
  // own buffer and the sender stays peer-limited) but the extra memory is
  // committed per connection by arrivals, not reserved.
  bool auto_window = false;
  size_t window_min_bytes = kDefaultWindowMinBytes;
  size_t window_max_bytes = kDefaultWindowMaxBytes;
  // Auto mode with BBR: let the ceiling follow the measured BDP instead of
  // stopping at the configured window_max_bytes (which is then only the floor
  // of the ceiling). A 1 MiB ceiling holds a 200 ms path to 40 Mbps however
  // good the controller is, so a session that keeps proving a larger BDP is
  // allowed to grow to this bound. 0 keeps the ceiling fixed (the old
  // behaviour); the engine derives a value from the operator's configuration.
  size_t window_ceiling_bytes = 0;
  // Emit one ACK per this many in-order data segments while the receive buffer
  // has no hole; out-of-order bytes, a fin and a closed window still ACK
  // immediately (the peer is waiting on those), and a pending ACK is flushed
  // after kAckDelayMs. 1 = one ACK per segment (the old behaviour, kept as the
  // unit-test default so the protocol tests stay bit-precise).
  uint8_t ack_every = 1;
  // Congestion controller for auto mode. BBR (bbr.h) is the default: it
  // derives the window from a delivery-rate estimate and paces the stream, so
  // loss is answered with retransmission rather than with a window cut. The
  // epoch controller (auto_window + slow start / AIMD / window_probe) remains
  // available with --no-bbr for comparison and for pinned regression tests.
  bool bbr = true;
  // BBR generation: 1 = BBRv1 (loss only stops a probe), 2 = BBRv2 (learns
  // inflight_hi/inflight_lo from the stream-level loss residue). Default 2.
  int bbr_version = 2;
  // Rate probe for the *epoch* controller only (auto mode, no BBR). A
  // stream-level hole on a FEC-protected path is not clean congestion evidence:
  // the parity already absorbed what it could, so the residue is a mix of
  // contention and random loss. When a lossy epoch still delivered data, has
  // no standing-queue evidence, and its delivery rate is still rising, the
  // window grows 25% instead of cutting. Ignored when `bbr` is on.
  bool window_probe = true;
  // Standing-queue allowance: an epoch whose minimum RTT is this far above the
  // historical minimum holds the window; two consecutive epochs at twice this
  // shrink it. Sized against Session's §8 guardrail (kQueueGuardrailGapMs
  // trims FEC k on the same evidence); half of it is short enough that the two
  // controllers do not fight. 0 disables the delay brake.
  int64_t window_queue_ms = kQueueGuardrailGapMs / 2;
  int64_t initial_srtt_ms = kDefaultSrttMs;
  // Prewarm priors for the controller (BBR only): the previous session's
  // delivery rate and minimum RTT. They let a new connection start at the
  // operating point the link already proved instead of re-running slow start
  // from the default window -- the per-connection cold start is what makes a
  // page of short-lived TCP connections feel slow. 0 = no prior.
  uint64_t initial_bw_bps = 0;
  int64_t initial_min_rtt_ms = 0;
  int64_t rto_min_ms = 100;
  int64_t rto_max_ms = 5000;
  // Teardown after this long with no inbound segment. Own traffic does not
  // count, so a dead peer is detected by the idle clock, not by an empty log.
  int64_t idle_timeout_ms = kDefaultIdleTimeoutMs;
  // Zero-window probing: resend one segment this often while the peer advertises
  // no room and we have nothing in flight to be acked.
  int64_t probe_ms = 1000;
};

class Stream {
 public:
  // One emitted segment: hand it to Session::on_kcp_output().
  using SegmentFn = std::function<void(const uint8_t* seg, size_t len)>;
  // In-order bytes for the local socket. The host applies backpressure through
  // write()/can_write(); this callback must not buffer without bound.
  using ReadFn = std::function<void(const uint8_t* bytes, size_t len)>;
  // The peer's fin is fully delivered: the read side is done, the write side is
  // not. A proxy maps this to shutdown(local, SHUT_WR) and keeps flushing.
  using EofFn = std::function<void()>;
  // Full teardown: nothing left in either direction, or a reset/idle timeout.
  // Fired at most once, from inside a send_/read_/tick path. Contract: this
  // callback may record the teardown, but must not destroy the Stream -- the
  // caller is still on its stack and checks state_ afterwards. Destroy the
  // Stream only from the host's own loop, outside any Stream call.
  using ClosedFn = std::function<void(CloseReason)>;
  // Smoothed RTT in ms; the host forwards it to Session::on_rtt_sample() so the
  // settlement guards (§5) and the queue guardrail (§8) see a real RTT.
  using RttFn = std::function<void(int64_t srtt_ms)>;
  using LogFn = std::function<void(const std::string& line)>;

  Stream(const StreamConfig& config, SegmentFn send, ReadFn read, ClosedFn closed,
         EofFn eof = EofFn(), RttFn rtt = RttFn(), LogFn log = LogFn());

  Stream(const Stream&) = delete;
  Stream& operator=(const Stream&) = delete;

  // One received data-symbol payload.
  void on_segment(const uint8_t* seg, size_t len, int64_t now_ms);
  // Queue app bytes; returns how many were accepted (backpressure signal).
  size_t write(const uint8_t* data, size_t len);
  bool can_write() const;
  // Graceful shutdown: flush what is queued, then send the fin segment.
  void close(int64_t now_ms);
  void abort(int64_t now_ms, uint8_t code = kStreamRstAbort);
  // Timer pump. 5-25ms is enough; it drives retransmit, zero-window probes,
  // fin completion and the idle clock.
  void on_tick(int64_t now_ms);
  // Earliest time this stream wants the host to call on_tick() again: the
  // coalesced ACK's deadline, or the moment the pacing token bucket has banked
  // enough for the next segment. 0 = nothing pending (the host's own tick is
  // enough). The reactor folds this into its select() timeout, which is what
  // lets the pacer work at a finer granularity than the 25 ms tick.
  int64_t next_wake_ms(int64_t now_ms) const;
  // PMTUD moved the session's payload size. A raise only affects the next
  // pump(); a lower moves re-cut every queued segment in place, preserving the
  // byte offsets, because a fallback has declared the larger datagrams
  // unsendable and leaving them carved at the old size would retransmit them
  // forever on a path that drops them.
  void set_max_segment(size_t bytes);

  StreamState state() const { return state_; }
  CloseReason reason() const { return reason_; }
  bool closed() const { return state_ == StreamState::kClosed; }

  // Tests only: pins the send-side offsets so the 4 GiB wrap of the byte
  // numbering (seq.h) can be exercised without pushing gigabytes. Caller owns
  // the state invariant (both queues empty; call before write()/close()).
  // Tests only: drive the RTT estimator directly, so the expiry of the
  // historical min RTT can be exercised without waiting kMinRttExpiryMs.
  void test_update_rtt(int64_t sample_ms, int64_t now_ms) {
    update_srtt(sample_ms, now_ms);
  }

  void test_set_send_offsets(uint32_t snd_nxt, uint32_t snd_una, uint32_t snd_max) {
    snd_nxt_ = snd_nxt;
    snd_una_ = snd_una;
    snd_max_ = snd_max;
  }

  // Bytes already delivered to the host that it has not taken back yet -- a
  // local socket whose send buffer is full, a target that is not reading. The
  // receive buffer has to hold them too, so the count is subtracted from the
  // advertised window and a stalled reader closes the sender's window instead
  // of growing this buffer without bound.
  void set_delivery_pending(size_t bytes) { delivery_pending_ = bytes; }
  size_t delivery_pending() const { return delivery_pending_; }

  // Diagnostics for the proxy stats line / GUI table.
  uint64_t bytes_queued() const { return bytes_queued_; }
  uint64_t bytes_acked() const { return bytes_acked_; }
  uint64_t bytes_delivered() const { return bytes_delivered_; }
  uint64_t retransmits() const { return retransmits_; }
  uint64_t retx_fast() const { return retx_fast_; }
  // Dup-burst repairs that a cumulative advance discounted as reordering;
  // each one widens the burst gates for this stream (P1-3).
  uint64_t spur_bursts() const { return spur_bursts_; }
  uint64_t retx_fill() const { return retx_fill_; }
  uint64_t retx_rto() const { return retx_rto_; }
  // Probes sent by the tail-loss timer, apart from RTO repairs and fills.
  uint64_t retx_tlp() const { return retx_tlp_; }
  uint64_t fill_passes() const { return fill_passes_; }
  uint64_t dup_bytes() const { return dup_bytes_; }
  uint64_t segs_sent() const { return segs_sent_; }
  // F-3: zero-window probes are real segments on the wire, but they are a
  // liveness device, not application data. Counted apart so a throughput or
  // redundancy-ratio reading can subtract them.
  uint64_t probes_sent() const { return probes_sent_; }
  uint64_t segs_rx() const { return segs_rx_; }
  uint64_t bad_segs() const { return bad_segs_; }
  uint64_t oob_drops() const { return oob_drops_; }
  size_t oob_chunks() const { return oob_.size(); }
  // Current send window (== send_window_bytes when auto_window is off) and the
  // autotune's state, for the teardown diagnostics and the unit tests.
  size_t send_window() const { return send_window_; }
  size_t ssthresh() const { return ssthresh_; }
  size_t loss_floor() const { return loss_floor_; }
  // BBR diagnostics (auto mode with bbr on).
  bool using_bbr() const { return cfg_.auto_window && cfg_.bbr; }
  Bbr::Mode bbr_mode() const { return bbr_.mode(); }
  uint64_t bbr_bandwidth_bps() const { return bbr_.bandwidth_bps(); }
  size_t bbr_bdp_bytes() const { return bbr_.bdp_bytes(); }
  double bbr_pacing_rate_bps() const { return bbr_.pacing_rate_bps(); }
  double bbr_pacing_gain() const { return bbr_.pacing_gain(); }
  double bbr_efficiency() const { return bbr_.delivery_efficiency(); }
  size_t bbr_inflight_hi() const { return bbr_.inflight_hi(); }
  size_t bbr_inflight_lo() const { return bbr_.inflight_lo(); }
  // Loss attribution for the shrink terms above.
  uint64_t dup_loss_events() const { return dup_loss_events_; }
  uint64_t rto_loss_events() const { return rto_loss_events_; }
  size_t last_target() const { return last_target_; }
  int64_t min_rtt_ms() const { return min_rtt_ms_; }
  size_t in_flight() const { return in_flight_; }
  size_t queued_bytes() const { return tx_pending_.size(); }
  size_t unacked_segs() const { return tx_.size(); }
  size_t oob_bytes() const { return oob_bytes_; }
  int64_t srtt_ms() const { return srtt_ms_; }
  int64_t rto_ms() const { return rto_ms_; }
  size_t peer_window() const { return peer_rwnd_; }
  size_t send_space() const;
  // Diagnostics: duplicate ACKs counted on the send side since the last cum
  // advance (0 when the last ACK moved cum).
  uint32_t dup_acks() const { return dup_acks_; }

 private:
  struct PendingSeg {
    uint32_t offset = 0;
    std::vector<uint8_t> bytes;
    bool fin = false;
    bool sent = false;
    bool retrans = false;
    // #27: covered by a SACK block; never a hole. The mark is a timestamp, not
    // a flag, because the evidence has to expire: a receiver cannot retract a
    // SACK, so one stale block (its out-of-order tail dropped under buffer
    // pressure, a forged packet, a lost-and-forgotten range) would otherwise
    // keep these segments out of both the RTO pass and fill_holes forever.
    int64_t sacked_ms = -1;
    int64_t sent_ms = 0;
    size_t wire_len() const { return bytes.size() + (fin ? 1 : 0); }
  };
  struct RcvChunk {
    uint32_t offset = 0;
    std::vector<uint8_t> bytes;
  };

  void emit_seg(const PendingSeg& seg);
  // `now_ms` stamps the ACK so on_tick can keep the SACK rotation alive while
  // the receive buffer is stalled and no new data arrives.
  void emit_ack(int64_t now_ms);
  // Apply the ACK coalescing policy for one delivered data segment. `urgent`
  // covers the cases where the peer is provably waiting on this ACK (its fin,
  // a hole, a closed window).
  void maybe_ack(int64_t now_ms, bool urgent);
  // Grow the send ceiling toward twice the BBR-measured BDP, bounded by
  // cfg_.window_ceiling_bytes. No-op when the ceiling is fixed.
  void refresh_window_ceiling();
  void emit_rst(uint8_t code);
  void pump(int64_t now_ms);
  void handle_data(const uint8_t* seg, size_t len, int64_t now_ms);
  void handle_ack(const uint8_t* seg, size_t len, int64_t now_ms);
  // The three duties one ACK can carry, split out of handle_ack() but called
  // from it in a fixed order (see stream_send.cc).
  void ack_dup_burst(uint32_t cum, int64_t now_ms);
  void ack_advance_cum(uint32_t cum, int64_t now_ms);
  void ack_fill_sack(uint32_t sack_start, uint32_t sack_end, int64_t now_ms);
  void insert_chunk(uint32_t offset, const uint8_t* data, size_t len);
  // Bytes this stream may still buffer out of order: the receive capacity minus
  // the out-of-order buffer *and* what the host has not taken back yet, which
  // is exactly what rwnd_out() advertises. Counting only the buffer would let
  // the receiver hold twice the window it promised.
  size_t oob_room() const;
  size_t oob_max_chunks() const;
  void deliver_prefix(int64_t now_ms);
  void fill_holes(uint32_t sack_start, int64_t now_ms);
  // Whether a SACK mark is still recent enough to keep the segment out of the
  // repair paths. See PendingSeg::sacked_ms for why it cannot be permanent.
  bool sack_fresh(const PendingSeg& seg, int64_t now_ms) const;
  void retransmit_timeouts(int64_t now_ms);
  // Tail loss probe: resend the newest un-SACKed segment when nothing has
  // progressed for roughly one RTT. tlp_due_ms() is the shared predicate, so
  // next_wake_ms() can schedule the tick that fires it.
  void tail_loss_probe(int64_t now_ms);
  int64_t tlp_due_ms(int64_t now_ms) const;
  int64_t tlp_pto_ms() const;
  void probe_zero_window(int64_t now_ms);
  void update_srtt(int64_t sample_ms, int64_t now_ms);
  void update_window(int64_t now_ms);
  // Token bucket for BBR pacing. Returns false when this segment must wait for
  // the next tick; a successful call charges the bytes.
  bool pace_allow(size_t bytes, int64_t now_ms);
  void finish(int64_t now_ms, CloseReason reason);
  uint32_t cum_out() const;
  size_t rwnd_out() const;

  StreamConfig cfg_;
  SegmentFn send_;
  ReadFn read_;
  ClosedFn closed_;
  EofFn eof_;
  RttFn rtt_;
  LogFn log_;

  uint32_t snd_nxt_ = 0;   // next byte offset to assign
  uint32_t snd_max_ = 0;   // highest offset ever put on the wire (A4)
  uint32_t snd_una_ = 0;   // lowest unacked byte offset
  StreamState state_ = StreamState::kOpen;
  CloseReason reason_ = CloseReason::kNone;

  std::deque<PendingSeg> tx_;        // unacked segments, oldest first
  std::vector<uint8_t> tx_pending_;  // queued by write(), not yet segmented
  bool fin_queued_ = false;          // close() called, fin not yet emitted
  bool fin_sent_ = false;
  uint32_t fin_offset_ = 0;          // sequence number occupied by our fin
  size_t in_flight_ = 0;             // bytes of sent-and-unacked segments
  size_t peer_rwnd_ = 0;
  bool probe_credit_ = false;        // let one segment past a closed window
  // F-3: persist-timer style backoff for zero-window probes. A peer that keeps
  // answering with the same closed window would otherwise pull one full segment
  // every probe_ms for as long as the ACKs keep coming.
  int64_t probe_backoff_ = 1;
  // peer_rwnd_ starts as a guess copied from our own config; the autotune only
  // reads a full window as path evidence once an ACK has confirmed the peer's.
  bool peer_rwnd_seen_ = false;

  std::deque<RcvChunk> oob_;         // sorted, disjoint, offset >= rcv_nxt_
  size_t oob_bytes_ = 0;
  size_t delivery_pending_ = 0;      // bytes the host has not taken back yet
  uint32_t rcv_nxt_ = 0;             // bytes delivered to the app
  bool peer_fin_ = false;
  uint32_t peer_fin_at_ = 0;         // offset where the peer's data ends
  // New holes are filled from here up to the SACK block start. Bytes below the
  // mark are not re-walked as first-time holes (a rotating single-block ACK
  // would otherwise keep re-sending ranges it has not reported yet), but a
  // repair below it is retried once per RTT -- see fill_holes().
  uint32_t sack_filled_up_to_ = 0;
  int64_t last_ack_ms_ = 0;          // last ACK emitted (out-of-order tick ACK)
  // #27: on repeated ACKs of the same cumulative point (the peer has data we
  // do not), rotate which oob chunk the single SACK block reports, so the
  // sender learns every hole in a few duplicates instead of one per RTT.
  uint32_t last_ack_cum_ = 0;
  uint32_t sack_rotate_ = 0;
  bool have_ack_cum_ = false;

  int64_t srtt_ms_ = 0;
  int64_t rto_ms_ = 0;
  // Window autotune (see StreamConfig::auto_window). send_window_ is what
  // send_space()/pump() read; the epoch counters turn "bytes acknowledged
  // since the last sample" into a delivery rate.
  size_t send_window_ = 0;
  size_t ssthresh_ = 0;
  size_t window_min_ = 0;
  size_t window_max_ = 0;
  // Hard bound for the BDP-following ceiling (cfg_.window_ceiling_bytes), or 0
  // when the ceiling is fixed at the configured window_max_bytes.
  size_t window_ceiling_ = 0;
  // ACK coalescing: segments delivered since the last ACK, and whether an ACK
  // is owed before the next kAckDelayMs deadline (see maybe_ack).
  uint32_t acks_owed_ = 0;
  bool ack_pending_ = false;
  // The deepest the loss term alone may take the window: the window the stream
  // started with. A stream-level hole on this stack is not clean congestion
  // evidence -- the FEC layer already absorbed what it could, so the residue is
  // a mix of contention and random loss the parity missed -- and a window below
  // the operator's `--window` is strictly worse there (measured 2026-10-31: a
  // 64 KiB window on a 160ms/17%-loss path ran at a third of the fixed 256 KiB
  // rate and never climbed back). Cutting on queue evidence is still allowed to
  // go all the way down to window_min_, because a standing queue of our own
  // making is a real signal.
  size_t loss_floor_ = 0;
  // Receive capacity backing the advertised window: rcv_buf_bytes, raised to
  // window_max_bytes in auto mode so the peer's growth is never clamped by a
  // buffer that is smaller than the window it is allowed to reach.
  size_t rcv_cap_ = 0;
  int64_t min_rtt_ms_ = 0;
  int64_t min_rtt_stamp_ms_ = 0;  // when min_rtt_ms_ was last refreshed
  int64_t epoch_min_rtt_ms_ = 0;  // lowest sample inside the current epoch
  int epoch_samples_ = 0;         // clean samples inside the current epoch
  size_t last_target_ = 0;        // recovery reference, and the slow-start bound
  // Delivery rate (bytes/s) at the last probe growth. The next growth has to
  // beat it by 5%: that is what makes the probe stop at the path's knee.
  uint64_t probe_rate_bps_ = 0;
  int64_t win_epoch_ms_ = 0;
  uint64_t epoch_acked_ = 0;
  bool loss_epoch_ = false;
  // True when this epoch's loss evidence was a dup-ACK hole (the peer is still
  // acknowledging, so data is flowing), as opposed to an RTO blackout. The
  // rate probe only trusts the former: a timeout is congestion/blackout
  // evidence and keeps the AIMD cut.
  bool loss_epoch_dup_ = false;
  // Which loss evidence showed up, counted separately because the two have
  // different remedies and a WAN log line cannot tell them apart afterwards:
  // `dup_loss_events` is a second duplicate-ACK burst with the first repair
  // still unacked (a hole the peer is waiting behind), `rto_loss_events` is a
  // timeout pass (nothing came back at all).
  uint64_t dup_loss_events_ = 0;
  uint64_t rto_loss_events_ = 0;
  bool limited_epoch_ = false;
  // Consecutive epochs whose minimum RTT sat over the queue allowance; the
  // delay brake fires on the second one, so path jitter cannot fake a queue.
  int queue_over_ = 0;
  // Exponential RTO backoff (Karn): doubled per timeout episode and reset by a
  // clean sample, so a silent peer is retransmitted at a decaying rate instead
  // of one full window every base RTO.
  int64_t rto_backoff_ = 1;
  // A dup-ACK burst that is still unexplained: the first forced retransmission
  // may just be reordering (FEC delivers symbols out of order), so the 30%
  // window cut waits for a second burst with the first repair still unacked.
  bool fast_retx_armed_ = false;
  int64_t last_activity_ms_ = 0;
  int64_t last_probe_ms_ = 0;
  // Tail loss probe state: when the peer last confirmed progress (cum moved, or
  // data went out after an idle period) and how many probes this stall has
  // already spent. Both reset on the next cumulative advance.
  int64_t progress_ms_ = 0;
  uint32_t tlp_probes_ = 0;
  bool eof_delivered_ = false;
  bool notified_ = false;            // ClosedFn fires at most once per stream
  // #27: duplicate-ACK tracking on the send side (same cumulative point as
  // the previous ACK while data is unacked). At the effective packet
  // threshold, force-retransmit tx_.front() once per batch — this is the only
  // path through the sack_filled_up_to_ guard when a repair itself was lost.
  uint32_t last_cum_ = 0;
  uint32_t dup_acks_ = 0;
  bool have_cum_ = false;

  // Adaptive reordering tolerance (borrowed from quic-go): a dup-ACK burst
  // that fires and is then confirmed by a cumulative advance sooner than one
  // round trip cannot have been answered by the repair copy — the repaired
  // byte needed its own transit — so the burst raced a reordered original and
  // the retransmission was spurious. Each observation widens the first-burst
  // time gate (`reorder_grace_ms_`) geometrically from one eighth of an RTT
  // up to a full RTT and doubles the packet threshold, so reordered shadows
  // stop firing repairs; behaviour is byte-identical to the fixed thresholds
  // until the first spurious repair is observed on that stream.
  int64_t reorder_grace_ms_ = 0;
  uint32_t dup_thresh_ = kDupAckThresh;
  // Earliest duplicate-burst retransmission still unexplained (for the
  // since-burst < RTT test above); -1 = none.
  int64_t dup_burst_ms_ = -1;
  uint64_t spur_bursts_ = 0;  // diagnostics: dup-bursts confirmed spurious

  // BBR (auto mode when cfg_.bbr): the model, the round boundary used to tell
  // "a new RTT has started" on a cumulative ACK, and the pacing token bucket.
  Bbr bbr_;
  uint32_t bbr_round_end_ = 0;
  double pace_tokens_ = 0.0;
  int64_t pace_ms_ = 0;

  uint64_t bytes_queued_ = 0;
  uint64_t bytes_acked_ = 0;
  uint64_t bytes_delivered_ = 0;
  uint64_t retransmits_ = 0;
  // Split for teardown forensics: which path re-sent the bytes.
  uint64_t retx_fast_ = 0;
  uint64_t retx_fill_ = 0;
  uint64_t retx_rto_ = 0;
  uint64_t retx_tlp_ = 0;
  uint64_t fill_passes_ = 0;
  uint64_t dup_bytes_ = 0;
  uint64_t segs_sent_ = 0;
  uint64_t probes_sent_ = 0;
  uint64_t segs_rx_ = 0;
  uint64_t bad_segs_ = 0;
  // Segments dropped because the out-of-order buffer was at its chunk ceiling.
  // The sender recovers them by retransmission; the counter makes the path
  // visible instead of looking like random loss.
  uint64_t oob_drops_ = 0;
};

}  // namespace fcp

#endif  // FCP_STREAM_H_
