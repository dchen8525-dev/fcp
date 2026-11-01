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
  size_t max_segment = 1336;
  // Send window. With auto_window off this is the fixed window (legacy
  // behaviour); with it on it is only the starting value -- see below.
  size_t send_window_bytes = 256 * 1024;
  size_t rcv_buf_bytes = 256 * 1024;
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
  size_t window_min_bytes = 64 * 1024;
  size_t window_max_bytes = 1024 * 1024;
  // Standing-queue allowance: an epoch whose minimum RTT is this far above the
  // historical minimum holds the window; two consecutive epochs at twice this
  // shrink it. Kept comfortably below the Session §8 guardrail (srtt -
  // min_srtt >= 40ms trims FEC k) so the two controllers do not fight.
  // 0 disables the delay brake.
  int64_t window_queue_ms = 20;
  int64_t initial_srtt_ms = 200;
  int64_t rto_min_ms = 100;
  int64_t rto_max_ms = 5000;
  // Teardown after this long with no inbound segment. Own traffic does not
  // count, so a dead peer is detected by the idle clock, not by an empty log.
  int64_t idle_timeout_ms = 300000;
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

  StreamState state() const { return state_; }
  CloseReason reason() const { return reason_; }
  bool closed() const { return state_ == StreamState::kClosed; }

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
  uint64_t dup_bytes() const { return dup_bytes_; }
  uint64_t segs_sent() const { return segs_sent_; }
  // F-3: zero-window probes are real segments on the wire, but they are a
  // liveness device, not application data. Counted apart so a throughput or
  // redundancy-ratio reading can subtract them.
  uint64_t probes_sent() const { return probes_sent_; }
  uint64_t segs_rx() const { return segs_rx_; }
  uint64_t bad_segs() const { return bad_segs_; }
  // Current send window (== send_window_bytes when auto_window is off) and the
  // autotune's state, for the teardown diagnostics and the unit tests.
  size_t send_window() const { return send_window_; }
  size_t ssthresh() const { return ssthresh_; }
  size_t loss_floor() const { return loss_floor_; }
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
    bool sacked = false;  // #27: covered by a SACK block; never a hole
    int64_t sent_ms = 0;
    size_t wire_len() const { return bytes.size() + (fin ? 1 : 0); }
  };
  struct RcvChunk {
    uint32_t offset = 0;
    std::vector<uint8_t> bytes;
  };

  void emit_seg(const PendingSeg& seg);
  void emit_ack();
  void emit_rst(uint8_t code);
  void pump(int64_t now_ms);
  void handle_data(const uint8_t* seg, size_t len, int64_t now_ms);
  void handle_ack(const uint8_t* seg, size_t len, int64_t now_ms);
  void insert_chunk(uint32_t offset, const uint8_t* data, size_t len);
  void deliver_prefix(int64_t now_ms);
  void fill_holes(uint32_t sack_start, int64_t now_ms);
  void retransmit_timeouts(int64_t now_ms);
  void probe_zero_window(int64_t now_ms);
  void update_srtt(int64_t sample_ms);
  void update_window(int64_t now_ms);
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
  uint32_t sack_filled_up_to_ = 0;   // never re-fill a hole below this
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
  int64_t epoch_min_rtt_ms_ = 0;  // lowest sample inside the current epoch
  int epoch_samples_ = 0;         // clean samples inside the current epoch
  size_t last_target_ = 0;        // recovery reference, and the slow-start bound
  int64_t win_epoch_ms_ = 0;
  uint64_t epoch_acked_ = 0;
  bool loss_epoch_ = false;
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
  bool eof_delivered_ = false;
  bool notified_ = false;            // ClosedFn fires at most once per stream
  // #27: duplicate-ACK tracking on the send side (same cumulative point as
  // the previous ACK while data is unacked). At kDupAckThresh, force-retransmit
  // tx_.front() once per batch — this is the only path through the
  // sack_filled_up_to_ guard when a repair itself was lost.
  uint32_t last_cum_ = 0;
  uint32_t dup_acks_ = 0;
  bool have_cum_ = false;

  uint64_t bytes_queued_ = 0;
  uint64_t bytes_acked_ = 0;
  uint64_t bytes_delivered_ = 0;
  uint64_t retransmits_ = 0;
  uint64_t dup_bytes_ = 0;
  uint64_t segs_sent_ = 0;
  uint64_t probes_sent_ = 0;
  uint64_t segs_rx_ = 0;
  uint64_t bad_segs_ = 0;
};

}  // namespace fcp

#endif  // FCP_STREAM_H_
