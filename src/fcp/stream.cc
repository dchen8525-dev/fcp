#include "fcp/stream.h"

#include <algorithm>
#include <string>

#include "fcp/seq.h"
#include "fcp/wire.h"

namespace fcp {
namespace {

int64_t clamp_ms(int64_t v, int64_t lo, int64_t hi) {
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

}  // namespace

Stream::Stream(const StreamConfig& config, SegmentFn send, ReadFn read, ClosedFn closed,
               EofFn eof, RttFn rtt, LogFn log)
    : cfg_(config),
      send_(std::move(send)),
      read_(std::move(read)),
      closed_(std::move(closed)),
      eof_(std::move(eof)),
      rtt_(std::move(rtt)),
      log_(std::move(log)),
      snd_nxt_(0),
      snd_una_(0),
      peer_rwnd_(config.rcv_buf_bytes),
      rcv_nxt_(0),
      srtt_ms_(config.initial_srtt_ms > 0 ? config.initial_srtt_ms : 200) {
  rto_ms_ = clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);

  // Autotune floor: two segments is the smallest window that can make
  // progress at all, whatever the config says.
  const size_t seg = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  window_min_ = std::max(cfg_.window_min_bytes, 2 * seg);
  window_max_ = std::max(cfg_.window_max_bytes, window_min_);
  send_window_ = cfg_.auto_window
                     ? std::clamp(cfg_.send_window_bytes, window_min_, window_max_)
                     : cfg_.send_window_bytes;
  loss_floor_ = send_window_;
  ssthresh_ = window_max_;
  // The peer's advertised window is clamped by our receive buffer, so in auto
  // mode the floor of that buffer has to cover what the sender may grow into;
  // otherwise the two ends tune against each other and neither moves.
  rcv_cap_ = cfg_.auto_window ? std::max(cfg_.rcv_buf_bytes, window_max_)
                              : cfg_.rcv_buf_bytes;
}

size_t Stream::send_space() const {
  if (state_ == StreamState::kClosed) {
    return 0;
  }
  // Everything written and not yet acknowledged -- not in_flight_ plus the
  // pending queue. pump() turns pending into segments regardless of the peer's
  // window, and a segment that the window has not released is neither in_flight_
  // nor pending, so the old measure was blind to exactly the bytes a stalled
  // reader accumulates: the writer kept being told it had room.
  const size_t used = bytes_queued_ > bytes_acked_ ? bytes_queued_ - bytes_acked_ : 0;
  return send_window_ > used ? send_window_ - used : 0;
}

bool Stream::can_write() const {
  return (state_ == StreamState::kOpen || state_ == StreamState::kPeerClosed) &&
         !fin_queued_ && !fin_sent_ && send_space() > 0;
}

size_t Stream::write(const uint8_t* data, size_t len) {
  if (!can_write()) {
    return 0;
  }
  const size_t room = send_space();
  const size_t n = std::min(room, len);
  if (n == 0) {
    return 0;
  }
  tx_pending_.insert(tx_pending_.end(), data, data + n);
  bytes_queued_ += n;
  return n;
}

void Stream::close(int64_t now_ms) {
  if (state_ == StreamState::kClosed || fin_queued_ || fin_sent_) {
    return;
  }
  // Always carry a fin, even with nothing queued and the peer already done: the
  // peer needs the signal to tear its side down, and one zero-length segment is
  // cheaper than an idle timeout on the far end.
  fin_queued_ = true;
  state_ = StreamState::kSendingFin;
  pump(now_ms);
}

void Stream::abort(int64_t now_ms, uint8_t code) {
  if (state_ == StreamState::kClosed) {
    return;
  }
  emit_rst(code);
  finish(now_ms, CloseReason::kReset);
}

void Stream::on_segment(const uint8_t* seg, size_t len, int64_t now_ms) {
  if (state_ == StreamState::kClosed || seg == nullptr || len < 1) {
    return;
  }
  ++segs_rx_;
  last_activity_ms_ = now_ms;
  switch (seg[0]) {
    case kStreamTypeData:
      if (len >= kStreamDataHdrLen) {
        handle_data(seg, len, now_ms);
      } else {
        ++bad_segs_;
      }
      break;
    case kStreamTypeAck:
      if (len >= kStreamAckLen) {
        handle_ack(seg, len, now_ms);
      } else {
        ++bad_segs_;
      }
      break;
    case kStreamTypeRst:
      finish(now_ms, CloseReason::kReset);
      break;
    default:
      // Unknown type: ignore rather than kill, so a newer stream revision can
      // add control segments without a version negotiation round.
      ++bad_segs_;
      break;
  }
}

void Stream::on_tick(int64_t now_ms) {
  if (state_ == StreamState::kClosed) {
    return;
  }
  if (last_activity_ms_ == 0) {
    last_activity_ms_ = now_ms;
  }
  retransmit_timeouts(now_ms);
  update_window(now_ms);
  pump(now_ms);
  probe_zero_window(now_ms);
  if (cfg_.idle_timeout_ms > 0 && now_ms - last_activity_ms_ >= cfg_.idle_timeout_ms) {
    finish(now_ms, CloseReason::kIdle);
  }
}

void Stream::pump(int64_t now_ms) {
  if (state_ == StreamState::kClosed) {
    return;
  }
  const size_t max_payload =
      cfg_.max_segment > kStreamDataHdrLen ? cfg_.max_segment - kStreamDataHdrLen : 0;
  if (max_payload == 0) {
    // F-5: max_segment is the session's payload_max (Session::mtu_limits()),
    // which is always above the stream header once the session config is
    // valid. If it is not, the loop below would carve zero-byte segments:
    // tx_pending_ never drains, the peer sees pure silence, and nothing on
    // either side says why. Close with a reason instead of stalling.
    if (log_) {
      log_("FCP stream: max_segment " + std::to_string(cfg_.max_segment) +
           " cannot carry the stream header; resetting");
    }
    finish(now_ms, CloseReason::kReset);
    return;
  }
  // Consume the queued bytes with a read cursor and drop the buffer once at the
  // end, instead of erase()-ing each symbol out of the front. Every erase moved
  // the whole remaining buffer, so an N-byte burst cost O(N^2): measured 469
  // MB/s at a 64 KiB window, 412 at 256 KiB, 147 at 1 MiB and 10.8 MB/s at
  // 4 MiB -- a 4 MiB burst took 391 ms, i.e. fifteen reactor ticks. The cursor
  // is a local because nothing in this loop can call back into the stream
  // (segments are only emitted by the loop below, after the buffer is cleared),
  // so no re-entrant pump can observe a half-consumed buffer.
  size_t consumed = 0;
  while (max_payload > 0 && consumed < tx_pending_.size()) {
    PendingSeg seg;
    seg.offset = snd_nxt_;
    const size_t n = std::min(tx_pending_.size() - consumed, max_payload);
    const auto from = static_cast<std::ptrdiff_t>(consumed);
    seg.bytes.assign(tx_pending_.begin() + from,
                     tx_pending_.begin() + from + static_cast<std::ptrdiff_t>(n));
    consumed += n;
    snd_nxt_ += static_cast<uint32_t>(n);
    tx_.push_back(std::move(seg));
  }
  if (consumed != 0) {
    tx_pending_.clear();  // keeps the capacity; the bytes are all in tx_ now
  }
  if (fin_queued_ && !fin_sent_ && tx_pending_.empty()) {
    PendingSeg seg;
    seg.offset = snd_nxt_;
    seg.fin = true;
    fin_offset_ = seg.offset;
    snd_nxt_ += 1;  // the fin occupies one sequence number, like TCP
    tx_.push_back(std::move(seg));
    fin_sent_ = true;
  }

  const size_t allowed = std::min(send_window_, peer_rwnd_);
  // A zero-window probe is one whole segment past the window: the peer said it
  // has no room, and only an arriving segment can make it advertise again.
  bool forced = probe_credit_;
  probe_credit_ = false;
  // Bookkeeping is applied before handing the bytes to the host: a host that
  // delivers synchronously (in-process loopback) can reach handle_ack() from
  // inside send_, and that pops segments out of tx_. Indexing freshly each round
  // keeps us off freed elements.
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    if (seg.sent) {
      continue;
    }
    if (!forced && in_flight_ + seg.wire_len() > allowed) {
      // Data is ready and held back. Only our own window being the binding
      // constraint says the next epoch's delivery rate measures the path
      // rather than the peer's receive buffer (see update_window). Until the
      // peer has actually advertised, its room is our guess, so a full local
      // window against that guess is not evidence about the path.
      limited_epoch_ = cfg_.auto_window && peer_rwnd_seen_ && send_window_ <= peer_rwnd_;
      break;
    }
    forced = false;
    seg.sent = true;
    seg.sent_ms = now_ms;
    in_flight_ += seg.wire_len();
    snd_max_ = seg.offset + static_cast<uint32_t>(seg.wire_len());
    emit_seg(seg);
  }
  // The host respects backpressure (write() stops at send_space()), so a full
  // window often has nothing left to hold back above; bytes on the wire up to
  // the window are the same "our window is the bottleneck" signal, and only
  // our own window can be that full (pump never passes the peer's rwnd).
  if (cfg_.auto_window && peer_rwnd_seen_ && in_flight_ >= send_window_) {
    limited_epoch_ = true;
  }
}

void Stream::emit_seg(const PendingSeg& seg) {
  std::vector<uint8_t> buf(kStreamDataHdrLen + seg.bytes.size());
  buf[0] = kStreamTypeData;
  put_le32(seg.offset, buf.data() + 1);
  buf[5] = seg.fin ? kStreamFlagFin : 0;
  std::copy(seg.bytes.begin(), seg.bytes.end(), buf.begin() + kStreamDataHdrLen);
  ++segs_sent_;
  send_(buf.data(), buf.size());
}

void Stream::emit_ack() {
  uint8_t buf[kStreamAckLen];
  const uint32_t cum = cum_out();
  buf[0] = kStreamTypeAck;
  put_le32(cum, buf + 1);
  put_le32(static_cast<uint32_t>(rwnd_out()), buf + 5);
  if (!oob_.empty()) {
    // #27: the wire carries one SACK block, so on a repeated cumulative point
    // (the peer is buffered past a hole) rotate through the buffered chunks —
    // every hole gets reported within oob_.size() duplicates instead of only
    // after the first hole heals and cum moves.
    if (have_ack_cum_ && cum == last_ack_cum_) {
      ++sack_rotate_;
    } else {
      sack_rotate_ = 0;
    }
    last_ack_cum_ = cum;
    have_ack_cum_ = true;
    const RcvChunk& blk = oob_[sack_rotate_ % oob_.size()];
    put_le32(blk.offset, buf + 9);
    put_le32(blk.offset + static_cast<uint32_t>(blk.bytes.size()), buf + 13);
  } else {
    have_ack_cum_ = false;
    sack_rotate_ = 0;
    put_le32(cum, buf + 9);
    put_le32(cum, buf + 13);
  }
  send_(buf, kStreamAckLen);
}

void Stream::emit_rst(uint8_t code) {
  uint8_t buf[kStreamRstLen] = {kStreamTypeRst, code};
  send_(buf, kStreamRstLen);
}

size_t Stream::rwnd_out() const {
  // Both the out-of-order buffer and whatever the host has not accepted yet are
  // still this stream's memory, so both count against the advertised window.
  const size_t used = oob_bytes_ + delivery_pending_;
  return rcv_cap_ > used ? rcv_cap_ - used : 0;
}

uint32_t Stream::cum_out() const {
  // Once the peer's fin is contiguous with what we delivered, its pseudo byte
  // counts as acknowledged too, so the sender can close without a second ack.
  if (peer_fin_ && seq_at_or_after(rcv_nxt_, peer_fin_at_)) {
    return rcv_nxt_ + 1;
  }
  return rcv_nxt_;
}

void Stream::handle_data(const uint8_t* seg, size_t len, int64_t now_ms) {
  const uint32_t offset = get_le32(seg + 1);
  const bool fin = (seg[5] & kStreamFlagFin) != 0;
  const size_t n = len - kStreamDataHdrLen;
  const uint32_t data_end = offset + static_cast<uint32_t>(n);
  const uint32_t seg_end = data_end + (fin ? 1u : 0u);

  if (!seq_after(seg_end, rcv_nxt_)) {
    // Entirely below the delivery point: a duplicate of something already
    // handed up. Still ack, or the sender's RTO keeps firing.
    dup_bytes_ += n;
    emit_ack();
    return;
  }
  if (seq_dist(offset, rcv_nxt_) > static_cast<int64_t>(rcv_cap_)) {
    return;  // beyond the advertised window; the sender recovers by timeout
  }
  // A zero-window probe is one segment pushed past a window we advertised as
  // closed. When the closure is our own stalled app (the host has not taken
  // bytes back), buffering it would let the peer grow that debt at the probe
  // rate; answer with the window and take nothing. When the closure comes from
  // the out-of-order buffer instead, the segment may be the hole that frees
  // everything, so it must still be accepted.
  if (delivery_pending_ >= rcv_cap_) {
    emit_ack();
    return;
  }
  // A22: the peer's fin offset is a fixed property of its stream; retransmissions
  // repeat the same pseudo byte. A fin at a different offset (or data reaching
  // past one already seen) is a protocol violation -- letting it rewrite
  // peer_fin_at_ would move the end of the stream and keep both the EOF
  // delivery and the cumulative fin ack from ever matching.
  if (peer_fin_) {
    if (fin && data_end != peer_fin_at_) {
      ++bad_segs_;
      return;
    }
    if (!fin && seq_after(data_end, peer_fin_at_)) {
      ++bad_segs_;
      return;
    }
  }

  const uint8_t* payload = seg + kStreamDataHdrLen;
  size_t keep = n;
  uint32_t at = offset;
  if (seq_dist(at, rcv_nxt_) < 0) {
    const uint32_t drop = static_cast<uint32_t>(-seq_dist(at, rcv_nxt_));
    dup_bytes_ += std::min<size_t>(drop, keep);
    if (drop >= keep) {
      keep = 0;
      at = rcv_nxt_;
    } else {
      keep -= drop;
      at += drop;
      payload += drop;
    }
  }
  if (keep > 0) {
    insert_chunk(at, payload, keep);
  }
  if (fin) {
    peer_fin_ = true;
    peer_fin_at_ = data_end;
  }
  deliver_prefix(now_ms);
  emit_ack();
}

void Stream::insert_chunk(uint32_t offset, const uint8_t* data, size_t len) {
  // In-order delivery and a modest reorder gap both land at or after the tail
  // of the sorted buffer. Sorting and rebuilding the whole deque per segment is
  // O(n log n), and the autotuned window allows ~800 chunks, so take that
  // common case directly; the full merge below only runs when a segment really
  // lands behind the tail (deep reordering).
  if (oob_.empty() || seq_dist(offset, oob_.back().offset) >= 0) {
    const size_t room = oob_bytes_ < rcv_cap_ ? rcv_cap_ - oob_bytes_ : 0;
    if (!oob_.empty()) {
      RcvChunk& last = oob_.back();
      const uint32_t last_end = last.offset + static_cast<uint32_t>(last.bytes.size());
      if (seq_dist(offset, last_end) <= 0) {
        // Overlaps the tail (a retransmission or a duplicate): append only the
        // bytes not already buffered, same rule as the merge below.
        const size_t overlap = static_cast<size_t>(seq_dist(last_end, offset));
        if (overlap >= len) {
          return;
        }
        const size_t take = std::min(len - overlap, room);
        if (take > 0) {
          last.bytes.insert(last.bytes.end(), data + overlap, data + overlap + take);
          oob_bytes_ += take;
        }
        return;
      }
    }
    if (room == 0) {
      return;
    }
    RcvChunk in;
    in.offset = offset;
    const size_t take = std::min(len, room);
    in.bytes.assign(data, data + take);
    oob_bytes_ += take;
    oob_.push_back(std::move(in));
    return;
  }

  RcvChunk in;
  in.offset = offset;
  in.bytes.assign(data, data + len);
  oob_.push_back(std::move(in));
  std::sort(oob_.begin(), oob_.end(),
            [](const RcvChunk& a, const RcvChunk& b) { return seq_dist(a.offset, b.offset) < 0; });

  // Merge overlapping/adjacent runs, keeping the bytes already buffered: the
  // stream is immutable once written, so an overlap is a retransmission of the
  // same bytes and either copy is correct.
  std::deque<RcvChunk> merged;
  size_t total = 0;
  for (RcvChunk& c : oob_) {
    if (total >= rcv_cap_) {
      break;
    }
    const size_t room = rcv_cap_ - total;
    if (!merged.empty()) {
      RcvChunk& last = merged.back();
      const uint32_t last_end = last.offset + static_cast<uint32_t>(last.bytes.size());
      if (seq_dist(c.offset, last_end) <= 0) {
        const size_t overlap = static_cast<size_t>(seq_dist(last_end, c.offset));
        if (overlap >= c.bytes.size()) {
          continue;  // fully contained
        }
        const size_t take = std::min(c.bytes.size() - overlap, room);
        last.bytes.insert(last.bytes.end(), c.bytes.begin() + overlap,
                          c.bytes.begin() + overlap + take);
        total += take;
        continue;
      }
    }
    const size_t take = std::min(c.bytes.size(), room);
    c.bytes.resize(take);  // the tail that does not fit is retransmitted later
    total += take;
    merged.push_back(std::move(c));
  }
  oob_.swap(merged);
  oob_bytes_ = 0;
  for (const RcvChunk& c : oob_) {
    oob_bytes_ += c.bytes.size();
  }
}

void Stream::deliver_prefix(int64_t now_ms) {
  while (!oob_.empty() && oob_.front().offset == rcv_nxt_) {
    // Detach before handing bytes to the host: read_ may re-enter with more
    // segments, and a chunk that is no longer at the front must not be dropped.
    RcvChunk c = std::move(oob_.front());
    oob_.pop_front();
    oob_bytes_ -= c.bytes.size();
    rcv_nxt_ += static_cast<uint32_t>(c.bytes.size());
    bytes_delivered_ += c.bytes.size();
    if (!c.bytes.empty()) {
      if (read_) {
        read_(c.bytes.data(), c.bytes.size());
      }
    }
  }
  if (peer_fin_ && !eof_delivered_ && seq_at_or_after(rcv_nxt_, peer_fin_at_)) {
    eof_delivered_ = true;
    state_ = StreamState::kPeerClosed;
    if (eof_) {
      eof_();  // read side finished; the write side may still have data queued
    }
    // The peer's fin completes the close only once OUR fin is acknowledged
    // (M2 §2.3: `cum >= fin_seq + 1`). fin_sent_ only says the segment was
    // built: closing on it would drop tx_ -- data that never left, or left and
    // was lost -- and the peer would wait for a fin that is never resent.
    // handle_ack() finishes the stream when the ack that covers our fin lands.
    if (fin_sent_ && seq_at_or_after(snd_una_, fin_offset_ + 1)) {
      finish(now_ms, CloseReason::kPeerClose);
    }
  }
}

void Stream::handle_ack(const uint8_t* seg, size_t len, int64_t now_ms) {
  (void)len;
  const uint32_t cum = get_le32(seg + 1);
  // #30 adversarial hardening, corrected by A4: the bound must be the highest
  // byte that actually reached the wire, not snd_nxt_ (segmentation runs ahead
  // of the send window). Accepting cum beyond snd_max_ would pop unsent
  // segments and strand their bytes for good. A lying oversized rwnd is
  // harmless — send_space() is clamped by our own send window — but a lying
  // cum is data loss.
  if (seq_after(cum, snd_max_)) {
    ++bad_segs_;
    return;
  }
  peer_rwnd_ = get_le32(seg + 5);
  peer_rwnd_seen_ = true;  // the autotune may now read a full window as path evidence
  uint32_t sack_start = get_le32(seg + 9);
  uint32_t sack_end = get_le32(seg + 13);
  // #30 hardening, same rule as cum above (A4 follow-up): the block must
  // describe a non-empty range above the cumulative point that actually
  // reached the wire. snd_nxt_ is the segmentation cursor and runs ahead of
  // the send window, so accepting a block beyond snd_max_ let one ACK mark
  // never-sent segments as SACKed (fill_holes then skipped them forever) and
  // jump sack_filled_up_to_ past every real hole. An inverted block is
  // malformed outright. Ignore the SACK half of such an ACK but keep its
  // cumulative point and window, which are bounded and useful on their own.
  if (sack_start != sack_end &&
      (!seq_at_or_after(sack_start, cum) || !seq_after(sack_end, sack_start) ||
       seq_after(sack_start, snd_max_) || seq_after(sack_end, snd_max_))) {
    ++bad_segs_;
    sack_start = cum;
    sack_end = cum;
  }
  const uint32_t prior_una = snd_una_;

  // #27 fast retransmit: a repeated cumulative point with unacked data is the
  // peer saying "I am buffered past a hole". After kDupAckThresh of them,
  // force one copy of the first unacked segment — the only path that beats
  // both the RTO and the sack_filled_up_to_ guard when a repair itself was
  // lost. Runs before fill_holes so the fill's fresh-retransmission guard
  // keeps this ACK from emitting the same segment twice. One trigger per
  // batch (counter resets here and on any cum advance); once the repair
  // lands, cum moves and the counting restarts.
  if (have_cum_ && cum == last_cum_) {
    ++dup_acks_;
  } else {
    dup_acks_ = 0;
  }
  last_cum_ = cum;
  have_cum_ = true;
  if (dup_acks_ >= kDupAckThresh && !tx_.empty() && tx_.front().sent) {
    dup_acks_ = 0;
    // FEC can deliver a set out of order, so three duplicates can mean a
    // reordered symbol rather than a lost one. The forced retransmission is
    // cheap either way; the 30% window cut is not, so only a second burst with
    // the first repair still unacked (cum has not moved) is taken as loss.
    if (fast_retx_armed_) {
      loss_epoch_ = true;  // the peer's buffer is stuck behind a hole
      ++dup_loss_events_;
    }
    fast_retx_armed_ = true;
    PendingSeg& first = tx_.front();
    first.sent_ms = now_ms;
    first.retrans = true;
    ++retransmits_;
    emit_seg(first);
  }

  if (seq_after(cum, snd_una_)) {
    bool popped_retrans = false;
    int64_t sample_ms = -1;
    while (!tx_.empty()) {
      const PendingSeg& front = tx_.front();
      const uint32_t front_end = front.offset + static_cast<uint32_t>(front.wire_len());
      if (seq_after(front_end, cum)) {
        break;  // still partly unacked
      }
      if (!front.sent) {
        break;  // A4: never pop a segment that has not been on the wire
      }
      in_flight_ = in_flight_ >= front.wire_len() ? in_flight_ - front.wire_len() : 0;
      if (front.retrans) {
        popped_retrans = true;
      } else if (front.sent_ms > 0) {
        sample_ms = now_ms - front.sent_ms;  // keep the newest clean sample
      }
      bytes_acked_ += front.bytes.size();
      tx_.pop_front();
    }
    snd_una_ = cum;
    fast_retx_armed_ = false;  // the hole healed: the burst was reordering
    // Karn's rule: while a retransmission is in the acked set the sample is
    // ambiguous (it may measure the timeout, not the path), so drop the round.
    if (sample_ms >= 0 && !popped_retrans) {
      update_srtt(sample_ms);
    }
  }
  // The hole is worth filling even when cum did not move: a peer that is
  // buffering past the hole keeps re-advertising the same SACK block, and waiting
  // a full RTO on top of that is exactly the stall this block exists to avoid.
  if (sack_end != sack_start) {
    // #27: the block says these bytes arrived — mark them so the rotating
    // blocks of later ACKs never re-fill a SACKed segment as if it were a hole.
    for (size_t i = 0; i < tx_.size(); ++i) {
      PendingSeg& s = tx_[i];
      const uint32_t s_end = s.offset + static_cast<uint32_t>(s.wire_len());
      if (s.sent && seq_at_or_after(s.offset, sack_start) &&
          seq_at_or_after(sack_end, s_end)) {
        s.sacked = true;
      }
    }
    fill_holes(sack_start, now_ms);
  }
  if (snd_una_ == prior_una) {
    return;  // nothing confirmed
  }
  if (fin_sent_ && seq_at_or_after(cum, fin_offset_ + 1)) {
    // Our side is flushed and confirmed. Stay readable until the peer's own fin
    // arrives, like TCP half-close: a server that answers after our EOF must not
    // have its reply dropped.
    if (eof_delivered_) {
      finish(now_ms, CloseReason::kLocalEof);
      return;
    }
  }
  pump(now_ms);
}

void Stream::fill_holes(uint32_t sack_start, int64_t now_ms) {
  // A SACK block past snd_una_ means the sender's next bytes are the hole, so
  // retransmit them now instead of waiting a full RTO. Measured burst loss
  // (spec §14.10) makes RTO-only recovery stall a 20 Mbps stream.
  if (!seq_after(sack_start, snd_una_) || !seq_after(sack_start, sack_filled_up_to_)) {
    return;
  }
  sack_filled_up_to_ = sack_start;
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    const uint32_t seg_end = seg.offset + static_cast<uint32_t>(seg.wire_len());
    if (!seq_after(seg_end, snd_una_) || !seg.sent || seg.sacked) {
      continue;  // acked, not on the wire (pump handles those), or not a hole
    }
    if (seq_dist(seg.offset, sack_start) >= 0) {
      break;  // at or past the hole
    }
    if (seg.retrans && now_ms - seg.sent_ms < rto_ms_) {
      continue;  // already re-filling this one
    }
    seg.sent_ms = now_ms;
    seg.retrans = true;
    ++retransmits_;
    emit_seg(seg);
  }
}

void Stream::retransmit_timeouts(int64_t now_ms) {
  // Exponential backoff (Karn): a silent peer must not be refilled with a whole
  // window every base RTO forever. Doubling per timeout episode (reset by the
  // next clean sample) turns a 1 MiB window from ~3 MB/s of futile traffic into
  // a decaying trickle. The pass is also charged against one window of bytes so
  // a malformed state can never emit more than in-flight in one tick.
  const int64_t rto = clamp_ms(rto_ms_ * rto_backoff_, cfg_.rto_min_ms, cfg_.rto_max_ms);
  size_t budget = send_window_;
  bool fired = false;
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    if (!seg.sent) {
      break;  // segments go out in order, so nothing later can be older
    }
    if (now_ms - seg.sent_ms < rto) {
      break;
    }
    if (fired && seg.wire_len() > budget) {
      break;
    }
    budget = budget >= seg.wire_len() ? budget - seg.wire_len() : 0;
    seg.sent_ms = now_ms;
    seg.retrans = true;
    loss_epoch_ = true;
    ++retransmits_;
    emit_seg(seg);
    fired = true;
  }
  if (fired) {
    ++rto_loss_events_;  // one timeout episode, however many segments it resent
    rto_backoff_ = std::min<int64_t>(rto_backoff_ * 2, 16);
  }
}

void Stream::probe_zero_window(int64_t now_ms) {
  // The first unsent segment sets the bar. A peer window that cannot carry it
  // deadlocks the sender even when the window is not zero: no segment fits,
  // nothing is in flight, and only an arriving segment can make the peer
  // advertise again (seen live as a freeze at peer_rwnd=906 with 1336-byte
  // segments). Probe exactly as for the classic rwnd==0 case.
  size_t next_len = 0;
  if (!tx_.empty()) {
    for (const PendingSeg& seg : tx_) {
      if (!seg.sent) {
        next_len = seg.wire_len();
        break;
      }
    }
  } else if (!tx_pending_.empty()) {
    next_len = std::min(tx_pending_.size(),
                        cfg_.max_segment > kStreamDataHdrLen
                            ? cfg_.max_segment - kStreamDataHdrLen
                            : tx_pending_.size()) +
               kStreamDataHdrLen;
  }
  if (next_len == 0 || peer_rwnd_ >= next_len) {
    // Not stuck (or nothing to send): the ladder resets here, before the
    // in-flight gate below, so a peer that reopens its window and closes it
    // again is probed at 1x instead of inheriting an old 16x deadline.
    probe_backoff_ = 1;
    return;
  }
  if (in_flight_ != 0) {
    return;  // something is already outstanding; its ack or RTO moves us
  }
  // F-3: back off like a TCP persist timer. Without this the probe rate is
  // pinned to probe_ms for as long as the peer answers each probe with the
  // same closed window — one full segment every probe_ms indefinitely, from a
  // path that should be ~silent. The cap (16x) keeps a recovering peer's
  // wake-up under a couple of seconds after the first few probes.
  const int64_t interval = cfg_.probe_ms * probe_backoff_;
  if (last_probe_ms_ != 0 && now_ms - last_probe_ms_ < interval) {
    return;
  }
  last_probe_ms_ = now_ms;
  probe_backoff_ = std::min<int64_t>(probe_backoff_ * 2, 16);
  probe_credit_ = true;
  ++probes_sent_;
  pump(now_ms);
}

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
  rto_ms_ = clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);
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
    const bool credible = epoch_samples_ >= kQueueMinSamples;
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

void Stream::finish(int64_t now_ms, CloseReason reason) {
  if (state_ == StreamState::kClosed) {
    return;
  }
  state_ = StreamState::kClosed;
  reason_ = reason;
  tx_.clear();
  tx_pending_.clear();
  oob_.clear();
  oob_bytes_ = 0;
  in_flight_ = 0;
  last_activity_ms_ = now_ms;
  if (closed_ && !notified_) {
    notified_ = true;
    closed_(reason);
  }
}

}  // namespace fcp
