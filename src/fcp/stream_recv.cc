// Stream, receive half: inbound data -> in-order bytes for the host, plus the
// ACK/RST we answer with. Split out of stream.cc so the receive path (reassembly,
// the A22 fin invariant, the rotating SACK block on the wire) can be read without
// the send path's retransmission logic in the way.

#include <algorithm>
#include <deque>

#include "fcp/seq.h"
#include "fcp/stream.h"
#include "fcp/wire.h"

namespace fcp {

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

}  // namespace fcp
