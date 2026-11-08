// Stream, receive half: inbound data -> in-order bytes for the host, plus the
// ACK/RST we answer with. Split out of stream.cc so the receive path (reassembly,
// the A22 fin invariant, the rotating SACK block on the wire) can be read without
// the send path's retransmission logic in the way.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

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
    emit_ack(now_ms);
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
    emit_ack(now_ms);
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
  // Even when deliver_prefix just closed the stream, this ACK still has to go
  // out: it is the one that acknowledges the peer's fin, and without it the peer
  // can only finish via its idle timer (kIdle instead of kLocalEof). A fin is
  // always urgent, which is what makes this call emit unconditionally.
  maybe_ack(now_ms, /*urgent=*/fin);
}

// ACK coalescing (StreamConfig::ack_every). Every data segment used to produce
// its own ACK: 17 bytes of payload in an 81-byte wire packet, one per segment
// -- ~6% of a download's bytes on the reverse path, plus a wakeup and an emit
// per packet at the receiver. A clean in-order stream does not need one ack per
// segment; a hole, a closed window or a fin does, because the sender is then
// actively waiting on this exact information.
void Stream::maybe_ack(int64_t now_ms, bool urgent) {
  if (state_ == StreamState::kClosed) {
    return;  // the close path already emitted the fin's ack (deliver_prefix)
  }
  if (urgent || !oob_.empty() || delivery_pending_ >= rcv_cap_ || cfg_.ack_every <= 1) {
    emit_ack(now_ms);
    return;
  }
  if (++acks_owed_ >= cfg_.ack_every) {
    emit_ack(now_ms);
    return;
  }
  // Owed but not urgent: on_tick flushes it after kAckDelayMs, and
  // next_wake_ms() tells the host when that is.
  ack_pending_ = true;
}

size_t Stream::oob_room() const {
  const size_t used = oob_bytes_ + delivery_pending_;
  return used < rcv_cap_ ? rcv_cap_ - used : 0;
}

size_t Stream::oob_max_chunks() const {
  return std::min(kMaxOobChunks, std::max(kMinOobChunks, rcv_cap_ / 512));
}

void Stream::insert_chunk(uint32_t offset, const uint8_t* data, size_t len) {
  if (len == 0) {
    return;
  }
  if (oob_.size() >= oob_max_chunks()) {
    // The chunk ceiling is the receiver's, not the sender's: dropping here
    // means a retransmission later, never silent data loss (the cumulative ack
    // does not move past the missing range). A byte ceiling alone is not
    // enough -- a peer can put one byte in each chunk.
    ++oob_drops_;
    return;
  }

  // Locate the insertion point. The runs are kept sorted and disjoint, so this
  // is a binary search over the deque rather than the sort-and-rebuild every
  // out-of-order arrival used to pay: O(n) allocations per packet and O(n log n)
  // comparisons turned a few MB of tiny segments into a spin loop.
  const auto first_after = [](const RcvChunk& c, uint32_t off) {
    return seq_dist(c.offset, off) < 0;
  };
  const size_t pos = static_cast<size_t>(
      std::lower_bound(oob_.begin(), oob_.end(), offset, first_after) - oob_.begin());

  // Build the merged run in a scratch buffer and splice it back once. Erasing
  // from the middle of a deque invalidates every iterator in it, so the merge
  // is done by index: an iterator captured before an erase cannot be reused.
  uint32_t start = offset;
  std::vector<uint8_t> bytes(data, data + len);
  size_t first = pos;

  if (pos > 0) {
    const RcvChunk& prev = oob_[pos - 1];
    const uint32_t prev_end = prev.offset + static_cast<uint32_t>(prev.bytes.size());
    if (seq_dist(offset, prev_end) <= 0) {
      // The new range starts inside the previous run or exactly at its end.
      // Everything below prev_end is already buffered, so only the tail of the
      // new segment is appended; an overlap is a retransmission of the same
      // immutable stream bytes, so either copy would do.
      const int64_t overlap64 = seq_dist(prev_end, offset);
      const size_t dup = static_cast<size_t>(std::min<int64_t>(
          overlap64, static_cast<int64_t>(bytes.size())));
      std::vector<uint8_t> merged;
      merged.reserve(prev.bytes.size() + bytes.size() - dup);
      merged.insert(merged.end(), prev.bytes.begin(), prev.bytes.end());
      merged.insert(merged.end(), bytes.begin() + static_cast<std::ptrdiff_t>(dup), bytes.end());
      bytes.swap(merged);
      start = prev.offset;
      first = pos - 1;
    }
  }

  // Absorb every following run that starts at or before the merged end.
  size_t next = pos;
  uint32_t end = start + static_cast<uint32_t>(bytes.size());
  while (next < oob_.size() && seq_dist(oob_[next].offset, end) <= 0) {
    const RcvChunk& c = oob_[next];
    const int64_t overlap64 = seq_dist(end, c.offset);
    const size_t dup = static_cast<size_t>(std::min<int64_t>(
        overlap64, static_cast<int64_t>(c.bytes.size())));
    bytes.insert(bytes.end(), c.bytes.begin() + static_cast<std::ptrdiff_t>(dup), c.bytes.end());
    end = start + static_cast<uint32_t>(bytes.size());
    ++next;
  }

  size_t removed = 0;
  for (size_t i = first; i < next; ++i) {
    removed += oob_[i].bytes.size();
  }
  oob_.erase(oob_.begin() + static_cast<std::ptrdiff_t>(first),
             oob_.begin() + static_cast<std::ptrdiff_t>(next));
  oob_bytes_ -= removed;

  RcvChunk in;
  in.offset = start;
  in.bytes = std::move(bytes);
  oob_bytes_ += in.bytes.size();
  oob_.insert(oob_.begin() + static_cast<std::ptrdiff_t>(first), std::move(in));

  // Whatever no longer fits is cut from the tail; the sender retransmits it.
  // The limit counts the host's un-taken backlog too, so the receive side never
  // holds more than the window rwnd_out() advertises.
  const size_t limit = rcv_cap_ > delivery_pending_ ? rcv_cap_ - delivery_pending_ : 0;
  while (oob_bytes_ > limit && !oob_.empty()) {
    RcvChunk& last = oob_.back();
    const size_t excess = std::min(oob_bytes_ - limit, last.bytes.size());
    last.bytes.resize(last.bytes.size() - excess);
    oob_bytes_ -= excess;
    if (last.bytes.empty()) {
      oob_.pop_back();
    }
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
      const bool was_closed = state_ == StreamState::kClosed;
      if (read_) {
        read_(c.bytes.data(), c.bytes.size());
      }
      if (was_closed || state_ == StreamState::kClosed) {
        // The host closed or reset the stream from inside read_ (a local
        // socket error, an abort). The delivery loop stops here: oob_ was
        // cleared by finish(), and a fin/eof that follows would fire a second
        // teardown on a stream the host already declared dead.
        return;
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
      // Acknowledge the peer's fin *before* finish(): the close callback may
      // drop the session from under this stream, and this ACK is the only thing
      // that lets the peer complete its own close (without it the peer can only
      // finish on its grace clock or idle timer). Sending after finish() is a
      // no-op in the host, so the order is the whole point.
      emit_ack(now_ms);
      finish(now_ms, CloseReason::kPeerClose);
    }
  }
}

void Stream::emit_ack(int64_t now_ms) {
  // Sending an ACK settles the coalescing debt no matter which path produced
  // it: an urgent fin ack, a duplicate segment, a zero-window answer or one of
  // the SACK-rotation burst. Only maybe_ack() cleared the flags, so a rotation
  // burst left ack_pending_ set and the peer got one redundant ACK a
  // kAckDelayMs later -- exactly the per-segment ACK the coalescing exists to
  // remove, just delayed.
  ack_pending_ = false;
  acks_owed_ = 0;
  last_ack_ms_ = now_ms;
  if (cfg_.ack_v2) {
    emit_ack_v2(now_ms);
    return;
  }
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

// FCP-STREAM ACK v2 (#78, 施工单 step 3): type | cum(4) | rwnd(4) |
// n_ranges(1) | (gap, len) varint pairs. Every out-of-order chunk is one
// block, closest to cum first and capped at kStreamAckV2MaxRanges -- one ACK
// names every hole, which is what retires the v1 single-block rotation for
// negotiated peers. Blocks are byte ranges relative to cum: block_0 starts at
// cum + gap_0, block_i starts at block_{i-1}.end + gap_i, so the encoding is
// wrap-free even though the offsets themselves are u32.
void Stream::emit_ack_v2(int64_t /*now_ms*/) {
  // Worst case: 64 ranges x (5-byte gap + 5-byte len) + the 9-byte header.
  uint8_t buf[kStreamAckV2MinLen + kStreamAckV2MaxRanges * 10];
  const uint32_t cum = cum_out();
  buf[0] = kStreamTypeAckV2;
  put_le32(cum, buf + 1);
  put_le32(static_cast<uint32_t>(rwnd_out()), buf + 5);
  size_t off = kStreamAckV2MinLen;
  size_t n = 0;
  uint32_t prev_end = cum;
  for (const RcvChunk& blk : oob_) {
    if (n >= kStreamAckV2MaxRanges) {
      break;
    }
    const int64_t gap = seq_dist(blk.offset, prev_end);  // blk.offset - prev_end
    if (gap < 0) {
      continue;  // below the cumulative point (fin pseudo byte); nothing to report
    }
    off += static_cast<size_t>(
        put_uvarint(static_cast<uint32_t>(gap), buf + off));
    off += static_cast<size_t>(
        put_uvarint(static_cast<uint32_t>(blk.bytes.size()), buf + off));
    prev_end = blk.offset + static_cast<uint32_t>(blk.bytes.size());
    ++n;
  }
  buf[9] = static_cast<uint8_t>(n);  // n_ranges sits after cum+rwnd, at index 9
  send_(buf, off);
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
