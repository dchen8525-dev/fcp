#include "fcp/stream.h"

#include <algorithm>

namespace fcp {
namespace {

// Sequence numbers are u32 byte offsets that wrap on long-lived connections
// (4 GiB is ~27 minutes at 20 Mbps), so every comparison is modular, same
// rule as set_id ordering in spec §14.5.
bool seq_after(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }
bool seq_at_or_after(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) >= 0; }
int64_t seq_dist(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b); }

void put_u32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t get_u32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

int64_t clamp_ms(int64_t v, int64_t lo, int64_t hi) {
  return v < lo ? lo : (v > hi ? hi : v);
}

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
}

size_t Stream::send_space() const {
  if (state_ == StreamState::kClosed) {
    return 0;
  }
  const size_t used = in_flight_ + tx_pending_.size();
  return cfg_.send_window_bytes > used ? cfg_.send_window_bytes - used : 0;
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
  while (max_payload > 0 && !tx_pending_.empty()) {
    PendingSeg seg;
    seg.offset = snd_nxt_;
    const size_t n = std::min(tx_pending_.size(), max_payload);
    seg.bytes.assign(tx_pending_.begin(), tx_pending_.begin() + n);
    tx_pending_.erase(tx_pending_.begin(), tx_pending_.begin() + n);
    snd_nxt_ += static_cast<uint32_t>(n);
    tx_.push_back(std::move(seg));
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

  const size_t allowed = std::min(cfg_.send_window_bytes, peer_rwnd_);
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
      break;
    }
    forced = false;
    seg.sent = true;
    seg.sent_ms = now_ms;
    in_flight_ += seg.wire_len();
    emit_seg(seg);
  }
}

void Stream::emit_seg(const PendingSeg& seg) {
  std::vector<uint8_t> buf(kStreamDataHdrLen + seg.bytes.size());
  buf[0] = kStreamTypeData;
  put_u32(buf.data() + 1, seg.offset);
  buf[5] = seg.fin ? kStreamFlagFin : 0;
  std::copy(seg.bytes.begin(), seg.bytes.end(), buf.begin() + kStreamDataHdrLen);
  ++segs_sent_;
  send_(buf.data(), buf.size());
}

void Stream::emit_ack() {
  uint8_t buf[kStreamAckLen];
  const uint32_t cum = cum_out();
  buf[0] = kStreamTypeAck;
  put_u32(buf + 1, cum);
  put_u32(buf + 5, static_cast<uint32_t>(rwnd_out()));
  if (!oob_.empty()) {
    put_u32(buf + 9, oob_.front().offset);
    put_u32(buf + 13, oob_.front().offset + static_cast<uint32_t>(oob_.front().bytes.size()));
  } else {
    put_u32(buf + 9, cum);
    put_u32(buf + 13, cum);
  }
  send_(buf, kStreamAckLen);
}

void Stream::emit_rst(uint8_t code) {
  uint8_t buf[kStreamRstLen] = {kStreamTypeRst, code};
  send_(buf, kStreamRstLen);
}

size_t Stream::rwnd_out() const {
  return cfg_.rcv_buf_bytes > oob_bytes_ ? cfg_.rcv_buf_bytes - oob_bytes_ : 0;
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
  const uint32_t offset = get_u32(seg + 1);
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
  if (seq_dist(offset, rcv_nxt_) > static_cast<int64_t>(cfg_.rcv_buf_bytes)) {
    return;  // beyond the advertised window; the sender recovers by timeout
  }
  if (peer_fin_ && seq_after(offset, peer_fin_at_)) {
    return;  // data after the peer's fin is a protocol violation
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
    if (total >= cfg_.rcv_buf_bytes) {
      break;
    }
    const size_t room = cfg_.rcv_buf_bytes - total;
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
    if (fin_sent_) {
      finish(now_ms, CloseReason::kPeerClose);
    }
  }
}

void Stream::handle_ack(const uint8_t* seg, size_t len, int64_t now_ms) {
  (void)len;
  const uint32_t cum = get_u32(seg + 1);
  peer_rwnd_ = get_u32(seg + 5);
  const uint32_t sack_start = get_u32(seg + 9);
  const uint32_t sack_end = get_u32(seg + 13);
  const uint32_t prior_una = snd_una_;

  if (seq_after(cum, snd_una_)) {
    bool popped_retrans = false;
    int64_t sample_ms = -1;
    while (!tx_.empty()) {
      const PendingSeg& front = tx_.front();
      const uint32_t front_end = front.offset + static_cast<uint32_t>(front.wire_len());
      if (seq_after(front_end, cum)) {
        break;  // still partly unacked
      }
      if (front.sent) {
        in_flight_ = in_flight_ >= front.wire_len() ? in_flight_ - front.wire_len() : 0;
        if (front.retrans) {
          popped_retrans = true;
        } else if (front.sent_ms > 0) {
          sample_ms = now_ms - front.sent_ms;  // keep the newest clean sample
        }
        bytes_acked_ += front.bytes.size();
      }
      tx_.pop_front();
    }
    snd_una_ = cum;
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
    if (!seq_after(seg_end, snd_una_) || !seg.sent) {
      continue;  // acked, or not on the wire yet (pump handles those)
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
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    if (!seg.sent) {
      break;  // segments go out in order, so nothing later can be older
    }
    if (now_ms - seg.sent_ms < rto_ms_) {
      break;
    }
    seg.sent_ms = now_ms;
    seg.retrans = true;
    ++retransmits_;
    emit_seg(seg);
  }
}

void Stream::probe_zero_window(int64_t now_ms) {
  if (peer_rwnd_ != 0 || in_flight_ != 0) {
    return;
  }
  if (tx_.empty() && tx_pending_.empty()) {
    return;
  }
  if (last_probe_ms_ != 0 && now_ms - last_probe_ms_ < cfg_.probe_ms) {
    return;
  }
  last_probe_ms_ = now_ms;
  probe_credit_ = true;
  pump(now_ms);
}

void Stream::update_srtt(int64_t sample_ms) {
  srtt_ms_ = srtt_ms_ + (sample_ms - srtt_ms_) / 8;
  if (srtt_ms_ < 1) {
    srtt_ms_ = 1;
  }
  rto_ms_ = clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);
  if (rtt_) {
    rtt_(srtt_ms_);
  }
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
