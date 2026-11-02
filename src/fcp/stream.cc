#include "fcp/stream.h"

#include <algorithm>
#include <string>

#include "fcp/seq.h"
#include "fcp/stream_util.h"
#include "fcp/wire.h"

namespace fcp {

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
  rto_ms_ = stream_detail::clamp_ms(2 * srtt_ms_, cfg_.rto_min_ms, cfg_.rto_max_ms);

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

void Stream::emit_rst(uint8_t code) {
  uint8_t buf[kStreamRstLen] = {kStreamTypeRst, code};
  send_(buf, kStreamRstLen);
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
