// Stream, send half: ACK processing, retransmission and the zero-window probe.
// The four ACK duties -- duplicate-ACK fast retransmit, SACK hole fill, the
// cumulative advance and the RTT sample -- share one entry point because they
// are decided from the same segment; the window they feed lives in
// stream_window.cc.

#include <algorithm>

#include "fcp/seq.h"
#include "fcp/stream.h"
#include "fcp/stream_util.h"
#include "fcp/wire.h"

namespace fcp {

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

  // Order matters and is unchanged from the single-function version: the
  // duplicate-ACK trigger runs before the SACK fill so the fill's
  // fresh-retransmission guard keeps this ACK from emitting the same segment
  // twice; the cumulative advance runs before the fill so a block already below
  // the new snd_una_ is not re-filled.
  ack_dup_burst(cum, now_ms);
  ack_advance_cum(cum, now_ms);
  ack_fill_sack(sack_start, sack_end, now_ms);

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

// Path 1 of the ACK: the duplicate-ACK burst (#27 fast retransmit).
void Stream::ack_dup_burst(uint32_t cum, int64_t now_ms) {
  // #27 fast retransmit: a repeated cumulative point with unacked data is the
  // peer saying "I am buffered past a hole". After kDupAckThresh of them,
  // force one copy of the first unacked segment — the only path that beats
  // both the RTO and the sack_filled_up_to_ guard when a repair itself was
  // lost. One trigger per batch (counter resets here and on any cum advance);
  // once the repair lands, cum moves and the counting restarts.
  if (have_cum_ && cum == last_cum_) {
    ++dup_acks_;
  } else {
    dup_acks_ = 0;
  }
  last_cum_ = cum;
  have_cum_ = true;
  if (dup_acks_ < kDupAckThresh || tx_.empty() || !tx_.front().sent) {
    return;
  }
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

// Path 2 of the ACK: the cumulative point advanced (pop what it covers).
void Stream::ack_advance_cum(uint32_t cum, int64_t now_ms) {
  if (!seq_after(cum, snd_una_)) {
    return;
  }
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

// Path 3 of the ACK: the SACK half. The hole is worth filling even when cum did
// not move: a peer that is buffering past the hole keeps re-advertising the same
// SACK block, and waiting a full RTO on top of that is exactly the stall this
// block exists to avoid.
void Stream::ack_fill_sack(uint32_t sack_start, uint32_t sack_end, int64_t now_ms) {
  if (sack_end == sack_start) {
    return;
  }
  // #27: the block says these bytes arrived — mark them so the rotating blocks
  // of later ACKs never re-fill a SACKed segment as if it were a hole.
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
  const int64_t rto = stream_detail::clamp_ms(rto_ms_ * rto_backoff_, cfg_.rto_min_ms, cfg_.rto_max_ms);
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

}  // namespace fcp
