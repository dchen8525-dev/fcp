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

// `len` is validated by on_segment() (>= kStreamAckLen) and never read here.
void Stream::handle_ack(const uint8_t* seg, size_t /*len*/, int64_t now_ms) {
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

// FCP-STREAM ACK v2 (#78, R9 hardening): the range set is validated in full
// before any of it is applied -- parse and act are separated so a malformed
// tail cannot ride on already-marked state. A block must sit at/after the
// cumulative point, end within snd_max_ (the A4 bound, same as v1), and the
// blocks must be ordered and disjoint (each start strictly after the previous
// end). Any violation discards the whole range set; the cumulative point and
// the window stay -- the same rule v1 applies to a bad single block. A lying
// cum stays fatal exactly as in v1.
void Stream::handle_ack_v2(const uint8_t* seg, size_t len, int64_t now_ms) {
  const uint32_t cum = get_le32(seg + 1);
  if (seq_after(cum, snd_max_)) {
    ++bad_segs_;
    return;
  }
  peer_rwnd_ = get_le32(seg + 5);
  peer_rwnd_seen_ = true;  // the autotune may now read a full window as path evidence
  struct Block {
    uint32_t start;
    uint32_t end;
  };
  Block blocks[kStreamAckV2MaxRanges];
  size_t n = 0;
  bool ok = true;
  size_t off = kStreamAckV2MinLen;  // ranges start after the 10-byte header
  const size_t n_decl =
      seg[9] > kStreamAckV2MaxRanges ? kStreamAckV2MaxRanges : seg[9];
  uint32_t prev_end = cum;
  for (size_t i = 0; ok && i < n_decl; ++i) {
    uint32_t gap = 0;
    uint32_t blen = 0;
    if (!get_uvarint(seg, len, &off, &gap) || !get_uvarint(seg, len, &off, &blen) ||
        blen == 0) {
      ok = false;
      break;
    }
    const uint32_t start = prev_end + gap;  // u32 wrap; validated via seq below
    const uint32_t end = start + blen;
    // i > 0 requires a strict gap: the sender emits disjoint ascending blocks.
    if (!seq_at_or_after(start, cum) || !seq_after(end, start) ||
        seq_after(end, snd_max_) ||
        (i > 0 && !seq_after(start, blocks[n - 1].end))) {
      ok = false;
      break;
    }
    blocks[n++] = Block{start, end};
    prev_end = end;
  }
  if (ok && off != len) {
    ok = false;  // trailing bytes past the declared ranges: malformed
  }
  if (!ok) {
    ++bad_segs_;
  }

  const uint32_t prior_una = snd_una_;
  // Order matters and matches v1: the duplicate-ACK trigger runs before the
  // SACK fill (its fresh-retransmission guard keeps one ACK from emitting the
  // same segment twice), the cumulative advance before the fill (a block below
  // the new snd_una_ is not re-filled).
  ack_dup_burst(cum, now_ms);
  ack_advance_cum(cum, now_ms);
  if (ok) {
    for (size_t i = 0; i < n; ++i) {
      ack_fill_sack(blocks[i].start, blocks[i].end, now_ms);
    }
  }
  if (snd_una_ == prior_una) {
    return;  // nothing confirmed
  }
  if (fin_sent_ && seq_at_or_after(cum, fin_offset_ + 1)) {
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
  if (dup_acks_ < dup_thresh_ || tx_.empty() || !tx_.front().sent) {
    return;
  }
  // A repair already on the wire gets one RTT to land. The peer ACKs every
  // received set, so on a 200ms path a 4 MiB window produces thousands of
  // ACKs per RTT with the same cumulative point; without this gate the burst
  // re-fires the head segment every three ACKs (~every few ms), turning one
  // hole into hundreds of copies of the same 1.3 KB segment per RTT. That
  // storm was ~26k retransmissions per 50 MB transfer on the 205ms/15% WAN
  // path and starved the very ACKs it was waiting for.
  PendingSeg& head = tx_.front();
  // Wait the path's current RTT, not its historical minimum: a standing
  // queue stretches the repair's round trip too.
  const int64_t rtt = std::max<int64_t>(std::max(min_rtt_ms_, srtt_ms_), 1);
  if (head.retrans && now_ms - head.sent_ms < rtt) {
    return;  // the previous repair is still in flight
  }
  // Adaptive first-burst gate (P1-3): after the tolerance has been widened,
  // the head must have had a chance to round-trip before a burst may blame
  // it. A genuinely lost head has unbounded age, so this only delays the
  // repair to ~grace; a reordered shadow fires below the gate and is mode
  // silently absorbed instead of being answered with duplicate bytes.
  if (!head.retrans && now_ms - head.sent_ms < reorder_grace_ms_) {
    return;
  }
  dup_burst_ms_ = now_ms;
  dup_acks_ = 0;
  // FEC can deliver a set out of order, so three duplicates can mean a
  // reordered symbol rather than a lost one. The forced retransmission is
  // cheap either way; the 30% window cut is not, so only a second burst with
  // the first repair still unacked (cum has not moved) is taken as loss.
  if (fast_retx_armed_) {
    loss_epoch_ = true;  // the peer's buffer is stuck behind a hole
    loss_epoch_dup_ = true;
    ++dup_loss_events_;
    if (using_bbr()) {
      bbr_.on_loss();  // a probe that cannot fill must not wait for its target
      bbr_.on_lost(tx_.front().wire_len());
    }
  }
  fast_retx_armed_ = true;
  ++retx_fast_;
  PendingSeg& first = tx_.front();
  first.sent_ms = now_ms;
  first.retrans = true;
  ++retransmits_;
  if (using_bbr()) {
    bbr_.on_sent(now_ms, first.wire_len(), in_flight_);
  }
  emit_seg(first);
}

// Path 2 of the ACK: the cumulative point advanced (pop what it covers).
void Stream::ack_advance_cum(uint32_t cum, int64_t now_ms) {
  if (!seq_after(cum, snd_una_)) {
    return;
  }
  bool popped_retrans = false;
  int64_t sample_ms = -1;
  size_t acked_wire = 0;
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
      // A clock that went backwards says nothing about the path: the sample
      // would be negative and, fed into srtt, would drag every timer with it.
      const int64_t sample = now_ms - front.sent_ms;
      if (sample >= 0) {
        sample_ms = sample;  // keep the newest clean sample
      }
    }
    bytes_acked_ += front.bytes.size();
    acked_wire += front.wire_len();
    tx_.pop_front();
  }
  snd_una_ = cum;
  // Adaptive reordering evidence (P1-3): the pending dup-burst repair was
  // confirmed too fast for its own bytes to have made the trip. The byte the
  // burst retransmitted sits at the cumulative point, so only its arrival can
  // advance cum — and an arrival within one RTT of the burst must be the
  // original, which the burst duplicated while it sat reordered in the peer's
  // receive window. That is quic-go's undo observation in FCP clothing.
  if (dup_burst_ms_ >= 0) {
    const int64_t since_burst = now_ms - dup_burst_ms_;
    dup_burst_ms_ = -1;
    const int64_t rtt = std::max<int64_t>(std::max(min_rtt_ms_, srtt_ms_), 1);
    if (popped_retrans && since_burst >= 0 && since_burst < rtt) {
      ++spur_bursts_;
      // quic-go widens the reordering tolerance up to 1xRTT and retires the
      // packet-count trigger at the ceiling; here doubling the count to 12
      // keeps one press of the brake (renaming it disabled invites a full-
      // window RTO recovery on a path that goes quiet mid-transfer).
      dup_thresh_ = std::min<uint32_t>(dup_thresh_ * 2, kDupAckThresh * 4);
      reorder_grace_ms_ =
          reorder_grace_ms_ == 0 ? std::max<int64_t>(rtt / 8, 1)
                                 : std::min<int64_t>(reorder_grace_ms_ * 2, rtt);
    }
  }
  // The peer confirmed progress: the tail-loss clock restarts and the probe
  // budget for the previous stall is spent.
  progress_ms_ = now_ms;
  tlp_probes_ = 0;
  // fill_holes only fills the range each SACK block newly reveals. Once cum
  // moves, the next hole is above the new cumulative point, so the watermark
  // has to follow it; leaving it ahead would ignore blocks between the two.
  sack_filled_up_to_ = cum;
  if (using_bbr() && acked_wire > 0) {
    // A new round starts when this ACK passes everything that was on the wire
    // when the previous round began. Byte offsets wrap at 4 GiB, so the
    // comparison has to go through seq_after() like every other offset.
    bool new_round = false;
    if (seq_after(cum, bbr_round_end_)) {
      new_round = true;
      bbr_round_end_ = snd_max_;
    }
    const int64_t rtt = sample_ms >= 0 && !popped_retrans ? sample_ms : 0;
    bbr_.on_acked(now_ms, acked_wire, rtt, new_round, in_flight_);
    send_window_ = std::clamp(bbr_.cwnd(), window_min_, window_max_);
  }
  fast_retx_armed_ = false;  // the hole healed: the burst was reordering
  // Karn's rule: while a retransmission is in the acked set the sample is
  // ambiguous (it may measure the timeout, not the path), so drop the round.
  if (sample_ms >= 0 && !popped_retrans) {
    update_srtt(sample_ms, now_ms);
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
      s.sacked_ms = now_ms;
    }
  }
  fill_holes(sack_start, now_ms);
}

bool Stream::sack_fresh(const PendingSeg& seg, int64_t now_ms) const {
  if (seg.sacked_ms < 0) {
    return false;
  }
  // Four base RTOs: long enough that ordinary reordering survives the mark (the
  // receive side re-confirms each rotating block on every ACK), short enough
  // that a SACK which can never be honoured costs one recovery window instead
  // of the whole stream.
  const int64_t trust = stream_detail::clamp_ms(4 * rto_ms_, 1000, 30000);
  return now_ms - seg.sacked_ms < trust;
}

void Stream::fill_holes(uint32_t sack_start, int64_t now_ms) {
  // A SACK block past snd_una_ means the sender's next bytes are the hole, so
  // retransmit them now instead of waiting a full RTO. Measured burst loss
  // (spec §14.10) makes RTO-only recovery stall a 20 Mbps stream.
  if (!seq_after(sack_start, snd_una_)) {
    return;
  }
  const size_t seg_cap = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  // A SACK block can reveal a hole of the whole window (the first block after a
  // burst loss). With BBR the token bucket is the burst limiter, so the whole
  // hole goes out in this one pass; without a pacer the old 32-segment cap still
  // keeps the repair from arriving as one back-to-back micro-burst.
  size_t budget = using_bbr() ? send_window_ : std::min(send_window_, 32 * seg_cap);
  // One repair per RTT. The gate used to be rto_ms_, which left a lost repair
  // to the RTO even though the peer keeps re-advertising the same hole; a round
  // trip is the earliest a second copy can do any good.
  const int64_t rtt = std::max<int64_t>(std::max(min_rtt_ms_, srtt_ms_), 1);
  bool sent_any = false;

  // First pass: the range this block newly reveals, from the watermark up to
  // the block start. Every eligible segment goes out, not one per ACK/RTT: a
  // burst hole is one recovery event.
  if (seq_after(sack_start, sack_filled_up_to_)) {
    const uint32_t from = sack_filled_up_to_;
    ++fill_passes_;
    sack_filled_up_to_ = sack_start;
    for (size_t i = 0; i < tx_.size(); ++i) {
      PendingSeg& seg = tx_[i];
      const uint32_t seg_end = seg.offset + static_cast<uint32_t>(seg.wire_len());
      if (!seq_after(seg_end, snd_una_) || !seg.sent || sack_fresh(seg, now_ms)) {
        continue;  // acked, not on the wire (pump handles those), or not a hole
      }
      if (seq_dist(seg.offset, sack_start) >= 0) {
        break;  // at or past the hole
      }
      if (seq_dist(seg.offset, from) < 0) {
        continue;  // an earlier block already owned this range
      }
      if (seg.retrans && now_ms - seg.sent_ms < rtt) {
        continue;  // already re-filling this one
      }
      if ((sent_any && seg.wire_len() > budget) ||
          !pace_allow(seg.wire_len(), now_ms)) {
        // The rest waits for the next ACK. Leave the watermark at this segment:
        // it was not sent, so a later block with a higher start has to be able
        // to fill it (advancing past it here would hand the range to nobody and
        // leave the hole to the RTO).
        sack_filled_up_to_ = seg.offset;
        return;
      }
      budget = budget >= seg.wire_len() ? budget - seg.wire_len() : 0;
      seg.sent_ms = now_ms;
      seg.retrans = true;
      // A fill is a repair too: if the peer is still stuck behind the same hole
      // a full RTT later, the next duplicate burst is loss evidence and not just
      // the fill arriving late (ack_dup_burst gates on the RTT).
      fast_retx_armed_ = true;
      ++retransmits_;
      ++retx_fill_;
      if (using_bbr()) {
        // A SACK fill is a speculative repair: the SACK block says where the
        // peer's buffer resumes, not that these bytes were lost. Counting every
        // fill as loss made a 2%-loss transfer look 60% lossy to BBRv2, whose
        // inflight_hi then ratcheted down to the 64 KiB floor for the whole
        // connection (0.16 MB/s). Only dup-ACK evidence and RTOs count.
        bbr_.on_sent(now_ms, seg.wire_len(), in_flight_);
      }
      emit_seg(seg);
      sent_any = true;
    }
  }

  // Second pass: repairs below the watermark that the peer's cumulative point
  // still has not passed. A lost fill used to be invisible: the watermark made
  // the range "owned", the SACK block keeps starting above it, and only the RTO
  // (two RTTs, then backoff) could send it again -- the multi-RTT tail of a
  // burst loss. One copy per RTT recovers it in a round trip. Original sends
  // are deliberately excluded: a segment below a reported block may simply sit
  // in a chunk this single-block ACK has not rotated to yet, and re-sending
  // those was the quadratic ~22k-retransmission storm.
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    const uint32_t seg_end = seg.offset + static_cast<uint32_t>(seg.wire_len());
    if (!seq_after(seg_end, snd_una_) || !seg.sent || sack_fresh(seg, now_ms)) {
      continue;
    }
    if (seq_dist(seg.offset, sack_start) >= 0) {
      break;
    }
    if (seq_at_or_after(seg.offset, sack_filled_up_to_)) {
      continue;  // the first pass owns this range
    }
    if (!seg.retrans || now_ms - seg.sent_ms < rtt) {
      continue;  // never filled, or a repair is still in flight
    }
    if ((sent_any && seg.wire_len() > budget) ||
        !pace_allow(seg.wire_len(), now_ms)) {
      return;  // the next ACK continues; the watermark is untouched
    }
    budget = budget >= seg.wire_len() ? budget - seg.wire_len() : 0;
    seg.sent_ms = now_ms;
    ++retransmits_;
    ++retx_fill_;
    if (using_bbr()) {
      bbr_.on_sent(now_ms, seg.wire_len(), in_flight_);
    }
    emit_seg(seg);
    sent_any = true;
  }
}

void Stream::retransmit_timeouts(int64_t now_ms) {
  // Exponential backoff (Karn): a silent peer must not be refilled with a whole
  // window every base RTO forever. Doubling per timeout episode (reset by the
  // next clean sample) turns a 1 MiB window from ~3 MB/s of futile traffic into
  // a decaying trickle. The pass is also charged against one window of bytes so
  // a malformed state can never emit more than in-flight in one tick.
  const int64_t rto = stream_detail::clamp_ms(rto_ms_ * rto_backoff_, cfg_.rto_min_ms, cfg_.rto_max_ms);
  // A timeout is a probe of the head of the queue, not a licence to dump the
  // whole window: every segment in a burst shares a send timestamp, so the old
  // "retransmit everything older than the RTO" rule re-sent up to 4 MiB at
  // once. Five such episodes accounted for the bulk of a 50 MB transfer's ~19k
  // retransmissions. 32 segments is enough to restart the pipe; the SACK fills
  // (and the ACKs they provoke) repair the rest.
  const size_t seg_cap = cfg_.max_segment > 0 ? cfg_.max_segment : 1;
  size_t budget = std::min(send_window_, 32 * seg_cap);
  bool fired = false;
  // What times out while the peer is advertising no room for even one segment
  // is the zero-window probe, not the path. Feeding that to BBR as congestion
  // made every stalled peer read as a lossy link and pinned inflight_hi to the
  // floor; the probe is still retransmitted, it just is not evidence.
  const bool peer_limited = peer_rwnd_ < seg_cap;
  for (size_t i = 0; i < tx_.size(); ++i) {
    PendingSeg& seg = tx_[i];
    if (!seg.sent) {
      break;  // segments go out in order, so nothing later can be older
    }
    // The peer's SACK already proved it holds these bytes; only the cumulative
    // point is blocked behind a hole. Resending them was the difference between
    // recovering one hole and dumping a whole 4 MiB window: on the 205ms WAN
    // path a single RTO re-sent the entire outstanding window, and 17 such
    // episodes accounted for ~27k retransmissions on a 45 MB transfer.
    if (sack_fresh(seg, now_ms)) {
      continue;
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
    ++retx_rto_;
    if (using_bbr()) {
      bbr_.on_sent(now_ms, seg.wire_len(), in_flight_);
      if (!peer_limited) {
        bbr_.on_loss();
        bbr_.on_lost(seg.wire_len());
      }
    }
    emit_seg(seg);
    fired = true;
  }
  if (fired) {
    ++rto_loss_events_;  // one timeout episode, however many segments it resent
    rto_backoff_ = std::min<int64_t>(rto_backoff_ * 2, 16);
  }
}

int64_t Stream::tlp_pto_ms() const {
  const int64_t rtt = std::max<int64_t>(srtt_ms_, 1);
  // ~1.5 RTT plus a little slack, floored above the host's 25 ms tick (delivery
  // is quantized to it, so a lossless round trip can look like a tick and a
  // half) and capped just below the base RTO, which takes over when the probe
  // itself is lost.
  const int64_t pto =
      std::max<int64_t>(kTlpMinPtoMs, rtt + std::max<int64_t>(kTlpSlackMs, rtt / 2));
  return std::min<int64_t>(pto, std::max<int64_t>(rto_ms_ - 1, 1));
}

int64_t Stream::tlp_due_ms(int64_t now_ms) const {
  if (state_ == StreamState::kClosed || in_flight_ == 0 || tlp_probes_ >= kTlpMaxProbes) {
    return 0;
  }
  // The newest segment on the wire is the tail. Segments pump() has built but
  // the window still holds back are not "lost": the window will release them.
  const PendingSeg* tail = nullptr;
  for (auto it = tx_.rbegin(); it != tx_.rend(); ++it) {
    if (it->sent) {
      tail = &*it;
      break;
    }
  }
  // A SACK block proves the peer holds this segment; any loss is below it,
  // where fill_holes() lives. A repair already in flight gets its own RTT, and
  // after that the RTO is the backstop.
  if (tail == nullptr || tail->retrans || sack_fresh(*tail, now_ms)) {
    return 0;
  }
  // Both clocks have to be quiet: no cumulative progress and the tail itself
  // outstanding for the probe interval. The pair keeps a busy stream (ACKs
  // flowing, tail freshly sent) and an app-limited tail wait -- where the only
  // thing outstanding is the ACK of the last segment -- off the probe.
  const int64_t since = std::max(progress_ms_, tail->sent_ms);
  return since + tlp_pto_ms();
}

void Stream::tail_loss_probe(int64_t now_ms) {
  const int64_t due = tlp_due_ms(now_ms);
  if (due == 0 || now_ms < due) {
    return;
  }
  PendingSeg* tail = nullptr;
  for (auto it = tx_.rbegin(); it != tx_.rend(); ++it) {
    if (it->sent) {
      tail = &*it;
      break;
    }
  }
  if (tail == nullptr) {
    return;
  }
  tail->sent_ms = now_ms;
  tail->retrans = true;
  ++tlp_probes_;
  ++retransmits_;
  ++retx_tlp_;
  if (using_bbr()) {
    // On the wire like any other repair, but not loss evidence: a delayed ACK
    // or a one-off tail drop must not move BBR's model.
    bbr_.on_sent(now_ms, tail->wire_len(), in_flight_);
  }
  emit_seg(*tail);
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
