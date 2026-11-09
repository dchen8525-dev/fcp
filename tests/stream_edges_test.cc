// FCP-STREAM edge-case tests (complements stream_test.cc).
//
// stream_test.cc covers the happy paths, the autotune control law, BBR, loss
// recovery and the ACK-v2 protocol. This file targets the branches those cases
// leave untaken: constructor clamps (srtt=0, max_segment=0), the closed/half-
// closed getters, idempotent close/abort, on_segment guards, every
// set_max_segment carve (including re-cutting unsent and SACKed segments),
// close-from-inside-a-callback at each on_tick step, BBR pacing token denial,
// the BDP-following window ceiling and its receive-cap mirror, the disabled
// delay brake, ACK-v2 fin completion, malformed SACK blocks below the
// cumulative point, receive-side read-callback variants, a paced zero-window
// probe, the SRTT floor and the tail-probe wake deadline.
//
// Everything is driven synchronously through the public Stream API with an
// explicit now_ms clock; no wall clock and no sockets are involved.

#include "fcp/stream.h"

#include "fcp/wire.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "test_util.h"

namespace {

using fcp::CloseReason;
using fcp::Stream;
using fcp::StreamConfig;
using fcp::StreamState;

uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void wr32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    b[at + i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

std::vector<uint8_t> MakeAck(uint32_t cum, uint32_t rwnd, uint32_t sack_start,
                             uint32_t sack_end) {
  std::vector<uint8_t> b(fcp::kStreamAckLen, 0);
  b[0] = fcp::kStreamTypeAck;
  wr32(b, 1, cum);
  wr32(b, 5, rwnd);
  wr32(b, 9, sack_start);
  wr32(b, 13, sack_end);
  return b;
}

std::vector<uint8_t> MakeAckV2(uint32_t cum, uint32_t rwnd,
                               std::vector<std::pair<uint32_t, uint32_t>> blocks) {
  std::vector<uint8_t> b(fcp::kStreamAckV2MinLen, 0);
  b[0] = fcp::kStreamTypeAckV2;
  wr32(b, 1, cum);
  wr32(b, 5, rwnd);
  b[9] = static_cast<uint8_t>(blocks.size());
  uint32_t prev_end = cum;
  for (const auto& blk : blocks) {
    uint8_t tmp[10];
    const size_t g = fcp::put_uvarint(blk.first - prev_end, tmp);
    b.insert(b.end(), tmp, tmp + g);
    const size_t l = fcp::put_uvarint(blk.second - blk.first, tmp);
    b.insert(b.end(), tmp, tmp + l);
    prev_end = blk.second;
  }
  return b;
}

std::vector<uint8_t> MakeData(uint32_t offset, const std::vector<uint8_t>& bytes, bool fin) {
  std::vector<uint8_t> b(fcp::kStreamDataHdrLen + bytes.size(), 0);
  b[0] = fcp::kStreamTypeData;
  wr32(b, 1, offset);
  b[5] = fin ? fcp::kStreamFlagFin : 0;
  for (size_t i = 0; i < bytes.size(); ++i) {
    b[fcp::kStreamDataHdrLen + i] = bytes[i];
  }
  return b;
}

std::vector<uint8_t> MakeBytes(size_t n, uint8_t seed) {
  std::vector<uint8_t> out(n);
  for (size_t i = 0; i < n; ++i) {
    out[i] = static_cast<uint8_t>((seed + i * 31 + (i >> 5)) & 0xFF);
  }
  return out;
}

bool IsData(const std::vector<uint8_t>& seg) {
  return seg.size() >= fcp::kStreamDataHdrLen && seg[0] == fcp::kStreamTypeData;
}

bool IsAck(const std::vector<uint8_t>& seg) {
  return seg.size() == fcp::kStreamAckLen && seg[0] == fcp::kStreamTypeAck;
}

// Small fixture in stream_test's style: one stream, an emit log, the delivered
// bytes and the teardown/eof/RTT callbacks. A few flags drop callbacks so the
// null-callback branches can be reached.
struct Harness {
  bool enable_read = true;
  bool enable_closed = true;
  bool enable_rtt = true;

  std::unique_ptr<Stream> stream;
  std::vector<std::vector<uint8_t>> sent;
  std::vector<uint8_t> delivered;
  std::vector<CloseReason> closes;
  std::vector<int64_t> rtts;
  int eof_count = 0;
  int64_t now = 1000;
  // By value: a test callback may reset the stream, which appends to `sent`
  // and could otherwise invalidate the reference it is looking at.
  std::function<void(std::vector<uint8_t>)> after_send;
  std::function<void()> after_read;

  Stream& make(const StreamConfig& cfg) {
    Stream::SegmentFn send_fn = [this](const uint8_t* p, size_t n) {
      sent.emplace_back(p, p + n);
      if (after_send) {
        after_send(sent.back());
      }
    };
    Stream::ReadFn read_fn;
    if (enable_read) {
      read_fn = [this](const uint8_t* p, size_t n) {
        delivered.insert(delivered.end(), p, p + n);
        if (after_read) {
          after_read();
        }
      };
    }
    Stream::ClosedFn closed_fn;
    if (enable_closed) {
      closed_fn = [this](CloseReason r) { closes.push_back(r); };
    }
    Stream::EofFn eof_fn = [this]() { ++eof_count; };
    Stream::RttFn rtt_fn;
    if (enable_rtt) {
      rtt_fn = [this](int64_t sample) { rtts.push_back(sample); };
    }
    stream = std::make_unique<Stream>(cfg, send_fn, read_fn, closed_fn, eof_fn, rtt_fn);
    return *stream;
  }

  Stream& s() { return *stream; }
  void feed(const std::vector<uint8_t>& seg) { stream->on_segment(seg.data(), seg.size(), now); }
  void tick(int64_t ms) {
    now += ms;
    stream->on_tick(now);
  }

  size_t count_type(uint8_t type) const {
    size_t n = 0;
    for (const std::vector<uint8_t>& seg : sent) {
      if (!seg.empty() && seg[0] == type) {
        ++n;
      }
    }
    return n;
  }
  size_t count_data() const {
    size_t n = 0;
    for (const std::vector<uint8_t>& seg : sent) {
      if (IsData(seg)) {
        ++n;
      }
    }
    return n;
  }
  size_t count_fin() const {
    size_t n = 0;
    for (const std::vector<uint8_t>& seg : sent) {
      if (IsData(seg) && (seg[5] & fcp::kStreamFlagFin) != 0) {
        ++n;
      }
    }
    return n;
  }
  std::vector<uint8_t> last_ack() const {
    for (auto it = sent.rbegin(); it != sent.rend(); ++it) {
      if (IsAck(*it)) {
        return *it;
      }
    }
    return {};
  }
};

// stream_test's shared config: 100-byte payloads, small windows.
StreamConfig SmallCfg() {
  StreamConfig c;
  c.max_segment = 106;
  c.send_window_bytes = 4096;
  c.rcv_buf_bytes = 2048;
  c.initial_srtt_ms = 200;
  c.rto_min_ms = 100;
  c.rto_max_ms = 5000;
  c.idle_timeout_ms = 300000;
  c.probe_ms = 500;
  return c;
}

// Default segment size, small windows: a total just above one segment leaves
// one big and one small segment in tx_ for the re-cut paths.
StreamConfig LargeCfg() {
  StreamConfig c;
  c.max_segment = 1336;
  c.send_window_bytes = 4096;
  c.rcv_buf_bytes = 2048;
  c.initial_srtt_ms = 200;
  c.rto_min_ms = 100;
  c.rto_max_ms = 5000;
  c.idle_timeout_ms = 300000;
  c.probe_ms = 500;
  return c;
}

// Constructor clamps: initial_srtt_ms <= 0 falls back to the default, and a
// zero max_segment floors the derived clamps at one byte. A stream that cannot
// carry the header must reset on the first pump instead of carving empty
// segments, and with no log callback that path must still close.
void TestConstructorDefaultsAndZeroSegment() {
  StreamConfig c;
  c.initial_srtt_ms = 0;
  c.max_segment = 0;
  Harness h;
  Stream& st = h.make(c);
  CHECK_EQ(st.srtt_ms(), fcp::kDefaultSrttMs);
  CHECK_EQ(st.rto_ms(), static_cast<int64_t>(400));

  const std::vector<uint8_t> src = MakeBytes(10, 1);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK(st.closed());
  CHECK_EQ(st.reason(), CloseReason::kReset);
  CHECK_EQ(h.closes.size(), 1u);
  CHECK_EQ(h.count_data(), 0u);
}

// send_space() is zero on a closed stream even when it still has room, and
// can_write() must follow both the window and the closed state. A repeated
// abort must not emit a second RST.
void TestClosedAccessorsAndRepeatedAbort() {
  StreamConfig c;
  c.send_window_bytes = 250;  // floored to two default segments
  Harness h;
  Stream& st = h.make(c);
  const std::vector<uint8_t> src = MakeBytes(st.send_window(), 2);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  CHECK(!st.can_write());
  CHECK_EQ(st.send_space(), 0u);

  st.abort(h.now);
  CHECK(st.closed());
  CHECK_EQ(st.reason(), CloseReason::kReset);
  CHECK_EQ(st.send_space(), 0u);
  CHECK(!st.can_write());
  CHECK_EQ(h.count_type(fcp::kStreamTypeRst), 1u);

  st.abort(h.now);  // already closed: a no-op
  CHECK_EQ(h.count_type(fcp::kStreamTypeRst), 1u);
  CHECK_EQ(h.closes.size(), 1u);
}

// Guards and idempotence: a null segment and a zero-length segment are ignored
// before any counter moves, close() twice queues exactly one fin, abort() after
// that emits exactly one RST, and traffic on a closed stream is discarded.
void TestSegmentGuardsAndCloseIdempotence() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  const std::vector<uint8_t> junk = MakeBytes(10, 3);
  st.on_segment(nullptr, 5, h.now);
  st.on_segment(junk.data(), 0, h.now);
  CHECK_EQ(st.segs_rx(), 0u);

  st.close(h.now);
  st.close(h.now);  // fin_queued_ is already set
  CHECK_EQ(h.count_fin(), 1u);

  st.abort(h.now);
  CHECK(st.closed());
  CHECK_EQ(h.count_type(fcp::kStreamTypeRst), 1u);
  st.abort(h.now);
  CHECK_EQ(h.count_type(fcp::kStreamTypeRst), 1u);
  CHECK_EQ(h.closes.size(), 1u);

  st.on_segment(junk.data(), junk.size(), h.now);  // closed state
  CHECK_EQ(st.segs_rx(), 0u);
  CHECK_EQ(st.bad_segs(), 0u);
}

// A short ACK-v2 frame is malformed and counted; a well-formed empty-range
// frame carries both the cumulative point and the window; a cumulative point
// past anything sent is a lie and rejected before the window is read.
void TestAckV2FrameGuards() {
  Harness h;
  Stream& st = h.make(SmallCfg());

  std::vector<uint8_t> short_v2 = {fcp::kStreamTypeAckV2};
  h.feed(short_v2);
  std::vector<uint8_t> short_v2_9(fcp::kStreamAckV2MinLen - 1, 0);
  short_v2_9[0] = fcp::kStreamTypeAckV2;
  h.feed(short_v2_9);
  CHECK_EQ(st.bad_segs(), 2u);

  h.feed(MakeAckV2(0, 4096, {}));
  CHECK_EQ(st.peer_window(), 4096u);
  CHECK_EQ(st.bad_segs(), 2u);

  h.feed(MakeAckV2(1u << 20, 4096, {}));
  CHECK_EQ(st.bad_segs(), 3u);
}

// set_max_segment() early returns for 0 and for an unchanged value, and refuses
// a downward move at or below the header (it cannot carry a payload anymore).
// In each case the old carving keeps working.
void TestSetMaxSegmentGuards() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  st.set_max_segment(0);
  st.set_max_segment(SmallCfg().max_segment);

  const std::vector<uint8_t> src = MakeBytes(100, 4);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(h.count_data(), 1u);

  st.set_max_segment(fcp::kStreamDataHdrLen);  // downward, too small: refused
  const std::vector<uint8_t> more = MakeBytes(100, 5);
  CHECK_EQ(st.write(more.data(), more.size()), more.size());
  h.tick(25);
  CHECK_EQ(h.count_data(), 2u);
  CHECK(!st.closed());
  CHECK_EQ(st.bad_segs(), 0u);
  for (const std::vector<uint8_t>& seg : h.sent) {
    if (IsData(seg)) {
      CHECK(seg.size() <= 106u);
    }
  }
}

// Downward re-cut on segments that are both big and SACKed: the pieces keep the
// SACK mark and the byte accounting, and a second, further cut hits the
// "smaller than the new piece" fast path (a segment carried over unchanged).
void TestSetMaxSegmentRecutSackedAndSmall() {
  Harness h;
  Stream& st = h.make(LargeCfg());  // 1330-byte payloads
  const std::vector<uint8_t> src = MakeBytes(1330 + 84, 6);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(st.unacked_segs(), 2u);
  CHECK_EQ(st.in_flight(), src.size());

  // [1000, 1414) is buffered by the peer: the small tail becomes SACKed.
  h.feed(MakeAck(0, 4096, 1000, 1414));
  CHECK(st.retransmits() >= 1u);

  st.set_max_segment(206);  // 200-byte pieces: 1330 -> 7, 84 -> kept
  CHECK_EQ(st.in_flight(), src.size());
  CHECK_EQ(st.unacked_segs(), 8u);

  st.set_max_segment(56);  // 50-byte pieces: SACKed pieces stay SACKed
  CHECK_EQ(st.in_flight(), src.size());
  CHECK_EQ(st.unacked_segs(), 29u);
  CHECK(!st.closed());
}

// A re-cut also has to cover segments that were never sent (the window held
// them back). They are re-carved at the new size and become eligible for the
// next timeout pass instead of keeping the old, unsendable carving.
void TestSetMaxSegmentRecutsUnsentTail() {
  StreamConfig c = SmallCfg();
  c.send_window_bytes = 250;
  c.rcv_buf_bytes = 250;
  Harness h;
  Stream& st = h.make(c);
  const std::vector<uint8_t> src = MakeBytes(600, 7);
  const size_t accepted = st.write(src.data(), src.size());
  CHECK(accepted > 0u && accepted <= src.size());
  h.tick(25);
  // Only what the 250-byte window admits is on the wire.
  CHECK(st.in_flight() <= 250u);

  st.set_max_segment(56);  // 50-byte pieces, including anything unsent
  CHECK(st.in_flight() > 0u);
  CHECK(st.in_flight() <= accepted);

  h.tick(25);  // the 0 stamp makes every re-cut piece RTO-eligible
  CHECK(st.retx_rto() >= 1u);
  CHECK(h.count_data() > 2u);
}

// A coalesced ACK's deadline flush that closes the stream from inside the send
// callback must return from on_tick without touching anything else.
void TestClosedFromInsideAckDeadline() {
  StreamConfig c = SmallCfg();
  c.ack_every = 2;
  Harness h;
  Stream& st = h.make(c);
  h.feed(MakeData(0, MakeBytes(100, 8), false));
  CHECK_EQ(h.count_type(fcp::kStreamTypeAck), 0u);

  bool arm = true;
  h.after_send = [&](const std::vector<uint8_t>& seg) {
    if (arm && IsAck(seg)) {
      arm = false;
      h.s().abort(h.now);
    }
  };
  h.tick(fcp::kAckDelayMs);
  CHECK(st.closed());
  CHECK_EQ(st.reason(), CloseReason::kReset);
  CHECK_EQ(h.closes.size(), 1u);
  CHECK_EQ(h.count_type(fcp::kStreamTypeAck), 1u);
  CHECK_EQ(h.count_type(fcp::kStreamTypeRst), 1u);
}

// The SACK-rotation burst on a tick must stop on the first ACK when the host
// closes the stream from inside that emit.
void TestClosedFromInsideAckRotation() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  h.feed(MakeData(100, MakeBytes(100, 9), false));  // out of order: immediate ACK
  CHECK_EQ(st.oob_chunks(), 1u);
  CHECK_EQ(h.count_type(fcp::kStreamTypeAck), 1u);

  bool arm = true;
  h.after_send = [&](const std::vector<uint8_t>& seg) {
    if (arm && IsAck(seg)) {
      arm = false;
      h.s().abort(h.now);
    }
  };
  h.tick(25);  // >= 10 ms since the last ACK: rotation fires
  CHECK(st.closed());
  CHECK_EQ(st.reason(), CloseReason::kReset);
  CHECK_EQ(h.count_type(fcp::kStreamTypeAck), 2u);
  CHECK_EQ(h.closes.size(), 1u);
}

// A SACK fill that closes the stream from inside its emit leaves handle_ack()
// to reach pump() on a closed stream: the early return must keep it off the
// wire and out of the queue.
void TestPumpAfterFillCloses() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  const std::vector<uint8_t> src = MakeBytes(400, 10);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(h.count_data(), 4u);

  bool arm = true;
  h.after_send = [&](const std::vector<uint8_t>& seg) {
    if (arm && IsData(seg)) {
      arm = false;
      h.s().abort(h.now);
    }
  };
  h.feed(MakeAck(100, 4096, 200, 400));
  CHECK(st.closed());
  CHECK_EQ(st.reason(), CloseReason::kReset);
  CHECK_EQ(st.unacked_segs(), 0u);
  CHECK(st.retransmits() >= 1u);
  CHECK_EQ(h.count_data(), 5u);  // four originals + the one fill copy
  CHECK_EQ(h.closes.size(), 1u);
}

// BBR pacing: the token bucket releases only what it has banked. The second
// segment fits the initial two-segment bucket, the third must wait; the host is
// told when the bucket will cover it, and a later tick releases the rest.
void TestPaceTokenBucketAndNextWake() {
  StreamConfig c = SmallCfg();
  c.auto_window = true;
  c.bbr = true;
  c.send_window_bytes = 256 * 1024;
  c.window_min_bytes = 64 * 1024;
  c.window_max_bytes = 1024 * 1024;
  c.rcv_buf_bytes = 1024 * 1024;
  Harness h;
  Stream& st = h.make(c);
  CHECK(st.using_bbr());
  h.feed(MakeAck(0, c.rcv_buf_bytes, 0, 0));  // the peer advertises room

  const std::vector<uint8_t> src = MakeBytes(500, 11);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  st.on_tick(h.now);
  CHECK_EQ(h.count_data(), 2u);  // the bucket admits two segments only

  const int64_t soon = st.next_wake_ms(h.now);
  CHECK(soon > h.now);
  CHECK(soon <= h.now + 5);
  // Far enough ahead the predicted bucket easily covers the next segment, so
  // only the tail-probe deadline remains.
  CHECK_EQ(st.next_wake_ms(h.now + 100), h.now + 300);

  h.tick(1);
  CHECK_EQ(h.count_data(), 5u);

  bool saw_tlp = false;
  for (int i = 0; i < 16 && !saw_tlp; ++i) {
    h.tick(25);
    saw_tlp = st.retx_tlp() >= 1u;
  }
  CHECK(saw_tlp);
  CHECK(st.retransmits() >= 1u);

  st.abort(h.now);
  CHECK_EQ(st.next_wake_ms(h.now), 0);
  CHECK_EQ(h.closes.size(), 1u);
}

// window_ceiling_bytes lets the ceiling follow the measured BDP; the receive
// capacity is raised to match so the peer's growth is not clamped by this
// end's buffer. Without a BDP estimate the configured MAX stays the ceiling.
void TestWindowCeilingRefresh() {
  StreamConfig c = SmallCfg();
  c.auto_window = true;
  c.bbr = true;
  c.send_window_bytes = 256 * 1024;
  c.window_min_bytes = 64 * 1024;
  c.window_max_bytes = 256 * 1024;
  c.window_ceiling_bytes = 4 * 1024 * 1024;
  c.rcv_buf_bytes = 256 * 1024;
  c.initial_bw_bps = 20ull * 1000 * 1000;
  c.initial_min_rtt_ms = 100;
  Harness h;
  Stream& st = h.make(c);
  st.on_tick(h.now);
  CHECK(st.send_window() > 256u * 1024);
  CHECK(st.send_window() <= 4u * 1024 * 1024);
  h.feed(MakeData(100, MakeBytes(100, 12), false));
  const std::vector<uint8_t> ack = h.last_ack();
  CHECK(!ack.empty());
  CHECK(rd32(ack.data() + 5) > 256u * 1024);  // the raised rcv cap

  // No prior and no sample: bdp_bytes() is 0, so the ceiling never moves.
  StreamConfig pinned = c;
  pinned.initial_bw_bps = 0;
  pinned.initial_min_rtt_ms = 0;
  Harness g;
  Stream& pst = g.make(pinned);
  pst.on_tick(g.now);
  CHECK_EQ(pst.send_window(), 256u * 1024);
  g.feed(MakeData(100, MakeBytes(100, 13), false));
  const std::vector<uint8_t> pack = g.last_ack();
  CHECK(!pack.empty());
  CHECK_EQ(rd32(pack.data() + 5), 256u * 1024 - 100u);
}

// window_queue_ms == 0 disables the delay brake: a limited epoch with an ACK
// advance must still run the growth law (with no credible sample, the additive
// one-segment step) instead of cutting.
void TestDisabledQueueBrakeStillGrows() {
  StreamConfig c = SmallCfg();
  c.auto_window = true;
  c.bbr = false;
  c.send_window_bytes = 16 * 1024;
  c.window_min_bytes = 4096;
  c.window_max_bytes = 16 * 1024;
  c.loss_floor_bytes = 4096;
  c.window_queue_ms = 0;
  c.rcv_buf_bytes = 16 * 1024;
  c.initial_srtt_ms = 100;
  c.rto_min_ms = 100;
  Harness h;
  Stream& st = h.make(c);
  h.feed(MakeAck(0, 16 * 1024, 0, 0));  // confirms the peer's window

  const std::vector<uint8_t> src = MakeBytes(16 * 1024, 14);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);  // the exact window fills: the epoch is limited
  CHECK_EQ(st.in_flight(), 16u * 1024);

  h.tick(75);   // first epoch boundary establishes the baseline
  h.tick(100);  // no ACK yet: a limited epoch with nothing acked does nothing
  h.tick(100);  // an RTO fires, cuts to 70% of 16 KiB
  CHECK_EQ(st.send_window(), 11469u);
  CHECK_EQ(st.loss_floor(), 4096u);

  h.feed(MakeAck(100, 16 * 1024, 0, 0));  // one segment acked, still limited
  h.tick(200);  // disabled brake: one additive segment instead of a cut
  CHECK_EQ(st.send_window(), 11575u);
  CHECK(st.retx_rto() >= 1u);
  CHECK(!st.closed());
}

// ACK-v2 covers the fin: with the peer's fin already delivered the stream
// finishes locally, and with it still outstanding only pump() runs until that
// fin arrives; the receive path then completes on kPeerClose.
void TestAckV2FinCompletion() {
  StreamConfig c = SmallCfg();
  c.ack_v2 = true;

  {
    Harness h;
    Stream& st = h.make(c);
    const std::vector<uint8_t> src = MakeBytes(300, 15);
    CHECK_EQ(st.write(src.data(), src.size()), src.size());
    h.tick(25);
    st.close(h.now);
    h.feed(MakeData(0, {}, true));  // the peer's fin arrives first
    CHECK_EQ(st.state(), StreamState::kPeerClosed);
    CHECK_EQ(h.eof_count, 1);

    h.feed(MakeAckV2(301, 4096, {}));  // covers all data and the fin
    CHECK(st.closed());
    CHECK_EQ(st.reason(), CloseReason::kLocalEof);
    CHECK_EQ(st.bytes_acked(), 300u);
    CHECK_EQ(st.unacked_segs(), 0u);
    CHECK_EQ(h.closes.size(), 1u);
  }

  {
    Harness h;
    Stream& st = h.make(c);
    const std::vector<uint8_t> src = MakeBytes(300, 16);
    CHECK_EQ(st.write(src.data(), src.size()), src.size());
    h.tick(25);
    st.close(h.now);
    h.feed(MakeAckV2(301, 4096, {}));  // eof not delivered yet: pump only
    CHECK_EQ(st.state(), StreamState::kSendingFin);
    CHECK_EQ(st.bytes_acked(), 300u);
    CHECK_EQ(st.unacked_segs(), 0u);

    h.feed(MakeData(0, {}, true));
    CHECK(st.closed());
    CHECK_EQ(st.reason(), CloseReason::kPeerClose);
    CHECK_EQ(h.eof_count, 1);
    CHECK_EQ(h.closes.size(), 1u);
  }
}

// SACK validation: a block below the cumulative point and a block past
// snd_max_ are both malformed, while a real block right after still repairs
// the hole in one pass.
void TestSackBlockValidationBranches() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  const std::vector<uint8_t> src = MakeBytes(400, 17);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(h.count_data(), 4u);

  h.feed(MakeAck(100, 4096, 50, 150));  // starts below cum
  CHECK_EQ(st.bad_segs(), 1u);
  CHECK_EQ(st.bytes_acked(), 100u);
  CHECK_EQ(st.retransmits(), 0u);

  h.feed(MakeAck(100, 4096, 200, 500));  // ends past snd_max_
  CHECK_EQ(st.bad_segs(), 2u);
  CHECK_EQ(st.retransmits(), 0u);

  h.feed(MakeAck(100, 4096, 200, 400));  // a real block fills the hole
  CHECK_EQ(st.bad_segs(), 2u);
  CHECK(st.retransmits() >= 1u);
  CHECK_EQ(h.count_data(), 5u);
}

// Receive-side callback variants: without a read callback the bytes are still
// delivered and counted; a read callback that resets the stream stops the
// delivery loop right there.
void TestReceiveReadCallbackEdges() {
  {
    Harness h;
    h.enable_read = false;
    Stream& st = h.make(SmallCfg());
    h.feed(MakeData(0, MakeBytes(100, 18), false));
    CHECK(h.delivered.empty());
    CHECK_EQ(st.bytes_delivered(), 100u);
    CHECK_EQ(st.oob_bytes(), 0u);
    CHECK(!st.closed());
  }
  {
    Harness h;
    Stream& st = h.make(SmallCfg());
    h.after_read = [&]() { h.s().abort(h.now); };
    h.feed(MakeData(0, MakeBytes(100, 19), false));
    CHECK_EQ(h.delivered.size(), 100u);
    CHECK_EQ(st.bytes_delivered(), 100u);
    CHECK(st.closed());
    CHECK_EQ(st.reason(), CloseReason::kReset);
    CHECK_EQ(h.closes.size(), 1u);
  }
}

// A zero-window probe is allowed past the window by probe_credit_, which also
// bypasses the pacer; after it, next_wake_ms() reports the tail deadline rather
// than a pacing wait because the window still admits nothing.
void TestZeroWindowProbeBypassesPacer() {
  StreamConfig c = SmallCfg();
  c.auto_window = true;
  c.bbr = true;
  c.send_window_bytes = 256 * 1024;
  c.window_min_bytes = 64 * 1024;
  c.window_max_bytes = 1024 * 1024;
  c.rcv_buf_bytes = 256 * 1024;
  Harness h;
  Stream& st = h.make(c);
  h.feed(MakeAck(0, 0, 0, 0));  // the peer's window is shut
  CHECK_EQ(st.peer_window(), 0u);

  const std::vector<uint8_t> src = MakeBytes(300, 20);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(st.probes_sent(), 1u);
  CHECK_EQ(h.count_data(), 1u);
  CHECK_EQ(st.next_wake_ms(h.now), h.now + 300);  // the probe's TLP deadline
  CHECK(!st.closed());
}

// update_srtt's floor: zero samples settle at 7 ms (integer division truncates
// toward zero) and a negative sample finally clamps to 1; with no RTT callback
// the estimator still advances without touching the host.
void TestSrttFloorAndMissingRttCallback() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  for (int i = 0; i < 100; ++i) {
    st.test_update_rtt(0, 1000 + i);
  }
  CHECK_EQ(st.srtt_ms(), static_cast<int64_t>(7));
  st.test_update_rtt(-1000, 1100);
  CHECK_EQ(st.srtt_ms(), 1);
  CHECK_EQ(h.rtts.size(), 101u);

  Harness quiet;
  quiet.enable_rtt = false;
  Stream& q = quiet.make(SmallCfg());
  q.test_update_rtt(50, 1000);
  CHECK(quiet.rtts.empty());
  CHECK_EQ(q.srtt_ms(), static_cast<int64_t>(182));
  CHECK_EQ(q.min_rtt_ms(), static_cast<int64_t>(50));
}

// next_wake_ms reports the tail-loss deadline so the host can probe before its
// next reactor tick; the probe consumes the stall and the deadline drops to 0.
void TestTailProbeNextWake() {
  Harness h;
  Stream& st = h.make(SmallCfg());
  const std::vector<uint8_t> src = MakeBytes(300, 21);
  CHECK_EQ(st.write(src.data(), src.size()), src.size());
  h.tick(25);
  CHECK_EQ(h.count_data(), 3u);
  CHECK_EQ(st.next_wake_ms(h.now), h.now + 300);

  h.tick(301);
  CHECK_EQ(st.retx_tlp(), 1u);
  CHECK_EQ(st.next_wake_ms(h.now), 0);
}

}  // namespace

int main() {
  TestConstructorDefaultsAndZeroSegment();
  TestClosedAccessorsAndRepeatedAbort();
  TestSegmentGuardsAndCloseIdempotence();
  TestAckV2FrameGuards();
  TestSetMaxSegmentGuards();
  TestSetMaxSegmentRecutSackedAndSmall();
  TestSetMaxSegmentRecutsUnsentTail();
  TestClosedFromInsideAckDeadline();
  TestClosedFromInsideAckRotation();
  TestPumpAfterFillCloses();
  TestPaceTokenBucketAndNextWake();
  TestWindowCeilingRefresh();
  TestDisabledQueueBrakeStillGrows();
  TestAckV2FinCompletion();
  TestSackBlockValidationBranches();
  TestReceiveReadCallbackEdges();
  TestZeroWindowProbeBypassesPacer();
  TestSrttFloorAndMissingRttCallback();
  TestTailProbeNextWake();
  return fcp_test::finish();
}
