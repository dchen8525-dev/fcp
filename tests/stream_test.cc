// FCP-STREAM unit tests (M2代理设计.md §8, lines T28/T29).
//
// The stream has no clock and no socket, so the fixture is two endpoints plus a
// wire with an injectable drop policy. Segments travel whole, exactly as they
// will inside FCP data symbols.

#include "fcp/stream.h"

#include "fcp/wire.h"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <utility>
#include <vector>

#include "test_util.h"

namespace {

using fcp::CloseReason;
using fcp::Stream;
using fcp::StreamConfig;
using fcp::StreamState;

constexpr int kA = 0;
constexpr int kB = 1;
constexpr int64_t kSettleRounds = 20000;

uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void wr32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    b[at + i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

std::vector<uint8_t> MakeAck(uint32_t cum, uint32_t rwnd, uint32_t sack_start, uint32_t sack_end) {
  std::vector<uint8_t> b(fcp::kStreamAckLen, 0);
  b[0] = fcp::kStreamTypeAck;
  wr32(b, 1, cum);
  wr32(b, 5, rwnd);
  wr32(b, 9, sack_start);
  wr32(b, 13, sack_end);
  return b;
}

// #78: hand-built ACK v2, blocks given as absolute [start, end) byte pairs
// (encoded relative to cum, exactly like the real emitter).
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

struct AckV2 {
  uint32_t cum = 0;
  uint32_t rwnd = 0;
  std::vector<std::pair<uint32_t, uint32_t>> blocks;  // absolute [start, end)
  bool ok = false;
};

AckV2 ParseAckV2(const std::vector<uint8_t>& seg) {
  AckV2 out;
  if (seg.size() < fcp::kStreamAckV2MinLen || seg[0] != fcp::kStreamTypeAckV2) {
    return out;
  }
  out.cum = rd32(seg.data() + 1);
  out.rwnd = rd32(seg.data() + 5);
  out.ok = true;
  size_t off = fcp::kStreamAckV2MinLen;  // ranges start after the 10-byte header
  uint32_t prev_end = out.cum;
  for (size_t i = 0; i < seg[9]; ++i) {
    uint32_t gap = 0;
    uint32_t len = 0;
    if (!fcp::get_uvarint(seg.data(), seg.size(), &off, &gap) ||
        !fcp::get_uvarint(seg.data(), seg.size(), &off, &len) || len == 0) {
      out.ok = false;
      break;
    }
    prev_end = prev_end + gap;
    out.blocks.emplace_back(prev_end, prev_end + len);
    prev_end = prev_end + len;
  }
  return out;
}

// DATA built by hand, so tests can inject overlaps, holes and lies.
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

bool IsData(const std::vector<uint8_t>& seg) {
  return seg.size() >= fcp::kStreamDataHdrLen && seg[0] == fcp::kStreamTypeData;
}

bool IsAck(const std::vector<uint8_t>& seg) {
  return seg.size() == fcp::kStreamAckLen && seg[0] == fcp::kStreamTypeAck;
}

std::vector<uint8_t> MakeBytes(size_t n, uint8_t seed) {
  std::vector<uint8_t> out(n);
  for (size_t i = 0; i < n; ++i) {
    out[i] = static_cast<uint8_t>((seed + i * 31 + (i >> 5)) & 0xFF);
  }
  return out;
}

std::vector<uint8_t> Concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  std::vector<uint8_t> out = a;
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

struct Packet {
  int from = 0;
  int to = 0;
  std::vector<uint8_t> seg;
};

StreamConfig DefaultCfg() {
  StreamConfig c;
  c.max_segment = 106;  // 100 payload bytes per segment
  c.send_window_bytes = 4096;
  c.rcv_buf_bytes = 2048;
  c.initial_srtt_ms = 200;  // -> rto 400ms
  c.rto_min_ms = 100;
  c.rto_max_ms = 5000;
  c.idle_timeout_ms = 300000;
  c.probe_ms = 500;
  return c;
}

class Fixture {
 public:
  struct End {
    std::unique_ptr<Stream> stream;
    std::vector<uint8_t> delivered;
    std::vector<std::vector<uint8_t>> sent;  // every segment emitted, in order
    std::vector<CloseReason> closes;
    std::vector<int64_t> rtts;
    int eof_count = 0;
  };

  Fixture() : Fixture(DefaultCfg()) {}
  explicit Fixture(const StreamConfig& cfg) {
    base_ = cfg;
    peer_ = cfg;
    attach(kA);
    attach(kB);
  }
  // Two configs: the autotune needs a peer whose advertised window does not
  // follow the local one, to show a peer-limited stream stays put.
  Fixture(const StreamConfig& cfg_a, const StreamConfig& cfg_b) {
    base_ = cfg_a;
    peer_ = cfg_b;
    attach(kA);
    attach(kB);
  }

  End& a() { return ends_[kA]; }
  End& b() { return ends_[kB]; }
  Stream& sa() { return *ends_[kA].stream; }
  Stream& sb() { return *ends_[kB].stream; }
  int64_t now() const { return now_; }
  const StreamConfig& cfg() const { return base_; }
  size_t payload() const { return base_.max_segment - fcp::kStreamDataHdrLen; }

  // Return true to drop the packet. Runs on the wire, before delivery.
  std::function<bool(const Packet&)> killer;

  // Called right after an endpoint hands bytes to its host, with the endpoint
  // index. A host that keeps what it delivered has to report that backlog here:
  // between ticks is too late, because a synchronous loopback delivers a whole
  // window inside one flush before the receive buffer ever sees the debt.
  std::function<void(int index)> on_deliver;
  // Called from inside an endpoint's send callback, after the segment is
  // logged. A synchronous host (in-process loopback) is modelled by feeding an
  // ACK from here: it re-enters the stream while pump() is still on the stack.
  std::function<void(int index, const std::vector<uint8_t>& seg)> on_send;

  void cut_all() { killer = [](const Packet&) { return true; }; }

  void tick(int64_t ms) {
    now_ += ms;
    sa().on_tick(now_);
    sb().on_tick(now_);
    flush();
  }

  // Tick until nothing is outstanding anywhere. Fails if it cannot settle.
  void drain(int64_t max_rounds = kSettleRounds) {
    for (int64_t round = 0; round < max_rounds; ++round) {
      tick(25);
      if (idle()) {
        return;
      }
    }
    CHECK(false);  // the stream never settled
  }

  void flush() {
    for (int guard = 0; guard < 100000 && !wire_.empty(); ++guard) {
      Packet p = wire_.front();
      wire_.pop_front();
      if (killer && killer(p)) {
        continue;
      }
      ends_[p.to].stream->on_segment(p.seg.data(), p.seg.size(), now_);
    }
  }

  // Hand one segment to an endpoint outside the wire: manual ordering and lies.
  void feed(int to, const std::vector<uint8_t>& seg) {
    ends_[to].stream->on_segment(seg.data(), seg.size(), now_);
  }

  // Push every byte, ticking so the send window can recycle.
  size_t push(int from, const std::vector<uint8_t>& data) {
    size_t off = 0;
    for (int round = 0; round < 4000 && off < data.size(); ++round) {
      Stream& s = *ends_[from].stream;
      if (s.can_write()) {
        off += s.write(data.data() + off, data.size() - off);
      }
      tick(25);
    }
    return off;
  }

  std::vector<std::vector<uint8_t>> data_of(int from) const {
    std::vector<std::vector<uint8_t>> out;
    for (const std::vector<uint8_t>& seg : ends_[from].sent) {
      if (IsData(seg)) {
        out.push_back(seg);
      }
    }
    return out;
  }

  // Every segment this endpoint ever emitted, without copying: the path models
  // scan it by index, so a long simulated blackout stays linear in new traffic
  // instead of quadratic in everything sent.
  const std::vector<std::vector<uint8_t>>& raw_sent(int from) const {
    return ends_[from].sent;
  }

  std::vector<uint8_t> last_ack(int from) const {
    for (auto it = ends_[from].sent.rbegin(); it != ends_[from].sent.rend(); ++it) {
      if (IsAck(*it)) {
        return *it;
      }
    }
    return {};
  }

  // The last segment this endpoint emitted of any kind (#78 tests read the
  // v2 ACK, which IsAck's 17-byte filter would skip).
  std::vector<uint8_t> last_sent(int from) const {
    return ends_[from].sent.empty() ? std::vector<uint8_t>() : ends_[from].sent.back();
  }

  std::vector<std::vector<uint8_t>> acks_of(int from) const {
    std::vector<std::vector<uint8_t>> out;
    for (const std::vector<uint8_t>& seg : ends_[from].sent) {
      if (IsAck(seg)) {
        out.push_back(seg);
      }
    }
    return out;
  }

  size_t data_with_offset(int from, uint32_t offset) const {
    size_t n = 0;
    for (const std::vector<uint8_t>& seg : data_of(from)) {
      if (rd32(seg.data() + 1) == offset) {
        ++n;
      }
    }
    return n;
  }

 private:
  void attach(int index) {
    const StreamConfig& c = index == kA ? base_ : peer_;
    const int peer = 1 - index;
    ends_[index].stream = std::make_unique<Stream>(
        c,
        [this, index, peer](const uint8_t* seg, size_t len) {
          // One copy: `sent` is the log, `wire_` takes ownership of the same
          // bytes, so the second push must not duplicate them.
          ends_[index].sent.emplace_back(seg, seg + len);
          wire_.push_back(Packet{index, peer, ends_[index].sent.back()});
          if (on_send) {
            on_send(index, ends_[index].sent.back());
          }
        },
        [this, index](const uint8_t* bytes, size_t len) {
          std::vector<uint8_t>& d = ends_[index].delivered;
          d.insert(d.end(), bytes, bytes + len);
          if (on_deliver) {
            on_deliver(index);
          }
        },
        [this, index](CloseReason reason) { ends_[index].closes.push_back(reason); },
        [this, index]() { ++ends_[index].eof_count; },
        [this, index](int64_t srtt_ms) { ends_[index].rtts.push_back(srtt_ms); });
  }

  bool idle() const {
    if (!wire_.empty()) {
      return false;
    }
    for (const End& e : ends_) {
      if (e.stream->closed()) {
        continue;
      }
      if (e.stream->unacked_segs() != 0 || e.stream->queued_bytes() != 0 ||
          e.stream->in_flight() != 0) {
        return false;
      }
    }
    return true;
  }

  StreamConfig base_;
  StreamConfig peer_;
  End ends_[2];
  std::deque<Packet> wire_;
  int64_t now_ = 1000;
};

// A path model for the autotune tests: A's segments cross immediately, B's ACKs
// come back after `rtt` ms, and the test can stop returning them at all. The
// stream then sees exactly the RTT and the delivery rate the test dictates,
// independent of tick jitter. Use with Fixture::cut_all().
//
// set_jitter(max) adds an independent uniform 0..max delay to every ACK: the
// modelled path has variable latency but no standing queue of our own, which is
// what a goodput-times-minimum-RTT estimate cannot tell apart from bufferbloat.
class DelayedPath {
 public:
  DelayedPath(Fixture& f, int64_t rtt_ms) : f_(f), rtt_ms_(rtt_ms) {}

  void run(int64_t ms) {
    for (int64_t t = 0; t < ms; t += 25) {
      f_.tick(25);
      deliver_acks();
      forward_data();
      collect_acks();
    }
  }

  void drop_acks() { drop_ = true; }
  void resume_acks() { drop_ = false; }
  void set_jitter(int64_t max_extra_ms) { jitter_ms_ = max_extra_ms; }

 private:
  void deliver_acks() {
    while (!held_.empty() && held_.begin()->first <= f_.now()) {
      f_.feed(kA, held_.begin()->second);
      held_.erase(held_.begin());
    }
  }
  void forward_data() {
    const std::vector<std::vector<uint8_t>>& segs = f_.raw_sent(kA);
    for (; out_ < segs.size(); ++out_) {
      if (IsData(segs[out_])) {
        f_.feed(kB, segs[out_]);
      }
    }
  }
  void collect_acks() {
    const std::vector<std::vector<uint8_t>>& acks = f_.raw_sent(kB);
    for (; in_ < acks.size(); ++in_) {
      if (drop_ || !IsAck(acks[in_])) {
        continue;
      }
      int64_t delay = rtt_ms_;
      if (jitter_ms_ > 0) {
        delay += static_cast<int64_t>(rng_() % (static_cast<uint64_t>(jitter_ms_) + 1));
      }
      held_.emplace(f_.now() + delay, acks[in_]);
    }
  }

  Fixture& f_;
  int64_t rtt_ms_;
  int64_t jitter_ms_ = 0;
  std::mt19937 rng_{20260131};
  size_t out_ = 0;
  size_t in_ = 0;
  bool drop_ = false;
  std::multimap<int64_t, std::vector<uint8_t>> held_;
};

// A writer bound to one stream and one byte source: push() offers whatever the
// stream will take from the current offset. A path-model loop is then just
// `w.push(); path.run(25);`, and `off` is how far the source got.
class Applier {
 public:
  Applier(Stream& s, const std::vector<uint8_t>& src) : s_(s), src_(src) {}
  void push() {
    if (s_.can_write()) {
      off += s_.write(src_.data() + off, src_.size() - off);
    }
  }
  size_t off = 0;

 private:
  Stream& s_;
  const std::vector<uint8_t>& src_;
};

// A rate-limited path: the link carries `rate_hz` bytes per second and adds a
// fixed `base_rtt_ms` round trip, so an oversized window builds its own queue
// and every ACK is delayed by exactly backlog/rate. Nothing is ever lost: this
// is the bufferbloat case the delay-based brake has to catch, where a loss
// signal never appears.
class BottleneckPath {
 public:
  BottleneckPath(Fixture& f, int64_t rate_hz, int64_t base_rtt_ms)
      : f_(f), rate_hz_(rate_hz), base_rtt_ms_(base_rtt_ms) {}

  void run(int64_t ms) {
    for (int64_t t = 0; t < ms; t += kStepMs) {
      f_.tick(kStepMs);
      deliver_acks();
      enqueue_data();
      serve_link();
      collect_acks();
    }
  }

  int64_t max_queue_ms() const { return max_queue_ms_; }
  // Slow start overshoots by design until the delay feedback closes the loop a
  // round later; the steady state is what has to stay inside the budget.
  void reset_stats() { max_queue_ms_ = 0; }

 private:
  static constexpr int64_t kStepMs = 5;

  void deliver_acks() {
    while (!returning_.empty() && returning_.front().first <= f_.now()) {
      f_.feed(kA, returning_.front().second);
      returning_.pop_front();
    }
  }
  void enqueue_data() {
    const std::vector<std::vector<uint8_t>>& segs = f_.raw_sent(kA);
    for (; sent_ < segs.size(); ++sent_) {
      if (IsData(segs[sent_])) {
        queued_bytes_ += static_cast<int64_t>(segs[sent_].size());
        queued_.push_back(segs[sent_]);
      }
    }
  }
  void serve_link() {
    tokens_ += rate_hz_ * kStepMs / 1000;
    // Buffer occupancy in service time, sampled before each round of serving:
    // what one RTT of the sender's own making costs the path.
    const int64_t depth_ms = queued_bytes_ * 1000 / rate_hz_;
    if (depth_ms > max_queue_ms_) {
      max_queue_ms_ = depth_ms;
    }
    while (!queued_.empty() && tokens_ >= static_cast<int64_t>(queued_.front().size())) {
      queued_bytes_ -= static_cast<int64_t>(queued_.front().size());
      tokens_ -= static_cast<int64_t>(queued_.front().size());
      f_.feed(kB, queued_.front());
      queued_.pop_front();
    }
  }
  void collect_acks() {
    const std::vector<std::vector<uint8_t>>& acks = f_.raw_sent(kB);
    for (; ack_in_ < acks.size(); ++ack_in_) {
      if (IsAck(acks[ack_in_])) {
        returning_.push_back({f_.now() + base_rtt_ms_, acks[ack_in_]});
      }
    }
  }

  Fixture& f_;
  int64_t rate_hz_;
  int64_t base_rtt_ms_;
  int64_t tokens_ = 0;
  int64_t max_queue_ms_ = 0;
  size_t sent_ = 0;
  size_t ack_in_ = 0;
  int64_t queued_bytes_ = 0;
  std::deque<std::vector<uint8_t>> queued_;
  std::deque<std::pair<int64_t, std::vector<uint8_t>>> returning_;
};

void TestOrderedFlow() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(3000, 7);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sa().bytes_acked(), src.size());
  CHECK_EQ(f.sa().bytes_queued(), src.size());
  CHECK_EQ(f.sa().in_flight(), 0u);
  CHECK_EQ(f.sa().queued_bytes(), 0u);
  CHECK_EQ(f.sa().retransmits(), 0u);
  CHECK_EQ(f.sa().retx_tlp(), 0u);  // ACKs flowing: the tail probe stays off
  CHECK_EQ(f.sb().dup_bytes(), 0u);
  CHECK_EQ(f.sb().bad_segs(), 0u);
  CHECK_EQ(f.sb().state(), StreamState::kOpen);
  CHECK_EQ(f.sb().oob_bytes(), 0u);

  // Segment geometry: capped payload, contiguous byte offsets.
  const size_t cap = f.payload();
  uint32_t expect = 0;
  for (const std::vector<uint8_t>& seg : f.data_of(kA)) {
    CHECK(seg.size() - fcp::kStreamDataHdrLen <= cap);
    CHECK_EQ(rd32(seg.data() + 1), expect);
    expect += static_cast<uint32_t>(seg.size() - fcp::kStreamDataHdrLen);
  }
  CHECK_EQ(expect, src.size());

  // Loopback samples measure ~0ms, so srtt must fall from the seeded 200ms and
  // the host must have been told each time.
  CHECK(!f.a().rtts.empty());
  CHECK(f.sa().srtt_ms() < 200 && f.sa().srtt_ms() >= 1);
  const int64_t two_srtt = f.sa().srtt_ms() * 2;
  CHECK_EQ(f.sa().rto_ms(), two_srtt < f.cfg().rto_min_ms ? f.cfg().rto_min_ms : two_srtt);
}

void TestBidirectional() {
  Fixture f;
  const std::vector<uint8_t> from_a = MakeBytes(1200, 3);
  const std::vector<uint8_t> from_b = MakeBytes(900, 200);
  size_t off_a = 0;
  size_t off_b = 0;
  for (int round = 0; round < 400 && (off_a < from_a.size() || off_b < from_b.size()); ++round) {
    if (off_a < from_a.size() && f.sa().can_write()) {
      off_a += f.sa().write(from_a.data() + off_a, from_a.size() - off_a);
    }
    if (off_b < from_b.size() && f.sb().can_write()) {
      off_b += f.sb().write(from_b.data() + off_b, from_b.size() - off_b);
    }
    f.tick(25);
  }
  f.drain();
  CHECK(f.a().delivered == from_b);
  CHECK(f.b().delivered == from_a);
  CHECK_EQ(f.sa().bytes_acked(), from_a.size());
  CHECK_EQ(f.sb().bytes_acked(), from_b.size());
}

// Out-of-order bytes are held back until the hole is filled, and the ACK reports
// the buffered run as one SACK block.
void TestOutOfOrderHeldAndSackBlock() {
  Fixture f;
  f.cut_all();  // nothing reaches the peer by itself; the test feeds by hand
  const std::vector<uint8_t> src = MakeBytes(400, 11);  // exactly 4 segments
  CHECK_EQ(f.push(kA, src), src.size());

  const std::vector<std::vector<uint8_t>> segs = f.data_of(kA);
  CHECK_EQ(segs.size(), 4u);
  const size_t cap = f.payload();
  f.feed(kB, segs[2]);
  f.feed(kB, segs[1]);
  f.feed(kB, segs[3]);

  CHECK(f.b().delivered.empty());
  const std::vector<uint8_t> ack = f.last_ack(kB);
  CHECK_EQ(rd32(ack.data() + 1), 0);                    // cum: nothing deliverable
  CHECK_EQ(rd32(ack.data() + 9), cap);              // sack_start
  CHECK_EQ(rd32(ack.data() + 13), 4 * cap);         // sack_end: 2..4 merged
  CHECK_EQ(rd32(ack.data() + 5), f.cfg().rcv_buf_bytes - 3 * cap);
  CHECK_EQ(f.sb().oob_bytes(), 3u * cap);

  f.feed(kB, segs[0]);
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sb().oob_bytes(), 0u);
  const std::vector<uint8_t> full = f.last_ack(kB);
  CHECK_EQ(rd32(full.data() + 1), src.size());
  CHECK_EQ(rd32(full.data() + 9), rd32(full.data() + 1));  // sack emptied
  CHECK_EQ(rd32(full.data() + 5), f.cfg().rcv_buf_bytes);
}

// A hole in front of a SACK block is retransmitted on the spot, before any RTO.
// The dup-ACK burst that follows must NOT add a second copy while the SACK
// repair is still in flight (2026-11-03): the peer ACKs every received set, so
// on a real 205ms path the unthrottled burst re-fired this repair every few
// milliseconds (26k copies per 50 MB, observed live). One repair per RTT is
// enough and is what keeps the ACK path from being drowned.
void TestSackFillsHoleWithoutTimeout() {
  Fixture f;
  int copies = 0;
  const uint32_t hole = 100;  // second segment
  f.killer = [&copies, hole](const Packet& p) {
    if (p.from != kA || !IsData(p.seg) || rd32(p.seg.data() + 1) != hole) {
      return false;
    }
    return ++copies == 1;  // lose only the first copy
  };
  const std::vector<uint8_t> src = MakeBytes(500, 5);  // 5 segments
  CHECK_EQ(f.push(kA, src), src.size());
  const int64_t t0 = f.now();
  f.drain();

  CHECK(f.b().delivered == src);
  CHECK_EQ(copies, 2);  // original + the SACK repair only
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK_EQ(f.sb().dup_bytes(), 0u);  // no redundant forced copy
  // No RTO can have elapsed: rto is 400ms at the seeded srtt, and the repair
  // came back inside a couple of 25ms ticks.
  CHECK(f.now() - t0 < f.sa().rto_ms());
}

// Overlapping and fully duplicate segments are trimmed by byte, never corrupted.
// All copies come out of one master buffer, so overlapping ranges agree — the
// stream is immutable once written.
void TestDupAndOverlapTrimming() {
  Fixture f;
  const size_t cap = f.payload();
  const std::vector<uint8_t> master = MakeBytes(2 * cap, 1);
  const std::vector<uint8_t> block(master.begin(), master.begin() + cap);
  f.feed(kB, MakeData(0, block, false));
  CHECK_EQ(f.b().delivered.size(), cap);

  f.feed(kB, MakeData(0, block, false));  // exact duplicate
  CHECK_EQ(f.b().delivered.size(), cap);
  CHECK_EQ(f.sb().dup_bytes(), cap);

  // Straddles the delivery point: the first half was already handed up.
  std::vector<uint8_t> straddle(master.begin() + cap / 2, master.end());
  f.feed(kB, MakeData(static_cast<uint32_t>(cap / 2), straddle, false));
  CHECK_EQ(f.b().delivered.size(), 2 * cap);
  CHECK_EQ(f.sb().dup_bytes(), cap + cap / 2);
  CHECK(f.b().delivered == master);

  f.feed(kB, MakeData(0, block, false));  // fully inside what was delivered
  CHECK_EQ(f.b().delivered.size(), 2 * cap);
  CHECK_EQ(f.sb().dup_bytes(), 2 * cap + cap / 2);
  CHECK_EQ(rd32(f.last_ack(kB).data() + 1), 2 * cap);
}

// Out-of-order bytes are capped at rcv_buf, and that is what rwnd advertises.
void TestReceiverBufferCapAndRwnd() {
  Fixture f;
  const size_t cap = f.payload();
  const size_t rcv_buf = f.cfg().rcv_buf_bytes;
  // One more chunk than the buffer can hold, all beyond the delivery point, plus
  // a final one that straddles the limit and gets truncated to fit exactly.
  for (size_t i = 1; i <= rcv_buf / cap; ++i) {
    f.feed(kB, MakeData(static_cast<uint32_t>(i * cap),
                        MakeBytes(cap, static_cast<uint8_t>(i)), false));
  }
  f.feed(kB, MakeData(static_cast<uint32_t>(rcv_buf), MakeBytes(cap, 77), false));
  CHECK_EQ(f.sb().oob_bytes(), rcv_buf);
  const std::vector<uint8_t> ack = f.last_ack(kB);
  CHECK_EQ(rd32(ack.data() + 5), 0u);  // rwnd shut
  CHECK_EQ(rd32(ack.data() + 9), cap);
  // Adjacent chunks merge, so the single SACK block spans the whole buffered run.
  CHECK_EQ(rd32(ack.data() + 13), rcv_buf + cap);

  // Filling the hole drains the buffer and reopens the window. Whatever no longer
  // fits stays unconfirmed, so the sender retransmits it — nothing is corrupted.
  f.feed(kB, MakeData(0, MakeBytes(cap, 0), false));
  const std::vector<uint8_t> reopened = f.last_ack(kB);
  CHECK_EQ(rd32(reopened.data() + 1), rcv_buf);
  CHECK_EQ(rd32(reopened.data() + 5), rcv_buf);
  CHECK_EQ(f.sb().oob_bytes(), 0u);
  CHECK_EQ(f.b().delivered.size(), rcv_buf);
}

// rwnd == 0 with nothing ackable is the classic deadlock; probes break it.
void TestZeroWindowProbeUnblocks() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(300, 40);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  const uint32_t cum = static_cast<uint32_t>(src.size());
  const size_t data_before = f.data_of(kA).size();
  CHECK_EQ(data_before, 3u);

  // A peer that closes its window in an ack: cum is already ours, so nothing is
  // popped and only the advertised window changes.
  f.feed(kA, MakeAck(cum, 0, cum, cum));
  CHECK_EQ(f.sa().peer_window(), 0u);

  // The peer then goes quiet and every probe copy is lost too.
  int probe_copies = 0;
  f.killer = [&probe_copies, cum](const Packet& p) {
    if (p.from == kB) {
      return true;
    }
    if (IsData(p.seg) && rd32(p.seg.data() + 1) == cum) {
      ++probe_copies;
      return true;
    }
    return false;
  };
  const std::vector<uint8_t> more = MakeBytes(250, 90);
  CHECK_EQ(f.sa().write(more.data(), more.size()), more.size());
  f.tick(25);
  CHECK_EQ(probe_copies, 1);  // the first probe goes out at once
  CHECK_EQ(f.data_of(kA).size(), data_before + 1);

  f.tick(3 * f.cfg().probe_ms);
  CHECK(probe_copies >= 2);
  // Only the probe offset ever goes out: the shut window holds the backlog.
  for (const std::vector<uint8_t>& seg : f.data_of(kA)) {
    if (rd32(seg.data() + 1) != cum) {
      CHECK(rd32(seg.data() + 1) < cum);
    }
  }

  f.killer = nullptr;
  f.drain();
  CHECK(f.b().delivered == Concat(src, more));
  CHECK_EQ(f.sa().peer_window(), f.cfg().rcv_buf_bytes);
  CHECK_EQ(f.sa().in_flight(), 0u);
}

// A window that reopened only to a sliver -- nonzero, but smaller than one
// segment -- used to deadlock the sender just like rwnd==0: nothing fits,
// nothing is in flight, and the probe only fired on an exactly-zero window
// (seen live as a loopback 2MiB freeze at peer_rwnd=906 with 1336-byte
// segments, #23). The sliver has to be probed too.
void TestSmallWindowProbeUnblocks() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(300, 40);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  const uint32_t cum = static_cast<uint32_t>(src.size());
  const size_t segs_before = f.data_of(kA).size();

  // Leave a sliver of window: nonzero, below one 117-byte wire segment.
  const uint32_t sliver = 50;
  f.feed(kA, MakeAck(cum, sliver, cum, cum));
  CHECK_EQ(f.sa().peer_window(), sliver);

  const std::vector<uint8_t> more = MakeBytes(4096, 90);
  CHECK_EQ(f.sa().write(more.data(), more.size()), more.size());
  // The peer goes quiet and drops every probe copy, so the only outbound
  // traffic is the probe itself and its RTO retries.
  int probe_copies = 0;
  f.killer = [&probe_copies, cum](const Packet& p) {
    if (p.from == kB) {
      return true;
    }
    if (IsData(p.seg) && rd32(p.seg.data() + 1) == cum) {
      ++probe_copies;
      return true;
    }
    return false;
  };
  f.tick(25);
  CHECK_EQ(f.data_of(kA).size(), segs_before + 1);  // the probe went out
  CHECK_EQ(probe_copies, 1);

  f.tick(3 * f.cfg().probe_ms);
  CHECK(probe_copies >= 2);

  // The peer answers with its real window and the backlog completes in order.
  f.killer = nullptr;
  f.drain();
  CHECK(f.b().delivered == Concat(src, more));
  CHECK_EQ(f.sa().peer_window(), f.cfg().rcv_buf_bytes);
  CHECK_EQ(f.sa().in_flight(), 0u);
}

// F-3: a peer that keeps its window shut but keeps ACKing the probes pulls one
// full segment per probe_ms forever unless the probe interval backs off. The
// RTO path does not cover this: each ACK pops the probe, so nothing is ever
// outstanding long enough to time out.
void TestZeroWindowProbeBacksOff() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(100, 40);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  uint32_t cum = static_cast<uint32_t>(src.size());
  f.feed(kA, MakeAck(cum, 0, cum, cum));  // window shut, everything acked
  CHECK_EQ(f.sa().peer_window(), 0u);

  // B is cut off: it must not ack anything on its own, so the only ACK A sees
  // is the one this test feeds — the "peer answers each probe then closes the
  // window again" pattern, with no RTO in between.
  f.cut_all();

  const std::vector<uint8_t> more = MakeBytes(400, 90);
  CHECK_EQ(f.sa().write(more.data(), more.size()), more.size());

  // Each probe covers one payload slice; acking it puts the stream back to
  // "nothing outstanding, window shut", so the probe path never leans on RTO.
  const int64_t unit = f.cfg().probe_ms;
  uint64_t seen = f.sa().probes_sent();
  int64_t last_at = -1;
  std::vector<int64_t> gaps;
  for (int round = 0; round < 48; ++round) {
    f.tick(unit / 4);  // finer than probe_ms: record when a probe actually fires
    if (f.sa().probes_sent() == seen) {
      continue;
    }
    seen = f.sa().probes_sent();
    if (last_at >= 0) {
      gaps.push_back(f.now() - last_at);
    }
    last_at = f.now();
    cum = static_cast<uint32_t>(src.size() + seen * f.payload());
    f.feed(kA, MakeAck(cum, 0, cum, cum));
  }
  // 12 probe_ms of ticking. Without backoff every gap is one probe_ms; with the
  // persist ladder the gaps are 1x, 2x, 4x, 8x, then capped at 16x.
  CHECK(!gaps.empty());
  CHECK(gaps[0] <= 2 * unit);  // first wait after the immediate probe
  CHECK(gaps.back() >= 4 * unit);
  for (size_t i = 1; i < gaps.size(); ++i) {
    CHECK(gaps[i] >= gaps[i - 1]);
  }
  CHECK(seen <= 8u);  // ~10 units of linear probing would be 10
  // The counter tracks the probes themselves, not their RTO retransmissions.
  CHECK(f.sa().segs_sent() >= f.sa().probes_sent());

  // Reopening the window resets the ladder, so a later stall probes at 1x
  // instead of inheriting a 16x deadline.
  const uint32_t sent_end = cum;  // highest offset on the wire
  f.feed(kA, MakeAck(sent_end, f.cfg().rcv_buf_bytes, sent_end, sent_end));
  CHECK(f.sa().peer_window() > 0u);
  f.tick(25);  // pump hands the rest over now that the window is open
  const uint32_t drained = static_cast<uint32_t>(src.size() + more.size());
  f.feed(kA, MakeAck(drained, 0, drained, drained));  // shut again, all acked
  CHECK_EQ(f.sa().in_flight(), 0u);
  CHECK_EQ(f.sa().peer_window(), 0u);

  f.tick(2 * unit);  // nothing to send: the ladder resets here
  // Write more with the window shut, then tick less than the old 16x deadline.
  const std::vector<uint8_t> tail = MakeBytes(200, 33);
  CHECK_EQ(f.sa().write(tail.data(), tail.size()), tail.size());
  const uint64_t before = f.sa().probes_sent();
  f.tick(unit / 2);
  CHECK(f.sa().probes_sent() > before);  // 1x, right away
}

// F-5: max_segment is the session's payload_max, so anything at or below the
// stream header is a contract violation. It used to make pump() carve zero-byte
// segments forever: the peer saw silence and nothing said why. It must close
// the stream with a reason instead.
void TestTooSmallMaxSegmentResets() {
  StreamConfig cfg = DefaultCfg();
  cfg.max_segment = fcp::kStreamDataHdrLen;  // exactly the header: no room left
  Fixture f(cfg);
  const std::vector<uint8_t> src = MakeBytes(10, 1);
  CHECK_EQ(f.sa().write(src.data(), src.size()), src.size());
  f.tick(25);
  CHECK_EQ(f.a().closes.size(), 1u);
  CHECK(f.a().closes[0] == CloseReason::kReset);
  CHECK_EQ(f.data_of(kA).size(), 0u);  // nothing ever reached the wire
  CHECK_EQ(f.sa().can_write(), false);
}

// A reader that has stopped taking bytes must bound the writer's memory.
// pump() turns the pending queue into segments whether or not the peer's window
// has released them, so the room a writer is offered has to be measured against
// every byte still unacknowledged: counting only what reached the wire leaves the
// unsent segments invisible and the queue growing for as long as the host writes.
void TestStalledReaderBoundsTheSendQueue() {
  Fixture f;
  const size_t window = f.cfg().send_window_bytes;
  const std::vector<uint8_t> src = MakeBytes(8 * window, 7);
  Applier w(f.sa(), src);
  size_t worst_backlog = 0;
  for (int round = 0; round < 400; ++round) {
    w.push();
    f.tick(25);
    // B's host has taken nothing, so everything it has received is still its
    // stream's delivery debt. That is what closes the advertised window.
    f.sb().set_delivery_pending(f.b().delivered.size());
    const size_t backlog = w.off - f.b().delivered.size();
    if (backlog > worst_backlog) {
      worst_backlog = backlog;
    }
  }
  CHECK(w.off > 0u);
  CHECK(worst_backlog <= window);
  // The stall is still in force: not even half the stream got through.
  CHECK(w.off < src.size());
  CHECK(f.b().delivered.size() < src.size());

  // Unstick it: the rest goes out and the whole stream arrives, in order.
  f.sb().set_delivery_pending(0);
  const std::vector<uint8_t> tail(src.begin() + static_cast<std::ptrdiff_t>(w.off), src.end());
  CHECK_EQ(f.push(kA, tail), tail.size());
  f.drain();
  CHECK(f.b().delivered == src);
}

// The ack that closes a repaired hole also pops clean segments: the round is
// ambiguous, so no RTT sample may be taken from it.
void TestKarnDropsAmbiguousSamples() {
  Fixture f;
  int copies = 0;
  f.killer = [&copies](const Packet& p) {
    if (p.from != kA || !IsData(p.seg) || rd32(p.seg.data() + 1) != 0) {
      return false;
    }
    return ++copies == 1;
  };
  const std::vector<uint8_t> src = MakeBytes(500, 61);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();

  CHECK(f.b().delivered == src);
  CHECK_EQ(copies, 2);  // original + SACK repair (the dup burst is throttled)
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK(f.a().rtts.empty());  // Karn: every copy of seg 0 was a retransmission
  CHECK_EQ(f.sa().srtt_ms(), f.cfg().initial_srtt_ms);
  CHECK_EQ(f.sa().bytes_acked(), src.size());
}

// A peer that receives but never acks: no cum, no SACK, so only the RTO works.
void TestRtoFiresWhenPeerStopsAcking() {
  Fixture f;
  f.killer = [](const Packet& p) {
    if (p.from == kB) {
      return true;
    }
    return IsData(p.seg) && rd32(p.seg.data() + 1) == 0;
  };
  const std::vector<uint8_t> src = MakeBytes(300, 77);
  CHECK_EQ(f.push(kA, src), src.size());
  const size_t before = f.data_of(kA).size();
  CHECK_EQ(before, 3u);

  for (int round = 0; round < 40; ++round) {
    f.tick(50);  // 2s: several RTOs
  }
  CHECK(f.sa().retransmits() >= 1u);
  CHECK(f.data_of(kA).size() > before);
  CHECK(f.b().delivered.empty());
  CHECK_EQ(f.sa().srtt_ms(), f.cfg().initial_srtt_ms);

  // The peer comes back and the stream finishes.
  f.killer = nullptr;
  f.drain();
  CHECK(f.b().delivered == src);
  CHECK(!f.sa().closed());
}

// A SACK cannot be retracted: the receiver's out-of-order tail can be dropped
// under buffer pressure (or a forged block can arrive), and the sender has no
// way to learn that the range is gone. If the mark were permanent the hole would
// never be filled again -- the RTO pass and fill_holes both skip sacked
// segments -- and the stream would freeze with no way out. The mark therefore
// expires, after which the normal repair paths pick the bytes back up.
void TestStaleSackExpiresAndRecovers() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(400, 42);  // 4 segments
  CHECK_EQ(f.push(kA, src), src.size());
  CHECK_EQ(f.data_of(kA).size(), 4u);

  const auto copies_of = [&f](uint32_t offset) {
    size_t n = 0;
    for (const std::vector<uint8_t>& seg : f.data_of(kA)) {
      if (IsData(seg) && rd32(seg.data() + 1) == offset) {
        ++n;
      }
    }
    return n;
  };

  // The peer claims the whole tail past the first segment is buffered. That
  // fills segment 0 only; the rest must stay put while the mark is fresh.
  f.feed(kA, MakeAck(0, 4096, 100, 400));
  CHECK_EQ(copies_of(100), 1u);
  f.tick(500);  // longer than the RTO, still inside the trust window
  CHECK_EQ(copies_of(100), 1u);

  // Once the mark is stale, a timeout has to be able to repair the range.
  for (int i = 0; i < 60; ++i) {
    f.tick(100);
  }
  CHECK(copies_of(100) >= 2u);
  CHECK(copies_of(300) >= 2u);
}

void TestHalfCloseThenPeerClose() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(250, 3);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  f.sa().close(f.now());
  f.drain();

  // The fin is its own zero-length segment holding one pseudo sequence number.
  const std::vector<std::vector<uint8_t>> segs = f.data_of(kA);
  CHECK_EQ(segs.back().size(), fcp::kStreamDataHdrLen);
  CHECK_EQ(segs.back()[5], static_cast<uint8_t>(fcp::kStreamFlagFin));
  CHECK_EQ(rd32(segs.back().data() + 1), src.size());
  CHECK_EQ(rd32(f.last_ack(kB).data() + 1), src.size() + 1);

  CHECK_EQ(f.b().eof_count, 1);
  CHECK_EQ(f.b().delivered.size(), src.size());
  CHECK_EQ(f.sb().state(), StreamState::kPeerClosed);
  CHECK_EQ(f.a().eof_count, 0);
  CHECK(f.a().closes.empty());
  CHECK(!f.sa().closed());
  CHECK(!f.sa().can_write());
  CHECK_EQ(f.sa().write(src.data(), 10), 0u);

  // A server may still answer after our EOF.
  const std::vector<uint8_t> reply = MakeBytes(100, 8);
  CHECK_EQ(f.sb().write(reply.data(), reply.size()), reply.size());
  f.drain();
  CHECK(f.a().delivered == reply);
  CHECK(!f.sb().closed());

  f.sb().close(f.now());
  f.drain();
  CHECK(f.sa().closed());
  CHECK(f.sb().closed());
  CHECK_EQ(f.sa().reason(), CloseReason::kPeerClose);
  CHECK_EQ(f.sb().reason(), CloseReason::kLocalEof);
  CHECK_EQ(f.a().closes.size(), 1u);
  CHECK_EQ(f.b().closes.size(), 1u);
}

void TestCloseWithNothingQueued() {
  Fixture f;
  f.sa().close(f.now());
  f.drain();
  CHECK_EQ(f.data_of(kA).size(), 1u);
  CHECK(f.b().delivered.empty());
  CHECK_EQ(f.b().eof_count, 1);
  CHECK_EQ(f.sb().state(), StreamState::kPeerClosed);
  CHECK(!f.sa().closed());  // waiting for the peer's own fin
  CHECK_EQ(rd32(f.last_ack(kB).data() + 1), 1);

  f.sb().close(f.now());
  f.drain();
  CHECK(f.sa().closed());
  CHECK_EQ(f.sa().reason(), CloseReason::kPeerClose);
  CHECK(f.sb().closed());
  CHECK_EQ(f.sb().reason(), CloseReason::kLocalEof);
}

void TestRstAborts() {
  Fixture f;
  f.sa().abort(f.now());
  f.flush();
  CHECK(f.sa().closed());
  CHECK_EQ(f.sa().reason(), CloseReason::kReset);
  CHECK(f.sb().closed());
  CHECK_EQ(f.sb().reason(), CloseReason::kReset);
  CHECK_EQ(f.a().closes.size(), 1u);
  CHECK_EQ(f.b().closes.size(), 1u);
  CHECK_EQ(f.b().eof_count, 0);
  CHECK(!f.sa().can_write());
  const std::vector<uint8_t> junk = MakeData(0, MakeBytes(10, 1), false);
  f.feed(kB, junk);
  f.feed(kA, junk);
  CHECK(f.b().delivered.empty());
  CHECK_EQ(f.sb().oob_bytes(), 0u);
}

void TestIdleTimeout() {
  Fixture f;
  f.tick(1);
  CHECK(!f.sa().closed());
  for (int round = 0; round < 400; ++round) {
    f.tick(1000);  // 400s of silence, neither direction
  }
  CHECK(f.sa().closed());
  CHECK_EQ(f.sa().reason(), CloseReason::kIdle);
  CHECK(f.sb().closed());
  CHECK_EQ(f.sb().reason(), CloseReason::kIdle);
  CHECK_EQ(f.a().closes.size(), 1u);

  // Traffic resets the clock.
  Fixture g;
  g.tick(1);
  for (int round = 0; round < 200; ++round) {
    g.tick(1000);
    if (round % 100 == 0) {
      const std::vector<uint8_t> keepalive = MakeBytes(1, 1);
      g.push(kA, keepalive);
      g.drain(500);
    }
  }
  CHECK(!g.sa().closed());
  CHECK(!g.sb().closed());
}

void TestMalformedSegments() {
  Fixture f;
  const std::vector<uint8_t> short_data = {fcp::kStreamTypeData, 1, 2};
  const std::vector<uint8_t> short_ack = {fcp::kStreamTypeAck, 1, 2};
  const std::vector<uint8_t> unknown_type = {9, 0, 0, 0, 0, 0};
  const std::vector<uint8_t> empty;
  f.feed(kB, short_data);
  f.feed(kB, short_ack);
  f.feed(kB, unknown_type);
  f.feed(kB, empty);
  CHECK_EQ(f.sb().bad_segs(), 3u);
  CHECK(!f.sb().closed());
  CHECK_EQ(f.sb().oob_bytes(), 0u);

  // Beyond the advertised window: dropped, and the sender recovers by timeout.
  const size_t cap = f.payload();
  const uint32_t far = static_cast<uint32_t>(f.cfg().rcv_buf_bytes) + 1;
  f.feed(kB, MakeData(far, MakeBytes(cap, 4), false));
  CHECK_EQ(f.sb().oob_bytes(), 0u);

  // Still usable afterwards.
  const std::vector<uint8_t> src = MakeBytes(120, 17);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
}

// Random loss over a long transfer: the bytes handed to the app must be exactly
// what was written, in order, with nothing repeated or lost.
void TestRandomLossEndToEnd() {
  for (uint32_t seed = 1; seed <= 6; ++seed) {
    std::mt19937 rng(seed);
    Fixture f;
    f.killer = [&rng](const Packet& p) {
      if (!IsData(p.seg)) {
        return false;  // control segments are never lost
      }
      std::uniform_int_distribution<int> d(0, 99);
      return d(rng) < 12;
    };
    const std::vector<uint8_t> src = MakeBytes(6000, static_cast<uint8_t>(seed));
    CHECK_EQ(f.push(kA, src), src.size());
    f.drain();
    CHECK(f.b().delivered == src);
    CHECK_EQ(f.sb().bad_segs(), 0u);
    CHECK_EQ(f.sa().queued_bytes(), 0u);
    CHECK_EQ(f.sa().in_flight(), 0u);
    CHECK_EQ(f.sa().unacked_segs(), 0u);
    CHECK(f.sa().retransmits() >= 1u);
  }
}

}  // namespace

// --- #27 fast retransmit / multi-hole SACK (M3控制设计.md §4) ---

// The single SACK block rotates on duplicate ACKs: three disjoint holes are
// all reported within three ACKs, and the sender repairs all of them without
// a single tick (no RTO could have fired).
void TestSackRotationReportsAllHoles() {
  Fixture f;
  f.cut_all();  // everything moves by hand; time stands still
  const std::vector<uint8_t> src = MakeBytes(600, 11);  // 6 segments
  CHECK_EQ(f.push(kA, src), src.size());
  const int64_t t_pushed = f.now();  // push() ticks; remember where time froze
  const auto segs = f.data_of(kA);
  CHECK_EQ(segs.size(), 6u);
  const size_t cap = f.payload();

  // Holes at offsets 0, 2*cap, 4*cap; survivors buffered out of order.
  f.feed(kB, segs[1]);
  f.feed(kB, segs[3]);
  f.feed(kB, segs[5]);
  const auto acks = f.acks_of(kB);
  CHECK_EQ(acks.size(), 3u);
  // Three distinct SACK blocks in three duplicate ACKs — the pre-#27 sender
  // only ever saw the front block [cap, 2*cap) until cum moved.
  CHECK_EQ(rd32(acks[0].data() + 9), 1u * cap);
  CHECK_EQ(rd32(acks[0].data() + 13), 2u * cap);
  CHECK_EQ(rd32(acks[1].data() + 9), 3u * cap);
  CHECK_EQ(rd32(acks[1].data() + 13), 4u * cap);
  CHECK_EQ(rd32(acks[2].data() + 9), 5u * cap);
  CHECK_EQ(rd32(acks[2].data() + 13), 6u * cap);

  // The sender repairs every hole from the far blocks alone: fill_holes
  // retransmits everything below each reported block, so blocks 2 and 3 cover
  // the holes the front block could not mention.
  for (const auto& ack : acks) {
    f.feed(kA, ack);
  }
  CHECK_EQ(f.sa().retransmits(), 3u);
  CHECK_EQ(f.data_with_offset(kA, 0), 2u);
  CHECK_EQ(f.data_with_offset(kA, 2u * static_cast<uint32_t>(cap)), 2u);
  CHECK_EQ(f.data_with_offset(kA, 4u * static_cast<uint32_t>(cap)), 2u);
  // Time never moved: this whole repair happened without any timeout.
  CHECK_EQ(f.now(), t_pushed);
}

// The dup-ACK path: the first SACK sighting repairs the hole via fill_holes.
// A forced copy of the first unacked segment happens only when that repair has
// had a full RTT to land: one repair per RTT, not one per three ACKs. No RTO
// is involved in any of these steps.
void TestDupAckForceRefill() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(400, 11);  // 4 segments
  CHECK_EQ(f.push(kA, src), src.size());
  const int64_t t_pushed = f.now();
  const auto segs = f.data_of(kA);

  for (int i = 1; i <= 3; ++i) {
    f.feed(kB, segs[i]);
  }
  const auto acks = f.acks_of(kB);
  CHECK_EQ(acks.size(), 3u);
  f.feed(kB, segs[1]);  // a pure duplicate: one more ACK at the same cum
  const auto acks2 = f.acks_of(kB);
  CHECK_EQ(acks2.size(), 4u);
  for (const auto& ack : acks2) {
    f.feed(kA, ack);
  }
  // ACK 1 repairs the hole via fill_holes. ACKs 2..4 are the dup burst; it
  // would force a copy, but the repair is still inside its RTT and a second
  // copy would only compete with the first one for the same loss.
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK_EQ(f.data_with_offset(kA, 0), 2u);  // original + fill
  CHECK_EQ(f.now(), t_pushed);              // no timeout was involved

  // After a full RTT with cum still stuck, the next burst is real loss
  // evidence and fires exactly one forced copy.
  f.tick(f.sa().srtt_ms() + 50);
  for (const auto& ack : acks2) {
    f.feed(kA, ack);
  }
  CHECK_EQ(f.sa().retransmits(), 2u);
  // A third burst inside the same RTT is suppressed again.
  for (const auto& ack : acks2) {
    f.feed(kA, ack);
  }
  CHECK_EQ(f.sa().retransmits(), 2u);
}

// P1-3 adaptive reordering tolerance (quic-go-style undo evidence): a dup-burst
// that is confirmed by a cumulative advance sooner than one RTT cannot have
// been answered by its own repair copy, so it retransmitted a byte the peer
// already held. Each observation widens the burst gates for the rest of the
// stream: the packet threshold doubles 3 -> 6 -> 12 and a first-burst age gate
// grows from rtt/8 towards one full RTT. Until the first spurious observation
// the thresholds behave exactly as before (TestDupAckForceRefill covers that).
void TestSpuriousBurstWidensTolerance() {
  Fixture f;
  f.cut_all();  // everything moves by hand; time stands still
  const std::vector<uint8_t> src = MakeBytes(600, 21);  // 6 segments
  CHECK_EQ(f.push(kA, src), src.size());
  const int64_t t0 = f.now();
  CHECK_EQ(f.sa().spur_bursts(), 0u);
  const uint64_t fast0 = f.sa().retx_fast();

  // Reordering: everything except the head reaches the peer (its copies are
  // what later ACK cums will be stuck behind), and the head itself will show
  // up out of order when the advance below feeds cum past it.
  const auto advance = [&f](uint32_t cum) {
    f.feed(kA, MakeAck(cum, 4096, 0, 0));
  };
  // A same-cum repeat: `count` of them drive the dup counter. Must be fed at
  // the cum the sender is standing on, so the repeat branch counts.
  const auto burst = [&f](uint32_t cum, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
      f.feed(kA, MakeAck(cum, 4096, 0, 0));
    }
  };

  // Enough clock below the RTO (400 ms) and above the grace that will be set
  // (rtt/8 = 25 ms): the burst path only, nothing else may fire.
  f.tick(220);  // now = t0 + 220; head age clears both later gates
  burst(0, 4);  // the first feed registers the cum, three repeats fire (thresh 3)
  CHECK_EQ(f.sa().retx_fast(), fast0 + 1);

  // The reorder resolves: the head's original copy arrives after the ACK
  // stream the burst retransmitted for — an advance within one RTT of the
  // burst, exactly the quic-go undo observation (none in this process can
  // carry the repair copy that fast).
  advance(100);
  CHECK_EQ(f.sa().spur_bursts(), 1u);

  // Losing the burst-triggered copy entirely is the probe that widens; the
  // stream may still burst again above the same stuck point, now at a doubled
  // packet threshold. Five duplicates no longer fire.
  burst(100, 5);
  CHECK_EQ(f.sa().retx_fast(), fast0 + 1);
  burst(100, 1);  // the sixth repeat must fire over the doubled threshold
  CHECK_EQ(f.sa().retx_fast(), fast0 + 2);

  // Second spurious observation: threshold to 12, gate to rtt/4.
  advance(200);
  CHECK_EQ(f.sa().spur_bursts(), 2u);
  for (uint32_t i = 0; i < 11; ++i) {
    f.feed(kA, MakeAck(200, 4096, 0, 0));
  }
  CHECK_EQ(f.sa().retx_fast(), fast0 + 2);  // 11 duplicates under the ceiling
  f.feed(kA, MakeAck(200, 4096, 0, 0));
  CHECK_EQ(f.sa().retx_fast(), fast0 + 3);

  // The logged state must not have drifted: nothing above ran a timer path.
  // (Time never advanced past the single tick; every step was a hand feed.)
  CHECK_EQ(f.now(), t0 + 220);
}

// Tail loss probe: the newest segment on the wire is lost and no later data
// exists, so there is neither a duplicate ACK nor a SACK block to reveal it.
// The old path could only wait for the RTO; the probe resends the tail after
// about one RTT, and the ACK it provokes completes the transfer without a
// timeout episode (no backoff, no BBR loss signal).
void TestTailLossProbeRepairsLostTail() {
  Fixture f;
  const size_t cap = f.payload();
  const uint32_t tail_off = 4u * static_cast<uint32_t>(cap);
  int copies = 0;
  f.killer = [&copies, tail_off](const Packet& p) {
    if (p.from != kA || !IsData(p.seg) || rd32(p.seg.data() + 1) != tail_off) {
      return false;
    }
    return ++copies == 1;  // lose the original tail, let the probe through
  };
  const std::vector<uint8_t> src = MakeBytes(5 * cap, 91);
  CHECK_EQ(f.push(kA, src), src.size());
  CHECK_EQ(copies, 1);
  CHECK_EQ(f.sa().retx_fill(), 0u);  // the tail is above every SACK block
  CHECK_EQ(f.sa().retx_tlp(), 0u);
  CHECK_EQ(f.sa().rto_loss_events(), 0u);
  const int64_t t0 = f.now();

  // Shorter than the probe interval: nothing may go out. The previous ACKs
  // already moved cum to the tail, so this is not a progress question.
  f.tick(10);
  CHECK_EQ(f.sa().retx_tlp(), 0u);

  // The probe has to fire within one RTO and repair the tail; if it needed the
  // timeout this loop would see rto_loss_events first.
  for (int i = 0; i < 100 && f.sa().retx_tlp() == 0; ++i) {
    f.tick(10);
  }
  CHECK_EQ(f.sa().retx_tlp(), 1u);
  CHECK_EQ(f.sa().rto_loss_events(), 0u);
  CHECK_EQ(f.sa().retx_rto(), 0u);
  CHECK(f.now() - t0 < f.sa().rto_ms());
  CHECK_EQ(f.data_with_offset(kA, tail_off), 2u);
  CHECK_EQ(copies, 2);

  f.drain();
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sa().retx_tlp(), 1u);  // one probe per stall, no storm
}

// A fill that is itself lost must not wait for the RTO. The watermark used to
// make the range "owned" and the peer keeps reporting the same block above it,
// so the hole sat there for 2 RTTs plus backoff. One retry per RTT, driven by
// that same SACK evidence, is enough.
void TestLostSackFillRetriedAfterOneRtt() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(4 * f.payload(), 12);
  const size_t cap = f.payload();
  CHECK_EQ(f.push(kA, src), src.size());
  const std::vector<uint8_t> ack =
      MakeAck(0, f.cfg().rcv_buf_bytes, static_cast<uint32_t>(cap),
              2u * static_cast<uint32_t>(cap));
  f.feed(kA, ack);  // hole at offset 0, the peer holds everything above it
  CHECK_EQ(f.sa().retx_fill(), 1u);
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK_EQ(f.sa().fill_passes(), 1u);

  // The same block inside one RTT: the first repair is still in flight.
  f.tick(50);
  f.feed(kA, ack);
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK_EQ(f.sa().retx_fill(), 1u);

  // A round trip later the cumulative point is still below the block, so the
  // repair is retried -- without any timeout.
  f.tick(200);
  f.feed(kA, ack);
  CHECK_EQ(f.sa().retx_fill(), 2u);
  CHECK_EQ(f.sa().retransmits(), 2u);
  CHECK_EQ(f.sa().fill_passes(), 1u);  // no new range was revealed
  CHECK_EQ(f.sa().rto_loss_events(), 0u);
  CHECK_EQ(f.sa().retx_rto(), 0u);
}

// A burst hole is one recovery event. With BBR pacing the whole revealed range
// goes out in a single pass; the old 32-segment budget needed another ACK (and
// on a stalled receiver, another ACK interval) before the hole was complete.
void TestSackFillsWholeHoleInOnePass() {
  StreamConfig c;
  c.max_segment = 106;  // 100-byte payload per segment
  c.send_window_bytes = 128 * 1024;
  c.rcv_buf_bytes = 128 * 1024;
  c.auto_window = true;
  c.window_min_bytes = 8 * 1024;
  c.window_max_bytes = 256 * 1024;
  c.initial_srtt_ms = 200;
  c.rto_min_ms = 100;
  c.rto_max_ms = 5000;
  c.idle_timeout_ms = 300000;
  Fixture f(c);
  f.cut_all();
  const size_t cap = f.payload();
  const size_t count = 60;
  const std::vector<uint8_t> src = MakeBytes(count * cap, 33);
  CHECK_EQ(f.push(kA, src), src.size());
  // push() only guarantees the bytes were accepted; the pacer releases them a
  // bucket at a time.
  for (int i = 0; i < 10 && f.data_of(kA).size() < count; ++i) {
    f.tick(25);
  }
  CHECK_EQ(f.data_of(kA).size(), count);

  // Let the token bucket bank one burst's worth (it is capped at 6 ms of the
  // pacing rate, ~11 KB here) without reaching any timer.
  f.tick(50);
  const std::vector<std::vector<uint8_t>> segs = f.data_of(kA);
  f.feed(kB, segs.back());  // the peer holds only the last segment
  const std::vector<uint8_t> ack = f.last_ack(kB);
  CHECK_EQ(rd32(ack.data() + 1), 0u);  // cum: everything below is a hole
  CHECK_EQ(rd32(ack.data() + 9), static_cast<uint32_t>((count - 1) * cap));
  f.feed(kA, ack);

  // 59 missing segments, above the old 32-segment cap, all in this one pass.
  CHECK_EQ(f.sa().retx_fill(), static_cast<uint64_t>(count - 1));
  CHECK_EQ(f.sa().fill_passes(), 1u);
  CHECK_EQ(f.data_with_offset(kA, 0), 2u);
  CHECK_EQ(f.data_with_offset(kA, static_cast<uint32_t>((count / 2) * cap)), 2u);
  CHECK_EQ(f.data_with_offset(kA, static_cast<uint32_t>((count - 2) * cap)), 2u);
  CHECK_EQ(f.data_with_offset(kA, static_cast<uint32_t>((count - 1) * cap)), 1u);
  CHECK_EQ(f.sa().rto_loss_events(), 0u);
}

// In-order ACKs never arm the fast-retransmit path.
void TestNoSpuriousFastRetransmit() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(400, 11);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sa().retransmits(), 0u);
  CHECK_EQ(f.sa().dup_acks(), 0u);
}


// #30 adversarial hardening: an ACK past everything we ever sent is a lie —
// accepting it would pop all unacked segments and strand the data for good.
void TestAckBeyondSndNxtIgnored() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(400, 11);  // 4 segments
  CHECK_EQ(f.push(kA, src), src.size());
  const size_t unacked_before = f.sa().unacked_segs();

  const std::vector<uint8_t> lie = MakeAck(1u << 20, 4096, 0, 0);
  f.feed(kA, lie);
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.sa().unacked_segs(), unacked_before);
  CHECK_EQ(f.sa().bytes_acked(), 0u);
  CHECK_EQ(f.sa().retransmits(), 0u);

  // A cum exactly at snd_nxt is the legitimate fin-ack boundary and must
  // still work: ack the first two segments for real.
  f.feed(kA, MakeAck(2 * f.payload(), 4096, 0, 0));
  CHECK_EQ(f.sa().unacked_segs(), unacked_before - 2);
  CHECK_EQ(f.sa().bad_segs(), 1u);
}

// The SACK block gets the same treatment as cum: a range above snd_nxt_ or an
// inverted range is a lie. Accepting one used to advance sack_filled_up_to_
// past every real hole and to mark unacked segments SACKed, which turns off
// the only repair path that beats the RTO.
void TestInvalidSackBlockIgnored() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(400, 11);  // 4 segments
  CHECK_EQ(f.push(kA, src), src.size());
  CHECK_EQ(f.data_of(kA).size(), 4u);
  const size_t cap = f.payload();

  // A block far past anything we sent. With a lying block accepted, fill_holes
  // would retransmit the whole queue and jump the fill gate beyond every hole.
  const uint32_t far = 1u << 20;
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, far, far + static_cast<uint32_t>(cap)));
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.sa().retransmits(), 0u);

  // Inverted range: malformed outright.
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, 2u * static_cast<uint32_t>(cap),
                     static_cast<uint32_t>(cap)));
  CHECK_EQ(f.sa().bad_segs(), 2u);
  CHECK_EQ(f.sa().retransmits(), 0u);

  // The forged blocks did not poison the gate: a real block still repairs the
  // hole at offset 0 without waiting for the RTO.
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, static_cast<uint32_t>(cap),
                     2u * static_cast<uint32_t>(cap)));
  CHECK(f.sa().retransmits() >= 1u);
  CHECK(f.data_with_offset(kA, 0) >= 2u);
  CHECK_EQ(f.sa().bad_segs(), 2u);
}

// 第四轮 F-6/O-1: the deep-reorder merge path must keep the oob accounting
// within the receive cap no matter how adversarial the arrival order is.
// Strictly descending order drives every insert through the merge branch
// (each segment lands behind the buffer tail, never the fast path); the
// duplicate right after exercises the tail-overlap fast path. Both must hold
// the bound after every single chunk, and the hole-filling last segment must
// deliver the whole stream.
void TestDeepReorderStaysUnderCap() {
  Fixture f;
  f.cut_all();
  const size_t cap = f.cfg().rcv_buf_bytes;      // 2048
  const size_t seg_payload = f.payload();        // 100
  const size_t n = cap / seg_payload;            // 20: fills the cap exactly
  const std::vector<uint8_t> src = MakeBytes(n * seg_payload, 21);
  CHECK_EQ(f.push(kA, src), src.size());  // 2000B fits the 4096B send window
  const std::vector<std::vector<uint8_t>> segs = f.data_of(kA);
  CHECK_EQ(segs.size(), n);

  for (size_t i = segs.size(); i-- > 0;) {
    f.feed(kB, segs[i]);
    CHECK(f.sb().oob_bytes() <= cap);
    f.feed(kB, segs[i]);  // duplicate: trim, never grow past the cap
    CHECK(f.sb().oob_bytes() <= cap);
  }
  // The final (offset 0) segment completes the prefix: everything delivers.
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sb().oob_bytes(), 0u);
}

// A segment that lands on two buffered runs at once has to join them into one:
// the receiver keeps its runs sorted and disjoint, and a detour through an
// intermediate iterator invalidated by the erase used to corrupt that invariant.
void TestOverlappingSegmentJoinsBothNeighbours() {
  Fixture f;
  f.cut_all();

  f.feed(kB, MakeData(200, MakeBytes(100, 1), false));  // [200, 300)
  f.feed(kB, MakeData(400, MakeBytes(100, 2), false));  // [400, 500)
  CHECK_EQ(f.sb().oob_chunks(), 2u);

  // [150, 480) starts before the first run and ends inside the second: both
  // are absorbed, and the pieces must be in byte order.
  std::vector<uint8_t> bridge = MakeBytes(100, 1);  // [200, 300) content
  bridge = Concat(MakeBytes(50, 9), bridge);        // [150, 200) new
  bridge = Concat(bridge, MakeBytes(80, 3));        // [300, 380) new
  bridge = Concat(bridge, MakeBytes(20, 2));        // [380, 400) redundant? no: [380,400) new
  CHECK_EQ(bridge.size(), 250u);
  f.feed(kB, MakeData(150, bridge, false));
  CHECK_EQ(f.sb().oob_chunks(), 1u);
  CHECK_EQ(f.sb().oob_bytes(), 350u);  // [150, 500)

  // Also the left-only case: a segment that starts inside the run below it.
  f.feed(kB, MakeData(100, MakeBytes(100, 7), false));  // [100, 200) overlaps
  CHECK_EQ(f.sb().oob_chunks(), 1u);
  CHECK_EQ(f.sb().oob_bytes(), 400u);  // [100, 500)

  // Filling the hole at 0 delivers every byte in order. The later segment's
  // copy wins for the [150, 200) overlap, so the seed-9 run is gone.
  std::vector<uint8_t> src = MakeBytes(100, 7);
  src = Concat(src, MakeBytes(100, 1));
  src = Concat(src, MakeBytes(80, 3));
  src = Concat(src, MakeBytes(20, 2));
  src = Concat(src, MakeBytes(100, 2));
  CHECK_EQ(src.size(), 400u);
  f.feed(kB, MakeData(0, MakeBytes(100, 0), false));
  CHECK_EQ(f.sb().oob_bytes(), 0u);
  CHECK(f.b().delivered == Concat(MakeBytes(100, 0), src));
}

// A peer that fills the receive buffer with one-byte chunks must not be able to
// turn the out-of-order deque into an unbounded allocation: the byte cap alone
// does not bound the number of entries, so there is a chunk ceiling too.
void TestOobChunkCeilingBoundsTinySegments() {
  StreamConfig cfg = DefaultCfg();
  cfg.rcv_buf_bytes = 32768;  // chunk ceiling still floors at kMinOobChunks
  Fixture f(cfg);
  f.cut_all();

  constexpr size_t kFeeds = 2000;
  for (size_t i = 0; i < kFeeds; ++i) {
    // Every other byte: each arrival is its own run, one byte long.
    f.feed(kB, MakeData(static_cast<uint32_t>(2 * i + 2), MakeBytes(1, static_cast<uint8_t>(i)),
                        false));
  }
  CHECK_EQ(f.sb().oob_chunks(), fcp::kMinOobChunks);
  CHECK_EQ(f.sb().oob_bytes(), fcp::kMinOobChunks);
  CHECK_EQ(f.sb().oob_drops(), kFeeds - fcp::kMinOobChunks);
}

// M2 §2.3: the close completes when OUR fin is acknowledged (cum >= fin_seq+1)
// and the peer's fin has been delivered. Receiving the peer's fin while our
// own fin is still unacked must not drop the retransmission queue: doing so
// truncates data that never left or was lost, and the peer never sees a fin.
void TestPeerFinDoesNotDropUnackedData() {
  Fixture f;
  f.cut_all();  // ACKs never reach A by themselves
  const std::vector<uint8_t> src = MakeBytes(400, 11);  // 4 segments
  CHECK_EQ(f.push(kA, src), src.size());
  f.sa().close(f.now());  // fin queued behind the data, nothing acked yet

  // B gets A's data and fin, and acks both -- but those ACKs are "lost".
  for (const std::vector<uint8_t>& seg : f.data_of(kA)) {
    f.feed(kB, seg);
  }
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.b().eof_count, 1);

  // B answers with its own fin. A has not seen one ACK for its data or fin.
  f.sb().close(f.now());
  const std::vector<std::vector<uint8_t>> from_b = f.data_of(kB);
  CHECK_EQ(from_b.size(), 1u);
  f.feed(kA, from_b.back());
  CHECK_EQ(f.a().eof_count, 1);   // read side is done
  CHECK(!f.sa().closed());        // write side is not
  CHECK(f.sa().unacked_segs() > 0u);

  // The lost ACKs arrive; only now may A finish, and it names the acked fin.
  for (const std::vector<uint8_t>& ack : f.acks_of(kB)) {
    f.feed(kA, ack);
  }
  CHECK(f.sa().closed());
  CHECK_EQ(f.sa().reason(), CloseReason::kLocalEof);
  CHECK_EQ(f.a().closes.size(), 1u);
}

// A4: the lie guard must compare against the highest byte that reached the
// wire, not snd_nxt_ (segmentation runs ahead of the send window). Otherwise a
// cum covering segmented-but-unsent bytes pops them silently and the
// application's data is gone.
void TestAckBeyondSentIgnored() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(4096, 21);
  CHECK_EQ(f.sa().write(src.data(), src.size()), src.size());
  f.tick(25);  // segment everything; the peer window withholds the tail
  const size_t unacked = f.sa().unacked_segs();
  const size_t inflight = f.sa().in_flight();
  CHECK_EQ(unacked, 41u);  // 40 full + one 96-byte segment
  CHECK(inflight < src.size());

  // cum == snd_nxt_: inside the old bound, but past every byte ever sent.
  f.feed(kA, MakeAck(static_cast<uint32_t>(src.size()), 4096, 0, 0));
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.sa().unacked_segs(), unacked);
  CHECK_EQ(f.sa().in_flight(), inflight);
  CHECK_EQ(f.sa().bytes_acked(), 0u);

  // The queue is intact: with the path restored every byte still arrives.
  f.killer = nullptr;
  f.drain();
  CHECK(f.b().delivered == src);
}

// A4 follow-up: the SACK half of the same lie. A block may only describe bytes
// that reached the wire (<= snd_max_), not the segmentation cursor (snd_nxt_),
// or one forged ACK marks never-sent segments as SACKed and jumps the fill gate
// past every real hole -- the repair path then waits a full RTO forever.
void TestSackBeyondSentIgnored() {
  Fixture f;
  f.cut_all();
  const std::vector<uint8_t> src = MakeBytes(4096, 22);
  CHECK_EQ(f.sa().write(src.data(), src.size()), src.size());
  f.tick(25);  // segments everything; the peer window withholds the tail
  const uint32_t sent = static_cast<uint32_t>(f.sa().in_flight());
  CHECK(sent > 0u);
  CHECK(sent < static_cast<uint32_t>(src.size()));

  // The block lies above snd_max_ but below snd_nxt_: the old bound accepted it.
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, sent + 50, sent + 150));
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.sa().retransmits(), 0u);

  // The rejected block did not poison the fill gate: a real block below
  // snd_max_ still repairs the hole at offset 0 immediately.
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, 1, sent));
  CHECK(f.sa().retransmits() >= 1u);
}

// A24 (对抗分析第 3 轮)：snd_max_ 的普通 std::max 前移在字节偏移越过 2^32
// 回绕后把它钉死在 0xFFFFFFFF 上 —— 此后对面送来的每一份诚实 cum（已回绕成
// 小值）都满足 seq_after(cum, snd_max_)，被 A4 门槛错杀；tx_ 永远弹不出、
// 每 25ms 的 RTO 重灌整窗，而对面 ACK 还在刷新 idle 时钟，永不超时。修复后：
// snd_max_ 按模半窗只向前移动，回绕后的 ACK 正常推进。
void TestSndMaxAdvancesAcrossWrap() {
  Fixture f;
  f.cut_all();  // ACK 是手工喂的，wire 上不路过

  // snd 空间几乎走满：下一段从 0xFFFFFFF0 起排，段尾跨过回绕。
  f.sa().test_set_send_offsets(0xFFFFFFF0u, 0xFFFFFFF0u, 0xFFFFFFF0u);
  const size_t chunk = 48;
  const std::vector<uint8_t> src = MakeBytes(chunk, 7);
  CHECK_EQ(f.sa().write(src.data(), src.size()), src.size());
  f.tick(25);  // 段已上 wire（对端窗口足够）
  CHECK_EQ(f.sa().unacked_segs(), 1u);

  // 诚实 cum = 已交付字节末端。流的字节编号只数 payload（6 字节段头不在
  // 序号空间里），所以 cum = 0xFFFFFFF0 + 48 = 回绕后的 0x20。旧实现把它
  // 错杀（bad_segs++）；修复后整段被弹走。
  const uint32_t cum = 0xFFFFFFF0u + chunk;  // 模 2^32 = 0x20
  f.feed(kA, MakeAck(cum, f.cfg().rcv_buf_bytes, 0, 0));
  CHECK_EQ(f.sa().bad_segs(), 0u);
  CHECK_EQ(f.sa().bytes_acked(), chunk);
  CHECK_EQ(f.sa().unacked_segs(), 0u);
  CHECK_EQ(f.sa().in_flight(), 0u);

  // 伪造的"future" cum 仍要被拒：回绕到小值侧后欺诈空间同样存在——
  // snd_max_ 现在是 0x30（48 个 payload 字节），假 cum越过段尾到 2^31 半窗内。
  f.sa().test_set_send_offsets(0u, 0u, 0u);
  CHECK_EQ(f.sa().write(src.data(), src.size()), src.size());
  f.tick(25);
  f.feed(kA, MakeAck(48u + 100u, f.cfg().rcv_buf_bytes, 0, 0));
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.sa().bytes_acked(), chunk);
}

// A24 续（同一替补修复）：fin 躺在最后一个序号上的收尾场景。fin 占据
// 0xFFFFFFFF 时它覆盖的 cum 会回绕成 0 —— 旧门槛把它一并错杀，发送侧永远
// 确认不了自己的 fin，对端也就等不到该侧的收尾。
void TestFinAckAcrossWrap() {
  Fixture f;
  f.cut_all();
  f.sa().test_set_send_offsets(0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu);
  f.sa().close(0);  // 无数据：fin 直接占据 0xFFFFFFFF，snd_nxt_ 回绕到 0
  CHECK_EQ(f.sa().state(), StreamState::kSendingFin);

  // 诚实 fin 覆盖 cum = fin_offset + 1 = 回绕后的 0。
  f.feed(kA, MakeAck(0, f.cfg().rcv_buf_bytes, 0, 0));
  CHECK_EQ(f.sa().bad_segs(), 0u);
  CHECK_EQ(f.sa().state(), StreamState::kSendingFin);  // 等对端 fin，别误关
}

// A22: the peer's fin offset is fixed once seen. A later fin at another offset
// must not move the end of the stream -- doing so keeps the EOF from ever being
// delivered and the fin from ever being cumulatively acked.
void TestFinOffsetRewriteRejected() {
  Fixture f;
  const std::vector<uint8_t> head = MakeBytes(10, 31);
  f.feed(kA, MakeData(0, head, true));  // fin at offset 10
  CHECK(f.a().delivered == head);
  CHECK_EQ(f.a().eof_count, 1);
  CHECK_EQ(f.sa().state(), StreamState::kPeerClosed);
  const auto acks = f.acks_of(kA);
  CHECK(!acks.empty());
  CHECK_EQ(rd32(acks.back().data() + 1), 11u);  // the pseudo byte is acked

  // A different fin offset is a protocol violation: dropped, never written.
  f.feed(kA, MakeData(20, {}, true));
  CHECK_EQ(f.sa().bad_segs(), 1u);
  CHECK_EQ(f.a().eof_count, 1);
  CHECK_EQ(rd32(f.acks_of(kA).back().data() + 1), 11u);

  // Data reaching past the known end is rejected the same way.
  f.feed(kA, MakeData(8, std::vector<uint8_t>(4, 0x33), false));
  CHECK_EQ(f.sa().bad_segs(), 2u);
  CHECK_EQ(f.a().delivered.size(), head.size());

  // Repeating the real fin is a duplicate, not a violation, and still acks.
  f.feed(kA, MakeData(10, {}, true));
  CHECK_EQ(f.sa().bad_segs(), 2u);
  CHECK_EQ(rd32(f.acks_of(kA).back().data() + 1), 11u);
}

// --- window autotune (StreamConfig::auto_window) ---

// Every autotune test shares these two bounds and reads them back in its
// assertions; naming them keeps the expectations tied to the cfg above.
constexpr size_t kAutoFloor = 16 * 1024;
constexpr size_t kAutoCeil = 256 * 1024;

StreamConfig AutoCfg() {
  StreamConfig c = DefaultCfg();
  c.auto_window = true;
  // These tests pin the epoch controller (slow start / AIMD / loss probe).
  // BBR is the shipping default and has its own tests below.
  c.bbr = false;
  c.send_window_bytes = kAutoFloor;
  c.window_min_bytes = kAutoFloor;
  c.window_max_bytes = kAutoCeil;
  c.rcv_buf_bytes = kAutoFloor;
  return c;
}

// The window grows only while the stream is its own bottleneck. With a fixed
// 100ms RTT and a pipe that carries whatever is in flight, the path never
// shows a queue and the delivery-rate estimate only rises with the window, so
// it doubles every epoch all the way to window_max -- the ceiling, not a BDP
// target it stops at.
void TestAutoWindowGrowsToCeiling() {
  Fixture f(AutoCfg());
  f.cut_all();
  DelayedPath path(f, 100);
  CHECK_EQ(f.sa().send_window(), kAutoFloor);

  const std::vector<uint8_t> src = MakeBytes(1024 * 1024, 9);
  Applier w(f.sa(), src);
  for (int round = 0; round < 400; ++round) {
    w.push();
    path.run(25);
  }
  CHECK_EQ(f.sa().min_rtt_ms(), 100);
  CHECK_EQ(f.sa().send_window(), kAutoCeil);  // capped
  CHECK_EQ(f.sa().ssthresh(), kAutoCeil);
  CHECK_EQ(f.sa().peer_window(), kAutoCeil);  // receive cap follows the window max
  CHECK(f.b().delivered == src);
}

// A stream-level loss (here: every ACK withheld until the RTO fires) is the
// only congestion signal the stream has, and it costs one 30% decrease per
// epoch. With no ACKs arriving nothing can grow it back, so the cut is exact.
void TestAutoWindowCutsOnLoss() {
  Fixture f(AutoCfg());
  f.cut_all();
  DelayedPath path(f, 100);
  // 4 MiB leaves the app still demanding when the window reaches the cap, so
  // the blackout starts with the window full and the RTO has something to fire
  // on. Stop growing as soon as the cap is hit.
  const std::vector<uint8_t> src = MakeBytes(4 * 1024 * 1024, 10);
  Applier w(f.sa(), src);
  for (int round = 0; round < 400 && f.sa().send_window() < kAutoCeil; ++round) {
    w.push();
    path.run(25);
  }
  const size_t cap = f.sa().send_window();
  CHECK_EQ(cap, kAutoCeil);
  CHECK(f.sa().in_flight() > 0u);

  path.drop_acks();
  size_t cut = 0;
  for (int round = 0; round < 40 && cut == 0; ++round) {  // <= 1s: a few RTOs
    // Keep the app demanding: once the acks already in flight have drained,
    // freshly written bytes are what the RTO then fires on.
    w.push();
    path.run(25);
    if (f.sa().send_window() < cap) {
      cut = f.sa().send_window();
    }
  }
  CHECK_EQ(cut, cap - cap * 3 / 10);
  // #P1-2: the cut window must stay recoverable. ssthresh is the boundary
  // between slow start and additive growth, so it keeps the last measured
  // target as the reference instead of collapsing onto the just-cut window --
  // additive-only recovery from 16 KiB to 256 KiB would take a hundred epochs.
  CHECK(f.sa().ssthresh() >= cut);

  // The floor holds under a long ACK blackout. RTOs back off exponentially, so
  // the cuts come slower and slower; the window still bottoms out at
  // window_min_bytes and never goes below it.
  for (int round = 0; round < 1600 && f.sa().send_window() > kAutoFloor; ++round) {
    w.push();
    path.run(25);
  }
  CHECK_EQ(f.sa().send_window(), kAutoFloor);

  // ACKs return: the retransmission that was in flight gets confirmed, the
  // window opens again, and the transfer finishes byte-exact.
  path.resume_acks();
  for (int round = 0; round < 2000 && w.off < src.size(); ++round) {
    w.push();
    path.run(25);
  }
  path.run(3000);
  CHECK_EQ(w.off, src.size());
  CHECK(f.sa().send_window() > kAutoFloor);
  CHECK(f.b().delivered == src);
}

// The 2026-10-31 WAN re-measure: on a 160ms path carrying ~17% datagram loss
// (~6% of FEC groups unrepairable), a stream hole is mostly random loss, not
// contention. Cutting on it every epoch drove the window to the 64 KiB engine
// floor inside a second and it stayed there for the whole transfer -- 1.61 Mbps
// against the fixed 256 KiB window's 4.0. A 64 KiB window is worse than slow
// there: one lost burst plus the RTO backoff leaves the tunnel starved.
// So loss alone stops at the window the stream started with; only standing-queue
// evidence (TestAutoWindowBrakesOnStandingQueue) may take it below.
void TestAutoWindowHoldsAtTheStartWindow() {
  StreamConfig c = AutoCfg();
  c.send_window_bytes = 64 * 1024;   // the start is what the loss term must respect
  c.window_min_bytes = kAutoFloor;    // below it, so a runaway cut is visible
  c.window_max_bytes = kAutoCeil;
  Fixture f(c);
  f.cut_all();
  DelayedPath path(f, 100);
  const std::vector<uint8_t> src = MakeBytes(4 * 1024 * 1024, 41);
  Applier w(f.sa(), src);
  auto feed_window = [&](int rounds) {
    for (int round = 0; round < rounds; ++round) {
      w.push();
      path.run(25);
    }
  };
  // Climb above the start first, otherwise "it stopped at the start" is vacuous.
  for (int round = 0; round < 400 && f.sa().send_window() < kAutoCeil; ++round) {
    w.push();
    path.run(25);
  }
  CHECK_EQ(f.sa().send_window(), kAutoCeil);

  path.drop_acks();
  feed_window(1600);  // 40s with no acknowledgement at all
  CHECK_EQ(f.sa().send_window(), 64u * 1024);
  CHECK_EQ(f.sa().loss_floor(), 64u * 1024);
  CHECK(f.sa().rto_loss_events() > 0u);  // the cuts really were timeout-driven

  // And the hold is not a dead end: once ACKs flow again the window reopens and
  // the transfer finishes byte-exact.
  path.resume_acks();
  for (int round = 0; round < 4000 && w.off < src.size(); ++round) {
    w.push();
    path.run(25);
  }
  path.run(3000);
  CHECK_EQ(w.off, src.size());
  CHECK(f.sa().send_window() > 64u * 1024);
  CHECK(f.b().delivered == src);
}

// 2026-11-03: a dup-ACK hole is not congestion evidence on a FEC-protected
// path -- the peer is still acknowledging, so data is flowing. With the probe
// the window grows instead of taking the 30% AIMD cut; an RTO blackout still
// cuts (TestAutoWindowCutsOnLoss) and the queue brake still owns shrinking.
void TestAutoWindowProbesOnDupAckLoss() {
  StreamConfig c = AutoCfg();
  c.initial_srtt_ms = 4000;   // -> epoch 4s, rto clamped to 5s: no timeout in view
  c.window_min_bytes = 4096;  // below the start, so a cut would be visible
  Fixture f(c);               // window_probe defaults to true
  f.cut_all();

  const std::vector<uint8_t> src = MakeBytes(4u * 1024 * 1024, 62);
  Applier w(f.sa(), src);
  w.push();
  f.tick(1);
  const size_t start = f.sa().send_window();
  CHECK_EQ(start, c.send_window_bytes);

  // Take the window above the start first: full ACKs with the window binding.
  for (int r = 0; r < 8 && f.sa().send_window() == start; ++r) {
    f.feed(kA, MakeAck(static_cast<uint32_t>(f.sa().bytes_acked() + f.sa().in_flight()),
                       64 * 1024, 0, 0));
    f.tick(4100);  // epoch boundary
    w.push();
    f.tick(1);
  }
  const size_t w0 = f.sa().send_window();
  CHECK(w0 > start);

  const uint32_t hole = 100;  // max_segment 106 -> 100 byte payloads
  const uint32_t base = static_cast<uint32_t>(f.sa().bytes_acked());
  const std::vector<uint8_t> dup =
      MakeAck(base, 64 * 1024, base + hole, base + 2 * hole);
  for (int i = 0; i < 4; ++i) {
    f.feed(kA, dup);  // the 4th is the third duplicate: repair, do not cut
  }
  CHECK_EQ(f.sa().dup_loss_events(), 0u);
  // Past one RTT: the repair has had its chance, so the next burst is evidence,
  // not the same burst arriving twice inside a repair's flight time.
  f.tick(f.sa().srtt_ms() + 500);
  CHECK_EQ(f.sa().send_window(), w0);  // one burst is not loss evidence

  for (int i = 0; i < 4; ++i) {
    f.feed(kA, dup);  // still stuck behind the same hole: this is a hole
  }
  CHECK(f.sa().dup_loss_events() > 0u);
  f.tick(4100);
  // The probe grows 25% (capped by the ceiling) instead of cutting.
  CHECK_EQ(f.sa().send_window(), std::min(w0 + w0 / 4, kAutoCeil));
  CHECK(f.sa().send_window() > w0);
}

// The prewarm prior raises the start window above the operator's --window; the
// loss floor must stay at the operator's value (StreamConfig::loss_floor_bytes),
// otherwise a warm connection that hits loss freezes at the prior instead of
// shrinking to the configured start (decision #37, on top of #33).
void TestAutoWindowLossFloorFollowsConfiguredStart() {
  StreamConfig c = AutoCfg();
  c.send_window_bytes = kAutoCeil;   // seeded by the previous session
  c.loss_floor_bytes = kAutoFloor;   // what --window actually asked for
  Fixture f(c);
  f.cut_all();
  CHECK_EQ(f.sa().send_window(), kAutoCeil);
  CHECK_EQ(f.sa().loss_floor(), kAutoFloor);

  DelayedPath path(f, 100);
  const std::vector<uint8_t> src = MakeBytes(4 * 1024 * 1024, 43);
  Applier w(f.sa(), src);
  path.drop_acks();
  for (int round = 0; round < 1600; ++round) {
    w.push();
    path.run(25);
  }
  // The old floor (the seeded start) would leave this at kAutoCeil.
  CHECK_EQ(f.sa().send_window(), kAutoFloor);
  CHECK(f.sa().rto_loss_events() > 0u);

  // Not a dead end: ACKs resume, the window reopens and the data is intact.
  path.resume_acks();
  for (int round = 0; round < 4000 && w.off < src.size(); ++round) {
    w.push();
    path.run(25);
  }
  path.run(3000);
  CHECK_EQ(w.off, src.size());
  CHECK(f.sa().send_window() > kAutoFloor);
  CHECK(f.b().delivered == src);
}

// A synchronous host can ACK from inside the send callback, which pops the
// just-sent segment and re-enters pump() while the outer pump is still walking
// tx_. That reindexes the queue under the scan, so the scan must relocate the
// segment it just emitted instead of trusting an index: the held-back segment
// has to stay queued and go out exactly once, in order, when the window opens.
void TestSynchronousAckDuringPumpKeepsQueueConsistent() {
  StreamConfig c = DefaultCfg();
  c.max_segment = 106;       // 100-byte payloads
  c.send_window_bytes = 250; // room to queue both segments after the reopen
  c.rcv_buf_bytes = 80;      // A's guess of the peer window: nothing fits, so A probes
  StreamConfig peer = c;
  peer.rcv_buf_bytes = 250;  // the peer really does have room for one segment
  Fixture f(c, peer);
  bool injected = false;
  f.on_send = [&](int index, const std::vector<uint8_t>& seg) {
    if (injected || !IsData(seg)) {
      return;
    }
    injected = true;
    const uint32_t off = rd32(seg.data() + 1);
    const uint32_t end = off + static_cast<uint32_t>(seg.size() - fcp::kStreamDataHdrLen);
    f.feed(index, MakeAck(end, 80, 0, 0));
  };

  const std::vector<uint8_t> src = MakeBytes(200, 77);
  CHECK_EQ(f.sa().write(src.data(), src.size()), 200u);
  f.tick(25);
  CHECK(injected);
  const auto after_first = f.data_of(kA);
  CHECK_EQ(after_first.size(), 1u);  // the zero-window probe
  CHECK_EQ(rd32(after_first[0].data() + 1), 0u);
  // The ACK was consumed from inside the callback; the second segment is held
  // back, not lost and not sent out of order.
  CHECK_EQ(f.sa().unacked_segs(), 1u);

  // Reopening the peer window releases the held-back segment in order.
  f.feed(kA, MakeAck(100, 250, 0, 0));
  f.tick(50);
  const auto after_reopen = f.data_of(kA);
  CHECK_EQ(after_reopen.size(), 2u);
  CHECK_EQ(rd32(after_reopen[0].data() + 1), 0u);
  CHECK_EQ(rd32(after_reopen[1].data() + 1), 100u);
  f.drain();
  CHECK(f.b().delivered == src);
}

// auto_window off is the fixed-window mode: no growth, no probes of the path.
void TestFixedWindowUnchanged() {
  Fixture f;
  const std::vector<uint8_t> src = MakeBytes(4000, 12);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sa().send_window(), f.cfg().send_window_bytes);
}

// A fixed window below one segment never lets a segment leave: pump() admits a
// segment only while in_flight + wire_len fits, so the stream accepted the
// app's bytes and stalled with an empty in-flight (`--no-auto-window
// --window=1`). The constructor floors the window at two segments.
void TestFixedWindowCannotGoBelowTwoSegments() {
  StreamConfig cfg = DefaultCfg();
  cfg.auto_window = false;
  cfg.send_window_bytes = 1;
  Fixture f(cfg);
  const std::vector<uint8_t> src = MakeBytes(150, 5);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
  CHECK_EQ(f.sa().send_window(), 2 * f.cfg().max_segment);
}

// The historical min RTT is the reference the delay brake measures queueing
// against. It has to expire: after a route change to a slower path a floor that
// never rises makes every epoch look like a standing queue, so the window brakes
// forever (and the §8 FEC guardrail stays closed for the same reason).
void TestMinRttExpiresOntoASlowerPath() {
  Fixture f;
  Stream& s = f.sa();
  s.test_update_rtt(200, 1000);
  CHECK_EQ(s.min_rtt_ms(), 200);
  s.test_update_rtt(500, 9500);  // inside the window: the floor holds
  CHECK_EQ(s.min_rtt_ms(), 200);
  s.test_update_rtt(520, 11500);  // expired: it follows the current path
  CHECK_EQ(s.min_rtt_ms(), 520);
  // A genuinely faster sample still lowers the floor immediately.
  s.test_update_rtt(180, 11600);
  CHECK_EQ(s.min_rtt_ms(), 180);
}

// The advertised window is backed by the receive buffer, so auto mode has to
// raise that buffer to the same ceiling — otherwise the sender's measured BDP
// is clamped by the peer's memory and the two ends tune against each other.
void TestAutoWindowRaisesRcvCap() {
  StreamConfig c = DefaultCfg();
  c.auto_window = true;
  c.rcv_buf_bytes = 2048;
  c.window_min_bytes = 2048;
  c.window_max_bytes = kAutoFloor;
  Fixture f(c);
  const size_t cap = f.payload();
  // Leave the first segment as a hole, then fill the autotuned buffer with one
  // contiguous out-of-order run up to the advertised edge. A 2 KiB buffer would
  // have truncated and shut the window long before.
  size_t at = cap;
  while (at + cap <= kAutoFloor) {
    f.feed(kB, MakeData(static_cast<uint32_t>(at), MakeBytes(cap, 0), false));
    at += cap;
  }
  f.feed(kB, MakeData(static_cast<uint32_t>(at), MakeBytes(kAutoFloor - at, 7), false));
  CHECK_EQ(f.sb().oob_bytes(), kAutoFloor - cap);  // everything but the front hole
  CHECK_EQ(rd32(f.last_ack(kB).data() + 5), cap);  // only the hole left open
}

// --- window autotune: control law regressions ---

// P0: the capacity estimate is goodput x min RTT, so any path latency above the
// minimum (here: random extra ACK delay, with no queue of our own) puts the
// estimate below the window in force. That estimate may not cap growth: after a
// loss the window has to climb back to the ceiling it had already proven.
void TestAutoWindowGrowsPastInflatedTarget() {
  StreamConfig c = AutoCfg();
  c.send_window_bytes = 32 * 1024;
  c.window_min_bytes = 16 * 1024;
  c.window_max_bytes = 64 * 1024;
  c.initial_srtt_ms = 400;  // -> rto 800ms, above the worst jittered round trip
  Fixture f(c);
  f.cut_all();
  DelayedPath path(f, 100);
  path.set_jitter(400);  // ~300ms mean round trip against a 100ms minimum

  const std::vector<uint8_t> src = MakeBytes(4 * 1024 * 1024, 21);
  Applier w(f.sa(), src);
  auto feed_window = [&](int64_t ms) {
    for (int64_t t = 0; t < ms; t += 25) {
      w.push();
      path.run(25);
    }
  };
  feed_window(2000);
  const size_t full = f.sa().send_window();
  CHECK_EQ(full, 64u * 1024);
  CHECK(f.sa().min_rtt_ms() <= 110);  // the fast tail of the jitter sets the floor

  // One timeout: an ACK blackout of just over one RTO plus an epoch. The window
  // leaves at 70% and ssthresh keeps the pre-loss reference -- while the estimate
  // (goodput x min RTT on a 300ms-mean, 100ms-min path) sits below it, which is
  // exactly what used to pin the window at the cut forever. Snapshot before the
  // held ACKs come back: a sample whose round trip included the blackout is not
  // a sample of the path.
  path.drop_acks();
  feed_window(450);
  CHECK(f.sa().retransmits() >= 1u);
  const size_t cut = f.sa().send_window();
  CHECK(cut < full);
  CHECK(cut >= full - full * 3 / 10);  // one decrease, not a collapse
  path.resume_acks();
  feed_window(100);
  CHECK(f.sa().ssthresh() <= full);  // the recovery reference, not the cut

  // Keep going: the estimate does not gate growth, so the window climbs back to
  // the ceiling it had already proven.
  feed_window(4000);
  CHECK_EQ(f.sa().send_window(), full);
  CHECK(std::equal(f.b().delivered.begin(), f.b().delivered.end(), src.begin()));
}

// P1-3 / P1-5: on a rate-limited path nothing is ever lost, so loss alone would
// leave the window at its peak and a standing queue of our own making forever.
// The delay-based brake holds and shrinks instead, keeping the queue inside the
// budget that the Session §8 guardrail (40ms) would otherwise punish by cutting
// FEC redundancy.
void TestAutoWindowBrakesOnStandingQueue() {
  Fixture f(AutoCfg());  // start = floor = 16 KiB, ceiling 256 KiB
  f.cut_all();
  // 400 KB/s with a 40ms round trip: one BDP is exactly the starting window, so
  // every byte of growth is a byte of queue.
  BottleneckPath path(f, 400 * 1024, 40);
  const std::vector<uint8_t> src = MakeBytes(4 * 1024 * 1024, 31);
  Applier w(f.sa(), src);
  // The first two seconds are the ramp: with the initial 200ms srtt guess the
  // epochs are long, so slow start overshoots before the estimate and the delay
  // feedback get a sample each. What has to hold is the equilibrium.
  for (int round = 0; round < 80; ++round) {
    w.push();
    path.run(25);
  }
  path.reset_stats();
  for (int round = 0; round < 320; ++round) {  // 8s of steady state
    w.push();
    path.run(25);
  }
  const size_t window = f.sa().send_window();
  CHECK(path.max_queue_ms() < 100);  // the standing queue stayed inside budget
  CHECK(window > kAutoFloor);        // it did grow: the link has headroom
  CHECK(window < 96u * 1024);        // ... and stopped far below the cap
  CHECK_EQ(f.sa().retransmits(), 0u);  // no loss: the brake, not the RTO
  CHECK_EQ(f.sa().retx_tlp(), 0u);     // ACKs flow even when the queue is deep
  CHECK(f.sa().min_rtt_ms() <= 45);
  CHECK(std::equal(f.b().delivered.begin(), f.b().delivered.end(), src.begin()));
}

// Growth is only evidence when the *local* window is what holds the stream back.
// A peer advertising a small receive buffer must not be read as an idle path.
void TestAutoWindowStaysPutWhenPeerLimited() {
  StreamConfig a = AutoCfg();  // 16 KiB start, 256 KiB ceiling
  StreamConfig b = DefaultCfg();  // fixed, 2 KiB receive buffer
  Fixture f(a, b);
  f.cut_all();
  DelayedPath path(f, 100);
  const std::vector<uint8_t> src = MakeBytes(256 * 1024, 41);
  Applier w(f.sa(), src);
  for (int round = 0; round < 200; ++round) {  // 5s
    w.push();
    path.run(25);
  }
  CHECK(f.sa().peer_window() <= b.rcv_buf_bytes);
  CHECK_EQ(f.sa().send_window(), a.send_window_bytes);  // never moved
  CHECK(f.b().delivered.size() > 0u);                   // yet the stream still flows
  CHECK(std::equal(f.b().delivered.begin(), f.b().delivered.end(), src.begin()));
}

// P3-14: three duplicate ACKs also happen when FEC delivers a set out of order.
// The forced retransmission is cheap, the 30% cut is not, so the cut waits for a
// second burst with the first repair still unacknowledged.
void TestDupAckCutWaitsForSecondBurst() {
  StreamConfig c = AutoCfg();
  c.initial_srtt_ms = 4000;  // -> epoch 4s, rto clamped to 5s: no timeout in view
  c.window_min_bytes = 4096;  // below the start, so a 30% cut is visible
  c.window_probe = false;     // this test pins the AIMD fallback
  Fixture f(c);
  f.cut_all();  // B receives nothing; the ACKs below are hand-made
  const std::vector<uint8_t> src = MakeBytes(4u * 1024 * 1024, 5);
  Applier w(f.sa(), src);
  w.push();
  f.tick(1);  // segment the window, nothing on the peer side
  const size_t start = f.sa().send_window();
  CHECK_EQ(start, c.send_window_bytes);

  // A cut has somewhere to land only above the loss floor, which is the window
  // the stream started with, so take it up first: full ACKs with the window
  // binding, one doubling per epoch.
  for (int r = 0; r < 8 && f.sa().send_window() == start; ++r) {
    f.feed(kA, MakeAck(static_cast<uint32_t>(f.sa().bytes_acked() + f.sa().in_flight()),
                       64 * 1024, 0, 0));
    f.tick(4100);  // epoch boundary
    w.push();
    f.tick(1);  // refill, so the next epoch is limited by our own window
  }
  const size_t w0 = f.sa().send_window();
  CHECK(w0 > start);

  const uint32_t hole = 100;  // max_segment 106 -> 100 byte payloads
  const uint32_t base = static_cast<uint32_t>(f.sa().bytes_acked());
  const std::vector<uint8_t> dup =
      MakeAck(base, 64 * 1024, base + hole, base + 2 * hole);
  for (int i = 0; i < 4; ++i) {
    f.feed(kA, dup);  // the 4th is the third duplicate: repair, do not cut
  }
  CHECK(f.sa().retransmits() >= 1u);
  CHECK_EQ(f.sa().dup_loss_events(), 0u);
  // Past one RTT: only a burst after the repair's own flight time is loss.
  f.tick(f.sa().srtt_ms() + 500);
  CHECK_EQ(f.sa().send_window(), w0);  // one burst is still compatible with a hole

  for (int i = 0; i < 4; ++i) {
    f.feed(kA, dup);  // still stuck behind the same hole: this is loss
  }
  CHECK(f.sa().dup_loss_events() > 0u);
  f.tick(4100);
  CHECK_EQ(f.sa().send_window(), w0 - w0 * 3 / 10);
  CHECK(f.sa().ssthresh() <= w0 - w0 * 3 / 10);
}

// P2-11: a zero-window probe is deliberately one segment past a closed window.
// When the window is closed because the local app stopped reading, accepting it
// would feed the host's backlog at the probe rate instead of bounding memory at
// the receive buffer, so the segment is answered and dropped.
void TestStalledAppDoesNotBufferProbes() {
  // rcv_buf a whole number of segments (100 payload bytes) below the window, so
  // the advertised room reaches exactly zero instead of a sub-segment remainder.
  StreamConfig c = DefaultCfg();
  c.rcv_buf_bytes = 2000;
  c.send_window_bytes = 4000;
  Fixture f(c);
  const size_t rcv = f.cfg().rcv_buf_bytes;
  const std::vector<uint8_t> src = MakeBytes(f.cfg().send_window_bytes, 3);
  // The host keeps everything it is handed until the test says it drained it.
  bool stalled = true;
  f.on_deliver = [&](int index) {
    if (index == kB && stalled) {
      f.sb().set_delivery_pending(f.b().delivered.size());
    }
  };
  Applier w(f.sa(), src);
  for (int round = 0; round < 40; ++round) {
    w.push();
    f.tick(25);
  }
  CHECK_EQ(f.b().delivered.size(), rcv);  // exactly one buffer, then the window shut
  CHECK_EQ(rd32(f.last_ack(kB).data() + 5), 0u);

  // 4s of probes and their timeouts: the debt stays, so nothing is buffered.
  const size_t before = f.b().delivered.size();
  for (int round = 0; round < 20; ++round) {
    f.tick(200);
  }
  CHECK_EQ(f.b().delivered.size(), before);
  CHECK(f.sa().retransmits() >= 1u);  // the probe itself did keep going out

  // Unstick the app: the held-back bytes arrive, in order.
  stalled = false;
  f.sb().set_delivery_pending(0);
  for (int round = 0; round < 400 && f.b().delivered.size() < src.size(); ++round) {
    w.push();
    f.tick(25);
  }
  CHECK_EQ(f.b().delivered.size(), src.size());
  CHECK(f.b().delivered == src);
}

// ACK coalescing (StreamConfig::ack_every). A clean in-order stream used to
// emit one 81-byte ACK packet per data segment; batching two halves that on the
// reverse path. A hole must still be reported at once (the sender is waiting on
// it), and a pending ACK has to go out on its own deadline rather than waiting
// for the next segment or the tick.
void TestAckCoalescingHalvesCleanPathAcks() {
  StreamConfig cfg = DefaultCfg();
  cfg.ack_every = 2;
  Fixture f(cfg);
  const std::vector<uint8_t> seg = MakeBytes(100, 1);
  f.feed(kB, MakeData(0, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 0u);  // owed, not sent yet
  f.feed(kB, MakeData(100, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 1u);  // the second segment flushes it

  // One more segment is owed; the host is told when it has to come back for it.
  f.feed(kB, MakeData(200, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 1u);
  const int64_t wake = f.sb().next_wake_ms(f.now());
  CHECK(wake > f.now());
  f.tick(fcp::kAckDelayMs);
  CHECK_EQ(f.acks_of(kB).size(), 2u);

  // Out of order is urgent: 300..499 is missing, so the peer needs the SACK
  // now, not after another arrival.
  f.feed(kB, MakeData(500, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 3u);
}

// Every ACK settles the delayed-ACK debt, not only the coalescing decision in
// maybe_ack(). A duplicate segment is answered at once (the sender's RTO would
// otherwise keep firing); if that immediate ACK left the debt standing, the
// tick would send a second copy kAckDelayMs later -- the per-segment pair the
// coalescing exists to remove, one delayed.
void TestAnyAckSettlesTheCoalescingDebt() {
  StreamConfig cfg = DefaultCfg();
  cfg.ack_every = 2;
  Fixture f(cfg);
  const std::vector<uint8_t> seg = MakeBytes(100, 1);
  f.feed(kB, MakeData(0, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 0u);  // owed, not sent yet
  f.feed(kB, MakeData(0, seg, false));
  CHECK_EQ(f.acks_of(kB).size(), 1u);  // duplicate: answered immediately
  f.tick(fcp::kAckDelayMs);
  CHECK_EQ(f.acks_of(kB).size(), 1u);  // and no delayed copy follows it
}

// Upward PMTUD raises the session's payload size on a live stream. A raise the
// send window cannot carry would send nothing at all (pump() admits on
// in_flight + wire_len <= window, and the zero-window probe covers the peer's
// window, not ours), so it is refused and the old segment size is kept.
void TestSetMaxSegmentRefusesAStallingRaise() {
  StreamConfig cfg = DefaultCfg();  // 106-byte segment, 100 payload bytes
  cfg.auto_window = false;
  cfg.send_window_bytes = 4096;
  Fixture f(cfg);
  f.sa().set_max_segment(9000);  // larger than the whole window: refused
  f.sa().set_max_segment(200);   // fits: accepted, so 194 payload bytes
  const std::vector<uint8_t> src = MakeBytes(1000, 7);
  CHECK_EQ(f.push(kA, src), src.size());
  f.drain();
  CHECK(f.b().delivered == src);
  // Cut at 194 bytes: six segments. A 9000-byte segment would have emitted none.
  CHECK_EQ(f.a().sent.size(), 6u);
}

// A PMTUD fallback lowers the session payload bound while segments carved at
// the larger size are still in flight. Leaving them carved would keep emitting
// datagrams the path has just been proven to drop, so set_max_segment() re-cuts
// them in place: the byte offsets the ARQ works in do not change, and the next
// tick re-sends the smaller pieces.
void TestSetMaxSegmentShrinksInFlightSegments() {
  StreamConfig cfg = DefaultCfg();
  cfg.auto_window = false;
  cfg.send_window_bytes = 4096;
  Fixture f(cfg);
  f.sa().set_max_segment(200);  // 194-byte payload pieces
  f.cut_all();                  // nothing reaches B: the pieces stay in flight

  const std::vector<uint8_t> src = MakeBytes(1000, 7);
  CHECK_EQ(f.push(kA, src), src.size());
  CHECK_EQ(f.b().delivered.size(), 0u);
  CHECK_EQ(f.sa().in_flight(), src.size());  // every byte is outstanding
  const size_t before = f.a().sent.size();

  f.sa().set_max_segment(106);  // 100-byte payload pieces
  CHECK_EQ(f.sa().in_flight(), src.size());  // same bytes, smaller carving
  f.killer = nullptr;
  f.drain();

  CHECK(f.b().delivered == src);
  // Every repair the fallback caused fits the new bound: no 200-byte segment
  // may survive it.
  for (size_t i = before; i < f.a().sent.size(); ++i) {
    CHECK(f.a().sent[i].size() <= 106u);
  }
}

// The send ceiling is the operator's MAX only when they pinned one. Otherwise a
// session that keeps proving a larger BDP may grow past it, up to the ceiling
// bound -- a 1 MiB ceiling is 40 Mbps at 200 ms however good the controller is.
void TestWindowCeilingFollowsMeasuredBdp() {
  StreamConfig cfg = DefaultCfg();
  cfg.auto_window = true;
  cfg.bbr = true;
  cfg.send_window_bytes = 256 * 1024;
  cfg.window_min_bytes = 64 * 1024;
  cfg.window_max_bytes = 256 * 1024;
  cfg.window_ceiling_bytes = 4 * 1024 * 1024;
  // A prewarm prior makes the BDP deterministic: 20 MB/s x 100 ms = 2 MiB.
  cfg.initial_bw_bps = 20u * 1000u * 1000u;
  cfg.initial_min_rtt_ms = 100;
  Fixture f(cfg);
  f.sa().on_tick(f.now());
  CHECK(f.sa().send_window() > cfg.window_max_bytes);
  CHECK(f.sa().send_window() <= cfg.window_ceiling_bytes);

  // Without a ceiling bound the configured MAX is the last word.
  StreamConfig pinned = cfg;
  pinned.window_ceiling_bytes = 0;
  Fixture g(pinned);
  g.sa().on_tick(g.now());
  CHECK(g.sa().send_window() <= pinned.window_max_bytes);
}

// The pacer must say *when* it can release the next segment. Relying on the
// 25 ms reactor tick is what turned BBR pacing into a burst emitter.
void TestPacerReportsItsNextWake() {
  StreamConfig cfg = DefaultCfg();
  cfg.auto_window = true;
  cfg.bbr = true;
  cfg.send_window_bytes = 256 * 1024;
  cfg.window_min_bytes = 64 * 1024;
  cfg.window_max_bytes = 1024 * 1024;
  cfg.rcv_buf_bytes = 1024 * 1024;
  cfg.initial_srtt_ms = 100;
  Fixture f(cfg);
  f.feed(kA, MakeAck(0, 1024 * 1024, 0, 0));  // the peer advertises room
  const std::vector<uint8_t> blob = MakeBytes(200000, 7);
  (void)f.sa().write(blob.data(), blob.size());
  f.sa().on_tick(f.now());
  CHECK(!f.data_of(kA).empty());
  const int64_t now = f.now();
  // The bucket was charged by the burst just emitted; the next segment has to
  // wait a fraction of the tick, and the host is told exactly when.
  CHECK(f.sa().next_wake_ms(now) > now);
}

// #78 (R1 acceptance): one v2 ACK names every hole, and one ACK repairs all
// of them -- no dup-ACK rotation, no per-RTT hole discovery.
void TestAckV2ReportsAllHolesInOneAck() {
  StreamConfig cfg = DefaultCfg();
  cfg.ack_v2 = true;
  Fixture f(cfg);
  const size_t cap = 100;  // payload per segment under DefaultCfg
  f.killer = [](const Packet&) { return true; };  // hold the wire
  std::vector<uint8_t> payload = MakeBytes(10 * cap, 1);
  CHECK_EQ(f.push(kA, payload), payload.size());
  f.killer = nullptr;
  const auto segs = f.data_of(kA);
  CHECK_EQ(segs.size(), 10u);

  // Deliver 0, 3, 6, 9: holes at [100,300), [400,600), [700,900).
  f.feed(kB, segs[0]);
  f.feed(kB, segs[3]);
  f.feed(kB, segs[6]);
  f.feed(kB, segs[9]);
  const AckV2 ack = ParseAckV2(f.last_sent(kB));
  CHECK(ack.ok);
  CHECK_EQ(ack.cum, 100u);
  CHECK_EQ(ack.blocks.size(), 3u);
  CHECK_EQ(ack.blocks[0].first, 300u);
  CHECK_EQ(ack.blocks[0].second, 400u);
  CHECK_EQ(ack.blocks[1].first, 600u);
  CHECK_EQ(ack.blocks[1].second, 700u);
  CHECK_EQ(ack.blocks[2].first, 900u);
  CHECK_EQ(ack.blocks[2].second, 1000u);

  // One ACK repairs every hole: the six hole segments go out once, the three
  // SACKed ones do not move.
  const size_t before = f.data_of(kA).size();
  f.feed(kA, f.last_sent(kB));
  CHECK_EQ(f.data_of(kA).size(), before + 6);
  for (const uint32_t off : {100u, 200u, 400u, 500u, 700u, 800u}) {
    CHECK_EQ(f.data_with_offset(kA, off), 2u);  // original + one repair
  }
  for (const uint32_t off : {0u, 300u, 600u, 900u}) {
    CHECK_EQ(f.data_with_offset(kA, off), 1u);  // SACKed, never resent
  }
}

// #78 (R9): any malformed range set is discarded whole -- nothing is applied,
// nothing is provoked; a valid set right after still works.
void TestAckV2MalformedDiscardsWholeSet() {
  StreamConfig cfg = DefaultCfg();
  cfg.ack_v2 = true;
  Fixture f(cfg);
  f.killer = [](const Packet&) { return true; };
  std::vector<uint8_t> payload = MakeBytes(4 * 100, 2);
  CHECK_EQ(f.push(kA, payload), payload.size());
  f.killer = nullptr;
  const auto segs = f.data_of(kA);
  CHECK_EQ(segs.size(), 4u);
  const size_t before = f.data_of(kA).size();

  // Vary the cumulative point per probe so none of them reads as a dup-ACK
  // (the dup-burst path would retransmit on its own and muddy the assertion).
  f.feed(kA, MakeAckV2(100, 4096, {{500, 600}}));  // block past snd_max_ (400)
  CHECK_EQ(f.data_of(kA).size(), before);
  f.feed(kA, MakeAckV2(150, 4096, {{150, 250}, {200, 400}}));  // overlap
  CHECK_EQ(f.data_of(kA).size(), before);
  {
    std::vector<uint8_t> a = MakeAckV2(200, 4096, {{250, 350}});
    a.push_back(0xEE);  // trailing byte past the declared ranges
    f.feed(kA, a);
    CHECK_EQ(f.data_of(kA).size(), before);
  }
  {
    std::vector<uint8_t> a = MakeAckV2(250, 4096, {});
    a[9] = 1;           // one range declared...
    a.push_back(0x80);  // ...but the varint never terminates
    f.feed(kA, a);
    CHECK_EQ(f.data_of(kA).size(), before);
  }
  // A well-formed set right after the rejects still repairs its hole.
  f.feed(kA, MakeAckV2(300, 4096, {{350, 400}}));
  CHECK_EQ(f.data_with_offset(kA, 300), 2u);
}

// #78: without the negotiated capability the wire stays v1 (17B); the new
// frame type never reaches a peer that did not offer the TLV.
void TestAckV2RequiresNegotiation() {
  Fixture f;  // DefaultCfg: ack_v2 off
  std::vector<uint8_t> payload = MakeBytes(100, 3);
  CHECK_EQ(f.push(kA, payload), payload.size());
  CHECK(!f.acks_of(kB).empty());
  for (const std::vector<uint8_t>& a : f.acks_of(kB)) {
    CHECK(IsAck(a));
    CHECK_EQ(a[0], fcp::kStreamTypeAck);
  }
}

// #79 (R2): a segment that fills a hole ACKs immediately -- the buffer may
// have emptied and coalescing would otherwise park the cumulative advance for
// kAckDelayMs, but the peer is waiting on exactly that advance. A clean
// in-order segment still coalesces.
void TestHoleFillAcksImmediately() {
  StreamConfig cfg = DefaultCfg();
  cfg.ack_every = 2;  // coalescing on, so the delayed path exists
  Fixture f(cfg);
  f.killer = [](const Packet&) { return true; };
  std::vector<uint8_t> payload = MakeBytes(3 * 100, 4);
  CHECK_EQ(f.push(kA, payload), payload.size());
  f.killer = nullptr;
  const auto segs = f.data_of(kA);
  CHECK_EQ(segs.size(), 3u);
  // Clean in-order: coalesced, nothing on the wire yet.
  f.feed(kB, segs[0]);
  CHECK(f.acks_of(kB).empty());
  // A new hole reports immediately (the !oob_.empty() branch).
  f.feed(kB, segs[2]);
  CHECK_EQ(f.acks_of(kB).size(), 1u);
  // Filling that hole is urgent too (#79): buffer emptied, cum advanced.
  f.feed(kB, segs[1]);
  CHECK_EQ(f.acks_of(kB).size(), 2u);
  CHECK_EQ(rd32(f.acks_of(kB).back().data() + 1), 300u);
}

int main() {
  TestAckV2ReportsAllHolesInOneAck();
  TestAckV2MalformedDiscardsWholeSet();
  TestAckV2RequiresNegotiation();
  TestHoleFillAcksImmediately();
  TestOrderedFlow();
  TestBidirectional();
  TestOutOfOrderHeldAndSackBlock();
  TestSackFillsHoleWithoutTimeout();
  TestSackRotationReportsAllHoles();
  TestDupAckForceRefill();
  TestSpuriousBurstWidensTolerance();
  TestTailLossProbeRepairsLostTail();
  TestLostSackFillRetriedAfterOneRtt();
  TestSackFillsWholeHoleInOnePass();
  TestNoSpuriousFastRetransmit();
  TestDupAndOverlapTrimming();
  TestReceiverBufferCapAndRwnd();
  TestZeroWindowProbeUnblocks();
  TestSmallWindowProbeUnblocks();
  TestZeroWindowProbeBacksOff();
  TestTooSmallMaxSegmentResets();
  TestStalledReaderBoundsTheSendQueue();
  TestKarnDropsAmbiguousSamples();
  TestRtoFiresWhenPeerStopsAcking();
  TestStaleSackExpiresAndRecovers();
  TestHalfCloseThenPeerClose();
  TestCloseWithNothingQueued();
  TestRstAborts();
  TestIdleTimeout();
  TestAckBeyondSndNxtIgnored();
  TestAckBeyondSentIgnored();
  TestSackBeyondSentIgnored();
  TestSndMaxAdvancesAcrossWrap();
  TestFinAckAcrossWrap();
  TestInvalidSackBlockIgnored();
  TestPeerFinDoesNotDropUnackedData();
  TestDeepReorderStaysUnderCap();
  TestOverlappingSegmentJoinsBothNeighbours();
  TestOobChunkCeilingBoundsTinySegments();
  TestFinOffsetRewriteRejected();
  TestMalformedSegments();
  TestRandomLossEndToEnd();
  TestAutoWindowGrowsToCeiling();
  TestAutoWindowCutsOnLoss();
  TestAutoWindowHoldsAtTheStartWindow();
  TestAutoWindowProbesOnDupAckLoss();
  TestAutoWindowLossFloorFollowsConfiguredStart();
  TestSynchronousAckDuringPumpKeepsQueueConsistent();
  TestFixedWindowUnchanged();
  TestFixedWindowCannotGoBelowTwoSegments();
  TestMinRttExpiresOntoASlowerPath();
  TestAutoWindowRaisesRcvCap();
  TestAutoWindowGrowsPastInflatedTarget();
  TestAutoWindowBrakesOnStandingQueue();
  TestAutoWindowStaysPutWhenPeerLimited();
  TestDupAckCutWaitsForSecondBurst();
  TestStalledAppDoesNotBufferProbes();
  TestAckCoalescingHalvesCleanPathAcks();
  TestAnyAckSettlesTheCoalescingDebt();
  TestSetMaxSegmentRefusesAStallingRaise();
  TestSetMaxSegmentShrinksInFlightSegments();
  TestWindowCeilingFollowsMeasuredBdp();
  TestPacerReportsItsNextWake();
  return fcp_test::finish();
}
