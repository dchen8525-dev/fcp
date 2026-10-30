// FCP-STREAM unit tests (docs/FCP_M2_PROXY.md §8, lines T28/T29).
//
// The stream has no clock and no socket, so the fixture is two endpoints plus a
// wire with an injectable drop policy. Segments travel whole, exactly as they
// will inside FCP data symbols.

#include "fcp/stream.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <random>
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

  Fixture() {
    base_.max_segment = 106;  // 100 payload bytes per segment
    base_.send_window_bytes = 4096;
    base_.rcv_buf_bytes = 2048;
    base_.initial_srtt_ms = 200;  // -> rto 400ms
    base_.rto_min_ms = 100;
    base_.rto_max_ms = 5000;
    base_.idle_timeout_ms = 300000;
    base_.probe_ms = 500;
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

  std::vector<uint8_t> last_ack(int from) const {
    for (auto it = ends_[from].sent.rbegin(); it != ends_[from].sent.rend(); ++it) {
      if (IsAck(*it)) {
        return *it;
      }
    }
    return {};
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
    const StreamConfig& c = base_;
    const int peer = 1 - index;
    ends_[index].stream = std::make_unique<Stream>(
        c,
        [this, index, peer](const uint8_t* seg, size_t len) {
          std::vector<uint8_t> copy(seg, seg + len);
          ends_[index].sent.push_back(copy);
          wire_.push_back(Packet{index, peer, std::move(copy)});
        },
        [this, index](const uint8_t* bytes, size_t len) {
          std::vector<uint8_t>& d = ends_[index].delivered;
          d.insert(d.end(), bytes, bytes + len);
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
  End ends_[2];
  std::deque<Packet> wire_;
  int64_t now_ = 1000;
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
  CHECK_EQ(copies, 2);  // original + exactly one repair
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK_EQ(f.sb().dup_bytes(), 0u);
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

// A reader that has stopped taking bytes must bound the writer's memory.
// pump() turns the pending queue into segments whether or not the peer's window
// has released them, so the room a writer is offered has to be measured against
// every byte still unacknowledged: counting only what reached the wire leaves the
// unsent segments invisible and the queue growing for as long as the host writes.
void TestStalledReaderBoundsTheSendQueue() {
  Fixture f;
  const size_t window = f.cfg().send_window_bytes;
  const std::vector<uint8_t> src = MakeBytes(8 * window, 7);
  size_t off = 0;
  size_t worst_backlog = 0;
  for (int round = 0; round < 400; ++round) {
    if (f.sa().can_write() && off < src.size()) {
      off += f.sa().write(src.data() + off, src.size() - off);
    }
    f.tick(25);
    // B's host has taken nothing, so everything it has received is still its
    // stream's delivery debt. That is what closes the advertised window.
    f.sb().set_delivery_pending(f.b().delivered.size());
    const size_t backlog = off - f.b().delivered.size();
    if (backlog > worst_backlog) {
      worst_backlog = backlog;
    }
  }
  CHECK(off > 0u);
  CHECK(worst_backlog <= window);
  // The stall is still in force: not even half the stream got through.
  CHECK(off < src.size());
  CHECK(f.b().delivered.size() < src.size());

  // Unstick it: the rest goes out and the whole stream arrives, in order.
  f.sb().set_delivery_pending(0);
  const std::vector<uint8_t> tail(src.begin() + static_cast<std::ptrdiff_t>(off), src.end());
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
  CHECK_EQ(copies, 2);
  CHECK_EQ(f.sa().retransmits(), 1u);
  CHECK(f.a().rtts.empty());
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

int main() {
  TestOrderedFlow();
  TestBidirectional();
  TestOutOfOrderHeldAndSackBlock();
  TestSackFillsHoleWithoutTimeout();
  TestDupAndOverlapTrimming();
  TestReceiverBufferCapAndRwnd();
  TestZeroWindowProbeUnblocks();
  TestStalledReaderBoundsTheSendQueue();
  TestKarnDropsAmbiguousSamples();
  TestRtoFiresWhenPeerStopsAcking();
  TestHalfCloseThenPeerClose();
  TestCloseWithNothingQueued();
  TestRstAborts();
  TestIdleTimeout();
  TestMalformedSegments();
  TestRandomLossEndToEnd();
  return fcp_test::finish();
}
