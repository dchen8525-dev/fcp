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
// #27: the dup-ACK burst that follows the loss also triggers one forced copy
// of the hole (kDupAckThresh duplicates arrive while the SACK repair is still
// in flight), so the wire carries original + fill + fast retransmit, and the
// receiver trims the redundant one.
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
  CHECK_EQ(copies, 3);  // original + SACK repair + fast retransmit
  CHECK_EQ(f.sa().retransmits(), 2u);
  CHECK_EQ(f.sb().dup_bytes(), f.payload());
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
  CHECK_EQ(copies, 3);  // original + SACK repair + fast retransmit (#27)
  CHECK_EQ(f.sa().retransmits(), 2u);
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

// --- #27 fast retransmit / multi-hole SACK (FCP_M3_CONTROL.md §4) ---

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

// The dup-ACK path: the first SACK sighting repairs the hole via fill_holes,
// and the third duplicate ACK adds exactly one forced copy of the first
// unacked segment (once per batch — more duplicates need another kDupAckThresh
// to fire again). No time passes, so nothing here can be an RTO.
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
  // ACK 1: fill_holes repairs the hole. ACKs 2..4: dups 1..3, the third
  // forces one extra copy of the first unacked segment.
  CHECK_EQ(f.sa().retransmits(), 2u);
  CHECK_EQ(f.data_with_offset(kA, 0), 3u);  // original + fill + forced copy
  CHECK_EQ(f.now(), t_pushed);              // no timeout was involved

  // Replaying the same four ACKs restarts the counter: dup 3 fires once more
  // (fill stays blocked by sack_filled_up_to_), proving the per-batch rule.
  for (const auto& ack : acks2) {
    f.feed(kA, ack);
  }
  CHECK_EQ(f.sa().retransmits(), 3u);
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

int main() {
  TestOrderedFlow();
  TestBidirectional();
  TestOutOfOrderHeldAndSackBlock();
  TestSackFillsHoleWithoutTimeout();
  TestSackRotationReportsAllHoles();
  TestDupAckForceRefill();
  TestNoSpuriousFastRetransmit();
  TestDupAndOverlapTrimming();
  TestReceiverBufferCapAndRwnd();
  TestZeroWindowProbeUnblocks();
  TestSmallWindowProbeUnblocks();
  TestStalledReaderBoundsTheSendQueue();
  TestKarnDropsAmbiguousSamples();
  TestRtoFiresWhenPeerStopsAcking();
  TestHalfCloseThenPeerClose();
  TestCloseWithNothingQueued();
  TestRstAborts();
  TestIdleTimeout();
  TestAckBeyondSndNxtIgnored();
  TestInvalidSackBlockIgnored();
  TestPeerFinDoesNotDropUnackedData();
  TestMalformedSegments();
  TestRandomLossEndToEnd();
  return fcp_test::finish();
}
