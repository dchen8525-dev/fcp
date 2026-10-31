// T30 (docs/FCP_M2_PROXY.md §8): FCP-STREAM on top of two real FCP sessions.
//
// stream_test.cc feeds hand-built segments straight into Stream::on_segment(),
// which proves the ARQ logic but says nothing about the carrier. Here every
// segment crosses Session: the AES-GCM envelope, the Cauchy RS set machinery,
// settlement and the FECSTAT feedback path. Whatever RS cannot repair has to be
// covered by the stream's own retransmission, so the acceptance line is
// "zero misorder, zero loss, real RTT samples, no identity violation".
//
// Loss is injected at the application layer before sendto, so every dropped
// datagram is known. Control and oob datagrams (handshake, FECSTAT) are never
// dropped: that keeps the negotiation and the report cadence deterministic and
// leaves data/parity loss as the only variable.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "e2e_link.h"
#include "fcp/stream.h"
#include "test_util.h"

namespace {

using namespace fcp_e2e;

inline std::vector<uint8_t> MakeBytes(size_t n, uint32_t seed) {
  std::vector<uint8_t> out(n);
  uint32_t s = seed;
  for (size_t i = 0; i < n; ++i) {
    s = s * 1664525u + 1013904223u;
    out[i] = static_cast<uint8_t>(s >> 24);
  }
  return out;
}

// Two Sessions, each with one Stream attached: the stream's segments are the
// session's KCP output and the session's deliveries are the stream's input.
class Link {
 public:
  bool Init(uint8_t p, int pinned_k, size_t window, size_t rcv_buf) {
    if (!winsock.ok() || !sock_a.Open() || !sock_b.Open()) {
      return false;
    }
    if (!sock_a.Connect(sock_b.port()) || !sock_b.Connect(sock_a.port())) {
      return false;
    }
    fcp::SessionConfig cfg_a =
        MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, p, pinned_k);
    fcp::SessionConfig cfg_b =
        MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, p, pinned_k);
    // The frame layer's default duplicate key reads the KCP sn at payload offset
    // 12. A stream segment has no such field, and a retransmitted byte range
    // deliberately repeats its id, so the dedup has to be off: the stream
    // dedups by offset and needs to see every duplicate in order to re-ack it.
    cfg_a.sn_of = nullptr;
    cfg_b.sn_of = nullptr;
    sess_a = std::make_unique<fcp::Session>(
        cfg_a,
        [this](const uint8_t* w, size_t n, fcp::SymbolType t) { from_a(w, n, t); },
        [this](const uint8_t* p2, size_t n) { st_a->on_segment(p2, n, now); },
        [this](const std::string& s) { log_a.push_back(s); });
    sess_b = std::make_unique<fcp::Session>(
        cfg_b,
        [this](const uint8_t* w, size_t n, fcp::SymbolType t) { from_b(w, n, t); },
        [this](const uint8_t* p2, size_t n) { st_b->on_segment(p2, n, now); },
        [this](const std::string& s) { log_b.push_back(s); });
    if (!sess_a->config_valid() || !sess_b->config_valid()) {
      return false;
    }

    fcp::StreamConfig sc;
    sc.max_segment = sess_a->mtu_limits().payload_max;
    sc.send_window_bytes = window;
    sc.rcv_buf_bytes = rcv_buf;
    st_a = std::make_unique<fcp::Stream>(
        sc, [this](const uint8_t* s, size_t n) { sess_a->on_kcp_output(s, n, now); },
        [this](const uint8_t* b, size_t n) { rx_a.insert(rx_a.end(), b, b + n); },
        [this](fcp::CloseReason r) { ++close_a; reason_a = r; }, [this]() { ++eof_a; },
        [this](int64_t srtt) { ++rtt_a; sess_a->on_rtt_sample(srtt); },
        [this](const std::string& s) { slog_a.push_back(s); });

    sc.max_segment = sess_b->mtu_limits().payload_max;
    st_b = std::make_unique<fcp::Stream>(
        sc, [this](const uint8_t* s, size_t n) { sess_b->on_kcp_output(s, n, now); },
        [this](const uint8_t* b, size_t n) { rx_b.insert(rx_b.end(), b, b + n); },
        [this](fcp::CloseReason r) { ++close_b; reason_b = r; }, [this]() { ++eof_b; },
        [this](int64_t srtt) { ++rtt_b; sess_b->on_rtt_sample(srtt); },
        [this](const std::string& s) { slog_b.push_back(s); });
    return true;
  }

  bool Handshake() {
    now = 0;
    sess_a->start(0);
    sess_b->start(0);
    sess_a->on_tick(0);
    sess_b->on_tick(0);
    pump();
    return sess_a->established() && sess_b->established();
  }

  void TickAt(int64_t t) {
    now = t;
    st_a->on_tick(t);
    st_b->on_tick(t);
    pump();
    sess_a->on_tick(t);
    pump();
    sess_b->on_tick(t);
    pump();
  }

  // Ticks until both read buffers reached the wanted sizes, or the budget runs
  // out. Returns whether the wanted amounts are in.
  bool WaitRx(size_t want_a, size_t want_b, int64_t budget_ms) {
    const int64_t deadline = now + budget_ms;
    while (now < deadline && (rx_a.size() < want_a || rx_b.size() < want_b)) {
      TickAt(now + fcp::kSessionTickMs);
    }
    return rx_a.size() >= want_a && rx_b.size() >= want_b;
  }

  // Keeps ticking after the payload is in, so the sets still open on the wire
  // reach the settlement guard and the counters are final when they are read.
  void Advance(int64_t ms) {
    const int64_t deadline = now + ms;
    while (now < deadline) {
      TickAt(now + fcp::kSessionTickMs);
    }
  }

  // A delivered byte is not an acked byte: the final ACK still has to travel
  // back, so the sender-side counters only settle one round trip later.
  bool WaitIdle(int64_t budget_ms) {
    const int64_t deadline = now + budget_ms;
    while (now < deadline &&
           (st_a->in_flight() || st_a->unacked_segs() || st_a->queued_bytes() ||
            st_b->in_flight() || st_b->unacked_segs() || st_b->queued_bytes())) {
      TickAt(now + fcp::kSessionTickMs);
    }
    return !st_a->in_flight() && !st_a->unacked_segs() && !st_a->queued_bytes() &&
           !st_b->in_flight() && !st_b->unacked_segs() && !st_b->queued_bytes();
  }

  // Feeds src into A as fast as the send window allows, ticking in between so
  // acks can free the window. Returns how many bytes were accepted.
  size_t PushA(const std::vector<uint8_t>& src, int64_t budget_ms) {
    size_t off = 0;
    const int64_t deadline = now + budget_ms;
    while (off < src.size() && now < deadline) {
      off += st_a->write(src.data() + off, src.size() - off);
      if (off < src.size()) {
        TickAt(now + fcp::kSessionTickMs);
      }
    }
    return off;
  }

  fcp::Stream* A() { return st_a.get(); }
  fcp::Stream* B() { return st_b.get(); }
  fcp::Session* SA() { return sess_a.get(); }
  fcp::Session* SB() { return sess_b.get(); }

  size_t WriteA(const std::vector<uint8_t>& src) {
    return st_a->write(src.data(), src.size());
  }
  size_t WriteB(const std::vector<uint8_t>& src) {
    return st_b->write(src.data(), src.size());
  }

  WinsockGuard winsock;
  UdpSocket sock_a;
  UdpSocket sock_b;
  std::unique_ptr<fcp::Session> sess_a;
  std::unique_ptr<fcp::Session> sess_b;
  std::unique_ptr<fcp::Stream> st_a;
  std::unique_ptr<fcp::Stream> st_b;

  std::vector<std::string> log_a;
  std::vector<std::string> log_b;
  std::vector<std::string> slog_a;
  std::vector<std::string> slog_b;
  std::vector<uint8_t> rx_a;  // bytes delivered to A (i.e. sent by B)
  std::vector<uint8_t> rx_b;  // bytes delivered to B (i.e. sent by A)

  int64_t now = 0;
  uint32_t close_a = 0;
  uint32_t close_b = 0;
  uint32_t eof_a = 0;
  uint32_t eof_b = 0;
  fcp::CloseReason reason_a = fcp::CloseReason::kNone;
  fcp::CloseReason reason_b = fcp::CloseReason::kNone;
  uint32_t rtt_a = 0;
  uint32_t rtt_b = 0;

  bool loss_enabled = false;
  uint32_t loss_percent = 20;
  uint32_t rng = 0x9E3779B9u;

  // Deterministic burst on A's data symbols: every burst_period-th datagram,
  // drop a run of burst_len. Only data goes out through the injector, so the
  // handshake and the FECSTAT cadence stay intact. The period must not be a
  // multiple of D, or every burst lands inside one set and the split between
  // "RS can repair this" and "ARQ has to" degenerates to one of the two.
  bool burst_enabled = false;
  uint32_t burst_period = 17;
  uint32_t burst_len = 4;
  uint32_t burst_seen = 0;

  uint32_t a_data = 0;
  uint32_t a_parity = 0;
  uint32_t a_oob = 0;
  uint32_t b_data = 0;
  uint32_t b_parity = 0;
  uint32_t b_oob = 0;
  uint32_t send_fail_a = 0;
  uint32_t send_fail_b = 0;
  uint32_t dropped_a = 0;  // datagrams the injector discarded, by direction
  uint32_t dropped_b = 0;

 private:
  bool drop(fcp::SymbolType type, bool from_a) {
    if (type != fcp::SymbolType::kData && type != fcp::SymbolType::kParity) {
      return false;
    }
    if (from_a && burst_enabled && type == fcp::SymbolType::kData) {
      return (burst_seen++ % burst_period) < burst_len;
    }
    if (!loss_enabled) {
      return false;
    }
    rng = rng * 1103515245u + 12345u;
    return ((rng >> 16) % 100) < loss_percent;
  }

  void from_a(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++a_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++a_parity;
    } else {
      ++a_oob;
    }
    if (drop(type, true)) {
      ++dropped_a;
      return;
    }
    if (!sock_a.Send(wire, len)) {
      ++send_fail_a;
    }
  }

  void from_b(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++b_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++b_parity;
    } else {
      ++b_oob;
    }
    if (drop(type, false)) {
      ++dropped_b;
      return;
    }
    if (!sock_b.Send(wire, len)) {
      ++send_fail_b;
    }
  }

  bool pump_once() {
    bool moved = false;
    uint8_t buf[2048];
    size_t len = 0;
    while (sock_b.Recv(buf, sizeof(buf), &len)) {
      sess_b->on_wire(buf, len, now);
      moved = true;
    }
    while (sock_a.Recv(buf, sizeof(buf), &len)) {
      sess_a->on_wire(buf, len, now);
      moved = true;
    }
    return moved;
  }

  void pump() {
    for (int guard = 0; guard < 4096; ++guard) {
      if (!pump_once()) {
        return;
      }
    }
    CHECK(false);  // the loop never drained: feedback cycle somewhere
  }
};

// The carrier must stay boring: no frame failed authentication or structure, no
// send failed because the socket was full, and the set accounting still adds up.
void CheckCarrierClean(Link& h) {
  CHECK_EQ(h.SA()->auth_fail(), 0u);
  CHECK_EQ(h.SB()->auth_fail(), 0u);
  CHECK_EQ(h.SA()->struct_fail(), 0u);
  CHECK_EQ(h.SB()->struct_fail(), 0u);
  CHECK_EQ(h.send_fail_a, 0u);
  CHECK_EQ(h.send_fail_b, 0u);
  CHECK(h.SA()->settle()->identity_ok());
  CHECK(h.SB()->settle()->identity_ok());
}

// Baseline: no loss, both directions, and the stream's RTT reaches the session.
void TestLosslessBothDirections() {
  Link h;
  CHECK(h.Init(3, -1, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());

  const std::vector<uint8_t> a_to_b = MakeBytes(40 * 1024, 11);
  const std::vector<uint8_t> b_to_a = MakeBytes(6 * 1024, 23);
  CHECK_EQ(h.WriteA(a_to_b), a_to_b.size());
  CHECK_EQ(h.WriteB(b_to_a), b_to_a.size());
  CHECK(h.WaitRx(b_to_a.size(), a_to_b.size(), 20000));
  CHECK(h.WaitIdle(5000));

  CHECK(h.rx_b == a_to_b);
  CHECK(h.rx_a == b_to_a);
  CHECK_EQ(h.A()->bytes_acked(), a_to_b.size());
  CHECK_EQ(h.B()->bytes_acked(), b_to_a.size());
  CHECK_EQ(h.A()->in_flight(), 0u);
  CHECK_EQ(h.A()->queued_bytes(), 0u);
  CHECK_EQ(h.A()->retransmits(), 0u);
  CHECK_EQ(h.B()->retransmits(), 0u);
  CHECK_EQ(h.B()->bad_segs(), 0u);

  // The stream measured a real round trip and pushed it into the session, so
  // T_flush and the settlement guards stop running on the 200ms cold default.
  CHECK(h.rtt_a > 0u);
  CHECK(h.SA()->srtt_ms() < 200);
  CheckCarrierClean(h);
}

// 20% data/parity loss with the adaptive strategy, below the reporter's sample
// gate: parity never goes on the wire, so the ARQ path alone has to close every
// hole - which is exactly the split of duties FCP-STREAM exists for.
void TestRandomLossArqCoversFec() {
  Link h;
  CHECK(h.Init(3, -1, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());
  h.loss_enabled = true;
  h.loss_percent = 20;

  const std::vector<uint8_t> src = MakeBytes(32 * 1024, 31);
  CHECK_EQ(h.WriteA(src), src.size());
  CHECK(h.WaitRx(0, src.size(), 30000));

  CHECK(h.rx_b == src);
  CHECK_EQ(h.B()->bytes_delivered(), src.size());
  CHECK(h.dropped_a > 0u);  // the injector really did drop something
  // 32 KiB is 25 symbols, under the reporter's 256-symbol gate, so no FECSTAT
  // ever reaches A and parity stays off: every hole below is filled by the
  // stream's own SACK/RTO path, with no FEC help at all.
  CHECK_EQ(h.a_parity, 0u);
  CHECK(h.A()->retransmits() > 0u);
  CHECK(!h.A()->closed());
  h.Advance(2000);
  CheckCarrierClean(h);
}

// Same loss, but parity pinned on from the first set: RS repairs the erasures
// it can and the stream only retransmits what a set could not rebuild.
void TestRandomLossPinnedKRepairs() {
  Link h;
  CHECK(h.Init(3, 3, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());
  CHECK_EQ(h.SA()->k(), 3u);
  h.loss_enabled = true;
  h.loss_percent = 20;

  const std::vector<uint8_t> src = MakeBytes(32 * 1024, 41);
  CHECK_EQ(h.WriteA(src), src.size());
  CHECK(h.WaitRx(0, src.size(), 30000));

  CHECK(h.rx_b == src);
  CHECK(h.a_parity > 0u);
  h.Advance(2000);
  CHECK(h.SB()->rx()->recovered() > 0u);
  CheckCarrierClean(h);
}

// Bursts longer than k defeat Reed-Solomon on purpose: part of the damage lands
// inside one set's repair budget and part does not, so recovery and
// retransmission both have to fire on the same transfer. The period has to be
// coprime-ish with D=10: a 5-in-25 pattern lines every burst up with a set
// boundary, so each damaged set loses exactly 5 symbols and the split degenerates
// into "nothing to repair" plus "nothing repairable".
void TestBurstLossExceedsFec() {
  Link h;
  CHECK(h.Init(3, 3, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());
  h.burst_enabled = true;
  h.burst_period = 17;
  h.burst_len = 4;

  const std::vector<uint8_t> src = MakeBytes(24 * 1024, 53);
  const int64_t t0 = h.now;
  CHECK_EQ(h.WriteA(src), src.size());
  CHECK(h.WaitRx(0, src.size(), 40000));
  const int64_t elapsed = h.now - t0;

  CHECK(h.rx_b == src);
  h.Advance(2000);
  CHECK(h.SB()->rx()->recovered() > 0u);
  CHECK(h.A()->retransmits() > 0u);
  // T38: multi-hole burst recovery is RTT-scale, not RTO-scale. Deterministic
  // virtual time, same seed: 25ms with the #27 rotation + fast retransmit vs
  // 225ms under the M2 hole-per-RTT pipeline (and holes x rto(400ms) far past
  // that). The bound catches a regression to the old pipeline.
  CHECK(elapsed < 200);
  CheckCarrierClean(h);
}

// Half-close over the carrier: A finishes its request, sends the fin, still
// reads, and only tears down once B's answer and fin arrive.
void TestHalfCloseOverSession() {
  Link h;
  CHECK(h.Init(3, -1, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());

  const std::vector<uint8_t> request = MakeBytes(3000, 61);
  CHECK_EQ(h.WriteA(request), request.size());
  h.A()->close(h.now);
  CHECK(h.WaitRx(0, request.size(), 20000));
  CHECK(h.rx_b == request);

  const std::vector<uint8_t> response = MakeBytes(2000, 67);
  CHECK_EQ(h.WriteB(response), response.size());
  h.B()->close(h.now + 1);
  CHECK(h.WaitRx(response.size(), request.size(), 20000));
  CHECK(h.rx_a == response);

  const int64_t deadline = h.now + 20000;
  while (h.now < deadline && (!h.A()->closed() || !h.B()->closed())) {
    h.TickAt(h.now + fcp::kSessionTickMs);
  }
  CHECK(h.A()->closed());
  CHECK(h.B()->closed());
  CHECK_EQ(h.eof_a, 1u);
  CHECK_EQ(h.eof_b, 1u);
  CHECK_EQ(h.close_a, 1u);
  CHECK_EQ(h.close_b, 1u);
  CHECK(h.reason_a == fcp::CloseReason::kLocalEof || h.reason_a == fcp::CloseReason::kPeerClose);
  CHECK(h.reason_b == fcp::CloseReason::kLocalEof || h.reason_b == fcp::CloseReason::kPeerClose);
  CheckCarrierClean(h);
}

// Sustained flow with loss on both directions at once: the receive buffers, the
// advertised windows and the set accounting all stay inside their invariants.
void TestSustainedFlowUnderLoss() {
  Link h;
  CHECK(h.Init(3, -1, 64 * 1024, 64 * 1024));
  CHECK(h.Handshake());
  h.loss_enabled = true;
  h.loss_percent = 12;

  const std::vector<uint8_t> src = MakeBytes(200 * 1024, 71);
  CHECK_EQ(h.PushA(src, 40000), src.size());
  CHECK(h.WaitRx(0, src.size(), 60000));

  CHECK(h.rx_b == src);
  CHECK(h.WaitIdle(30000));
  CHECK_EQ(h.A()->bytes_acked(), src.size());
  CHECK_EQ(h.B()->bytes_delivered(), src.size());
  CHECK_EQ(h.B()->oob_bytes(), 0u);
  CHECK(h.B()->peer_window() <= 64 * 1024);
  CHECK(h.a_data > src.size() / 1330u);
  h.Advance(3000);
  CheckCarrierClean(h);

  // Deliveries may never exceed what the receiver can account for, and with the
  // transfer finished plus a full settlement guard no set may still be open.
  CHECK(h.SB()->settle()->delivered_le_sum());
  CHECK_EQ(h.SB()->rx()->active_sets(), 0u);
}

}  // namespace

int main() {
  TestLosslessBothDirections();
  TestRandomLossArqCoversFec();
  TestRandomLossPinnedKRepairs();
  TestBurstLossExceedsFec();
  TestHalfCloseOverSession();
  TestSustainedFlowUnderLoss();
  return fcp_test::finish();
}
