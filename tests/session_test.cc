#include "fcp/session.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/fecstat.h"
#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

const uint8_t kKey[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                          0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
const uint8_t kSalt[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
const uint8_t kSalt2[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

// KCP-like segment: 16 bytes with the sn at offset 12 (dedup key).
Bytes Segment(uint32_t sn) {
  Bytes out(16, 0);
  out[12] = static_cast<uint8_t>(sn);
  out[13] = static_cast<uint8_t>(sn >> 8);
  out[14] = static_cast<uint8_t>(sn >> 16);
  out[15] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 0; i < 12; ++i) {
    out[i] = static_cast<uint8_t>(sn * 31 + i * 7);
  }
  return out;
}

uint32_t SnOf(const Bytes& payload) {
  return static_cast<uint32_t>(payload[12]) |
         (static_cast<uint32_t>(payload[13]) << 8) |
         (static_cast<uint32_t>(payload[14]) << 16) |
         (static_cast<uint32_t>(payload[15]) << 24);
}

fcp::SessionConfig MakeConfig(fcp::Direction send, fcp::Direction recv,
                              const uint8_t* salt = kSalt, int pinned_k = -1) {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, kKey, sizeof(kKey));
  std::memcpy(cfg.salt, salt, sizeof(cfg.salt));
  cfg.send_direction = send;
  cfg.recv_direction = recv;
  cfg.d = 10;
  cfg.p = 3;
  cfg.p_max = fcp::kDefaultPmax;
  cfg.pinned_k = pinned_k;
  return cfg;
}

// R3-1: a hand-made HELLO has to carry a non-zero draw. Sessions still
// draw their own from the CSPRNG, so an ACK built here must echo
// `session.handshake_nonce()` -- see the ACK call sites.
const uint8_t* PeerDraw() {
  static const uint8_t kPeer[fcp::kHandshakeNonceLen] = {
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
  return kPeer;
}

// R3-1: after the handshake the data envelope is keyed by both draws, so a
// test that peeks at a session's output has to derive the same key. Handshake
// messages still use the bootstrap key, hence the plain readers further down.
fcp::Envelope DataReader(fcp::Direction send, fcp::Direction recv,
                         const uint8_t client_nonce[16],
                         const uint8_t server_nonce[16]) {
  fcp::Envelope env(kKey, kSalt, send, recv);
  uint8_t key[16];
  fcp::derive_session_key_v7(kKey, kSalt, client_nonce, server_nonce, key);
  env.rekey(key);
  return env;
}

bool HasLine(const std::vector<std::string>& logs, const std::string& want) {
  for (const std::string& line : logs) {
    if (line == want) {
      return true;
    }
  }
  return false;
}

bool HasPrefix(const std::vector<std::string>& logs, const std::string& prefix) {
  for (const std::string& line : logs) {
    if (line.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

struct FecstatLogFields {
  uint32_t sets = 0;
  uint32_t expect = 0;
  uint32_t rx = 0;
  uint32_t rec = 0;
  uint32_t late = 0;
  uint32_t lost = 0;
  uint32_t pre = 0;
  uint32_t usable = 0;
  unsigned k = 0;
  std::string state;
};

bool ParseFecstatLog(const std::vector<std::string>& logs, FecstatLogFields* out) {
  for (const std::string& line : logs) {
    if (line.rfind("FECSTAT sets=", 0) != 0) {
      continue;
    }
    char state[8] = {};
    const int n = std::sscanf(
        line.c_str(),
        "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u pre=%uppm "
        "usable=%uppm -> k=%u state=%7s",
        &out->sets, &out->expect, &out->rx, &out->rec, &out->late, &out->lost,
        &out->pre, &out->usable, &out->k, state);
    if (n == 10) {
      out->state = state;
      return true;
    }
  }
  return false;
}

// Synchronous in-memory link with per-symbol loss injection. Control and OOB
// datagrams are never dropped so the handshake and FECSTAT cadence stay
// deterministic; data/parity loss drives recovery and the strategy.
struct Link {
  fcp::Session* a = nullptr;
  fcp::Session* b = nullptr;
  bool loss_enabled = false;
  uint32_t loss_percent = 20;
  // Gilbert–Elliott two-state channel (#26, FCP_M3_CONTROL.md §3): Bad drops
  // ge_p_bad percent, Good ge_p_good; per-symbol transitions with the same
  // LCG. Mean loss ≈ (g2b/(g2b+b2g))·p_bad, mean bad stretch ≈ 100/b2g.
  bool ge_enabled = false;
  uint32_t ge_p_good = 0;
  uint32_t ge_p_bad = 50;
  uint32_t ge_g2b = 5;
  uint32_t ge_b2g = 20;
  bool ge_bad = false;
  bool drop_oob_from_b = false;
  uint32_t rng = 0x9E3779B9u;
  int64_t now = 0;

  uint32_t a_data = 0;
  uint32_t a_parity = 0;
  uint32_t a_oob = 0;
  uint32_t a_control = 0;
  uint32_t b_data = 0;
  uint32_t b_parity = 0;
  uint32_t b_oob = 0;
  uint32_t b_control = 0;
  std::vector<Bytes> b_oob_wires;

  bool drop(fcp::SymbolType type) {
    if (!loss_enabled && !ge_enabled) {
      return false;
    }
    if (type != fcp::SymbolType::kData && type != fcp::SymbolType::kParity) {
      return false;
    }
    rng = rng * 1103515245u + 12345u;
    if (ge_enabled) {
      // Data-only (same convention as the socket harness's burst injector):
      // dropping parity here would blind settlement (sets_k_unknown over the
      // trust gate) and turn every report untrusted — the R(k) feedback path
      // we are trying to exercise, not a link property.
      if (type != fcp::SymbolType::kData) {
        return false;
      }
      // Transition roll, then a drop roll — separate draws keep the state
      // chain independent of the per-symbol loss.
      const uint32_t t = (rng >> 16) % 100;
      if (ge_bad) {
        if (t < ge_b2g) {
          ge_bad = false;
        }
      } else if (t < ge_g2b) {
        ge_bad = true;
      }
      rng = rng * 1103515245u + 12345u;
      const uint32_t d = (rng >> 16) % 100;
      return (ge_bad ? d < ge_p_bad : d < ge_p_good);
    }
    return ((rng >> 16) % 100) < loss_percent;
  }

  void from_a(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++a_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++a_parity;
    } else if (type == fcp::SymbolType::kOob) {
      ++a_oob;
    } else {
      ++a_control;
    }
    if (drop(type)) {
      return;
    }
    b->on_wire(wire, len, now);
  }

  void from_b(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++b_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++b_parity;
    } else if (type == fcp::SymbolType::kOob) {
      ++b_oob;
      b_oob_wires.emplace_back(wire, wire + len);
    } else {
      ++b_control;
    }
    if (type == fcp::SymbolType::kOob && drop_oob_from_b) {
      return;
    }
    if (drop(type)) {
      return;
    }
    a->on_wire(wire, len, now);
  }
};

void TestFullLoop() {
  Link link;
  std::vector<std::string> log_a;
  std::vector<std::string> log_b;
  std::vector<Bytes> delivered_b;
  std::vector<Bytes> delivered_a;

  fcp::Session a(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_a(w, n, t); },
      [&delivered_a](const uint8_t* p, size_t n) { delivered_a.emplace_back(p, p + n); },
      [&log_a](const std::string& s) { log_a.push_back(s); });
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_b(w, n, t); },
      [&delivered_b](const uint8_t* p, size_t n) { delivered_b.emplace_back(p, p + n); },
      [&log_b](const std::string& s) { log_b.push_back(s); });
  link.a = &a;
  link.b = &b;

  CHECK(a.config_valid());
  CHECK(b.config_valid());

  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);

  CHECK(a.established());
  CHECK(b.established());
  CHECK_EQ(static_cast<int>(a.params().d), 10);
  CHECK_EQ(static_cast<int>(a.params().p), 3);
  CHECK(a.mode() == fcp::SessionMode::kFramedRepair);
  CHECK_EQ(a.k(), 0);
  CHECK_EQ(a.cached_segments(), 0u);
  CHECK(HasLine(log_a,
                "FCP v6 negotiated: data=10 parity=3 pmax=4 flags=framed,stats (peer V3)"));
  CHECK(HasLine(log_b,
                "FCP v6 negotiated: data=10 parity=3 pmax=4 flags=framed,stats (peer V3)"));

  // Phase 1: 400 segments, k=0, 20% loss. Sets 0..38 account; set 39 is the
  // highest and never becomes eligible (no parity) -> tail drop at 1s.
  link.loss_enabled = true;
  link.now = 0;
  for (uint32_t sn = 0; sn < 400; ++sn) {
    const Bytes seg = Segment(sn);
    a.on_kcp_output(seg.data(), seg.size(), link.now);
  }
  CHECK_EQ(link.a_data, 400u);
  CHECK_EQ(link.a_parity, 0u);

  for (int64_t t = 25; t <= 2000; t += fcp::kSessionTickMs) {
    link.now = t;
    a.on_tick(t);
    b.on_tick(t);
  }

  // b's oob stream: one HELLO_ACK during the handshake, then the FECSTAT sent
  // twice (#28⑤ F3).
  CHECK_EQ(link.b_oob, 3u);
  CHECK(a.strategy() != nullptr);
  CHECK(a.strategy()->state() == fcp::FecState::kOn);
  const uint8_t k1 = a.k();
  CHECK(k1 >= 1);
  CHECK(static_cast<uint8_t>(k1) <= a.params().p);  // k <= P'

  FecstatLogFields first;
  CHECK(ParseFecstatLog(log_a, &first));
  CHECK_EQ(first.state, std::string("ON"));
  CHECK_EQ(static_cast<uint8_t>(first.k), k1);
  CHECK(first.expect >= fcp::kMinSamplePackets);
  CHECK(first.sets > 0);
  CHECK_EQ(static_cast<uint64_t>(first.rx) + first.rec + first.late,
           static_cast<uint64_t>(first.expect) - first.lost);
  CHECK_EQ(first.pre, static_cast<uint32_t>(static_cast<uint64_t>(first.expect - first.rx) *
                                            1000000ull / first.expect));
  CHECK_EQ(first.usable,
           static_cast<uint32_t>(static_cast<uint64_t>(first.expect - first.rx - first.rec) *
                                 1000000ull / first.expect));
  // Spec §10 stats-line fields are exposed by the session.
  CHECK_EQ(a.fecstat_rx(), 1u);  // accepted (kOk) reports only
  CHECK_EQ(a.fecstat_dup(), 1u);  // #28⑤ (F3): second copy ignored as duplicate
  CHECK_EQ(a.last_pre_ppm(), first.pre);
  CHECK_EQ(a.last_usable_ppm(), first.usable);

  // Phase 2: 400 more segments spread 1ms apart so repair latency is non-zero;
  // every set locks the k chosen from the first report.
  const uint32_t parity_before = link.a_parity;
  for (uint32_t sn = 400; sn < 800; ++sn) {
    link.now = 2100 + static_cast<int64_t>(sn - 400);
    const Bytes seg = Segment(sn);
    a.on_kcp_output(seg.data(), seg.size(), link.now);
  }
  CHECK_EQ(link.a_parity - parity_before, 40u * k1);
  CHECK_EQ(a.tx()->data_symbols(), 800u);
  CHECK_EQ(a.tx()->parity_symbols(), 40u * k1);

  for (int64_t t = 2500; t <= 3000; t += fcp::kSessionTickMs) {
    link.now = t;
    a.on_tick(t);
    b.on_tick(t);
  }

  const fcp::SettleCounters& c = b.settle()->counters();
  CHECK_EQ(c.sets_expected, 40u);
  // A set whose parity was fully lost undercounts n by at most its highest
  // data index (§4.5), so expected can trail 400 but never exceed it.
  CHECK(c.data_expected <= 400u);
  CHECK(c.data_expected > 0u);
  CHECK_EQ(c.data_rx_orig < 400u, true);
  CHECK_EQ(c.parity_expected, 40u * k1);
  CHECK(c.parity_rx > 0);
  CHECK(c.parity_rx < 40u * k1);
  CHECK(c.data_recovered_dl > 0);
  CHECK_EQ(c.data_recovered_late, 0u);
  CHECK(b.settle()->identity_ok());
  CHECK(b.settle()->delivered_le_sum());
  CHECK_EQ(b.rx()->data_delivered(), static_cast<uint32_t>(delivered_b.size()));
  CHECK_EQ(b.struct_fail(), 0u);  // no parity index ever exceeded S

  for (const Bytes& payload : delivered_b) {
    CHECK_EQ(payload.size(), 16u);
    CHECK(payload == Segment(SnOf(payload)));
  }

  for (int64_t t = 3025; t <= 4000; t += fcp::kSessionTickMs) {
    link.now = t;
    a.on_tick(t);
    b.on_tick(t);
  }
  CHECK_EQ(link.b_oob, 5u);  // HELLO_ACK + two FECSTATs, each sent twice (#28⑤ F3)

  // Decode the second report end to end and check the fields the design §11
  // line and the strategy rely on. b_oob_wires[0] is the handshake ACK; [1]/[2]
  // are the two copies of report 1, [3]/[4] of report 2 (#28⑤ F3).
  fcp::Envelope reader = DataReader(fcp::Direction::kS2C, fcp::Direction::kS2C,
                                  a.handshake_nonce(), b.handshake_nonce());
  Bytes plain;
  CHECK(reader.open(link.b_oob_wires[3].data(), link.b_oob_wires[3].size(), &plain));
  fcp::FecHdr hdr{};
  CHECK(fcp::parse_hdr(plain.data(), plain.size(), &hdr));
  CHECK(fcp::hdr_type(hdr.type_k) == fcp::SymbolType::kOob);
  CHECK_EQ(hdr.set_id, 0u);  // §4.7: oob headers carry set_id = index = 0
  CHECK_EQ(hdr.index, 0);
  fcp::FecstatPacket pkt{};
  CHECK(fcp::decode_fecstat(plain.data() + fcp::kFecHdrLen,
                            plain.size() - fcp::kFecHdrLen, kSalt,
                            &pkt) == fcp::FecstatStatus::kOk);
  CHECK_EQ(pkt.flg & fcp::kFlgDirection, fcp::kFlgDirection);
  CHECK_EQ(pkt.interval_ms, 2000);
  CHECK_EQ(pkt.sets_expected, 40u);
  CHECK(pkt.data_expected <= 400u);
  CHECK(pkt.data_expected > 0u);
  CHECK_EQ(pkt.parity_expected, 40u * k1);
  CHECK(pkt.data_recovered_dl > 0);
  CHECK(pkt.repair_lat_p50_ms > 0);
  CHECK(pkt.repair_lat_p95_ms >= pkt.repair_lat_p50_ms);

  // The first interval has no parity at all; the byte counters must reflect the
  // inbound wire budget (28B envelope + 6B header + 2B len + 16B payload = 52B).
  fcp::Envelope reader0 = DataReader(fcp::Direction::kS2C, fcp::Direction::kS2C,
                                   a.handshake_nonce(), b.handshake_nonce());
  Bytes plain0;
  CHECK(reader0.open(link.b_oob_wires[1].data(), link.b_oob_wires[1].size(), &plain0));
  fcp::FecHdr hdr0{};
  CHECK(fcp::parse_hdr(plain0.data(), plain0.size(), &hdr0));
  CHECK(fcp::hdr_type(hdr0.type_k) == fcp::SymbolType::kOob);
  CHECK_EQ(hdr0.set_id, 0u);
  fcp::FecstatPacket pkt0{};
  CHECK(fcp::decode_fecstat(plain0.data() + fcp::kFecHdrLen,
                            plain0.size() - fcp::kFecHdrLen, kSalt,
                            &pkt0) == fcp::FecstatStatus::kOk);
  CHECK_EQ(pkt0.parity_bytes_rx, 0u);
  // Every received data datagram is 52 wire bytes; the tail set (never eligible,
  // hence tail-dropped) is billed but not in data_rx_orig.
  CHECK_EQ(pkt0.data_bytes_rx % 52u, 0u);
  CHECK_EQ(pkt0.sets_tail_dropped, 1u);
  const uint32_t rx_total = pkt0.data_bytes_rx / 52u;
  CHECK(rx_total >= pkt0.data_rx_orig);
  CHECK(rx_total <= pkt0.data_rx_orig + 10u);

  CHECK_EQ(a.auth_fail(), 0u);
  CHECK_EQ(a.fecstat_dropped(), 0u);
  CHECK_EQ(a.fecstat_stale(), 0u);
  CHECK_EQ(a.fecstat_rx(), 2u);  // accepted reports (copies are kDuplicate)
  CHECK_EQ(a.fecstat_dup(), 2u);
  CHECK_EQ(b.auth_fail(), 0u);
  // The feedback path is healthy: no §8 "no report" warning.
  CHECK(!HasPrefix(log_a, "FEC WARNING: no FECSTAT"));
}

// Handshake messages travel as oob frames (erratum #25): start() + the first
// tick emit HELLO as type=2 with set_id=index=0, and the KCP output path has no
// content classification — a segment that starts with the HELLO magic is cached
// as ordinary data like any other.
void TestHandshakeRidesOob() {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  fcp::Session s(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&sent](const uint8_t* w, size_t n, fcp::SymbolType t) {
        sent.emplace_back(Bytes(w, w + n), t);
      },
      nullptr, nullptr);

  s.start(0);
  s.on_tick(0);
  CHECK_EQ(sent.size(), 1u);
  CHECK(sent[0].second == fcp::SymbolType::kOob);

  fcp::Envelope reader(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kC2S);
  Bytes plain;
  CHECK(reader.open(sent[0].first.data(), sent[0].first.size(), &plain));
  fcp::FecHdr hdr{};
  CHECK(fcp::parse_hdr(plain.data(), plain.size(), &hdr));
  CHECK(fcp::hdr_type(hdr.type_k) == fcp::SymbolType::kOob);
  CHECK_EQ(hdr.set_id, 0u);
  CHECK_EQ(hdr.index, 0);
  CHECK_EQ(plain.size() - fcp::kFecHdrLen, fcp::kHelloLen);
  CHECK(fcp::is_hello(plain.data() + fcp::kFecHdrLen, plain.size() - fcp::kFecHdrLen));

  // A KCP output segment that happens to start with the HELLO magic is data:
  // it lands in the pre-negotiation cache, no oob is emitted for it.
  uint8_t fake[fcp::kHelloLen];
  fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                   PeerDraw(), fake);
  s.on_kcp_output(fake, sizeof(fake), 0);
  CHECK_EQ(s.cached_segments(), 1u);
  CHECK_EQ(sent.size(), 1u);
}

// T23: the reply to a HELLO is a HELLO_ACK oob frame, type=2 with set_id=index=0,
// and it never touches the collection counters.
void TestHandshakeAckRidesOob() {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&sent](const uint8_t* w, size_t n, fcp::SymbolType t) {
        sent.emplace_back(Bytes(w, w + n), t);
      },
      nullptr, nullptr);
  b.start(0);

  uint8_t hello[fcp::kHelloLen];
  fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                   PeerDraw(), hello);
  Bytes plain(fcp::kFecHdrLen + sizeof(hello));
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      plain.data());
  std::memcpy(plain.data() + fcp::kFecHdrLen, hello, sizeof(hello));

  fcp::Envelope peer(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
  Bytes wire;
  CHECK(peer.seal(plain.data(), plain.size(), &wire));
  b.on_wire(wire.data(), wire.size(), 1);
  CHECK(b.established());
  CHECK_EQ(sent.size(), 1u);
  CHECK(sent[0].second == fcp::SymbolType::kOob);

  // The ACK still rides the bootstrap key: it is sealed before the session key
  // exists, which is exactly why the handshake keeps its own envelope.
  fcp::Envelope reader(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  Bytes ack_plain;
  CHECK(reader.open(sent[0].first.data(), sent[0].first.size(), &ack_plain));
  fcp::FecHdr hdr{};
  CHECK(fcp::parse_hdr(ack_plain.data(), ack_plain.size(), &hdr));
  CHECK(fcp::hdr_type(hdr.type_k) == fcp::SymbolType::kOob);
  CHECK_EQ(hdr.set_id, 0u);
  CHECK_EQ(hdr.index, 0);
  CHECK_EQ(ack_plain.size() - fcp::kFecHdrLen, fcp::kHelloAckLen);
  CHECK(fcp::is_hello_ack(ack_plain.data() + fcp::kFecHdrLen,
                          ack_plain.size() - fcp::kFecHdrLen));
}

// A local codec geometry outside the caps bounds must be refused up front: with
// D' = 0 the sender would divide by zero closing a set.
void TestInvalidLocalCaps() {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  std::vector<std::string> logs;
  fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.d = 0;
  fcp::Session s(
      cfg,
      [&sent](const uint8_t* w, size_t n, fcp::SymbolType t) {
        sent.emplace_back(Bytes(w, w + n), t);
      },
      nullptr, [&logs](const std::string& line) { logs.push_back(line); });

  s.start(0);
  s.on_tick(0);
  CHECK(s.state() == fcp::HandshakeState::kIdle);
  CHECK(sent.empty());
  CHECK(HasLine(logs, "FCP config invalid: local D/P out of range"));

  // A valid peer HELLO may negotiate on paper, but no codec is built either.
  uint8_t hello[fcp::kHelloLen];
  fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                   PeerDraw(), hello);
  Bytes plain(fcp::kFecHdrLen + sizeof(hello));
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      plain.data());
  std::memcpy(plain.data() + fcp::kFecHdrLen, hello, sizeof(hello));
  fcp::Envelope peer(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  Bytes wire;
  CHECK(peer.seal(plain.data(), plain.size(), &wire));
  s.on_wire(wire.data(), wire.size(), 5);
  CHECK(s.tx() == nullptr);
  CHECK(s.rx() == nullptr);

  const Bytes seg = Segment(1);
  s.on_kcp_output(seg.data(), seg.size(), 10);
  CHECK_EQ(s.cached_segments(), 0u);  // already established: nothing is buffered
  CHECK(s.tx() == nullptr);
  s.on_tick(25);
  CHECK(s.tx() == nullptr);
}

// The operator pin is a request: it can never exceed the negotiated P'.
void TestPinnedKClampedToNegotiatedP() {
  Link link;
  std::vector<Bytes> delivered_b;
  fcp::Session a(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C, kSalt, 5),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_a(w, n, t); },
      nullptr, nullptr);
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_b(w, n, t); },
      [&delivered_b](const uint8_t* p, size_t n) { delivered_b.emplace_back(p, p + n); },
      nullptr);
  link.a = &a;
  link.b = &b;

  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK_EQ(static_cast<int>(a.params().p), 3);
  CHECK(a.strategy() != nullptr);
  CHECK(a.strategy()->pinned());
  CHECK_EQ(a.k(), 3);

  link.now = 10;
  for (uint32_t sn = 0; sn < 10; ++sn) {
    const Bytes seg = Segment(sn);
    a.on_kcp_output(seg.data(), seg.size(), link.now);
  }
  CHECK_EQ(link.a_parity, 3u);  // one full set, k_eff = pinned (clamped) k
  CHECK_EQ(delivered_b.size(), 10u);
}

void TestHandshakeTimeout() {
  std::vector<std::string> logs;
  fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C), nullptr,
                 nullptr, [&logs](const std::string& line) { logs.push_back(line); });
  s.start(0);
  s.on_tick(0);
  s.on_tick(300);
  s.on_tick(900);
  CHECK(s.state() == fcp::HandshakeState::kHelloSent);
  s.on_tick(2100);
  CHECK(s.state() == fcp::HandshakeState::kFailed);
  CHECK(s.error() == fcp::HandshakeError::kNoAck);
  CHECK(HasLine(logs, "FEC handshake failed: V4 no ACK after 3 tries"));
}

void TestPreNegotiationCache() {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  fcp::Session s(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&sent](const uint8_t* w, size_t n, fcp::SymbolType t) {
        sent.emplace_back(Bytes(w, w + n), t);
      },
      nullptr, nullptr);

  s.start(0);  // HelloSent; no tick yet, so no HELLO leaves the session
  const Bytes seg = Segment(77);
  s.on_kcp_output(seg.data(), seg.size(), 0);
  CHECK_EQ(s.cached_segments(), 1u);
  CHECK(sent.empty());

  uint8_t ack[fcp::kHelloAckLen];
  fcp::build_hello_ack(
      fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
      s.handshake_nonce(), PeerDraw(), ack);
  Bytes plain(fcp::kFecHdrLen + sizeof(ack));
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      plain.data());
  std::memcpy(plain.data() + fcp::kFecHdrLen, ack, sizeof(ack));

  fcp::Envelope peer(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  Bytes wire;
  CHECK(peer.seal(plain.data(), plain.size(), &wire));
  s.on_wire(wire.data(), wire.size(), 5);

  CHECK(s.established());
  CHECK_EQ(s.cached_segments(), 0u);
  CHECK_EQ(sent.size(), 1u);  // the cached segment is replayed after setup
  CHECK(sent[0].second == fcp::SymbolType::kData);

  fcp::Envelope reader =
      DataReader(fcp::Direction::kC2S, fcp::Direction::kC2S, s.handshake_nonce(),
                 PeerDraw());
  Bytes data_plain;
  CHECK(reader.open(sent[0].first.data(), sent[0].first.size(), &data_plain));
  fcp::FecHdr hdr{};
  CHECK(fcp::parse_hdr(data_plain.data(), data_plain.size(), &hdr));
  CHECK(fcp::hdr_type(hdr.type_k) == fcp::SymbolType::kData);
  CHECK_EQ(hdr.set_id, 0u);
  CHECK_EQ(hdr.index, 0);
  const size_t declared = static_cast<size_t>(data_plain[fcp::kFecHdrLen]) |
                          (static_cast<size_t>(data_plain[fcp::kFecHdrLen + 1]) << 8);
  CHECK_EQ(declared, data_plain.size() - fcp::kFecHdrLen);
  CHECK(std::memcmp(data_plain.data() + fcp::kFecHdrLen + 2, seg.data(), seg.size()) == 0);
}

// §4.5/#23⑤: an authenticated datagram above the MTU budget is struct_fail at
// any handshake state, including before negotiation (where it would otherwise
// be buffered or dropped without a diagnostic).
void TestPreNegotiationMtuReject() {
  fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C), nullptr,
                 nullptr, nullptr);
  s.start(0);
  const size_t symbol_max = s.mtu_limits().symbol_max;
  CHECK(symbol_max > 2);

  const size_t symbol_len = symbol_max + 1;
  Bytes plain(fcp::kFecHdrLen + symbol_len, 0);
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kData))},
      plain.data());
  plain[fcp::kFecHdrLen] = static_cast<uint8_t>(symbol_len & 0xFF);
  plain[fcp::kFecHdrLen + 1] = static_cast<uint8_t>((symbol_len >> 8) & 0xFF);

  fcp::Envelope peer(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  Bytes wire;
  CHECK(peer.seal(plain.data(), plain.size(), &wire));
  s.on_wire(wire.data(), wire.size(), 1);
  CHECK_EQ(s.struct_fail(), 1u);
  CHECK_EQ(s.cached_segments(), 0u);
  CHECK(s.state() == fcp::HandshakeState::kHelloSent);

  // The exact boundary (header + symbol_max) is inside the budget and does not
  // count as a structural failure; it is still dropped, because inbound data
  // cannot be framed before negotiation (§6.2).
  plain.resize(fcp::kFecHdrLen + symbol_max);
  plain[fcp::kFecHdrLen] = static_cast<uint8_t>(symbol_max & 0xFF);
  plain[fcp::kFecHdrLen + 1] = static_cast<uint8_t>((symbol_max >> 8) & 0xFF);
  Bytes wire2;
  CHECK(peer.seal(plain.data(), plain.size(), &wire2));
  s.on_wire(wire2.data(), wire2.size(), 2);
  CHECK_EQ(s.struct_fail(), 1u);
  CHECK_EQ(s.cached_segments(), 0u);
}

// §4.6/T2: oob obeys the path-MTU budget too, and the frozen 128-byte FECSTAT
// is the largest oob. An MTU below 6 + 128 + 28 (envelope) + IP + UDP can
// never carry a report, so start() must refuse it rather than negotiate a
// codec whose feedback path the peer's MTU guard would reject.
void TestMtuMustCarryOob() {
  size_t sent = 0;
  std::vector<std::string> logs;
  auto send = [&sent](const uint8_t*, size_t, fcp::SymbolType) { ++sent; };
  auto log = [&logs](const std::string& line) { logs.push_back(line); };

  fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.mtu = 189;  // IPv4 floor is 190
  fcp::Session small(cfg, send, nullptr, log);
  small.start(0);
  CHECK(small.state() == fcp::HandshakeState::kIdle);
  small.on_tick(0);
  CHECK_EQ(sent, 0u);
  CHECK(HasPrefix(logs, "FCP config invalid: MTU too small"));

  cfg.mtu = 190;
  fcp::Session edge(cfg, send, nullptr, log);
  edge.start(0);
  CHECK(edge.state() == fcp::HandshakeState::kHelloSent);
  edge.on_tick(0);
  CHECK_EQ(sent, 1u);  // HELLO fits (20-byte payload)

  cfg.ip_hdr_len = 40;  // IPv6 floor is 210
  cfg.mtu = 209;
  fcp::Session v6_small(cfg, send, nullptr, log);
  v6_small.start(0);
  CHECK(v6_small.state() == fcp::HandshakeState::kIdle);
  cfg.mtu = 210;
  fcp::Session v6_edge(cfg, send, nullptr, log);
  v6_edge.start(0);
  CHECK(v6_edge.state() == fcp::HandshakeState::kHelloSent);
}

// §6.2: before negotiation only oob may go online. Inbound data/parity frames
// must be dropped, never handed to the handshake cache — that cache holds our
// outbound KCP segments and is replayed into the transmitter, so feeding it
// inbound frames echoed the peer's segment back as our own data.
void TestPreNegotiationInboundDropped() {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  std::vector<Bytes> delivered;
  fcp::Session s(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&sent](const uint8_t* w, size_t n, fcp::SymbolType t) {
        sent.emplace_back(Bytes(w, w + n), t);
      },
      [&delivered](const uint8_t* p, size_t n) { delivered.emplace_back(p, p + n); },
      nullptr);
  s.start(0);

  fcp::Envelope peer(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  auto seal = [&peer](const Bytes& plain) {
    Bytes wire;
    CHECK(peer.seal(plain.data(), plain.size(), &wire));
    return wire;
  };

  // Well-formed data frame from a peer that is already established.
  Bytes data_plain(fcp::kFecHdrLen + 2 + 16, 0);
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kData))},
      data_plain.data());
  data_plain[fcp::kFecHdrLen] = 18;
  std::memcpy(data_plain.data() + fcp::kFecHdrLen + 2, Segment(900).data(), 16);
  const Bytes data_wire = seal(data_plain);
  s.on_wire(data_wire.data(), data_wire.size(), 1);

  // A parity frame is equally premature: no codec exists yet.
  Bytes parity_plain(fcp::kFecHdrLen + 18, 0x5A);
  fcp::pack_hdr(
      fcp::FecHdr{0, 10, fcp::pack_type_k(1, 0, static_cast<uint8_t>(fcp::SymbolType::kParity))},
      parity_plain.data());
  const Bytes parity_wire = seal(parity_plain);
  s.on_wire(parity_wire.data(), parity_wire.size(), 2);

  CHECK_EQ(s.struct_fail(), 0u);  // both frames were structurally valid
  CHECK_EQ(s.cached_segments(), 0u);
  CHECK(sent.empty());  // and neither was echoed back
  CHECK(delivered.empty());

  // Our own outbound segment still buffers and replays after the ACK.
  const Bytes seg = Segment(77);
  s.on_kcp_output(seg.data(), seg.size(), 3);
  CHECK_EQ(s.cached_segments(), 1u);

  uint8_t ack[fcp::kHelloAckLen];
  fcp::build_hello_ack(
      fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
      s.handshake_nonce(), PeerDraw(), ack);
  Bytes ack_plain(fcp::kFecHdrLen + sizeof(ack));
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      ack_plain.data());
  std::memcpy(ack_plain.data() + fcp::kFecHdrLen, ack, sizeof(ack));
  const Bytes ack_wire = seal(ack_plain);
  s.on_wire(ack_wire.data(), ack_wire.size(), 4);

  CHECK(s.established());
  CHECK_EQ(sent.size(), 1u);  // only our segment: nothing was reflected
  CHECK(sent[0].second == fcp::SymbolType::kData);
  fcp::Envelope reader =
      DataReader(fcp::Direction::kC2S, fcp::Direction::kC2S, s.handshake_nonce(),
                 PeerDraw());
  Bytes out_plain;
  CHECK(reader.open(sent[0].first.data(), sent[0].first.size(), &out_plain));
  fcp::FecHdr hdr{};
  CHECK(fcp::parse_hdr(out_plain.data(), out_plain.size(), &hdr));
  CHECK_EQ(hdr.set_id, 0u);
  CHECK_EQ(hdr.index, 0);
  CHECK(std::memcmp(out_plain.data() + fcp::kFecHdrLen + 2, seg.data(), seg.size()) == 0);
  CHECK(delivered.empty());
  CHECK_EQ(s.cached_segments(), 0u);
}

// §8 queue guardrail: "queued" means srtt - min_rtt >= 40ms. min_rtt must be
// the minimum *observed* RTT; a fixed baseline excludes every high-RTT link
// (srtt - 200ms >= 40ms permanently) and pins k at 1. The regression: on a
// 300ms link an ON strategy still grows k toward k_for(loss), and only a
// genuine srtt increase above the observed minimum triggers the guardrail.
void TestQueuedGuardrailUsesObservedMinRtt() {
  fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C), nullptr,
                 nullptr, nullptr);
  s.start(0);

  // Two epochs: the HELLO_ACK rides the bootstrap (psk, salt) envelope, while
  // every FECSTAT after establishment rides the v7 data envelope. `active` is
  // switched right after the ACK — feeding reports through the bootstrap key
  // would make them fail authentication and leave the ledger empty.
  fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kS2C);
  fcp::Envelope* active = &boot;
  auto feed = [&active, &s](const Bytes& plain) {
    Bytes wire;
    CHECK(active->seal(plain.data(), plain.size(), &wire));
    s.on_wire(wire.data(), wire.size(), 10);
  };

  uint8_t ack[fcp::kHelloAckLen];
  fcp::build_hello_ack(
      fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
      s.handshake_nonce(), PeerDraw(), ack);
  Bytes ack_plain(fcp::kFecHdrLen + sizeof(ack));
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      ack_plain.data());
  std::memcpy(ack_plain.data() + fcp::kFecHdrLen, ack, sizeof(ack));
  feed(ack_plain);
  CHECK(s.established());

  fcp::Envelope data_env = DataReader(fcp::Direction::kS2C, fcp::Direction::kS2C,
                                      s.handshake_nonce(), PeerDraw());
  active = &data_env;

  auto report = [&feed](uint32_t key, uint32_t expect, uint32_t rx) {
    fcp::FecstatPacket p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = key;
    p.sets_expected = expect / 10;
    p.data_expected = expect;
    p.data_rx_orig = rx;
    uint8_t packet[fcp::kFecstatLen];
    fcp::encode_fecstat(p, packet);
    Bytes plain(fcp::kFecHdrLen + fcp::kFecstatLen);
    fcp::pack_hdr(
        fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
        plain.data());
    std::memcpy(plain.data() + fcp::kFecHdrLen, packet, sizeof(packet));
    feed(plain);
  };

  s.on_rtt_sample(300);
  CHECK_EQ(s.srtt_ms(), 300);

  report(1, 1000, 980);  // 2%: OFF -> ON at k_for(2%) = 1
  CHECK(s.strategy()->state() == fcp::FecState::kOn);
  CHECK_EQ(s.k(), 1);

  report(2, 1000, 800);  // 20%: not queued -> +1 per report toward 3 (P')
  report(3, 1000, 800);
  report(4, 1000, 800);
  CHECK_EQ(s.k(), 3);

  // A real RTT rise above the observed minimum does engage the guardrail.
  s.on_rtt_sample(350);
  report(5, 1000, 800);
  report(6, 1000, 800);
  CHECK_EQ(s.k(), 3);  // still no growth while queued
  report(7, 1000, 800);
  CHECK_EQ(s.k(), 2);  // third consecutive queued report -> k - 1
}

// Spec §8 "无报告": while outbound data keeps flowing, three local 2s report
// periods without an inbound FECSTAT freeze k and log a single warning.
void TestMissingFecstatWarning() {
  Link link;
  std::vector<std::string> log_a;
  fcp::Session a(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_a(w, n, t); },
      [](const uint8_t*, size_t) {}, [&log_a](const std::string& s) { log_a.push_back(s); });
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_b(w, n, t); },
      nullptr, nullptr);
  link.a = &a;
  link.b = &b;
  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK(b.established());
  link.drop_oob_from_b = true;  // HELLO_ACK landed; feedback path now dead

  uint32_t sn = 0;
  for (int64_t t = fcp::kSessionTickMs; t <= 7000; t += fcp::kSessionTickMs) {
    link.now = t;
    for (int i = 0; i < 16; ++i) {
      const Bytes seg = Segment(sn++);
      a.on_kcp_output(seg.data(), seg.size(), t);
    }
    a.on_tick(t);
    b.on_tick(t);
  }

  CHECK_EQ(a.fecstat_rx(), 0u);
  CHECK_EQ(a.fecstat_dropped(), 0u);
  CHECK_EQ(a.k(), 0);
  CHECK(a.strategy()->state() == fcp::FecState::kOff);
  CHECK_EQ(b.reporter()->reports(), 3u);  // b reported at 2s / 4s / 6s
  int warnings = 0;
  for (const std::string& line : log_a) {
    if (line.rfind("FEC WARNING: no FECSTAT", 0) == 0) {
      ++warnings;
    }
  }
  CHECK_EQ(warnings, 1);
  CHECK(HasLine(log_a, "FEC WARNING: no FECSTAT for 3 report periods, keeping k=0"));
}

void TestSessionTable() {
  fcp::Session a(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C), nullptr,
                 nullptr, nullptr);
  fcp::Session b(MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S, kSalt2), nullptr,
                 nullptr, nullptr);
  fcp::Session clash(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C), nullptr,
                     nullptr, nullptr);

  fcp::SessionTable table;
  CHECK(table.add(&a));
  CHECK(!table.add(&clash));  // same salt already bound
  CHECK(table.add(&b));

  CHECK_EQ(table.size(), 2u);
  CHECK(table.find(kSalt) == &a);
  CHECK(table.find(kSalt2) == &b);

  table.remove(&a);
  CHECK(table.find(kSalt) == nullptr);
  CHECK_EQ(table.size(), 1u);
  table.remove(&a);  // idempotent
  CHECK_EQ(table.size(), 1u);
}

}  // namespace

// Every k the FECSTAT log line announced, in order (T35 trajectory view).
std::vector<unsigned> AllKs(const std::vector<std::string>& logs) {
  std::vector<unsigned> ks;
  FecstatLogFields f;
  for (const std::string& line : logs) {
    if (line.rfind("FECSTAT sets=", 0) != 0) {
      continue;
    }
    char state[8] = {};
    unsigned k = 0;
    if (std::sscanf(line.c_str(),
                    "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u "
                    "pre=%uppm usable=%uppm -> k=%u state=%7s",
                    &f.sets, &f.expect, &f.rx, &f.rec, &f.late, &f.lost, &f.pre,
                    &f.usable, &k, state) == 10) {
      ks.push_back(k);
    }
  }
  return ks;
}

// T35 at injection level (FCP_M3_CONTROL.md §8): two arms at ~10% mean loss,
// different texture. i.i.d. — the ledger confirms the binomial answer, k
// holds at 2. Gilbert–Elliott bursts — the empirical group-failure rate
// exceeds the binomial prediction, p_eff lifts the loss input, and k steps
// to 3 and STAYS there through reports whose plain mean loss would send it
// back to 2 (the ledger, not the mean, holds it up). Deterministic: fixed
// LCG seeds, no wall clock.
void TestLedgerLiftsKUnderBursts() {
  const uint32_t kSegments = 8000;  // 800 full sets ≈ 8 report intervals

  struct ArmResult {
    std::vector<unsigned> ks;
    std::vector<std::string> ledger_lines;
  };
  auto run_arm = [&](bool ge) {
    Link link;
    if (ge) {
      // Bad state drops every data symbol in stretches of mean ~4.5
      // (b2g = 22), entered 3% per symbol: mean loss ≈ 12%, fully clustered —
      // runs of 3-4 land inside single groups and push the empirical
      // group-failure rate at k=2 far above the binomial ~11%, so p_eff
      // crosses the k=3 threshold (≈0.135) on its own.
      link.ge_enabled = true;
      link.ge_p_bad = 100;
      link.ge_b2g = 22;
      link.ge_g2b = 3;
    } else {
      link.loss_enabled = true;
      link.loss_percent = 10;
    }
    std::vector<std::string> log_a;
    std::vector<Bytes> delivered;
    // Both arms start ON at k=2 (the prewarm seed): the first report's ledger
    // then measures a pure k=2 interval, so the k=3 step at report 2 is
    // attributable to p_eff alone, not to a mean-loss rise.
    fcp::SessionConfig cfg_a = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg_a.initial_k = 2;
    fcp::SessionConfig cfg_b = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
    cfg_b.initial_k = 2;
    fcp::Session a(
        cfg_a,
        [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_a(w, n, t); },
        [](const uint8_t*, size_t) {},
        [&log_a](const std::string& s) { log_a.push_back(s); });
    fcp::Session b(
        cfg_b,
        [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_b(w, n, t); },
        [&delivered](const uint8_t* p, size_t n) { delivered.emplace_back(p, p + n); },
        [](const std::string&) {});
    link.a = &a;
    link.b = &b;
    CHECK(a.config_valid());
    CHECK(b.config_valid());
    a.start(0);
    b.start(0);
    a.on_tick(0);
    b.on_tick(0);
    CHECK(a.established());
    CHECK(b.established());

    // Interleave sends and ticks: the report at ~2.1s must reach the sender
    // while segments are still flowing, or every set locks k=0 and the
    // ledger stays empty.
    uint32_t sn = 0;
    for (int64_t t = fcp::kSessionTickMs; t <= 15000; t += fcp::kSessionTickMs) {
      link.now = t;
      while (sn < kSegments && 100 + static_cast<int64_t>(sn) <= t) {
        const Bytes seg = Segment(sn);
        a.on_kcp_output(seg.data(), seg.size(), link.now);
        ++sn;
      }
      a.on_tick(t);
      b.on_tick(t);
    }
    CHECK_EQ(sn, kSegments);
    CHECK(b.settle()->identity_ok());
    CHECK(b.settle()->delivered_le_sum());
    // Every delivered byte is the segment that was sent (RS recovery, no
    // corruption) — spot-check the sn trailer like TestFullLoop does.
    CHECK_EQ(b.rx()->data_delivered(), static_cast<uint32_t>(delivered.size()));
    ArmResult out;
    out.ks = AllKs(log_a);
    for (const std::string& s : log_a) {
      if (s.rfind("FEC ledger: ", 0) == 0) {
        out.ledger_lines.push_back(s);
      }
    }
    return out;
  };

  const ArmResult iid = run_arm(false);
  CHECK(!iid.ks.empty());
  unsigned iid_max = 0;
  for (const unsigned k : iid.ks) {
    iid_max = std::max(iid_max, k);
  }
  CHECK_EQ(iid_max, 2u);  // k_for(0.10) = 2, and the ledger must not lift it

  const ArmResult burst = run_arm(true);
  CHECK(!burst.ks.empty());
  unsigned burst_max = 0;
  for (const unsigned k : burst.ks) {
    burst_max = std::max(burst_max, k);
  }
  CHECK(burst_max >= 3);   // p_eff > binomial answer under clustered loss
  CHECK(burst.ks.back() >= 3);  // and it holds at the end of the run
  // The burst detector saw the texture and the correction actually acted.
  CHECK(burst.ledger_lines.size() >= 3);
  double kl_max = 0.0;
  unsigned applied_max = 0;
  for (const std::string& s : burst.ledger_lines) {
    double kl = 0.0;
    unsigned applied = 0;
    if (std::sscanf(s.c_str(), "FEC ledger: groups=%*u fail=%*uppm k=%*u "
                              "peff=%*lf (binomial %*lf) kl=%lf applied=%u",
                    &kl, &applied) >= 1) {
      kl_max = std::max(kl_max, kl);
      applied_max = std::max(applied_max, applied);
    }
  }
  CHECK(kl_max >= 1.0);       // i.i.d. sits at ~0; this texture is far off
  CHECK(applied_max >= 3);    // p_eff corrections kept applying
}

// #26①/T25: the envelope refuses the 2^32nd packet. The session has to expose
// that state so the host can disconnect instead of leaving a tunnel whose
// every send is silently dropped (engine.cc closes on nonce_exhausted()).
void TestSendNonceExhaustionIsObservable() {
  Link link;
  fcp::Session a(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_a(w, n, t); },
      [](const uint8_t*, size_t) {}, [](const std::string&) {});
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&link](const uint8_t* w, size_t n, fcp::SymbolType t) { link.from_b(w, n, t); },
      [](const uint8_t*, size_t) {}, [](const std::string&) {});
  link.a = &a;
  link.b = &b;
  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK(!a.nonce_exhausted());

  CHECK(a.set_send_nonce(fcp::Envelope::kNonceLimit - 1));
  const uint32_t before = link.a_data;
  const Bytes last = Segment(900);
  a.on_kcp_output(last.data(), last.size(), link.now);
  CHECK_EQ(link.a_data, before + 1);  // the final nonce still seals
  CHECK(a.nonce_exhausted());

  const Bytes refused = Segment(901);
  a.on_kcp_output(refused.data(), refused.size(), link.now);
  CHECK_EQ(link.a_data, before + 1);  // exhausted: nothing leaves the session
}

// R3-1: a recorded handshake must not revive a session.
//
// Phase 1 records every datagram in both directions during a real handshake and
// a few data segments. Phase 2 rebuilds the two sessions with the SAME PSK and
// the SAME salt -- exactly the attacker's input, since the salt is on the wire
// and the PSK is the shared secret he already needs -- and replays the
// recording at them. Under the v6 derivation this re-established the session
// and re-delivered every payload (same key, same IVs, fresh replay window).
// The nonce pair is what makes the replay useless now: the server draws a new
// nonce, so the recorded ciphertext no longer authenticates, and the recorded
// ACK echoes a challenge the fresh client never issued.
void TestReplayCannotReviveSession() {
  std::vector<Bytes> a_to_b;
  std::vector<Bytes> b_to_a;
  std::vector<Bytes> delivered_b;
  fcp::Session* pa = nullptr;
  fcp::Session* pb = nullptr;

  fcp::Session a(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [&](const uint8_t* w, size_t n, fcp::SymbolType) {
        a_to_b.emplace_back(w, w + n);
        if (pb != nullptr) {
          pb->on_wire(w, n, 0);
        }
      },
      [](const uint8_t*, size_t) {}, [](const std::string&) {});
  fcp::Session b(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [&](const uint8_t* w, size_t n, fcp::SymbolType) {
        b_to_a.emplace_back(w, w + n);
        if (pa != nullptr) {
          pa->on_wire(w, n, 0);
        }
      },
      [&delivered_b](const uint8_t* p, size_t n) { delivered_b.emplace_back(p, p + n); },
      [](const std::string&) {});
  pa = &a;
  pb = &b;

  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK(b.established());

  for (uint32_t sn = 0; sn < 8; ++sn) {
    const Bytes seg = Segment(sn);
    a.on_kcp_output(seg.data(), seg.size(), 0);
  }
  for (int64_t t = 25; t <= 400; t += fcp::kSessionTickMs) {
    a.on_tick(t);
    b.on_tick(t);
  }
  CHECK(!delivered_b.empty());   // the honest run delivers
  CHECK(!a_to_b.empty());
  CHECK(!b_to_a.empty());

  // Phase 2: two fresh sessions, same PSK, same salt, replayed transcript.
  std::vector<Bytes> delivered_b2;
  std::vector<Bytes> delivered_a2;
  fcp::Session a2(
      MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
      [](const uint8_t*, size_t, fcp::SymbolType) {},
      [&delivered_a2](const uint8_t* p, size_t n) { delivered_a2.emplace_back(p, p + n); },
      [](const std::string&) {});
  fcp::Session b2(
      MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
      [](const uint8_t*, size_t, fcp::SymbolType) {},
      [&delivered_b2](const uint8_t* p, size_t n) { delivered_b2.emplace_back(p, p + n); },
      [](const std::string&) {});
  a2.start(0);
  b2.start(0);
  a2.on_tick(0);
  b2.on_tick(0);
  for (const Bytes& w : a_to_b) {
    b2.on_wire(w.data(), w.size(), 0);
  }
  for (const Bytes& w : b_to_a) {
    a2.on_wire(w.data(), w.size(), 0);
  }
  for (int64_t t = 25; t <= 400; t += fcp::kSessionTickMs) {
    a2.on_tick(t);
    b2.on_tick(t);
  }

  // The recorded ACK answers a challenge this client never issued, so the echo
  // check rejects it and the client never establishes.
  CHECK(!a2.established());
  CHECK(a2.nonce_mismatch() > 0);
  // The recorded data was sealed under (salt, c_recorded, s_recorded); the
  // fresh server drew a different nonce, so none of it authenticates.
  CHECK(delivered_b2.empty());
  CHECK(delivered_a2.empty());
  CHECK(b2.auth_fail() > 0);
  // The fresh server *does* complete V4 off the replayed HELLO — it is
  // authentic for epoch 1 — but it draws its own nonce, so its v7 session key
  // is not the recorded one and not one byte of recorded data authenticates.
  // That is the whole point: re-keying is what kills the replay, and the echo
  // check is what keeps the client from believing it.
  CHECK(b2.established());

  // Replaying the transcript a second time changes nothing.
  for (const Bytes& w : a_to_b) {
    b2.on_wire(w.data(), w.size(), 0);
  }
  for (int64_t t = 425; t <= 800; t += fcp::kSessionTickMs) {
    a2.on_tick(t);
    b2.on_tick(t);
  }
  CHECK(delivered_b2.empty());
  CHECK(!a2.established());
}

int main() {
  TestFullLoop();
  TestHandshakeRidesOob();
  TestHandshakeAckRidesOob();
  TestInvalidLocalCaps();
  TestPinnedKClampedToNegotiatedP();
  TestHandshakeTimeout();
  TestPreNegotiationCache();
  TestPreNegotiationInboundDropped();
  TestPreNegotiationMtuReject();
  TestMtuMustCarryOob();
  TestQueuedGuardrailUsesObservedMinRtt();
  TestMissingFecstatWarning();
  TestSessionTable();
  TestLedgerLiftsKUnderBursts();
  TestSendNonceExhaustionIsObservable();
  TestReplayCannotReviveSession();
  return fcp_test::finish();
}
