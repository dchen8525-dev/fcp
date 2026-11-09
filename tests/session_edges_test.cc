// Session / handshake / logging edge branches.
//
// The happy paths and the module shape live in session_test.cc and
// handshake_test.cc; defensive_test.cc pins the first layer of reject-junk
// paths. This file adds the remaining branches the release coverage gate needs:
// start() refusal codes, pre-negotiation inbound framing, bootstrap-key and
// stateless-reset edges, post-negotiation FECSTAT status/gate/budget paths,
// PMTUD probe/ack/EMSGSIZE/black-hole edges, SessionTable bookkeeping, the
// handshake state-machine corners, and every status/state pair of the
// session_log helpers. Everything is deterministic: in-memory links, hand
// crafted sealed frames, explicit clocks.

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/fecstat.h"
#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "fcp/log_level.h"
#include "fcp/pmtu.h"
#include "fcp/prewarm.h"
#include "fcp/random.h"
#include "fcp/session.h"
#include "fcp/session_log.h"
#include "fcp/strategy.h"
#include "fcp/wire.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

const uint8_t kKey[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                          0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
const uint8_t kOtherKey[16] = {0x9C, 0x4D, 0x0E, 0x5F, 0x1A, 0x2B, 0x3C, 0x4D,
                               0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5};
const uint8_t kSalt[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
const uint8_t kSaltB[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
const uint8_t kSaltC[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

fcp::SessionConfig MakeConfig(fcp::Direction send, fcp::Direction recv,
                              uint8_t d = 10, uint8_t p = 3,
                              const uint8_t* salt = kSalt) {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, kKey, sizeof(kKey));
  std::memcpy(cfg.salt, salt, sizeof(cfg.salt));
  cfg.send_direction = send;
  cfg.recv_direction = recv;
  cfg.d = d;
  cfg.p = p;
  cfg.p_max = fcp::kDefaultPmax;
  return cfg;
}

const uint8_t* PeerDraw() {
  static const uint8_t kPeer[fcp::kHandshakeNonceLen] = {
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
  return kPeer;
}

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

bool HasPrefix(const std::vector<std::string>& logs, const std::string& prefix) {
  for (const std::string& line : logs) {
    if (fcp::LineBody(line).rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

bool HasText(const std::vector<std::string>& logs, const std::string& text) {
  for (const std::string& line : logs) {
    if (line.find(text) != std::string::npos) {
      return true;
    }
  }
  return false;
}

size_t CountType(const std::vector<std::pair<Bytes, fcp::SymbolType>>& sent,
                 fcp::SymbolType type) {
  size_t n = 0;
  for (const auto& item : sent) {
    if (item.second == type) {
      ++n;
    }
  }
  return n;
}

struct Recorder {
  std::vector<std::pair<Bytes, fcp::SymbolType>> sent;
  std::vector<Bytes> delivered;
  std::vector<std::string> logs;
};

// ---- frame construction / sealing helpers ----

Bytes OobPlain(const uint8_t* body, size_t len) {
  Bytes plain(fcp::kFecHdrLen);
  fcp::pack_hdr(
      fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, static_cast<uint8_t>(fcp::SymbolType::kOob))},
      plain.data());
  if (len != 0) {
    plain.insert(plain.end(), body, body + len);
  }
  return plain;
}

Bytes FramePlain(uint8_t type, uint8_t index, uint32_t set_id, const Bytes& body) {
  Bytes plain(fcp::kFecHdrLen);
  fcp::pack_hdr(fcp::FecHdr{set_id, index, fcp::pack_type_k(0, 0, type)}, plain.data());
  plain.insert(plain.end(), body.begin(), body.end());
  return plain;
}

Bytes Seal(fcp::Envelope& env, const Bytes& plain) {
  Bytes wire;
  CHECK(env.seal(plain.data(), plain.size(), &wire));
  return wire;
}

bool Feed(fcp::Session& s, fcp::Envelope& env, const Bytes& plain, int64_t now_ms) {
  const Bytes wire = Seal(env, plain);
  const bool opened = s.on_wire(wire.data(), wire.size(), now_ms);
  CHECK(opened);
  return opened;
}

bool FeedOob(fcp::Session& s, fcp::Envelope& env, const uint8_t* body, size_t len,
             int64_t now_ms) {
  return Feed(s, env, OobPlain(body, len), now_ms);
}

std::unique_ptr<fcp::Envelope> BootstrapPeer(fcp::Direction send, fcp::Direction recv) {
  return std::make_unique<fcp::Envelope>(kKey, kSalt, send, recv);
}

std::unique_ptr<fcp::Envelope> DataPeer(fcp::Direction peer_send,
                                        const uint8_t client_nonce[16],
                                        const uint8_t server_nonce[16]) {
  uint8_t key[16];
  fcp::derive_session_key_v7(kKey, kSalt, client_nonce, server_nonce, key);
  auto env = std::make_unique<fcp::Envelope>(kKey, kSalt, peer_send,
                                             fcp::Direction::kC2S);
  env->rekey(key);
  return env;
}

// Establish a C2S client with a hand-built ACK that echoes the session's own
// draw. `ack_flags` carries PMTUD when the test needs it.
void EstablishClient(fcp::Session& s, uint8_t ack_flags, uint8_t parity = 3) {
  CHECK_EQ(s.start(0), fcp::Session::StartStatus::kOk);
  s.on_tick(0);
  uint8_t ack[fcp::kHelloAckLen];
  fcp::build_hello_ack(fcp::HandshakeCaps{fcp::kCapsVersion, 10, parity, ack_flags},
                       s.handshake_nonce(), PeerDraw(), ack);
  fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  const Bytes plain = OobPlain(ack, sizeof(ack));
  Bytes wire;
  CHECK(boot.seal(plain.data(), plain.size(), &wire));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK(s.established());
}

// Open a bootstrap-sealed HELLO this session emitted, for TLV inspection.
Bytes OpenSentHello(const Bytes& wire) {
  fcp::Envelope reader(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  CHECK(reader.init_bootstrap_nonce(1u << 16));
  Bytes plain;
  CHECK(reader.open(wire.data(), wire.size(), &plain));
  return plain;
}

bool FindTlv(const Bytes& plain, uint8_t type, Bytes* value) {
  std::vector<fcp::HandshakeTlv> tlvs;
  const size_t off = fcp::kFecHdrLen;
  CHECK(fcp::hello_tlvs(plain.data() + off, plain.size() - off, /*is_ack=*/false, &tlvs));
  for (const auto& tlv : tlvs) {
    if (tlv.type == type) {
      if (value != nullptr) {
        *value = tlv.value;
      }
      return true;
    }
  }
  return false;
}

// ---- 1. kcp_sn_of null arguments ----

void TestKcpSnOfNulls() {
  uint32_t sn = 0x12345678;
  CHECK(!fcp::kcp_sn_of(nullptr, 16, &sn));
  CHECK_EQ(sn, 0x12345678u);

  uint8_t payload[16] = {};
  CHECK(!fcp::kcp_sn_of(payload, sizeof(payload), nullptr));

  CHECK(fcp::kcp_sn_of(payload, sizeof(payload), &sn));
  CHECK_EQ(sn, 0u);

  CHECK(!fcp::kcp_sn_of(payload, 15, &sn));
  CHECK_EQ(sn, 0u);
}

// ---- 2. start() refusal codes ----

void TestStartRefusals() {
  std::vector<std::string> logs;
  auto send = [](const uint8_t*, size_t, fcp::SymbolType) {};
  auto log = [&logs](const std::string& line) { logs.push_back(line); };

  fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);

  cfg.mtu = 189;  // IPv4 floor is 190: 6+128+28+20+8
  logs.clear();
  fcp::Session small(cfg, send, nullptr, log);
  CHECK_EQ(small.start(0), fcp::Session::StartStatus::kBadConfig);
  CHECK(small.state() == fcp::HandshakeState::kIdle);
  CHECK(HasPrefix(logs, "FCP config invalid: MTU too small"));

  cfg.mtu = 190;
  fcp::Session edge(cfg, send, nullptr, log);
  CHECK_EQ(edge.start(0), fcp::Session::StartStatus::kOk);
  CHECK(edge.state() == fcp::HandshakeState::kHelloSent);

  cfg.ip_hdr_len = 40;
  cfg.mtu = 209;
  fcp::Session v6_small(cfg, send, nullptr, log);
  CHECK_EQ(v6_small.start(0), fcp::Session::StartStatus::kBadConfig);
  cfg.mtu = 210;
  fcp::Session v6_edge(cfg, send, nullptr, log);
  CHECK_EQ(v6_edge.start(0), fcp::Session::StartStatus::kOk);

  cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.mtu = 0;
  logs.clear();
  fcp::Session no_mtu(cfg, send, nullptr, log);
  CHECK_EQ(no_mtu.start(0), fcp::Session::StartStatus::kBadConfig);
  CHECK(!no_mtu.config_valid());
  CHECK(HasPrefix(logs, "FCP config invalid: MTU leaves no room"));

  cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.d = 0;
  logs.clear();
  fcp::Session d0(cfg, send, nullptr, log);
  CHECK_EQ(d0.start(0), fcp::Session::StartStatus::kBadConfig);
  CHECK(HasPrefix(logs, "FCP config invalid: local D/P out of range"));

  cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.p = 8;
  fcp::Session p8(cfg, send, nullptr, log);
  CHECK_EQ(p8.start(0), fcp::Session::StartStatus::kBadConfig);

  cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.d = 250;  // 250 + 7 = 257 > 256
  cfg.p = 7;
  fcp::Session dsum(cfg, send, nullptr, log);
  CHECK_EQ(dsum.start(0), fcp::Session::StartStatus::kBadConfig);

  cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.d = 1;
  cfg.p = 0;
  fcp::Session stats_ok(cfg, send, nullptr, log);
  CHECK_EQ(stats_ok.start(0), fcp::Session::StartStatus::kOk);

  // A failed CSPRNG draw fails the session rather than running on a guessable
  // counter start; lifting the injection restores normal start.
  fcp::set_random_failure_injection(true);
  logs.clear();
  fcp::Session entropy(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                      send, nullptr, log);
  CHECK_EQ(entropy.start(0), fcp::Session::StartStatus::kNoEntropy);
  CHECK(HasPrefix(logs, "FCP session refused: OS CSPRNG unavailable"));
  fcp::set_random_failure_injection(false);

  fcp::Session recovered(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                         send, nullptr, log);
  CHECK_EQ(recovered.start(0), fcp::Session::StartStatus::kOk);
}

// ---- 3. prewarm ticket, TLV offer and accessors ----

void TestPrewarmAndStreamTlv() {
  const Bytes ticket(fcp::kPrewarmTlvLen, 0x5A);

  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, nullptr);
    s.set_prewarm_tlv(Bytes(11, 0xAB));  // wrong length: ignored
    s.start(0);
    s.on_tick(0);
    CHECK_EQ(rec.sent.size(), 1u);
    Bytes plain = OpenSentHello(rec.sent[0].first);
    CHECK(!FindTlv(plain, fcp::kTlvTypePrewarm, nullptr));
  }
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, nullptr);
    s.set_prewarm_tlv(ticket);
    s.start(0);
    s.on_tick(0);
    Bytes plain = OpenSentHello(rec.sent[0].first);
    Bytes got;
    CHECK(FindTlv(plain, fcp::kTlvTypePrewarm, &got));
    CHECK(got == ticket);
    CHECK(FindTlv(plain, fcp::kTlvTypeAckV2, nullptr));
  }
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, nullptr);
    s.start(0);  // already HelloSent: staging is ignored from here on
    s.set_prewarm_tlv(ticket);
    s.on_tick(0);
    Bytes plain = OpenSentHello(rec.sent[0].first);
    CHECK(!FindTlv(plain, fcp::kTlvTypePrewarm, nullptr));
  }

  struct Link {
    fcp::Session* a = nullptr;
    fcp::Session* b = nullptr;
    void from_a(const uint8_t* w, size_t n, fcp::SymbolType) { b->on_wire(w, n, 0); }
    void from_b(const uint8_t* w, size_t n, fcp::SymbolType) { a->on_wire(w, n, 0); }
  };

  // Both ends offer the extension: ACK v2 is agreed and the prewarm ticket
  // travels A -> B only.
  {
    Link link;
    Recorder ra;
    Recorder rb;
    fcp::Session a(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_a(w, n, t);
                   }, nullptr, nullptr);
    fcp::Session b(MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
                   [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_b(w, n, t);
                   }, nullptr, nullptr);
    link.a = &a;
    link.b = &b;
    a.set_prewarm_tlv(ticket);
    a.start(0);
    b.start(0);
    a.on_tick(0);
    b.on_tick(0);
    CHECK(a.established());
    CHECK(b.established());
    CHECK(a.stream_ack_v2());
    CHECK(b.stream_ack_v2());
    CHECK(b.peer_prewarm_tlv() == ticket);
    CHECK(a.peer_prewarm_tlv().empty());
    (void)ra;
    (void)rb;
  }

  // Both ends without the ACK-v2 offer and without a ticket: no TLV at all.
  {
    Link link;
    fcp::SessionConfig ca = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::SessionConfig cb = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
    ca.stream_ack_v2 = false;
    cb.stream_ack_v2 = false;
    fcp::Session a(ca, [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_a(w, n, t);
                   }, nullptr, nullptr);
    fcp::Session b(cb, [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_b(w, n, t);
                   }, nullptr, nullptr);
    link.a = &a;
    link.b = &b;
    a.start(0);
    b.start(0);
    a.on_tick(0);
    b.on_tick(0);
    CHECK(a.established());
    CHECK(!a.stream_ack_v2());
    CHECK(!b.stream_ack_v2());
    CHECK(a.peer_prewarm_tlv().empty());
    CHECK(b.peer_prewarm_tlv().empty());
  }

  // A offers ACK v2, B does not: B echoes the TLV bit with an empty block, so
  // the extension negotiates but the type was never offered by both ends.
  {
    Link link;
    fcp::SessionConfig ca = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    fcp::SessionConfig cb = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
    cb.stream_ack_v2 = false;
    fcp::Session a(ca, [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_a(w, n, t);
                   }, nullptr, nullptr);
    fcp::Session b(cb, [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     link.from_b(w, n, t);
                   }, nullptr, nullptr);
    link.a = &a;
    link.b = &b;
    a.start(0);
    b.start(0);
    a.on_tick(0);
    b.on_tick(0);
    CHECK(a.established());
    CHECK(!a.stream_ack_v2());  // negotiated TLV, but ACK v2 not agreed
    CHECK(!b.stream_ack_v2());
    CHECK(a.peer_prewarm_tlv().empty());
    CHECK(b.peer_prewarm_tlv().empty());
  }
}

// ---- 4. pre-negotiation inbound framing ----

void TestPreNegotiationInboundEdges() {
  Recorder rec;
  fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                 [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   rec.sent.emplace_back(Bytes(w, w + n), t);
                 },
                 [&rec](const uint8_t* p, size_t n) {
                   rec.delivered.emplace_back(p, p + n);
                 },
                 nullptr);
  auto boot = BootstrapPeer(fcp::Direction::kS2C, fcp::Direction::kC2S);

  // Plain shorter than the FEC header.
  Feed(s, *boot, Bytes(2, 0), 0);
  // Data symbol shorter than the 2-byte declared length.
  Feed(s, *boot, FramePlain(0, 0, 0, Bytes{1}), 0);
  // Declared length disagrees with the symbol.
  Feed(s, *boot, FramePlain(0, 0, 0, Bytes{5, 0}), 0);
  // Retired type 3.
  Feed(s, *boot, FramePlain(3, 0, 0, Bytes{2, 0}), 0);
  // Structurally valid parity and data: dropped without a struct failure.
  Feed(s, *boot, FramePlain(1, 0, 0, Bytes{2, 0}), 0);
  Feed(s, *boot, FramePlain(0, 0, 0, Bytes{2, 0}), 0);
  // A PMTU-looking oob before negotiation: not a probe yet, so it reaches the
  // FECSTAT validator and is a bad-length drop.
  uint8_t pm[fcp::kPmtuHeaderLen] = {};
  fcp::pmtu_build(fcp::PmtuMessage{fcp::kPmtuProbe, 7, 1450}, pm, sizeof(pm));
  FeedOob(s, *boot, pm, sizeof(pm), 0);
  // An empty oob body is also a bad-length report.
  FeedOob(s, *boot, nullptr, 0, 0);

  CHECK_EQ(s.struct_fail(), 4u);
  CHECK_EQ(s.cached_segments(), 0u);
  CHECK(rec.sent.empty());
  CHECK(rec.delivered.empty());
  CHECK(s.fecstat_dropped() >= 2u);
  CHECK_EQ(s.fecstat_rx(), 0u);
  CHECK(s.strategy() == nullptr);
  CHECK_EQ(s.k(), 0);
}

// ---- 5. bootstrap epoch and stateless-reset edges ----

void TestBootstrapAndResetEdges() {
  // Retried HELLO / short / non-handshake frames on the bootstrap key.
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);

    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    uint8_t hello[fcp::kHelloLen];
    fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                     PeerDraw(), hello);
    Bytes plain = OobPlain(hello, sizeof(hello));
    Bytes wire;
    CHECK(boot.seal_at(10, plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 100));  // bootstrap re-ACK path

    Bytes tiny(2, 0);
    CHECK(boot.seal_at(11, tiny.data(), tiny.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 110));

    fcp::FecstatPacket stat = fcp::MakeFecstatPacket(kSalt);
    uint8_t body[fcp::kFecstatLen];
    fcp::encode_fecstat(stat, body);
    plain = OobPlain(body, sizeof(body));
    CHECK(boot.seal_at(12, plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 120));  // not HELLO/ACK

    plain = FramePlain(0, 0, 0, Bytes(16, 0x33));
    CHECK(boot.seal_at(13, plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 130));  // bootstrap data frame

    CHECK_EQ(s.struct_fail(), 3u);  // short + oob + data
    CHECK(s.established());
  }

  // Bootstrap AEAD budget: 64 probes per second, then silence until the window
  // rolls, even for a correctly sealed retried HELLO.
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);

    for (int i = 0; i < 70; ++i) {
      const Bytes junk(40, static_cast<uint8_t>(i));
      CHECK(!s.on_wire(junk.data(), junk.size(), 1000));
    }
    const uint32_t fails = s.auth_fail();
    CHECK(fails >= 70u);

    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    uint8_t hello[fcp::kHelloLen];
    fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                     PeerDraw(), hello);
    Bytes plain = OobPlain(hello, sizeof(hello));
    Bytes wire;
    CHECK(boot.seal_at(51, plain.data(), plain.size(), &wire));
    CHECK(!s.on_wire(wire.data(), wire.size(), 1000));  // budget exhausted
    CHECK(s.auth_fail() > fails);

    // Next second: the window resets and the same bootstrap epoch is readable.
    CHECK(s.on_wire(wire.data(), wire.size(), 2000));
  }

  // A valid reset after the bootstrap receive window has advanced: the normal
  // open fails on replay, open_reset accepts it, and a replay of the reset is
  // just an auth failure.
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);

    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    uint8_t hello[fcp::kHelloLen];
    fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                     PeerDraw(), hello);
    Bytes plain = OobPlain(hello, sizeof(hello));
    Bytes wire;
    CHECK(boot.seal_at(5000, plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 100));

    const uint8_t reset[8] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
    fcp::Envelope reset_env(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    Bytes reset_wire;
    CHECK(reset_env.seal(reset, sizeof(reset), &reset_wire));
    CHECK(s.on_wire(reset_wire.data(), reset_wire.size(), 200));
    CHECK(s.peer_dead());
    CHECK(HasText(rec.logs, "stateless reset"));

    CHECK(!s.on_wire(reset_wire.data(), reset_wire.size(), 210));
    CHECK(s.peer_dead());
  }

  // A reset sealed with the wrong key never reaches open_reset.
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);
    const uint8_t reset[8] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
    fcp::Envelope wrong(kOtherKey, kSalt, fcp::Direction::kS2C,
                        fcp::Direction::kC2S);
    Bytes wire;
    CHECK(wrong.seal(reset, sizeof(reset), &wire));
    CHECK(!s.on_wire(wire.data(), wire.size(), 300));
    CHECK(!s.peer_dead());
    CHECK(s.auth_fail() > 0u);
  }

  // The server side ignores a reset aimed at it.
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kOk);
    s.on_tick(0);
    uint8_t hello[fcp::kHelloLen];
    fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                     PeerDraw(), hello);
    Bytes plain = OobPlain(hello, sizeof(hello));
    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
    Bytes wire;
    CHECK(boot.seal(plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 0));
    CHECK(s.established());

    // Advance the bootstrap receive window with a valid client HELLO.
    CHECK(boot.seal_at(5000, plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 100));

    const uint8_t reset[8] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
    fcp::Envelope reset_env(kKey, kSalt, fcp::Direction::kC2S,
                            fcp::Direction::kS2C);
    Bytes reset_wire;
    CHECK(reset_env.seal(reset, sizeof(reset), &reset_wire));
    const uint32_t fails = s.auth_fail();
    CHECK(!s.on_wire(reset_wire.data(), reset_wire.size(), 200));
    CHECK(!s.peer_dead());
    CHECK(s.auth_fail() > fails);
  }
}

// ---- 6. amplification bound and nonce exhaustion ----

void TestAmplificationAndNonceExhaustion() {
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kOk);
    s.on_tick(0);  // first HELLO is exempt (no inbound bytes yet)

    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    Bytes tiny(2, 0);
    Feed(s, boot, tiny, 0);  // 30 inbound bytes -> 90-byte reply allowance

    s.on_tick(250);
    s.on_tick(750);
    s.on_tick(1750);
    CHECK_EQ(rec.sent.size(), 1u);  // every retry is suppressed
    CHECK_EQ(s.amp_limited_drops(), 3u);
    CHECK(HasText(rec.logs, "amplification bound hit"));
  }

  {
    Recorder rec;
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.key_update = false;
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);
    CHECK(s.set_send_nonce(fcp::Envelope::kNonceLimit - 1));
    CHECK(!s.nonce_exhausted());

    const Bytes seg = Segment(1);
    s.on_kcp_output(seg.data(), seg.size(), 10);
    CHECK(s.nonce_exhausted());
    CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kData), 1u);

    s.on_kcp_output(seg.data(), seg.size(), 20);
    CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kData), 1u);
    s.on_kcp_output(seg.data(), seg.size(), 30);
    CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kData), 1u);

    size_t exhausted_logs = 0;
    for (const std::string& line : rec.logs) {
      if (fcp::LineBody(line).rfind("FCP session exhausted nonce space", 0) == 0) {
        ++exhausted_logs;
      }
    }
    CHECK_EQ(exhausted_logs, 1u);
  }
}

// ---- 7. FECSTAT validator statuses ----

void TestFecstatStatuses() {
  Recorder rec;
  fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                 [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   rec.sent.emplace_back(Bytes(w, w + n), t);
                 },
                 nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
  EstablishClient(s, fcp::kLocalFlagsM1);
  auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());

  auto packet = [](uint32_t key, uint32_t expect, uint32_t rx) {
    fcp::FecstatPacket p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = key;
    p.sets_expected = 100;
    p.data_expected = expect;
    p.data_rx_orig = rx;
    return p;
  };
  auto bytes_of = [](const fcp::FecstatPacket& p) {
    uint8_t buf[fcp::kFecstatLen];
    fcp::encode_fecstat(p, buf);
    return Bytes(buf, buf + sizeof(buf));
  };

  const Bytes report10 = bytes_of(packet(10, 1000, 980));
  FeedOob(s, *data, report10.data(), report10.size(), 10);
  CHECK_EQ(s.fecstat_rx(), 1u);
  CHECK_EQ(s.fecstat_dup(), 0u);

  FeedOob(s, *data, report10.data(), report10.size(), 20);  // exact repeat
  CHECK_EQ(s.fecstat_dup(), 1u);
  CHECK_EQ(s.fecstat_rx(), 1u);

  const Bytes report8 = bytes_of(packet(8, 1000, 980));
  FeedOob(s, *data, report8.data(), report8.size(), 30);
  CHECK_EQ(s.fecstat_stale(), 1u);
  CHECK_EQ(s.fecstat_dropped(), 1u);

  const Bytes report11 = bytes_of(packet(11, 1000, 960));
  FeedOob(s, *data, report11.data(), report11.size(), 40);
  CHECK_EQ(s.fecstat_rx(), 2u);

  const uint8_t one_byte = 0xAA;
  FeedOob(s, *data, &one_byte, 1, 50);  // bad length
  const Bytes zeros(fcp::kFecstatLen, 0);
  FeedOob(s, *data, zeros.data(), zeros.size(), 60);  // bad magic
  const Bytes bad_salt = bytes_of(fcp::MakeFecstatPacket(kSaltB));
  FeedOob(s, *data, bad_salt.data(), bad_salt.size(), 70);  // bad salt
  fcp::FecstatPacket bad_ver = packet(13, 1000, 980);
  bad_ver.ver = 2;
  const Bytes bad_ver_bytes = bytes_of(bad_ver);
  FeedOob(s, *data, bad_ver_bytes.data(), bad_ver_bytes.size(), 80);  // bad version

  const uint32_t future = 11u + fcp::kFecstatMaxForwardSets + 1u;
  const Bytes report_future = bytes_of(packet(future, 1000, 980));
  FeedOob(s, *data, report_future.data(), report_future.size(), 90);  // stale

  CHECK_EQ(s.fecstat_rx(), 2u);
  CHECK_EQ(s.fecstat_dup(), 1u);
  CHECK_EQ(s.fecstat_stale(), 2u);  // behind + implausible forward jump
  CHECK_EQ(s.fecstat_dropped(), 6u);
  CHECK(HasText(rec.logs, "reason=bad_length"));
  CHECK(HasText(rec.logs, "reason=bad_magic"));
  CHECK(HasText(rec.logs, "reason=bad_salt"));
  CHECK(HasText(rec.logs, "reason=bad_ver"));
  CHECK(HasText(rec.logs, "reason=stale"));

  // An accepted report before negotiate has no strategy to feed: counted and
  // discarded, not an error.
  {
    Recorder r2;
    fcp::Session pre(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                     nullptr, nullptr, nullptr);
    auto boot = BootstrapPeer(fcp::Direction::kS2C, fcp::Direction::kC2S);
    const Bytes report = bytes_of(packet(50, 1000, 980));
    FeedOob(pre, *boot, report.data(), report.size(), 0);
    CHECK_EQ(pre.fecstat_rx(), 0u);
    CHECK_EQ(pre.fecstat_dropped(), 0u);
    CHECK(pre.strategy() == nullptr);
    CHECK_EQ(pre.k(), 0);
  }
}

// ---- 8. sample gates, trace, ledger and budget transitions ----

void TestFecstatGatesLogsAndBudget() {
  // Gates + raw counters + trace.
  {
    Recorder rec;
    std::vector<fcp::TraceEntry> traces;
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.trace = [&traces](const fcp::TraceEntry& entry) { traces.push_back(entry); };
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);
    auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());

    auto bytes_of = [](const fcp::FecstatPacket& p) {
      uint8_t buf[fcp::kFecstatLen];
      fcp::encode_fecstat(p, buf);
      return Bytes(buf, buf + sizeof(buf));
    };
    auto p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = 1;
    p.sets_expected = 10;
    p.sets_k_unknown = 2;  // > 10%
    p.data_expected = 1000;
    p.data_rx_orig = 980;
    Bytes body = bytes_of(p);
    FeedOob(s, *data, body.data(), body.size(), 10);
    CHECK_EQ(s.fecstat_rx(), 1u);
    CHECK(HasText(rec.logs, "FEC sample untrusted"));

    p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = 2;
    p.sets_expected = 10;
    p.data_expected = 100;  // below kMinSamplePackets
    p.data_rx_orig = 90;
    body = bytes_of(p);
    FeedOob(s, *data, body.data(), body.size(), 20);
    CHECK(HasText(rec.logs, "FEC sample too small"));

    p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = 3;
    p.sets_expected = 100;
    p.data_expected = 1000;
    p.data_rx_orig = 950;
    p.data_recovered_dl = 30;
    p.data_late_rx = 5;
    p.data_bytes_rx = 200;
    p.parity_bytes_rx = 40;
    body = bytes_of(p);
    FeedOob(s, *data, body.data(), body.size(), 30);
    CHECK_EQ(s.last_pre_ppm(), 50000u);      // 50 / 1000
    CHECK_EQ(s.last_usable_ppm(), 20000u);   // 20 / 1000
    CHECK_EQ(s.last_peer_expected(), 1000u);
    CHECK_EQ(s.last_peer_lost(), 50u);
    CHECK(HasText(rec.logs, "FECSTAT sets=100"));

    // Peer claims more received than expected, and no byte evidence: both
    // subtraction branches clamp to zero.
    p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = 4;
    p.sets_expected = 100;
    p.data_expected = 300;
    p.data_rx_orig = 350;
    p.data_recovered_dl = 20;
    p.data_late_rx = 0;
    p.data_bytes_rx = 0;
    p.parity_bytes_rx = 5;
    body = bytes_of(p);
    FeedOob(s, *data, body.data(), body.size(), 40);
    CHECK_EQ(s.last_pre_ppm(), 0u);
    CHECK_EQ(s.last_usable_ppm(), 0u);
    CHECK_EQ(s.last_peer_lost(), 0u);
    CHECK_EQ(s.fecstat_rx(), 4u);

    CHECK_EQ(traces.size(), 4u);
    CHECK_EQ(traces.back().stat.accounted_through_set_id, 4u);
    CHECK_EQ(static_cast<int>(traces.back().snapshot.d), 10);
  }

  // Ledger active / skipped.
  {
    Recorder rec;
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.initial_k = 2;
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);
    CHECK(s.strategy()->state() == fcp::FecState::kOn);
    CHECK_EQ(s.k(), 2);
    auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());
    auto bytes_of = [](const fcp::FecstatPacket& p) {
      uint8_t buf[fcp::kFecstatLen];
      fcp::encode_fecstat(p, buf);
      return Bytes(buf, buf + sizeof(buf));
    };

    auto ledger_packet = [](uint32_t key, uint32_t groups, uint8_t k_meta) {
      fcp::FecstatPacket p = fcp::MakeFecstatPacket(kSalt);
      p.flg = fcp::kFlgDirection | fcp::kFlgLedger;
      p.interval_ms = 2000;
      p.accounted_through_set_id = key;
      p.sets_expected = 100;
      p.data_expected = 1000;
      p.data_rx_orig = 980;
      p.ledger_groups = groups;
      p.ledger_fail_ppm = 100000;
      p.ledger_meta = k_meta | (100u << 16);
      return p;
    };

    Bytes body = bytes_of(ledger_packet(1, 100, 2));  // k matches the running k
    FeedOob(s, *data, body.data(), body.size(), 10);
    CHECK(s.strategy()->ledger_active());
    CHECK(s.strategy()->last_p_eff() > 0.0);
    CHECK(HasText(rec.logs, "FEC ledger:"));

    body = bytes_of(ledger_packet(2, 10, 2));  // too few groups
    FeedOob(s, *data, body.data(), body.size(), 20);
    CHECK(!s.strategy()->ledger_active());
    CHECK(s.strategy()->ledger_skipped() >= 1u);

    body = bytes_of(ledger_packet(3, 100, 5));  // k mismatch
    FeedOob(s, *data, body.data(), body.size(), 30);
    CHECK(s.strategy()->ledger_skipped() >= 2u);

    size_t ledger_lines = 0;
    for (const std::string& line : rec.logs) {
      if (fcp::LineBody(line).rfind("FEC ledger:", 0) == 0) {
        ++ledger_lines;
      }
    }
    CHECK_EQ(ledger_lines, 1u);
  }

  // Budget: ON -> Capped, Capped -> ON, then five clean reports ON -> OFF.
  {
    Recorder rec;
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.initial_k = 2;
    cfg.fec_budget = 0.10;
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    EstablishClient(s, fcp::kLocalFlagsM1);
    CHECK(s.strategy()->state() == fcp::FecState::kOn);
    auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());
    auto bytes_of = [](const fcp::FecstatPacket& p) {
      uint8_t buf[fcp::kFecstatLen];
      fcp::encode_fecstat(p, buf);
      return Bytes(buf, buf + sizeof(buf));
    };
    auto budget_packet = [](uint32_t key, uint32_t data_bytes, uint32_t parity_bytes,
                            uint32_t expect, uint32_t rx) {
      fcp::FecstatPacket p = fcp::MakeFecstatPacket(kSalt);
      p.flg = fcp::kFlgDirection;
      p.interval_ms = 2000;
      p.accounted_through_set_id = key;
      p.sets_expected = 100;
      p.data_expected = expect;
      p.data_rx_orig = rx;
      p.data_bytes_rx = data_bytes;
      p.parity_bytes_rx = parity_bytes;
      return p;
    };

    Bytes body = bytes_of(budget_packet(1, 100, 60, 300, 300));
    FeedOob(s, *data, body.data(), body.size(), 10);
    CHECK(s.strategy()->state() == fcp::FecState::kCapped);
    CHECK_EQ(s.k(), 1);
    CHECK(HasText(rec.logs, "FEC capped:"));

    body = bytes_of(budget_packet(2, 100, 1, 300, 300));
    FeedOob(s, *data, body.data(), body.size(), 20);
    CHECK(s.strategy()->state() == fcp::FecState::kOn);
    CHECK(HasText(rec.logs, "FEC budget restored:"));

    for (uint32_t key = 3; key <= 7; ++key) {
      body = bytes_of(budget_packet(key, 0, 0, 300, 300));
      FeedOob(s, *data, body.data(), body.size(), static_cast<int64_t>(key) * 10);
    }
    CHECK(s.strategy()->state() == fcp::FecState::kOff);
    CHECK_EQ(s.k(), 0);
    CHECK(HasText(rec.logs, "FEC off: pre<0.30%"));
  }
}

// ---- 9. RTT baseline expiry and queue guardrail ----

void TestRttBaselineExpiry() {
  {
    Recorder rec;
    fcp::Session s(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C),
                   nullptr, nullptr, nullptr);
    s.on_rtt_sample(0);
    s.on_rtt_sample(-5);
    CHECK_EQ(s.srtt_ms(), fcp::kDefaultSrttMs);
    s.on_rtt_sample(50);
    CHECK_EQ(s.srtt_ms(), 50);
  }

  {
    Recorder rec;
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.initial_k = 2;
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, nullptr);
    EstablishClient(s, fcp::kLocalFlagsM1);
    CHECK_EQ(s.k(), 2);

    s.on_rtt_sample(100, 1000);   // baseline 100, stamped at 1000
    s.on_rtt_sample(300, 2000);   // not expired: baseline stays 100 (queued)
    CHECK_EQ(s.srtt_ms(), 300);
    s.on_rtt_sample(300, 12000);  // expired (>=10s): baseline follows to 300

    auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());
    fcp::FecstatPacket p = fcp::MakeFecstatPacket(kSalt);
    p.flg = fcp::kFlgDirection;
    p.interval_ms = 2000;
    p.accounted_through_set_id = 1;
    p.sets_expected = 100;
    p.data_expected = 1000;
    p.data_rx_orig = 800;  // 20% loss -> k_for(...) = 3 at P'=3
    uint8_t body[fcp::kFecstatLen];
    fcp::encode_fecstat(p, body);
    FeedOob(s, *data, body, sizeof(body), 13000);
    CHECK_EQ(s.k(), 3);  // grew: the stale min baseline no longer queues us
  }
}

// ---- 10. SessionTable bookkeeping ----

void TestSessionTableEdges() {
  fcp::Session a(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C,
                           10, 3, kSalt),
                 nullptr, nullptr, nullptr);
  fcp::Session a_same_salt(MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C,
                                     10, 3, kSalt),
                           nullptr, nullptr, nullptr);
  fcp::Session b(MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S,
                           10, 3, kSaltB),
                 nullptr, nullptr, nullptr);

  fcp::SessionTable table;
  CHECK(!table.add(nullptr));
  table.remove(nullptr);
  CHECK(table.find(nullptr) == nullptr);
  CHECK_EQ(table.size(), 0u);

  CHECK(table.add(&a));
  CHECK(!table.add(&a));           // same pointer, same key
  CHECK(!table.add(&a_same_salt));  // one salt, one session
  CHECK(table.add(&b));
  CHECK_EQ(table.size(), 2u);

  CHECK(table.find(kSalt) == &a);
  CHECK(table.find(kSaltB) == &b);
  CHECK(table.find(kSaltC) == nullptr);

  table.remove(&a_same_salt);  // key found, pointer differs: keep `a`
  CHECK(table.find(kSalt) == &a);
  table.remove(&a);
  CHECK(table.find(kSalt) == nullptr);
  CHECK_EQ(table.size(), 1u);

  table.remove(&b);
  CHECK_EQ(table.size(), 0u);
}

// ---- 11. ensure_configured refusals and cache overflow ----

void TestEnsureConfiguredRefusals() {
  auto feed_hello = [](fcp::Session& s, fcp::Direction peer_send,
                        fcp::Direction peer_recv) {
    uint8_t hello[fcp::kHelloLen];
    fcp::build_hello(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3, fcp::kLocalFlagsM1},
                     PeerDraw(), hello);
    Bytes plain = OobPlain(hello, sizeof(hello));
    fcp::Envelope boot(kKey, kSalt, peer_send, peer_recv);
    Bytes wire;
    CHECK(boot.seal(plain.data(), plain.size(), &wire));
    CHECK(s.on_wire(wire.data(), wire.size(), 0));
    CHECK(s.established());
  };

  // MTU too small for the largest oob: the handshake can still establish, but
  // no codec is ever built.
  {
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.mtu = 189;
    Recorder rec;
    fcp::Session s(cfg,
                   [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                     rec.sent.emplace_back(Bytes(w, w + n), t);
                   },
                   nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kBadConfig);
    feed_hello(s, fcp::Direction::kS2C, fcp::Direction::kC2S);
    CHECK(s.tx() == nullptr);
    CHECK(s.rx() == nullptr);
    CHECK_EQ(s.config_valid(), true);  // limits are fine; only the oob floor fails
    s.flush_report(25);                 // no reporter: no-op
    CHECK_EQ(s.dup_after_recovered(), 0u);
    const Bytes seg = Segment(1);
    s.on_kcp_output(seg.data(), seg.size(), 10);
    CHECK_EQ(s.cached_segments(), 0u);  // established: not buffered either
    s.on_tick(25);
    CHECK(s.tx() == nullptr);
  }

  // limits_.valid false (mtu 0) and local caps invalid (d = 0) both block the
  // codec even though negotiation itself succeeds.
  {
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.mtu = 0;
    fcp::Session s(cfg, nullptr, nullptr, nullptr);
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kBadConfig);
    feed_hello(s, fcp::Direction::kS2C, fcp::Direction::kC2S);
    CHECK(s.tx() == nullptr);
    CHECK_EQ(s.config_valid(), false);
  }
  {
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.d = 0;
    fcp::Session s(cfg, nullptr, nullptr, nullptr);
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kBadConfig);
    feed_hello(s, fcp::Direction::kS2C, fcp::Direction::kC2S);
    CHECK(s.tx() == nullptr);
    CHECK_EQ(static_cast<int>(s.params().d), 0);
  }

  // Cache overflow fails the handshake and logs once.
  {
    fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
    cfg.handshake_cache_segments = 1;
    cfg.handshake_cache_bytes = 64;
    Recorder rec;
    fcp::Session s(cfg, nullptr, nullptr,
                   [&rec](const std::string& l) { rec.logs.push_back(l); });
    CHECK_EQ(s.start(0), fcp::Session::StartStatus::kOk);
    const Bytes seg = Segment(1);
    s.on_kcp_output(seg.data(), seg.size(), 0);
    CHECK_EQ(s.cached_segments(), 1u);
    s.on_kcp_output(seg.data(), seg.size(), 1);
    CHECK(s.state() == fcp::HandshakeState::kFailed);
    CHECK(s.error() == fcp::HandshakeError::kCacheOverflow);
    CHECK_EQ(s.cached_segments(), 0u);
    CHECK(HasPrefix(rec.logs, "FEC handshake failed: pre-negotiation data cache overflow"));

    s.on_kcp_output(seg.data(), seg.size(), 2);  // failed: silently dropped
    CHECK_EQ(s.cached_segments(), 0u);

    // Inbound data on a failed handshake is dropped without a struct count.
    const uint32_t before = s.struct_fail();
    fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
    Feed(s, boot, FramePlain(0, 0, 0, Bytes{2, 0}), 3);
    CHECK_EQ(s.struct_fail(), before);
  }
}

// ---- 12. PMTUD probe/ack and kernel-refusal edges ----

void TestPmtuHandlingEdges() {
  Recorder rec;
  fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  cfg.pmtud = true;
  cfg.pmtu_max_mtu = 1500;
  fcp::Session s(cfg,
                 [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   rec.sent.emplace_back(Bytes(w, w + n), t);
                 },
                 nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
  EstablishClient(s, static_cast<uint8_t>(fcp::kLocalFlagsM1 | fcp::kCapPmtud));
  CHECK(!s.pmtu_search_done());

  auto data = DataPeer(fcp::Direction::kS2C, s.handshake_nonce(), PeerDraw());
  auto probe_plain = [&](uint16_t mtu, uint32_t token, bool pad) {
    fcp::PmtuMessage msg{fcp::kPmtuProbe, token, mtu};
    Bytes body = pad ? Bytes(fcp::pmtu_probe_len(mtu, 20)) : Bytes(fcp::kPmtuHeaderLen);
    fcp::pmtu_build(msg, body.data(), body.size());
    return OobPlain(body.data(), body.size());
  };

  // A correctly sized probe raises the receive bound and is acked.
  const size_t oob_before = CountType(rec.sent, fcp::SymbolType::kOob);
  Feed(s, *data, probe_plain(1450, 0x1111, true), 10);
  CHECK_EQ(s.recv_symbol_max(),
           fcp::pmtu_udp_payload(1450, 20) - fcp::Envelope::kOverhead - fcp::kFecHdrLen);
  CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kOob), oob_before + 1u);
  CHECK_EQ(s.struct_fail(), 0u);

  // A probe whose datagram is shorter than the size it advertises is a
  // structural failure.
  Feed(s, *data, probe_plain(1450, 0x2222, false), 20);
  CHECK_EQ(s.struct_fail(), 1u);

  // Out-of-range probes are consumed silently.
  Feed(s, *data, probe_plain(1400, 0x3333, false), 30);  // <= configured base
  Feed(s, *data, probe_plain(1501, 0x4444, false), 40);  // > local ceiling
  CHECK_EQ(s.struct_fail(), 1u);

  // An unmatched ack token is ignored.
  fcp::PmtuMessage ack{fcp::kPmtuAck, 0xBEEF, 1450};
  Bytes ack_body(fcp::kPmtuHeaderLen);
  fcp::pmtu_build(ack, ack_body.data(), ack_body.size());
  Feed(s, *data, OobPlain(ack_body.data(), ack_body.size()), 50);
  CHECK_EQ(s.pmtu_probes_acked(), 0u);
  CHECK_EQ(s.struct_fail(), 1u);

  // One tick sends a probe (srtt default 200 -> 1000ms spacing); the kernel
  // then refuses a bulk datagram at the current bound, cancelling the probe.
  s.on_tick(1025);
  CHECK_EQ(s.pmtu_probes_sent(), 1u);
  s.on_kernel_send_too_big(1372, 1100);  // IP 1400 == the bound, step to 1380
  CHECK_EQ(s.path_mtu(), 1380u);
  CHECK_EQ(s.pmtu_probes_lost(), 1u);
  CHECK_EQ(s.payload_max(), fcp::compute_mtu_limits(1380, 20).payload_max);

  // A refusal above the bound only feeds the ledger.
  s.on_kernel_send_too_big(1462, 1125);  // IP 1490 > 1380
  CHECK_EQ(s.path_mtu(), 1380u);
  CHECK_EQ(s.payload_max(), fcp::compute_mtu_limits(1380, 20).payload_max);

  // A target below the codec floor is refused without touching the bound.
  s.on_kernel_send_too_big(52, 1150);  // IP 80, target 60 -> invalid limits
  CHECK_EQ(s.path_mtu(), 1380u);

  // payload_max == 0 (config invalid): the kernel refusal is ignored outright.
  fcp::SessionConfig zero = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  zero.mtu = 0;
  fcp::Session z(zero, nullptr, nullptr, nullptr);
  z.on_kernel_send_too_big(100, 0);
  CHECK_EQ(z.path_mtu(), 0u);
}

// ---- 13. PMTUD black-hole fallback and re-climb clamp ----

void TestPmtuBlackholeAndClamp() {
  struct Link {
    fcp::Session* a = nullptr;
    fcp::Session* b = nullptr;
    bool drop_oob_from_b = false;
    void from_a(const uint8_t* w, size_t n, fcp::SymbolType) { b->on_wire(w, n, 0); }
    void from_b(const uint8_t* w, size_t n, fcp::SymbolType t) {
      if (drop_oob_from_b && t == fcp::SymbolType::kOob) {
        return;
      }
      a->on_wire(w, n, 0);
    }
  };

  fcp::SessionConfig ca = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C);
  fcp::SessionConfig cb = MakeConfig(fcp::Direction::kS2C, fcp::Direction::kC2S);
  ca.pmtud = true;
  cb.pmtud = true;
  ca.pmtu_max_mtu = 3000;
  cb.pmtu_max_mtu = 3000;

  Link link;
  std::vector<std::string> log_a;
  fcp::Session a(ca,
                 [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   link.from_a(w, n, t);
                 }, nullptr, [&log_a](const std::string& l) { log_a.push_back(l); });
  fcp::Session b(cb,
                 [&link](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   link.from_b(w, n, t);
                 }, nullptr, nullptr);
  link.a = &a;
  link.b = &b;

  // A 1000ms SRTT puts probe spacing at 5s and lets the watchdog line up with
  // a probe send.
  a.on_rtt_sample(1000);
  a.start(0);
  b.start(0);
  a.on_tick(0);
  b.on_tick(0);
  CHECK(a.established());
  CHECK(b.established());
  CHECK_EQ(a.path_mtu(), 1400u);

  a.on_tick(5000);
  CHECK_EQ(a.path_mtu(), 2200u);
  CHECK_EQ(a.pmtu_probes_acked(), 1u);
  a.on_tick(10000);
  CHECK_EQ(a.path_mtu(), 2600u);
  CHECK_EQ(a.pmtu_probes_acked(), 2u);

  // Bulk at the raised size disappears while probes still answer; 300 symbols
  // over 6+ seconds with no feedback is the watchdog condition.
  for (uint32_t sn = 0; sn < 300; ++sn) {
    const Bytes seg = Segment(sn);
    a.on_kcp_output(seg.data(), seg.size(), 14000);
  }
  // Suppress the probe's synchronous ack so it is genuinely in flight when the
  // watchdog fires; the fallback cancels it without evidence.
  link.drop_oob_from_b = true;
  a.on_tick(15000);
  link.drop_oob_from_b = false;

  CHECK(HasText(log_a, "unreachable"));
  CHECK_EQ(a.path_mtu(), 1400u);
  CHECK_EQ(a.payload_max(), 1336u);
  CHECK_EQ(a.pmtu_probes_sent(), 3u);
  CHECK_EQ(a.pmtu_probes_lost(), 0u);  // cancellation is not a resolve-loss

  // The clamped search re-climbs beneath the dead rung in halving steps, and a
  // candidate above the clamp is skipped without spending a probe.
  a.on_tick(20000);
  CHECK_EQ(a.path_mtu(), 2000u);
  a.on_tick(25000);
  CHECK_EQ(a.path_mtu(), 2500u);
  CHECK_EQ(a.pmtu_probes_sent(), 5u);

  for (int64_t t = 30000; t <= 130000; t += 5000) {
    a.on_tick(t);
  }
  CHECK_EQ(a.pmtu_probes_sent(), 5u);  // 2750 > clamp: no probes

  // Hold over: the clamp lifts and the same candidate now goes out.
  a.on_tick(135000);
  CHECK_EQ(a.path_mtu(), 2750u);
  CHECK_EQ(a.pmtu_probes_sent(), 6u);
  CHECK_EQ(a.pmtu_probes_acked(), 5u);
  CHECK(HasText(log_a, "black-hole hold over"));
  CHECK(!a.pmtu_search_done());
}

// ---- 14. handshake state-machine corners ----

struct HPeer {
  std::vector<Bytes> sent;
  Bytes nonce;
  fcp::Handshake hs;

  HPeer(uint8_t d, uint8_t p, fcp::HandshakeRole role, uint8_t fill,
        size_t segs = fcp::kHandshakeMaxCachedSegments,
        size_t bytes = fcp::kHandshakeMaxCachedBytes, int64_t rtt = 0)
      : sent(),
        nonce(fcp::kHandshakeNonceLen, fill),
        hs(d, p,
           [this](const uint8_t* data, size_t len) {
             sent.emplace_back(data, data + len);
           },
           role, nonce.data(), fcp::kLocalFlagsM1, segs, bytes, rtt) {}
};

Bytes MakeHelloOf(const Bytes& nonce, uint8_t ver = 1, uint8_t data = 10,
                  uint8_t parity = 3, uint8_t flags = fcp::kLocalFlagsM1) {
  Bytes out(fcp::kHelloLen);
  fcp::build_hello(fcp::HandshakeCaps{ver, data, parity, flags}, nonce.data(),
                   out.data());
  return out;
}

Bytes MakeAckOf(const Bytes& c_nonce, const Bytes& s_nonce, uint8_t ver = 1,
                uint8_t data = 10, uint8_t parity = 3,
                uint8_t flags = fcp::kLocalFlagsM1) {
  Bytes out(fcp::kHelloAckLen);
  fcp::build_hello_ack(fcp::HandshakeCaps{ver, data, parity, flags}, c_nonce.data(),
                       s_nonce.data(), out.data());
  return out;
}

void TestHandshakeEdgeCases() {
  // Established duplicate HELLO: same draw re-ACKs, a different draw is refused.
  {
    HPeer s(10, 3, fcp::HandshakeRole::kServer, 0x22);
    const Bytes peer = Bytes(fcp::kHandshakeNonceLen, 0x11);
    const Bytes hello = MakeHelloOf(peer);
    CHECK(s.hs.on_oob(hello.data(), hello.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(s.hs.established());
    CHECK_EQ(s.sent.size(), 1u);
    CHECK(s.hs.on_oob(hello.data(), hello.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK_EQ(s.sent.size(), 2u);
    CHECK_EQ(s.hs.hello_refused(), 0u);

    const Bytes other = Bytes(fcp::kHandshakeNonceLen, 0x44);
    const Bytes other_hello = MakeHelloOf(other);
    CHECK(s.hs.on_oob(other_hello.data(), other_hello.size()) ==
          fcp::HandshakeStatus::kConsumed);
    CHECK_EQ(s.hs.hello_refused(), 1u);
    CHECK_EQ(s.sent.size(), 2u);
    CHECK(s.hs.established());
  }

  // A stray ACK in Idle establishes nothing.
  {
    HPeer c(10, 3, fcp::HandshakeRole::kClient, 0x11);
    const Bytes ack = MakeAckOf(Bytes(fcp::kHandshakeNonceLen, 0x11),
                                Bytes(fcp::kHandshakeNonceLen, 0x22));
    CHECK(c.hs.on_oob(ack.data(), ack.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(c.hs.state() == fcp::HandshakeState::kIdle);
    CHECK_EQ(c.sent.size(), 0u);
  }

  // Server role: the echoed server draw matches, but the peer's (client) draw
  // is all zeros and therefore unusable.
  {
    HPeer s(10, 3, fcp::HandshakeRole::kServer, 0x22);
    s.hs.start(0);
    s.hs.on_tick(0);
    const Bytes zero(fcp::kHandshakeNonceLen, 0);
    const Bytes ack = MakeAckOf(zero, s.nonce);
    CHECK(s.hs.on_oob(ack.data(), ack.size()) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK(s.hs.error() == fcp::HandshakeError::kBadNonce);
  }

  // An ACK that claims a TLV block but carries none is a caps failure.
  {
    HPeer c(10, 3, fcp::HandshakeRole::kClient, 0x11);
    c.hs.start(0);
    c.hs.on_tick(0);
    const uint8_t flags = static_cast<uint8_t>(fcp::kLocalFlagsM1 | fcp::kCapTlv);
    const Bytes ack = MakeAckOf(c.nonce, Bytes(fcp::kHandshakeNonceLen, 0x22),
                                1, 10, 3, flags);
    CHECK(c.hs.on_oob(ack.data(), ack.size()) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK(c.hs.error() == fcp::HandshakeError::kBadCaps);
  }

  // A peer error TLV carrying kBadNonce fails immediately with that code.
  {
    HPeer c(10, 3, fcp::HandshakeRole::kClient, 0x11);
    c.hs.start(0);
    c.hs.on_tick(0);
    Bytes ack(fcp::kHelloAckLen + fcp::kTlvBlockLenBytes + 3, 0);
    fcp::build_hello_ack(
        fcp::HandshakeCaps{fcp::kCapsVersion, 10, 3,
                           static_cast<uint8_t>(fcp::kLocalFlagsM1 | fcp::kCapTlv)},
        c.nonce.data(), Bytes(fcp::kHandshakeNonceLen, 0x22).data(), ack.data());
    ack[fcp::kHelloAckLen] = 0x03;
    ack[fcp::kHelloAckLen + 2] = fcp::kTlvTypeError;
    ack[fcp::kHelloAckLen + 3] = 0x01;
    ack[fcp::kHelloAckLen + 4] = static_cast<uint8_t>(fcp::HandshakeError::kBadNonce);
    CHECK(c.hs.on_oob(ack.data(), ack.size()) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK(c.hs.error() == fcp::HandshakeError::kBadNonce);
    CHECK(c.hs.peer_error() == fcp::HandshakeError::kBadNonce);
  }

  // A negative RTT seed does not seed the backoff; the base gap stays.
  {
    HPeer p(10, 3, fcp::HandshakeRole::kClient, 0x77, fcp::kHandshakeMaxCachedSegments,
            fcp::kHandshakeMaxCachedBytes, -5);
    p.hs.start(0);
    p.hs.on_tick(0);
    CHECK_EQ(p.hs.next_retry_ms(), 250);
  }

  // A failed CSPRNG draw fails the handshake at construction.
  {
    fcp::set_random_failure_injection(true);
    {
      fcp::Handshake h(10, 3, [](const uint8_t*, size_t) {},
                       fcp::HandshakeRole::kClient, nullptr);
      CHECK(h.state() == fcp::HandshakeState::kFailed);
      CHECK(h.error() == fcp::HandshakeError::kBadNonce);
    }
    fcp::set_random_failure_injection(false);
  }

  // A missing send callback is legal: the state machine still runs.
  {
    fcp::Handshake h(10, 3, nullptr, fcp::HandshakeRole::kServer,
                     Bytes(fcp::kHandshakeNonceLen, 0x22).data());
    h.start(0);
    h.on_tick(0);
    CHECK(h.state() == fcp::HandshakeState::kHelloSent);
    const Bytes peer = Bytes(fcp::kHandshakeNonceLen, 0x11);
    const Bytes hello = MakeHelloOf(peer);
    CHECK(h.on_oob(hello.data(), hello.size()) == fcp::HandshakeStatus::kConsumed);
    CHECK(h.established());
  }

  // A client never sends the server-only error ACK, and a sendless server
  // cannot either. Both reject the HELLO with kBadCaps.
  {
    HPeer c(10, 3, fcp::HandshakeRole::kClient, 0x11);
    const uint8_t bad_flags = static_cast<uint8_t>(fcp::kLocalFlagsM1 | fcp::kCapTlv);
    const Bytes bad = MakeHelloOf(Bytes(fcp::kHandshakeNonceLen, 0x11), 1, 0, 3,
                                  bad_flags);
    CHECK(c.hs.on_oob(bad.data(), bad.size()) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK_EQ(c.sent.size(), 0u);

    fcp::Handshake server(10, 3, nullptr, fcp::HandshakeRole::kServer,
                          Bytes(fcp::kHandshakeNonceLen, 0x22).data());
    CHECK(server.on_oob(bad.data(), bad.size()) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK(server.error() == fcp::HandshakeError::kBadCaps);
  }

  // An unencodable local TLV falls back to the plain HELLO / ACK shape.
  {
    HPeer c(10, 3, fcp::HandshakeRole::kClient, 0x11);
    c.hs.set_local_tlvs({{0, {1}}});
    c.hs.start(0);
    c.hs.on_tick(0);
    CHECK_EQ(c.sent.size(), 1u);
    CHECK_EQ(c.sent[0].size(), fcp::kHelloLen);
    CHECK(fcp::is_hello(c.sent[0].data(), c.sent[0].size()));

    HPeer peer(10, 3, fcp::HandshakeRole::kClient, 0x33);
    peer.hs.set_local_tlvs({{0x90, {1}}});
    peer.hs.start(0);
    peer.hs.on_tick(0);
    CHECK(peer.sent[0].size() > fcp::kHelloLen);

    HPeer s(10, 3, fcp::HandshakeRole::kServer, 0x22);
    s.hs.set_local_tlvs({{0, {1}}});
    s.hs.start(0);
    s.hs.on_tick(0);
    CHECK(s.hs.on_oob(peer.sent[0].data(), peer.sent[0].size()) ==
          fcp::HandshakeStatus::kConsumed);
    CHECK(s.hs.established());
    CHECK_EQ(s.sent.back().size(), fcp::kHelloAckLen);
    CHECK(fcp::is_hello_ack(s.sent.back().data(), s.sent.back().size()));
  }

  // hello_tlvs with a truncated message reports "no block claimed".
  {
    std::vector<fcp::HandshakeTlv> tlvs;
    uint8_t junk[10] = {};
    CHECK(fcp::hello_tlvs(junk, sizeof(junk), false, &tlvs));
    CHECK(tlvs.empty());
  }
}

// ---- 15. session_log: every status and every state pair ----

void TestSessionLogCoverage() {
  std::vector<std::string> lines;
  auto cap = [&lines](const std::string& s) { lines.push_back(s); };

  // Empty sinks are no-ops for every entry point.
  fcp::log_fecstat_dropped({}, fcp::FecstatStatus::kStale);
  fcp::log_fecstat_untrusted({}, fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_too_small({}, fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_report({}, fcp::MakeFecstatPacket(kSalt), fcp::FecSampleRates{},
                          0, fcp::FecState::kOff);
  fcp::log_fec_ledger({}, fcp::MakeFecstatPacket(kSalt), fcp::FecLedgerView{});
  CHECK(lines.empty());

  // Every status, including the out-of-range "unknown" fallback.
  const fcp::FecstatStatus statuses[] = {
      fcp::FecstatStatus::kOk,        fcp::FecstatStatus::kBadLength,
      fcp::FecstatStatus::kBadMagic,  fcp::FecstatStatus::kBadSalt,
      fcp::FecstatStatus::kBadVer,    fcp::FecstatStatus::kStale,
      fcp::FecstatStatus::kDuplicate};
  for (const fcp::FecstatStatus status : statuses) {
    fcp::log_fecstat_dropped(cap, status);
    CHECK_EQ(lines.size(), 1u);
    CHECK(lines[0].rfind(fcp::kTagDebug, 0) == 0);
    lines.clear();
  }
  fcp::log_fecstat_dropped(cap, static_cast<fcp::FecstatStatus>(200));
  CHECK_EQ(lines.size(), 1u);
  CHECK(HasText(lines, "reason=unknown"));

  lines.clear();
  fcp::log_fecstat_untrusted(cap, fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_too_small(cap, fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_report(cap, fcp::MakeFecstatPacket(kSalt), fcp::FecSampleRates{},
                          1, fcp::FecState::kOn);
  fcp::log_fec_ledger(cap, fcp::MakeFecstatPacket(kSalt), fcp::FecLedgerView{});
  CHECK_EQ(lines.size(), 4u);
  CHECK(lines[0].rfind(fcp::kTagDebug, 0) == 0);
  CHECK(lines[2].rfind(fcp::kTagInfo, 0) == 0);

  // All nine state pairs, with and without a sink. Only ON->CAPPED,
  // CAPPED->ON and ON->OFF emit; CAPPED->OFF is deliberately silent.
  const fcp::FecState states[] = {fcp::FecState::kOff, fcp::FecState::kOn,
                                  fcp::FecState::kCapped};
  for (const fcp::FecState before : states) {
    for (const fcp::FecState after : states) {
      fcp::log_fec_budget_transitions({}, before, after, 0.5, 0.5, 2, 0.01);
      lines.clear();
      fcp::log_fec_budget_transitions(cap, before, after, 0.5, 0.5, 2, 0.01);
      const bool expect =
          (before != fcp::FecState::kCapped && after == fcp::FecState::kCapped) ||
          (before == fcp::FecState::kCapped && after == fcp::FecState::kOn) ||
          (before == fcp::FecState::kOn && after == fcp::FecState::kOff);
      CHECK_EQ(lines.size(), expect ? 1u : 0u);
    }
  }
  lines.clear();
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kOff, fcp::FecState::kCapped,
                                  0.6, 0.5, 3, 0.1);
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kCapped, fcp::FecState::kOn,
                                  0.4, 0.5, 2, 0.1);
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kOn, fcp::FecState::kOff,
                                  0.1, 0.5, 1, 0.001);
  CHECK_EQ(lines.size(), 3u);
  CHECK(HasText(lines, "FEC capped:"));
  CHECK(HasText(lines, "FEC budget restored:"));
  CHECK(HasText(lines, "FEC off: pre<0.30%"));
}

// ---- 16. log_level structural branches ----

void TestLogLevelEdges() {
  int severity = 0;
  CHECK(fcp::TaggedLine("[d] debug", &severity));
  CHECK_EQ(severity, fcp::Severity(fcp::LogLevel::kDebug));
  CHECK(fcp::TaggedLine("[i] ", &severity));  // exactly four characters
  CHECK_EQ(severity, fcp::Severity(fcp::LogLevel::kInfo));
  CHECK(fcp::TaggedLine("[w] warn", &severity));
  CHECK(fcp::TaggedLine("[e] err", &severity));

  CHECK(!fcp::TaggedLine("", &severity));
  CHECK(!fcp::TaggedLine("abc", &severity));
  CHECK(!fcp::TaggedLine("abcd", &severity));
  CHECK(!fcp::TaggedLine("x]  body", &severity));
  CHECK(!fcp::TaggedLine("[i]x", &severity));
  CHECK(!fcp::TaggedLine("[i} body", &severity));
  CHECK(!fcp::TaggedLine("[x] body", &severity));
  CHECK_EQ(severity, fcp::Severity(fcp::LogLevel::kInfo));

  CHECK_EQ(fcp::LineBody("[d] body"), std::string("body"));
  CHECK_EQ(fcp::LineBody("plain"), std::string("plain"));
  CHECK_EQ(fcp::LineBody("[x] body"), std::string("[x] body"));

  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kDebug))),
           std::string("DEBUG"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kInfo))),
           std::string("INFO"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kWarn))),
           std::string("WARN"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kError))),
           std::string("ERROR"));

  const std::string stamp = fcp::LogStamp();
  CHECK(stamp.empty() || stamp.size() >= 19u);
  const std::string line = fcp::LogLine(fcp::Severity(fcp::LogLevel::kWarn), "body");
  CHECK(line.find(" [WARN] body") != std::string::npos);
}

// ---- 17. framed-stats session (P' == 0) ----

void TestStatsModeSession() {
  Recorder rec;
  fcp::SessionConfig cfg = MakeConfig(fcp::Direction::kC2S, fcp::Direction::kS2C,
                                      10, 0);
  cfg.initial_k = 2;  // dropped in stats mode (p_max == 0)
  fcp::Session s(cfg,
                 [&rec](const uint8_t* w, size_t n, fcp::SymbolType t) {
                   rec.sent.emplace_back(Bytes(w, w + n), t);
                 },
                 nullptr, [&rec](const std::string& l) { rec.logs.push_back(l); });
  CHECK_EQ(s.start(0), fcp::Session::StartStatus::kOk);
  s.on_tick(0);
  uint8_t ack[fcp::kHelloAckLen];
  fcp::build_hello_ack(fcp::HandshakeCaps{fcp::kCapsVersion, 10, 0, fcp::kLocalFlagsM1},
                       s.handshake_nonce(), PeerDraw(), ack);
  fcp::Envelope boot(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  const Bytes plain = OobPlain(ack, sizeof(ack));
  Bytes wire;
  CHECK(boot.seal(plain.data(), plain.size(), &wire));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));

  CHECK(s.established());
  CHECK(s.mode() == fcp::SessionMode::kFramedStats);
  CHECK_EQ(static_cast<int>(s.params().p), 0);
  CHECK_EQ(static_cast<int>(s.k()), 0);
  CHECK(s.strategy()->state() == fcp::FecState::kOff);
  CHECK(s.strategy()->pinned());
  CHECK_EQ(s.strategy()->initial_k(), -1);
  CHECK_EQ(s.payload_max(), fcp::compute_mtu_limits(1400, 20).payload_max);
  CHECK(HasText(rec.logs, "flags=framed,stats"));

  // No parity is ever planned at P' == 0.
  for (uint32_t sn = 0; sn < 20; ++sn) {
    const Bytes seg = Segment(sn);
    s.on_kcp_output(seg.data(), seg.size(), 10);
  }
  CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kData), 20u);
  CHECK_EQ(CountType(rec.sent, fcp::SymbolType::kParity), 0u);
}

}  // namespace

int main() {
  TestKcpSnOfNulls();
  TestStartRefusals();
  TestPrewarmAndStreamTlv();
  TestPreNegotiationInboundEdges();
  TestBootstrapAndResetEdges();
  TestAmplificationAndNonceExhaustion();
  TestFecstatStatuses();
  TestFecstatGatesLogsAndBudget();
  TestRttBaselineExpiry();
  TestSessionTableEdges();
  TestEnsureConfiguredRefusals();
  TestPmtuHandlingEdges();
  TestPmtuBlackholeAndClamp();
  TestHandshakeEdgeCases();
  TestSessionLogCoverage();
  TestLogLevelEdges();
  TestStatsModeSession();
  return fcp_test::finish();
}
