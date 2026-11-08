#include "fcp/handshake.h"

#include <cstring>
#include <string>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/wire.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;
using fcp::HandshakeRole;
using fcp::HandshakeStatus;

Bytes Nonce(uint8_t fill) { return Bytes(fcp::kHandshakeNonceLen, fill); }

Bytes MakeHello(const Bytes& sender_nonce, uint8_t ver = 1, uint8_t data = 10,
                uint8_t parity = 3, uint8_t flags = 0x07) {
  Bytes out(fcp::kHelloLen);
  fcp::build_hello(fcp::HandshakeCaps{ver, data, parity, flags}, sender_nonce.data(),
                   out.data());
  return out;
}

Bytes MakeAck(const Bytes& c_nonce, const Bytes& s_nonce, uint8_t ver = 1,
              uint8_t data = 10, uint8_t parity = 3, uint8_t flags = 0x07) {
  Bytes out(fcp::kHelloAckLen);
  fcp::build_hello_ack(fcp::HandshakeCaps{ver, data, parity, flags}, c_nonce.data(),
                       s_nonce.data(), out.data());
  return out;
}

// `nonce` must be declared before `hs`: the send callback captures `this`, and
// hs's constructor is handed nonce.data().
struct Peer {
  std::vector<Bytes> sent;
  Bytes nonce;
  fcp::Handshake hs;

  Peer(uint8_t d, uint8_t p, HandshakeRole role, uint8_t fill,
       uint8_t flags = fcp::kLocalFlagsM1,
       size_t segs = fcp::kHandshakeMaxCachedSegments,
       size_t bytes = fcp::kHandshakeMaxCachedBytes)
      : sent(),
        nonce(Nonce(fill)),
        hs(d, p,
           [this](const uint8_t* data, size_t len) {
             sent.emplace_back(data, data + len);
           },
           role, nonce.data(), flags, segs, bytes) {}

  HandshakeStatus deliver(const Bytes& msg) { return hs.on_oob(msg.data(), msg.size()); }

  bool is_client() const { return hs.role() == HandshakeRole::kClient; }

  // HELLO carrying this peer's own draw.
  Bytes hello(uint8_t ver = 1, uint8_t data = 10, uint8_t parity = 3,
              uint8_t flags = 0x07) const {
    return MakeHello(nonce, ver, data, parity, flags);
  }

  // The ACK this peer would send in answer to a peer that drew `peer_nonce`.
  Bytes ack(const Bytes& peer_nonce, uint8_t ver = 1, uint8_t data = 10,
            uint8_t parity = 3, uint8_t flags = 0x07) const {
    const Bytes& c = is_client() ? nonce : peer_nonce;
    const Bytes& s = is_client() ? peer_nonce : nonce;
    return MakeAck(c, s, ver, data, parity, flags);
  }
};

// #77: TLV codec round-trip and rejection edges.
void TestTlvCodec() {
  uint8_t buf[64];
  // An empty set still encodes the 2-byte zero length (the server echoes
  // kCapTlv with an empty block when it has nothing to offer).
  CHECK_EQ(fcp::tlv_encode({}, buf, sizeof(buf)), fcp::kTlvBlockLenBytes);
  CHECK_EQ(fcp::get_le16(buf), 0u);

  std::vector<fcp::HandshakeTlv> tlvs = {{0x81, {1, 2, 3}}, {0x7F, {}}};
  CHECK_EQ(fcp::tlv_encode(tlvs, buf, sizeof(buf)),
           fcp::kTlvBlockLenBytes + 3 + 2 + 2 + 0);
  std::vector<fcp::HandshakeTlv> back;
  CHECK(fcp::tlv_parse(buf + fcp::kTlvBlockLenBytes, fcp::get_le16(buf), &back));
  CHECK_EQ(back.size(), 2u);
  CHECK_EQ(back[0].type, 0x81);
  CHECK(back[0].value == Bytes({1, 2, 3}));
  CHECK(back[1].value.empty());

  // Unencodable: reserved type 0, value over 255, block over 1024.
  CHECK_EQ(fcp::tlv_encode({{0, {1}}}, buf, sizeof(buf)), 0u);
  CHECK_EQ(fcp::tlv_encode({{1, Bytes(fcp::kTlvMaxValueLen + 1, 9)}}, buf,
                           sizeof(buf)),
           0u);
  std::vector<fcp::HandshakeTlv> many(
      8, fcp::HandshakeTlv{9, Bytes(fcp::kTlvMaxValueLen, 7)});
  CHECK_EQ(fcp::tlv_encode(many, buf, sizeof(buf)), 0u);
  // And an output buffer that is simply too small.
  CHECK_EQ(fcp::tlv_encode(tlvs, buf, 4), 0u);

  // Malformed parses: truncated header, truncated value, reserved type 0.
  CHECK(!fcp::tlv_parse(buf, 1, &back));
  const uint8_t trunc[] = {5, 4, 1, 2};
  CHECK(!fcp::tlv_parse(trunc, sizeof(trunc), &back));
  const uint8_t zero_type[] = {0, 1, 9};
  CHECK(!fcp::tlv_parse(zero_type, sizeof(zero_type), &back));
}

// #77: negotiation with the TLV block on both ends; unknown types ride
// through untouched, and the negotiated bit is set only when both ends used
// the extension.
void TestTlvNegotiation() {
  Peer c(10, 3, HandshakeRole::kClient, 0x11);
  Peer s(10, 3, HandshakeRole::kServer, 0x22);
  // 0x90 has no consumer anywhere in the codebase -- exactly the
  // forward-compatibility case the extension exists for.
  const std::vector<fcp::HandshakeTlv> offer = {{0x90, {0xAB}}};
  c.hs.set_local_tlvs(offer);
  s.hs.set_local_tlvs(offer);
  c.hs.start(0);
  s.hs.start(0);
  c.hs.on_tick(0);
  s.hs.on_tick(0);
  CHECK_EQ(c.sent.size(), 1u);
  CHECK(c.sent[0].size() > fcp::kHelloLen);
  CHECK(fcp::is_hello(c.sent[0].data(), c.sent[0].size()));
  CHECK(s.deliver(c.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(s.hs.established());
  CHECK(s.hs.tlv_negotiated());
  CHECK_EQ(s.hs.peer_tlvs().size(), 1u);
  CHECK_EQ(s.hs.peer_tlvs()[0].type, 0x90);
  // s also opened simultaneously: its own HELLO went out first, the ACK is
  // the second datagram it emitted.
  CHECK_EQ(s.sent.size(), 2u);
  CHECK(s.sent[1].size() > fcp::kHelloAckLen);
  CHECK(fcp::is_hello_ack(s.sent[1].data(), s.sent[1].size()));
  CHECK(c.deliver(s.sent[1]) == HandshakeStatus::kConsumed);
  CHECK(c.hs.established());
  CHECK(c.hs.tlv_negotiated());
  // Keying is untouched by the extension: the nonce binding still holds.
  CHECK(std::memcmp(c.hs.client_nonce(), s.hs.client_nonce(),
                    fcp::kHandshakeNonceLen) == 0);
  CHECK(std::memcmp(c.hs.server_nonce(), s.hs.server_nonce(),
                    fcp::kHandshakeNonceLen) == 0);

  // The kCapTlv-only peer (client offers, server has no local TLVs) still
  // negotiates: the server echoes the bit with an empty block.
  Peer c2(10, 3, HandshakeRole::kClient, 0x33);
  Peer s2(10, 3, HandshakeRole::kServer, 0x44);
  c2.hs.set_local_tlvs({{0x91, {2}}});
  c2.hs.start(0);
  s2.hs.start(0);
  c2.hs.on_tick(0);
  s2.hs.on_tick(0);
  CHECK(s2.deliver(c2.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(s2.hs.established());
  CHECK_EQ(s2.sent.size(), 2u);  // its own HELLO, then the ACK
  CHECK(s2.sent[1].size() > fcp::kHelloAckLen);  // bit set, empty block
  CHECK(c2.deliver(s2.sent[1]) == HandshakeStatus::kConsumed);
  CHECK(c2.hs.established());
  CHECK(c2.hs.tlv_negotiated());
  CHECK(c2.hs.peer_tlvs().empty());
}

// #77: the downgrade probe -- a peer that predates the bit never answers the
// kCapTlv HELLOs, so the third send goes out in the plain v7 shape and a
// plain ACK still establishes.
void TestTlvDowngrade() {
  Peer c(10, 3, HandshakeRole::kClient, 0x11);
  c.hs.set_local_tlvs({{0x90, {1}}});
  c.hs.start(0);
  c.hs.on_tick(0);
  CHECK(c.sent[0].size() > fcp::kHelloLen);  // ext shape
  c.hs.on_tick(250);
  CHECK(c.sent[1].size() > fcp::kHelloLen);  // still probing
  CHECK(!c.hs.tlv_downgraded());
  c.hs.on_tick(750);
  CHECK(c.hs.tlv_downgraded());
  CHECK_EQ(c.sent[2].size(), fcp::kHelloLen);  // plain v7 shape
  c.hs.on_tick(1750);
  CHECK_EQ(c.sent[3].size(), fcp::kHelloLen);
  // A plain ACK (what a v7-shaped server returns) establishes without TLVs.
  const Bytes server_draw = Nonce(0x33);
  CHECK(c.deliver(MakeAck(c.nonce, server_draw)) == HandshakeStatus::kConsumed);
  CHECK(c.hs.established());
  CHECK(!c.hs.tlv_negotiated());
}

// #77 (H2): a kCapTlv HELLO the server cannot accept is answered with an
// error ACK; the client fails immediately with the peer's code instead of
// running out the retry table.
void TestTlvErrorAck() {
  Peer s(10, 3, HandshakeRole::kServer, 0x22);
  s.hs.start(0);
  s.hs.on_tick(0);
  // data < 1 is a caps error, and the fixed 36B message claims a TLV block it
  // does not carry -- rejected either way, but through the error channel now.
  const Bytes bad = MakeHello(Nonce(0x11), 1, 0, 3,
                              static_cast<uint8_t>(0x07 | fcp::kCapTlv));
  CHECK(s.deliver(bad) == HandshakeStatus::kProtocolFailure);
  CHECK(s.hs.state() == fcp::HandshakeState::kFailed);
  CHECK_EQ(s.hs.error(), fcp::HandshakeError::kBadCaps);
  CHECK_EQ(s.sent.size(), 2u);  // its own HELLO + the error ACK
  CHECK(fcp::is_hello_ack(s.sent[1].data(), s.sent[1].size()));
  CHECK(s.sent[1].size() > fcp::kHelloAckLen);

  Peer c(10, 3, HandshakeRole::kClient, 0x11);
  c.hs.start(0);
  c.hs.on_tick(0);
  CHECK_EQ(c.sent.size(), 1u);
  CHECK(c.deliver(s.sent[1]) == HandshakeStatus::kProtocolFailure);
  CHECK(c.hs.state() == fcp::HandshakeState::kFailed);
  CHECK(c.hs.error() == fcp::HandshakeError::kBadCaps);
  CHECK(c.hs.peer_error() == fcp::HandshakeError::kBadCaps);
  // No further retries: the peer refused, waiting cannot help.
  c.hs.on_tick(250);
  c.hs.on_tick(750);
  CHECK_EQ(c.sent.size(), 1u);
}

void TestWireGolden() {
  CHECK_EQ(fcp::kHelloLen, 36u);
  CHECK_EQ(fcp::kHelloAckLen, 52u);
  CHECK_EQ(static_cast<int>(fcp::kLocalFlagsM1), 0x07);

  // "FCP_HELLO_V1" + 4 NUL padding (16-byte oob magic) |
  // sender nonce (16) | caps (4).
  const Bytes hello = MakeHello(Nonce(0x11));
  CHECK_EQ(fcp_test::hex(hello.data(), hello.size()),
           "4643505f48454c4c4f5f563100000000"
           "11111111111111111111111111111111"
           "010a0307");

  // ... and the ACK repeats the client's draw before its own.
  const Bytes ack = MakeAck(Nonce(0x11), Nonce(0x22));
  CHECK_EQ(fcp_test::hex(ack.data(), ack.size()),
           "4643505f48454c4c4f5f41434b5f5631"
           "11111111111111111111111111111111"
           "22222222222222222222222222222222"
           "010a0307");

  CHECK(fcp::is_hello(hello.data(), hello.size()));
  CHECK(!fcp::is_hello_ack(hello.data(), hello.size()));
  CHECK(fcp::is_hello_ack(ack.data(), ack.size()));
  CHECK(!fcp::is_hello(ack.data(), ack.size()));

  // The magic doubles as the handshake version: a well-shaped 36-byte message
  // whose magic differs by one character is not a HELLO, and anything that is
  // not a HELLO cannot enter our key schedule.
  Bytes stranger(36);
  std::memcpy(stranger.data(), "FCP_HELLO_V2\0\0\0\0", 16);
  stranger[16] = 1;
  stranger[17] = 10;
  stranger[18] = 3;
  stranger[19] = 0x07;
  std::memcpy(stranger.data() + 20, Nonce(0x11).data(), 16);
  CHECK(!fcp::is_hello(stranger.data(), stranger.size()));
  CHECK(stranger.size() == fcp::kHelloLen);

  CHECK(!fcp::is_hello(hello.data(), hello.size() - 1));
  CHECK(!fcp::is_hello_ack(ack.data(), ack.size() - 1));
  CHECK(!fcp::is_hello(nullptr, hello.size()));

  const Bytes junk(fcp::kHelloLen, 0xAA);
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  CHECK(p.deliver(junk) == HandshakeStatus::kNotHandshake);
  CHECK(p.deliver(hello) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
}

void TestMutualHandshake() {
  Peer a(10, 3, HandshakeRole::kClient, 0x11);
  Peer b(10, 3, HandshakeRole::kServer, 0x22);
  a.hs.start(0);
  b.hs.start(0);
  a.hs.on_tick(0);
  b.hs.on_tick(0);
  CHECK_EQ(a.sent.size(), 1u);
  CHECK_EQ(b.sent.size(), 1u);
  CHECK(fcp::is_hello(a.sent[0].data(), a.sent[0].size()));

  // B sees A's HELLO: ACK + establish.
  CHECK(b.deliver(a.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(b.hs.established());
  CHECK_EQ(b.sent.size(), 2u);
  CHECK(fcp::is_hello_ack(b.sent[1].data(), b.sent[1].size()));
  CHECK_EQ(b.hs.params().d, 10);
  CHECK_EQ(b.hs.params().p, 3);
  CHECK(b.hs.params().mode == fcp::SessionMode::kFramedRepair);

  // A sees B's HELLO (simultaneous open): it now knows both draws and
  // establishes, then ACKs with the pair it already has.
  CHECK(a.deliver(b.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK_EQ(a.sent.size(), 2u);
  CHECK(fcp::is_hello_ack(a.sent[1].data(), a.sent[1].size()));

  // Crossed ACKs are duplicates.
  CHECK(a.deliver(b.sent[1]) == HandshakeStatus::kConsumed);
  CHECK(b.deliver(a.sent[1]) == HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK(b.hs.established());
  CHECK_EQ(a.hs.hello_refused(), 0u);
  CHECK_EQ(b.hs.hello_refused(), 0u);

  // Both ends agree on the nonce pair even though the exchange crossed.
  CHECK(std::memcmp(a.hs.client_nonce(), b.hs.client_nonce(), fcp::kHandshakeNonceLen) == 0);
  CHECK(std::memcmp(a.hs.server_nonce(), b.hs.server_nonce(), fcp::kHandshakeNonceLen) == 0);

  // No retries after establishment.
  a.hs.on_tick(10000);
  CHECK_EQ(a.sent.size(), 2u);
  CHECK(a.hs.error() == fcp::HandshakeError::kNone);
}

// The whole point of the nonces: the two ends must derive the same key even
// when neither ACK is needed to complete the exchange.
void TestKeyAgreement() {
  const uint8_t psk[16] = {0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
                           0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0};
  const uint8_t salt[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  Peer a(10, 3, HandshakeRole::kClient, 0x11);
  Peer b(10, 3, HandshakeRole::kServer, 0x22);
  a.hs.start(0);
  b.hs.start(0);
  a.hs.on_tick(0);
  b.hs.on_tick(0);
  CHECK(b.deliver(a.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(a.deliver(b.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK(b.hs.established());

  uint8_t key_a[16];
  uint8_t key_b[16];
  fcp::derive_session_key_v7(psk, salt, a.hs.client_nonce(), a.hs.server_nonce(),
                             key_a);
  fcp::derive_session_key_v7(psk, salt, b.hs.client_nonce(), b.hs.server_nonce(),
                             key_b);
  CHECK(std::memcmp(key_a, key_b, 16) == 0);  // 16 = AES-128 session key, not a nonce
}

// R3-1: an ACK that does not echo our own draw belongs to someone else's
// handshake (typically a recording). It must not establish anything.
void TestAckEchoMismatch() {
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  p.hs.on_tick(0);
  const Bytes stale_s = Nonce(0x33);

  // Echoes a challenge we never issued.
  CHECK(p.deliver(MakeAck(Nonce(0x99), stale_s)) == HandshakeStatus::kConsumed);
  CHECK(!p.hs.established());
  CHECK_EQ(p.hs.nonce_mismatch(), 1u);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);

  // The mismatch must not consume the retry budget: the retransmit timer is
  // what recovers from a recording flooding us with stale ACKs.
  p.hs.on_tick(300);
  CHECK_EQ(p.sent.size(), 2u);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);

  // The real ACK (echoing our draw) still completes the handshake.
  CHECK(p.deliver(MakeAck(p.nonce, stale_s)) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK_EQ(p.hs.nonce_mismatch(), 1u);
}

// R3-1 cuts both ways: with a simultaneous open the *server* also sends a
// HELLO and receives an ACK, and the field that must echo its own draw is the
// server nonce. The client-side test above cannot catch a swapped-field bug
// on this branch.
void TestServerAckEchoMismatch() {
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK_EQ(p.sent.size(), 1u);  // the server's own HELLO (simultaneous open)

  // The client nonce is a legitimate draw, but the server field echoes a
  // server draw this end never issued.
  CHECK(p.deliver(MakeAck(Nonce(0x99), Nonce(0x33))) == HandshakeStatus::kConsumed);
  CHECK(!p.hs.established());
  CHECK_EQ(p.hs.nonce_mismatch(), 1u);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);

  // A real ACK (correct echo) still completes the handshake.
  CHECK(p.deliver(MakeAck(Nonce(0x99), p.nonce)) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK(std::memcmp(p.hs.peer_nonce(), Nonce(0x99).data(), fcp::kHandshakeNonceLen) == 0);
  CHECK_EQ(p.hs.nonce_mismatch(), 1u);
}

// R3-24: an established session must not be restarted by a HELLO carrying a
// different draw -- that is what a replayed recording looks like.
void TestEstablishedRefusesNewHello() {
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  CHECK(p.deliver(MakeHello(Nonce(0x11))) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK_EQ(p.sent.size(), 1u);
  const fcp::NegotiatedParams params = p.hs.params();

  // A different draw: refused, state untouched, no ACK (an ACK would carry the
  // new pair and desync the live peer).
  CHECK(p.deliver(MakeHello(Nonce(0x44))) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK_EQ(p.hs.hello_refused(), 1u);
  CHECK_EQ(p.sent.size(), 1u);
  CHECK_EQ(p.hs.params().d, params.d);
  CHECK_EQ(p.hs.params().p, params.p);

  // The same draw is a duplicate whose ACK was lost: re-ACK, unchanged.
  CHECK(p.deliver(MakeHello(Nonce(0x11))) == HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 2u);
  CHECK(p.hs.established());
  CHECK_EQ(p.hs.hello_refused(), 1u);
  CHECK(std::memcmp(p.hs.peer_nonce(), Nonce(0x11).data(), fcp::kHandshakeNonceLen) == 0);
}

// A draw of all zeros carries no freshness; accepting it would let a forgery
// claim the same "challenge" without guessing anything.
void TestZeroNonceRejected() {
  const uint8_t zero[16] = {};
  fcp::Handshake hs(10, 3, nullptr, HandshakeRole::kClient, zero);
  CHECK(hs.state() == fcp::HandshakeState::kFailed);
  CHECK(hs.error() == fcp::HandshakeError::kBadNonce);
  hs.start(0);
  hs.on_tick(0);
  CHECK(hs.state() == fcp::HandshakeState::kFailed);

  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  CHECK(p.deliver(MakeHello(Nonce(0))) == HandshakeStatus::kProtocolFailure);
  CHECK(p.hs.state() == fcp::HandshakeState::kFailed);
  CHECK(p.hs.error() == fcp::HandshakeError::kBadNonce);
  CHECK_EQ(p.sent.size(), 0u);  // never ACK an unusable HELLO

  // Same on the ACK path: a zero server draw is unusable.
  Peer q(10, 3, HandshakeRole::kClient, 0x11);
  q.hs.start(0);
  q.hs.on_tick(0);
  CHECK(q.deliver(MakeAck(q.nonce, Nonce(0))) == HandshakeStatus::kProtocolFailure);
  CHECK(q.hs.error() == fcp::HandshakeError::kBadNonce);
}

void TestCapsNegotiation() {
  // min(D), min(P), AND(flags); bit3 is dropped because M1 does not set it.
  Peer a(10, 4, HandshakeRole::kClient, 0x11, 0x0F);
  Peer b(8, 2, HandshakeRole::kServer, 0x22, 0x03);
  a.hs.start(0);
  a.hs.on_tick(0);
  b.hs.start(0);
  b.hs.on_tick(0);
  CHECK(b.deliver(a.sent[0]) == HandshakeStatus::kConsumed);
  CHECK_EQ(b.hs.params().d, 8);
  CHECK_EQ(b.hs.params().p, 2);
  CHECK_EQ(static_cast<int>(b.hs.params().flags), 0x03);
  CHECK(b.hs.params().mode == fcp::SessionMode::kFramedRepair);

  Peer c(10, 3, HandshakeRole::kClient, 0x33);
  c.hs.start(0);
  c.hs.on_tick(0);
  CHECK(c.deliver(b.sent[0]) == HandshakeStatus::kConsumed);
  CHECK_EQ(c.hs.params().d, 8);
  CHECK_EQ(c.hs.params().p, 2);
}

void TestStatsMode() {
  Peer a(10, 3, HandshakeRole::kClient, 0x11);
  Peer b(10, 0, HandshakeRole::kServer, 0x22);
  a.hs.start(0);
  b.hs.start(0);
  a.hs.on_tick(0);
  b.hs.on_tick(0);
  CHECK(a.deliver(b.sent[0]) == HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK_EQ(a.hs.params().p, 0);
  CHECK(a.hs.params().mode == fcp::SessionMode::kFramedStats);
}

void TestInvalidCaps() {
  struct Case {
    uint8_t ver;
    uint8_t data;
    uint8_t parity;
    uint8_t flags;
    bool error_ack;
  };
  static const Case kCases[] = {
      {2, 10, 3, 0x07, false},  // wrong caps version
      {1, 0, 3, 0x07, false},   // data < 1
      {1, 10, 8, 0x07, false},  // parity > 7
      {1, 250, 7, 0x07, false}, // 257 > 256, u8 math would wrap to 1
      {1, 10, 3, 0x20, true},   // kCapTlv claimed, block missing (#77)
      {1, 10, 3, 0x87, false},  // reserved high bit
  };
  for (const Case& c : kCases) {
    Peer p(10, 3, HandshakeRole::kServer, 0x22);
    p.hs.start(0);
    p.hs.on_tick(0);
    const size_t before = p.sent.size();
    CHECK(p.deliver(MakeHello(Nonce(0x11), c.ver, c.data, c.parity, c.flags)) ==
          HandshakeStatus::kProtocolFailure);
    CHECK(p.hs.state() == fcp::HandshakeState::kFailed);
    CHECK(p.hs.error() == fcp::HandshakeError::kBadCaps);
    if (c.error_ack) {
      // #77 (H2): the peer set kCapTlv, so it gets the rejection channel --
      // one ext-shaped error ACK ahead of the loud failure.
      CHECK_EQ(p.sent.size(), before + 1);
      CHECK(p.sent.back().size() > fcp::kHelloAckLen);
      CHECK(fcp::is_hello_ack(p.sent.back().data(), p.sent.back().size()));
    } else {
      CHECK_EQ(p.sent.size(), before);  // never ACK an invalid HELLO
    }
  }

  // Bad caps also fail through the ACK path.
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK(p.deliver(MakeAck(p.nonce, Nonce(0x22), 1, 0, 3, 0x07)) ==
        HandshakeStatus::kProtocolFailure);
  CHECK(p.hs.error() == fcp::HandshakeError::kBadCaps);

  // Boundary: D + P == 256 is legal.
  Peer q(10, 3, HandshakeRole::kServer, 0x22);
  q.hs.start(0);
  q.hs.on_tick(0);
  CHECK(q.deliver(MakeHello(Nonce(0x11), 1, 249, 7, 0x07)) == HandshakeStatus::kConsumed);
  CHECK(q.hs.established());
  CHECK_EQ(q.hs.params().d, 10);
  CHECK_EQ(q.hs.params().p, 3);
}

void TestMissingCapability() {
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  p.hs.start(0);
  p.hs.on_tick(0);
  const size_t before = p.sent.size();
  CHECK(p.deliver(MakeHello(Nonce(0x11), 1, 10, 3, 0x06)) ==
        HandshakeStatus::kProtocolFailure);  // no framing
  CHECK(p.hs.error() == fcp::HandshakeError::kMissingCapability);
  CHECK_EQ(p.sent.size(), before);

  Peer q(10, 3, HandshakeRole::kServer, 0x22);
  q.hs.start(0);
  q.hs.on_tick(0);
  CHECK(q.deliver(MakeHello(Nonce(0x11), 1, 10, 3, 0x05)) ==
        HandshakeStatus::kProtocolFailure);  // no FECSTAT
  CHECK(q.hs.error() == fcp::HandshakeError::kMissingCapability);
}

void TestTimeout() {
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  CHECK_EQ(p.hs.retries(), 0);
  p.hs.on_tick(0);
  CHECK_EQ(p.sent.size(), 1u);
  // Backoff gaps double from 250ms and cap at 8s (#27①, #76), so the sends
  // land at 0/250/750/1750/3750/7750/15750/23750/31750 and the handshake
  // fails one cap interval after the last send, at 39750ms total (the old
  // 3-send budget failed at 2100ms). Each on_tick call fires at most one
  // send, so the schedule is driven one stage per call.
  p.hs.on_tick(249);
  CHECK_EQ(p.sent.size(), 1u);
  p.hs.on_tick(250);
  CHECK_EQ(p.sent.size(), 2u);
  p.hs.on_tick(749);
  CHECK_EQ(p.sent.size(), 2u);
  p.hs.on_tick(750);
  CHECK_EQ(p.sent.size(), 3u);
  for (const Bytes& msg : p.sent) {
    CHECK(fcp::is_hello(msg.data(), msg.size()));
  }
  p.hs.on_tick(1750);
  p.hs.on_tick(3750);
  p.hs.on_tick(7750);
  p.hs.on_tick(15750);
  p.hs.on_tick(23750);
  CHECK_EQ(p.sent.size(), 8u);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);
  p.hs.on_tick(31750);
  CHECK_EQ(p.sent.size(), 9u);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);
  p.hs.on_tick(39749);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);
  p.hs.on_tick(39750);
  CHECK(p.hs.state() == fcp::HandshakeState::kFailed);
  CHECK(p.hs.error() == fcp::HandshakeError::kNoAck);
  CHECK_EQ(p.sent.size(), 9u);
  CHECK(std::string(fcp::handshake_error_text(p.hs.error())) ==
        "no ACK before the retry budget ran out");

  // A late tick after failure stays quiet.
  p.hs.on_tick(50000);
  CHECK_EQ(p.sent.size(), 9u);
}

// T26 (#27①, #76): the retry timer backs off exponentially, an ACK at any
// stage stops it, and a lossy link (fatal under the old 3-send/2.1s budget)
// now completes the handshake.
void TestRetryBackoff() {
  // Gap sequence: 250 after the first send, then 500, then 1000.
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK_EQ(p.hs.retries(), 1);
  CHECK_EQ(p.hs.next_retry_ms(), 250);
  p.hs.on_tick(250);
  CHECK_EQ(p.hs.retries(), 2);
  CHECK_EQ(p.hs.next_retry_ms(), 750);
  p.hs.on_tick(750);
  CHECK_EQ(p.hs.retries(), 3);
  CHECK_EQ(p.hs.next_retry_ms(), 1750);
  CHECK_EQ(p.sent.size(), 3u);

  // An ACK arriving during any backoff stage stops the timer permanently.
  const Bytes server_draw = Nonce(0x33);
  CHECK(p.deliver(MakeAck(p.nonce, server_draw)) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  p.hs.on_tick(1750);
  p.hs.on_tick(100000);
  CHECK_EQ(p.sent.size(), 3u);

  // RTT=500ms link, first two HELLOs lost: sends at 0 (lost) and 250 (lost);
  // the third send at 750 gets its ACK at 1250 — established, no failure.
  // The old budget kept this scenario green as well, so this asserts the
  // tighter 250ms base did not break the property #27① bought.
  Peer q(10, 3, HandshakeRole::kClient, 0x44);
  q.hs.start(0);
  q.hs.on_tick(0);    // lost
  q.hs.on_tick(250);  // lost
  q.hs.on_tick(750);  // delivered; ACK arrives at 1250
  CHECK(q.deliver(MakeAck(q.nonce, server_draw)) == HandshakeStatus::kConsumed);
  CHECK(q.hs.established());
  q.hs.on_tick(1750);
  q.hs.on_tick(100000);
  CHECK_EQ(q.sent.size(), 3u);

  // Duplicate HELLO handling is unaffected by the backoff: the same draw is
  // re-ACKed (the peer may still be retrying because our ACK was lost).
  CHECK(p.deliver(MakeHello(server_draw)) == HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 4u);
  CHECK(fcp::is_hello_ack(p.sent.back().data(), p.sent.back().size()));
}

// #76: a prewarm RTT prior seeds the first gap to clamp(2*srtt, 250, 8000)
// instead of the 250ms base; later gaps double and keep the cap.
void TestRetrySeededFromRtt() {
  // 2*3000 = 6000 lands inside [250, 8000]: used as-is, then capped doubling.
  {
    fcp::Handshake hs(10, 3, [&](const uint8_t*, size_t) {},
                      fcp::HandshakeRole::kClient, Nonce(0x77).data(),
                      fcp::kLocalFlagsM1, fcp::kHandshakeMaxCachedSegments,
                      fcp::kHandshakeMaxCachedBytes, 3000);
    hs.start(0);
    hs.on_tick(0);
    CHECK_EQ(hs.next_retry_ms(), 6000);
    hs.on_tick(6000);
    CHECK_EQ(hs.next_retry_ms(), 14000);  // min(6000<<1, 8000)
  }
  // 2*50 = 100 floors at the 250ms base.
  {
    fcp::Handshake hs(10, 3, [&](const uint8_t*, size_t) {},
                      fcp::HandshakeRole::kClient, Nonce(0x77).data(),
                      fcp::kLocalFlagsM1, fcp::kHandshakeMaxCachedSegments,
                      fcp::kHandshakeMaxCachedBytes, 50);
    hs.start(0);
    hs.on_tick(0);
    CHECK_EQ(hs.next_retry_ms(), 250);
  }
  // 2*10000 caps at 8s immediately.
  {
    fcp::Handshake hs(10, 3, [&](const uint8_t*, size_t) {},
                      fcp::HandshakeRole::kClient, Nonce(0x77).data(),
                      fcp::kLocalFlagsM1, fcp::kHandshakeMaxCachedSegments,
                      fcp::kHandshakeMaxCachedBytes, 10000);
    hs.start(0);
    hs.on_tick(0);
    CHECK_EQ(hs.next_retry_ms(), 8000);
  }
  // No prior (the cold default) stays on the base gap.
  {
    fcp::Handshake hs(10, 3, [&](const uint8_t*, size_t) {},
                      fcp::HandshakeRole::kClient, Nonce(0x77).data());
    hs.start(0);
    hs.on_tick(0);
    CHECK_EQ(hs.next_retry_ms(), 250);
  }
}

void TestAckStopsRetries() {
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK_EQ(p.sent.size(), 1u);
  CHECK(p.deliver(MakeAck(p.nonce, Nonce(0x22))) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  p.hs.on_tick(600);
  p.hs.on_tick(10000);
  CHECK_EQ(p.sent.size(), 1u);
  CHECK(p.hs.state() == fcp::HandshakeState::kEstablished);
}

void TestIdempotent() {
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  const Bytes hello = MakeHello(Nonce(0x11));
  CHECK(p.deliver(hello) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK_EQ(p.sent.size(), 1u);  // one ACK
  const auto params = p.hs.params();

  // Duplicate HELLO: no renegotiation, but the ACK is resent.
  CHECK(p.deliver(hello) == HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 2u);
  CHECK_EQ(p.hs.params().d, params.d);
  CHECK_EQ(p.hs.params().p, params.p);

  // Duplicate ACK: swallowed.
  const Bytes ack = MakeAck(Nonce(0x11), Nonce(0x22));
  CHECK(p.deliver(ack) == HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 2u);

  // A stray ACK before start() does not establish anything.
  Peer q(10, 3, HandshakeRole::kClient, 0x33);
  CHECK(q.deliver(ack) == HandshakeStatus::kConsumed);
  CHECK(q.hs.state() == fcp::HandshakeState::kIdle);
  CHECK_EQ(q.sent.size(), 0u);
}

void TestDataCache() {
  Peer p(10, 3, HandshakeRole::kServer, 0x22);
  p.hs.start(0);
  CHECK(p.hs.buffering_data());
  CHECK(p.hs.cache_data(Bytes{'a'}));
  CHECK(p.hs.cache_data(Bytes{'b', 'b'}));
  CHECK(p.hs.cache_data(Bytes{'c', 'c', 'c'}));
  CHECK_EQ(p.hs.cached_segments(), 3u);
  CHECK_EQ(p.hs.cached_bytes(), 6u);
  CHECK(p.hs.take_cached_data().empty());  // not established yet

  CHECK(p.deliver(MakeHello(Nonce(0x11))) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK(!p.hs.buffering_data());
  auto drained = p.hs.take_cached_data();
  CHECK_EQ(drained.size(), 3u);
  CHECK(drained[0] == Bytes({'a'}));
  CHECK(drained[1] == Bytes({'b', 'b'}));
  CHECK(drained[2] == Bytes({'c', 'c', 'c'}));
  CHECK_EQ(p.hs.cached_segments(), 0u);
  CHECK_EQ(p.hs.cached_bytes(), 0u);
  CHECK(p.hs.take_cached_data().empty());

  // After negotiation data goes straight to the frame layer.
  CHECK(!p.hs.cache_data(Bytes{'x'}));
}

void TestCacheLimits() {
  // #28③ (F2): limits are per-handshake configurable; small explicit values
  // pin the boundary semantics.
  const uint8_t nonce[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  {
    fcp::Handshake p(10, 3, nullptr, HandshakeRole::kClient, nonce, fcp::kLocalFlagsM1,
                     4, 16);
    p.start(0);
    for (size_t i = 0; i < 4; ++i) {
      CHECK(p.cache_data(Bytes(1, static_cast<uint8_t>(i))));
    }
    CHECK_EQ(p.cached_segments(), 4u);
    CHECK(!p.cache_data(Bytes(1, 0xEE)));  // 5th -> overflow
    CHECK(p.state() == fcp::HandshakeState::kFailed);
    CHECK(p.error() == fcp::HandshakeError::kCacheOverflow);
    CHECK_EQ(p.cached_segments(), 0u);  // dropped on failure
  }
  {
    fcp::Handshake q(10, 3, nullptr, HandshakeRole::kClient, nonce, fcp::kLocalFlagsM1,
                     4, 16);
    q.start(0);
    CHECK(q.cache_data(Bytes(16, 0x11)));  // byte cap, exactly
    CHECK(!q.cache_data(Bytes(1, 0x22)));
    CHECK(q.error() == fcp::HandshakeError::kCacheOverflow);

    // A single oversize segment fails immediately.
    fcp::Handshake r(10, 3, nullptr, HandshakeRole::kClient, nonce, fcp::kLocalFlagsM1,
                     4, 16);
    r.start(0);
    CHECK(!r.cache_data(Bytes(17, 0x33)));
    CHECK(r.error() == fcp::HandshakeError::kCacheOverflow);
  }
  {
    // Default limits (512 segs / 512 KiB, #28③ F2): 512 x 1 KiB fits exactly.
    fcp::Handshake d(10, 3, nullptr, HandshakeRole::kClient, nonce);
    d.start(0);
    for (size_t i = 0; i < fcp::kHandshakeMaxCachedSegments; ++i) {
      CHECK(d.cache_data(Bytes(1024, 0)));
    }
    CHECK_EQ(d.cached_segments(), fcp::kHandshakeMaxCachedSegments);
    CHECK(!d.cache_data(Bytes(1, 0xEE)));
    CHECK(d.error() == fcp::HandshakeError::kCacheOverflow);
  }

  // A failed handshake drops whatever was buffered (#76: the schedule runs to
  // 39750ms; on_tick fires at most one send per call, so drive every 250ms).
  Peer s(10, 3, HandshakeRole::kClient, 0x55);
  s.hs.start(0);
  CHECK(s.hs.cache_data(Bytes(10, 0x44)));
  s.hs.on_tick(0);
  for (int64_t t = 250; t <= 39750; t += 250) {
    s.hs.on_tick(t);
  }
  CHECK(s.hs.state() == fcp::HandshakeState::kFailed);
  CHECK_EQ(s.hs.cached_segments(), 0u);
  CHECK(s.hs.take_cached_data().empty());
}

// The default (nullptr) nonce comes from the OS CSPRNG: two handshakes must not
// share a draw, or two sessions under one PSK would collide on the key.
void TestNonceIsRandom() {
  fcp::Handshake a(10, 3, nullptr, HandshakeRole::kClient);
  fcp::Handshake b(10, 3, nullptr, HandshakeRole::kClient);
  CHECK(a.state() == fcp::HandshakeState::kIdle);
  CHECK(b.state() == fcp::HandshakeState::kIdle);
  CHECK(std::memcmp(a.local_nonce(), b.local_nonce(), fcp::kHandshakeNonceLen) != 0);

  uint8_t acc = 0;
  for (size_t i = 0; i < 16; ++i) {
    acc |= a.local_nonce()[i];
  }
  CHECK(acc != 0);
}

}  // namespace

int main() {
  TestTlvCodec();
  TestTlvNegotiation();
  TestTlvDowngrade();
  TestTlvErrorAck();
  TestWireGolden();
  TestMutualHandshake();
  TestKeyAgreement();
  TestAckEchoMismatch();
  TestServerAckEchoMismatch();
  TestEstablishedRefusesNewHello();
  TestZeroNonceRejected();
  TestCapsNegotiation();
  TestStatsMode();
  TestInvalidCaps();
  TestMissingCapability();
  TestTimeout();
  TestRetryBackoff();
  TestRetrySeededFromRtt();
  TestAckStopsRetries();
  TestIdempotent();
  TestDataCache();
  TestCacheLimits();
  TestNonceIsRandom();
  return fcp_test::finish();
}
