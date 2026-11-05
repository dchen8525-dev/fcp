#include "fcp/handshake.h"

#include <cstring>
#include <string>
#include <vector>

#include "fcp/envelope.h"
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
  };
  static const Case kCases[] = {
      {2, 10, 3, 0x07},   // wrong caps version
      {1, 0, 3, 0x07},    // data < 1
      {1, 10, 8, 0x07},   // parity > 7
      {1, 250, 7, 0x07},  // 257 > 256, u8 math would wrap to 1
      {1, 10, 3, 0x20},   // reserved flag bit (bit 4 is kCapPmtud)
      {1, 10, 3, 0x87},   // reserved high bit
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
    CHECK_EQ(p.sent.size(), before);  // never ACK an invalid HELLO
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
  // Backoff gaps are 300/600/1200ms (#27①), so the sends land at 0/300/900
  // and the handshake fails at 2100ms total (was 0/300/600 → fail at 900).
  p.hs.on_tick(299);
  CHECK_EQ(p.sent.size(), 1u);
  p.hs.on_tick(300);
  p.hs.on_tick(899);
  CHECK_EQ(p.sent.size(), 2u);
  p.hs.on_tick(900);
  CHECK_EQ(p.sent.size(), 3u);
  for (const Bytes& msg : p.sent) {
    CHECK(fcp::is_hello(msg.data(), msg.size()));
  }
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);
  p.hs.on_tick(2099);
  CHECK(p.hs.state() == fcp::HandshakeState::kHelloSent);
  p.hs.on_tick(2100);
  CHECK(p.hs.state() == fcp::HandshakeState::kFailed);
  CHECK(p.hs.error() == fcp::HandshakeError::kNoAck);
  CHECK_EQ(p.sent.size(), 3u);
  CHECK(std::string(fcp::handshake_error_text(p.hs.error())) == "no ACK after 3 tries");

  // A late tick after failure stays quiet.
  p.hs.on_tick(5000);
  CHECK_EQ(p.sent.size(), 3u);
}

// T26 (#27①): the retry timer backs off exponentially, an ACK at any stage
// stops it, and an RTT=500ms link (fatal under the old fixed 900ms budget)
// now completes the handshake.
void TestRetryBackoff() {
  // Gap sequence: 300 after the first send, then 600, then failure check 1200
  // after the third send (no 4th HELLO).
  Peer p(10, 3, HandshakeRole::kClient, 0x11);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK_EQ(p.hs.retries(), 1);
  CHECK_EQ(p.hs.next_retry_ms(), 300);
  p.hs.on_tick(300);
  CHECK_EQ(p.hs.retries(), 2);
  CHECK_EQ(p.hs.next_retry_ms(), 900);
  p.hs.on_tick(900);
  CHECK_EQ(p.hs.retries(), 3);
  CHECK_EQ(p.hs.next_retry_ms(), 2100);
  CHECK_EQ(p.sent.size(), 3u);

  // An ACK arriving during any backoff stage stops the timer permanently.
  const Bytes server_draw = Nonce(0x33);
  CHECK(p.deliver(MakeAck(p.nonce, server_draw)) == HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  p.hs.on_tick(2100);
  p.hs.on_tick(100000);
  CHECK_EQ(p.sent.size(), 3u);

  // RTT=500ms link, first two HELLOs lost: sends at 0 (lost) and 300 (lost);
  // the third send at 900 gets its ACK at 1400 — established, no failure.
  // The old fixed budget declared failure at 900ms before the ACK arrived.
  Peer q(10, 3, HandshakeRole::kClient, 0x44);
  q.hs.start(0);
  q.hs.on_tick(0);    // lost
  q.hs.on_tick(300);  // lost
  q.hs.on_tick(900);  // delivered; ACK arrives at 1400
  CHECK(q.deliver(MakeAck(q.nonce, server_draw)) == HandshakeStatus::kConsumed);
  CHECK(q.hs.established());
  q.hs.on_tick(2100);
  q.hs.on_tick(100000);
  CHECK_EQ(q.sent.size(), 3u);

  // Duplicate HELLO handling is unaffected by the backoff: the same draw is
  // re-ACKed (the peer may still be retrying because our ACK was lost).
  CHECK(p.deliver(MakeHello(server_draw)) == HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 4u);
  CHECK(fcp::is_hello_ack(p.sent.back().data(), p.sent.back().size()));
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

  // A failed handshake drops whatever was buffered.
  Peer s(10, 3, HandshakeRole::kClient, 0x55);
  s.hs.start(0);
  CHECK(s.hs.cache_data(Bytes(10, 0x44)));
  s.hs.on_tick(0);
  s.hs.on_tick(300);
  s.hs.on_tick(900);
  s.hs.on_tick(2100);
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
  TestAckStopsRetries();
  TestIdempotent();
  TestDataCache();
  TestCacheLimits();
  TestNonceIsRandom();
  return fcp_test::finish();
}
