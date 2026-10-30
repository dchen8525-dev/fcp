#include "fcp/handshake.h"

#include <string>
#include <vector>

#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

struct Peer {
  std::vector<Bytes> sent;
  fcp::Handshake hs;

  explicit Peer(uint8_t d, uint8_t p, uint8_t flags = fcp::kLocalFlagsM1)
      : hs(d, p,
           [this](const uint8_t* data, size_t len) {
             sent.emplace_back(data, data + len);
           },
           flags) {}

  fcp::HandshakeStatus deliver(const Bytes& msg) { return hs.on_oob(msg.data(), msg.size()); }
};

Bytes Hello(uint8_t ver, uint8_t data, uint8_t parity, uint8_t flags) {
  Bytes out(fcp::kHelloLen);
  fcp::build_hello(fcp::HandshakeCaps{ver, data, parity, flags}, out.data());
  return out;
}

Bytes HelloAck(uint8_t ver, uint8_t data, uint8_t parity, uint8_t flags) {
  Bytes out(fcp::kHelloAckLen);
  fcp::build_hello_ack(fcp::HandshakeCaps{ver, data, parity, flags}, out.data());
  return out;
}

void TestWireGolden() {
  CHECK_EQ(fcp::kHelloLen, 20u);
  CHECK_EQ(fcp::kHelloAckLen, 20u);
  CHECK_EQ(static_cast<int>(fcp::kLocalFlagsM1), 0x07);

  const Bytes hello = Hello(1, 10, 3, 0x07);
  // "FCP_HELLO_V3" + 4 NUL padding (16-byte oob magic, erratum #25) + caps.
  CHECK_EQ(fcp_test::hex(hello.data(), hello.size()),
           "4643505f48454c4c4f5f563300000000010a0307");

  const Bytes ack = HelloAck(1, 10, 3, 0x07);
  CHECK_EQ(fcp_test::hex(ack.data(), ack.size()),
           "4643505f48454c4c4f5f41434b5f5633010a0307");

  CHECK(fcp::is_hello(hello.data(), hello.size()));
  CHECK(!fcp::is_hello_ack(hello.data(), hello.size()));
  CHECK(fcp::is_hello_ack(ack.data(), ack.size()));
  CHECK(!fcp::is_hello(ack.data(), ack.size()));

  CHECK(!fcp::is_hello(hello.data(), hello.size() - 1));
  CHECK(!fcp::is_hello_ack(ack.data(), ack.size() - 1));

  const Bytes junk(20, 0xAA);
  Peer p(10, 3);
  CHECK(p.deliver(junk) == fcp::HandshakeStatus::kNotHandshake);
  CHECK(p.deliver(hello) == fcp::HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
}

void TestMutualHandshake() {
  Peer a(10, 3);
  Peer b(10, 3);
  a.hs.start(0);
  b.hs.start(0);
  a.hs.on_tick(0);
  b.hs.on_tick(0);
  CHECK_EQ(a.sent.size(), 1u);
  CHECK_EQ(b.sent.size(), 1u);
  CHECK(fcp::is_hello(a.sent[0].data(), a.sent[0].size()));

  // B sees A's HELLO: ACK + establish.
  CHECK(b.deliver(a.sent[0]) == fcp::HandshakeStatus::kConsumed);
  CHECK(b.hs.established());
  CHECK_EQ(b.sent.size(), 2u);
  CHECK(fcp::is_hello_ack(b.sent[1].data(), b.sent[1].size()));
  CHECK_EQ(b.hs.params().d, 10);
  CHECK_EQ(b.hs.params().p, 3);
  CHECK(b.hs.params().mode == fcp::SessionMode::kFramedRepair);

  // A sees B's HELLO (simultaneous open): ACK + establish.
  CHECK(a.deliver(b.sent[0]) == fcp::HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK_EQ(a.sent.size(), 2u);
  CHECK(fcp::is_hello_ack(a.sent[1].data(), a.sent[1].size()));

  // Crossed ACKs are duplicates.
  CHECK(a.deliver(b.sent[1]) == fcp::HandshakeStatus::kConsumed);
  CHECK(b.deliver(a.sent[1]) == fcp::HandshakeStatus::kConsumed);
  CHECK(a.hs.established());
  CHECK(b.hs.established());

  // No retries after establishment.
  a.hs.on_tick(10000);
  CHECK_EQ(a.sent.size(), 2u);
  CHECK(a.hs.error() == fcp::HandshakeError::kNone);
}

void TestCapsNegotiation() {
  // min(D), min(P), AND(flags); bit3 is dropped because M1 does not set it.
  Peer a(10, 4, 0x0F);
  Peer b(8, 2, 0x03);
  a.hs.start(0);
  a.hs.on_tick(0);
  b.hs.start(0);
  b.hs.on_tick(0);
  CHECK(b.deliver(a.sent[0]) == fcp::HandshakeStatus::kConsumed);
  CHECK_EQ(b.hs.params().d, 8);
  CHECK_EQ(b.hs.params().p, 2);
  CHECK_EQ(static_cast<int>(b.hs.params().flags), 0x03);
  CHECK(b.hs.params().mode == fcp::SessionMode::kFramedRepair);

  Peer c(10, 3);
  c.hs.start(0);
  c.hs.on_tick(0);
  CHECK(c.deliver(b.sent[0]) == fcp::HandshakeStatus::kConsumed);
  CHECK_EQ(c.hs.params().d, 8);
  CHECK_EQ(c.hs.params().p, 2);
}

void TestStatsMode() {
  Peer a(10, 3);
  Peer b(10, 0);
  a.hs.start(0);
  b.hs.start(0);
  a.hs.on_tick(0);
  b.hs.on_tick(0);
  CHECK(a.deliver(b.sent[0]) == fcp::HandshakeStatus::kConsumed);
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
      {1, 10, 3, 0x10},   // reserved flag bit
      {1, 10, 3, 0x87},   // reserved high bit
  };
  for (const Case& c : kCases) {
    Peer p(10, 3);
    p.hs.start(0);
    p.hs.on_tick(0);
    const size_t before = p.sent.size();
    CHECK(p.deliver(Hello(c.ver, c.data, c.parity, c.flags)) ==
          fcp::HandshakeStatus::kProtocolFailure);
    CHECK(p.hs.state() == fcp::HandshakeState::kFailed);
    CHECK(p.hs.error() == fcp::HandshakeError::kBadCaps);
    CHECK_EQ(p.sent.size(), before);  // never ACK an invalid HELLO
  }

  // Bad caps also fail through the ACK path.
  Peer p(10, 3);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK(p.deliver(HelloAck(1, 0, 3, 0x07)) == fcp::HandshakeStatus::kProtocolFailure);
  CHECK(p.hs.error() == fcp::HandshakeError::kBadCaps);

  // Boundary: D + P == 256 is legal.
  Peer q(10, 3);
  q.hs.start(0);
  q.hs.on_tick(0);
  CHECK(q.deliver(Hello(1, 249, 7, 0x07)) == fcp::HandshakeStatus::kConsumed);
  CHECK(q.hs.established());
  CHECK_EQ(q.hs.params().d, 10);
  CHECK_EQ(q.hs.params().p, 3);
}

void TestMissingCapability() {
  Peer p(10, 3);
  p.hs.start(0);
  p.hs.on_tick(0);
  const size_t before = p.sent.size();
  CHECK(p.deliver(Hello(1, 10, 3, 0x06)) == fcp::HandshakeStatus::kProtocolFailure);  // no framing
  CHECK(p.hs.error() == fcp::HandshakeError::kMissingCapability);
  CHECK_EQ(p.sent.size(), before);

  Peer q(10, 3);
  q.hs.start(0);
  q.hs.on_tick(0);
  CHECK(q.deliver(Hello(1, 10, 3, 0x05)) == fcp::HandshakeStatus::kProtocolFailure);  // no FECSTAT
  CHECK(q.hs.error() == fcp::HandshakeError::kMissingCapability);
}

void TestTimeout() {
  Peer p(10, 3);
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
  CHECK(std::string(fcp::handshake_error_text(p.hs.error())) == "V3 no ACK after 3 tries");

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
  Peer p(10, 3);
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
  CHECK(p.deliver(HelloAck(1, 10, 3, 0x07)) == fcp::HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  p.hs.on_tick(2100);
  p.hs.on_tick(100000);
  CHECK_EQ(p.sent.size(), 3u);

  // RTT=500ms link, first two HELLOs lost: sends at 0 (lost) and 300 (lost);
  // the third send at 900 gets its ACK at 1400 — established, no failure.
  // The old fixed budget declared failure at 900ms before the ACK arrived.
  Peer q(10, 3);
  q.hs.start(0);
  q.hs.on_tick(0);    // lost
  q.hs.on_tick(300);  // lost
  q.hs.on_tick(900);  // delivered; ACK arrives at 1400
  CHECK(q.deliver(HelloAck(1, 10, 3, 0x07)) == fcp::HandshakeStatus::kConsumed);
  CHECK(q.hs.established());
  q.hs.on_tick(2100);
  q.hs.on_tick(100000);
  CHECK_EQ(q.sent.size(), 3u);

  // Duplicate HELLO handling is unaffected by the backoff: still re-ACKed.
  CHECK(p.deliver(Hello(1, 10, 3, 0x07)) == fcp::HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 4u);
  CHECK(fcp::is_hello_ack(p.sent.back().data(), p.sent.back().size()));
}

void TestAckStopsRetries() {
  Peer p(10, 3);
  p.hs.start(0);
  p.hs.on_tick(0);
  CHECK_EQ(p.sent.size(), 1u);
  CHECK(p.deliver(HelloAck(1, 10, 3, 0x07)) == fcp::HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  p.hs.on_tick(600);
  p.hs.on_tick(10000);
  CHECK_EQ(p.sent.size(), 1u);
  CHECK(p.hs.state() == fcp::HandshakeState::kEstablished);
}

void TestIdempotent() {
  Peer p(10, 3);
  const Bytes hello = Hello(1, 10, 3, 0x07);
  CHECK(p.deliver(hello) == fcp::HandshakeStatus::kConsumed);
  CHECK(p.hs.established());
  CHECK_EQ(p.sent.size(), 1u);  // one ACK
  const auto params = p.hs.params();

  // Duplicate HELLO: no renegotiation, but the ACK is resent.
  CHECK(p.deliver(hello) == fcp::HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 2u);
  CHECK_EQ(p.hs.params().d, params.d);
  CHECK_EQ(p.hs.params().p, params.p);

  // Duplicate ACK: swallowed.
  const Bytes ack = HelloAck(1, 10, 3, 0x07);
  CHECK(p.deliver(ack) == fcp::HandshakeStatus::kConsumed);
  CHECK_EQ(p.sent.size(), 2u);

  // A stray ACK before start() does not establish anything.
  Peer q(10, 3);
  CHECK(q.deliver(ack) == fcp::HandshakeStatus::kConsumed);
  CHECK(q.hs.state() == fcp::HandshakeState::kIdle);
  CHECK_EQ(q.sent.size(), 0u);
}

void TestDataCache() {
  Peer p(10, 3);
  p.hs.start(0);
  CHECK(p.hs.buffering_data());
  CHECK(p.hs.cache_data(Bytes{'a'}));
  CHECK(p.hs.cache_data(Bytes{'b', 'b'}));
  CHECK(p.hs.cache_data(Bytes{'c', 'c', 'c'}));
  CHECK_EQ(p.hs.cached_segments(), 3u);
  CHECK_EQ(p.hs.cached_bytes(), 6u);
  CHECK(p.hs.take_cached_data().empty());  // not established yet

  CHECK(p.deliver(Hello(1, 10, 3, 0x07)) == fcp::HandshakeStatus::kConsumed);
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
  {
    fcp::Handshake p(10, 3, nullptr, fcp::kLocalFlagsM1, 4, 16);
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
    fcp::Handshake q(10, 3, nullptr, fcp::kLocalFlagsM1, 4, 16);
    q.start(0);
    CHECK(q.cache_data(Bytes(16, 0x11)));  // byte cap, exactly
    CHECK(!q.cache_data(Bytes(1, 0x22)));
    CHECK(q.error() == fcp::HandshakeError::kCacheOverflow);

    // A single oversize segment fails immediately.
    fcp::Handshake r(10, 3, nullptr, fcp::kLocalFlagsM1, 4, 16);
    r.start(0);
    CHECK(!r.cache_data(Bytes(17, 0x33)));
    CHECK(r.error() == fcp::HandshakeError::kCacheOverflow);
  }
  {
    // Default limits (512 segs / 512 KiB, #28③ F2): 512 x 1 KiB fits exactly.
    fcp::Handshake d(10, 3, nullptr);
    d.start(0);
    for (size_t i = 0; i < fcp::kHandshakeMaxCachedSegments; ++i) {
      CHECK(d.cache_data(Bytes(1024, 0)));
    }
    CHECK_EQ(d.cached_segments(), fcp::kHandshakeMaxCachedSegments);
    CHECK(!d.cache_data(Bytes(1, 0xEE)));
    CHECK(d.error() == fcp::HandshakeError::kCacheOverflow);
  }

  // A failed handshake drops whatever was buffered.
  Peer s(10, 3);
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

}  // namespace

int main() {
  TestWireGolden();
  TestMutualHandshake();
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
  return fcp_test::finish();
}
