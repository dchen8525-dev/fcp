// Defensive paths across module boundaries.
//
// The happy path is covered by the module tests; the branches pinned here are
// the ones that only exist to reject junk or to fail closed — malformed
// handshake framing, envelope boundaries ordinary traffic never reaches, and
// entry points a host can call with shapes a healthy peer cannot produce.
// Each case is the code's answer to "what if the peer (or the host) lies".

#include <cstring>
#include <string>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/fecstat.h"
#include "fcp/frame_rx.h"
#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "fcp/session.h"
#include "fcp/wire.h"
#include "test_util.h"

namespace {

using Bytes = std::vector<uint8_t>;

const uint8_t kKey[16] = {0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
                          0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0};
const uint8_t kSalt[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
const uint8_t kSaltB[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

// ---- handshake: error text and extension framing ----

void TestErrorText() {
  using fcp::HandshakeError;
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kNone)),
           std::string("none"));
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kNoAck)),
           std::string("no ACK before the retry budget ran out"));
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kBadCaps)),
           std::string("invalid caps"));
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kMissingCapability)),
           std::string("missing required capability"));
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kCacheOverflow)),
           std::string("pre-negotiation data cache overflow"));
  CHECK_EQ(std::string(fcp::handshake_error_text(HandshakeError::kBadNonce)),
           std::string("invalid handshake nonce"));
  // An out-of-range code still renders as text an operator can read.
  CHECK_EQ(std::string(fcp::handshake_error_text(static_cast<HandshakeError>(200))),
           std::string("unknown"));
}

void TestExtBuilderRejects() {
  Bytes nonce(16, 0x11);
  Bytes out(fcp::kHelloAckLen + 64, 0);
  const uint8_t plain_caps = fcp::kLocalFlagsM1;
  const uint8_t tlv_caps = plain_caps | fcp::kCapTlv;

  // No kCapTlv flag: the block must not be emitted.
  CHECK_EQ(fcp::build_hello_ext({1, 10, 3, plain_caps}, nonce.data(), {}, out.data(),
                                out.size()),
           0u);
  CHECK_EQ(fcp::build_hello_ack_ext({1, 10, 3, plain_caps}, nonce.data(),
                                    nonce.data(), {}, out.data(), out.size()),
           0u);
  // Not even room for the fixed message.
  CHECK_EQ(fcp::build_hello_ext({1, 10, 3, tlv_caps}, nonce.data(), {}, out.data(),
                                fcp::kHelloLen - 1),
           0u);
  CHECK_EQ(fcp::build_hello_ack_ext({1, 10, 3, tlv_caps}, nonce.data(), nonce.data(),
                                    {}, out.data(), fcp::kHelloAckLen - 1),
           0u);
  // A reserved type cannot be encoded, so the whole block is refused.
  CHECK_EQ(fcp::build_hello_ext({1, 10, 3, tlv_caps}, nonce.data(), {{0, {1}}},
                                out.data(), out.size()),
           0u);
  CHECK_EQ(fcp::build_hello_ack_ext({1, 10, 3, tlv_caps}, nonce.data(), nonce.data(),
                                    {{0, {1}}}, out.data(), out.size()),
           0u);
  // The empty block still round-trips as "bit set, length 0".
  CHECK_EQ(fcp::build_hello_ext({1, 10, 3, tlv_caps}, nonce.data(), {}, out.data(),
                                out.size()),
           fcp::kHelloLen + fcp::kTlvBlockLenBytes);
  CHECK_EQ(fcp::build_hello_ack_ext({1, 10, 3, tlv_caps}, nonce.data(), nonce.data(),
                                    {}, out.data(), out.size()),
           fcp::kHelloAckLen + fcp::kTlvBlockLenBytes);
}

void TestHelloFraming() {
  Bytes nonce(16, 0x22);
  Bytes hello(fcp::kHelloLen, 0);
  fcp::build_hello({1, 10, 3, fcp::kLocalFlagsM1 | fcp::kCapTlv}, nonce.data(),
                   hello.data());

  // kCapTlv set but only one byte follows: not enough for a block length, so
  // the message is not a handshake message at all.
  Bytes one_byte(hello);
  one_byte.push_back(0x00);
  CHECK(!fcp::is_hello(one_byte.data(), one_byte.size()));

  // A consistent empty block is a valid message.
  Bytes empty_block(hello);
  empty_block.push_back(0x00);
  empty_block.push_back(0x00);
  CHECK(fcp::is_hello(empty_block.data(), empty_block.size()));
  std::vector<fcp::HandshakeTlv> tlvs;
  CHECK(fcp::hello_tlvs(empty_block.data(), empty_block.size(), false, &tlvs));
  CHECK(tlvs.empty());

  // The declared block length must match the buffer.
  Bytes mismatch(empty_block);
  mismatch[fcp::kHelloLen] = 0x07;
  CHECK(!fcp::is_hello(mismatch.data(), mismatch.size()));
  CHECK(!fcp::hello_tlvs(mismatch.data(), mismatch.size(), false, &tlvs));

  // A block over kTlvBlockMaxLen is refused before parsing.
  Bytes too_big(empty_block);
  too_big[fcp::kHelloLen] = 0x00;
  too_big[fcp::kHelloLen + 1] = 0x08;  // 2048
  CHECK(!fcp::hello_tlvs(too_big.data(), too_big.size(), false, &tlvs));

  // No kCapTlv: "no block claimed" is success with an empty list.
  Bytes plain(hello);
  plain[fcp::kHelloLen - 1] = fcp::kLocalFlagsM1;
  CHECK(fcp::hello_tlvs(plain.data(), plain.size(), false, &tlvs));
  CHECK(tlvs.empty());
}

struct Peer {
  std::vector<Bytes> sent;
  Bytes nonce;
  fcp::Handshake hs;

  Peer(fcp::HandshakeRole role, uint8_t fill)
      : sent(),
        nonce(16, fill),
        hs(10, 3,
           [this](const uint8_t* data, size_t len) {
             sent.emplace_back(data, data + len);
           },
           role, nonce.data(), fcp::kLocalFlagsM1,
           fcp::kHandshakeMaxCachedSegments, fcp::kHandshakeMaxCachedBytes, 0) {}
};

void TestFailedHandshakeIgnoresHello() {
  Peer p(fcp::HandshakeRole::kClient, 0x33);
  p.hs.start(0);
  // Version 2 is not a capability this build knows: fail, don't negotiate.
  Bytes bad(fcp::kHelloLen, 0);
  fcp::build_hello({2, 10, 3, fcp::kLocalFlagsM1}, p.nonce.data(), bad.data());
  CHECK(p.hs.on_oob(bad.data(), bad.size()) == fcp::HandshakeStatus::kProtocolFailure);
  CHECK(p.hs.state() == fcp::HandshakeState::kFailed);

  // Once failed, a well-formed HELLO is consumed without being interpreted:
  // a second injection must not be able to restart the state machine.
  Bytes good(fcp::kHelloLen, 0);
  fcp::build_hello({1, 10, 3, fcp::kLocalFlagsM1}, p.nonce.data(), good.data());
  CHECK(p.hs.on_oob(good.data(), good.size()) == fcp::HandshakeStatus::kConsumed);
}

void TestBadNonceGetsErrorAck() {
  // Only the server answers a rejected HELLO with an error ACK (the client's
  // counterpart is the peer-error path in TestPeerErrorCodeNormalises).
  Peer p(fcp::HandshakeRole::kServer, 0x44);
  p.hs.start(0);
  const uint8_t zero_nonce[16] = {};
  Bytes hello(fcp::kHelloLen + fcp::kTlvBlockLenBytes, 0);
  fcp::build_hello({1, 10, 3, fcp::kLocalFlagsM1 | fcp::kCapTlv}, zero_nonce,
                   hello.data());
  // Empty block, so the framing is consistent and the caps check passes.
  CHECK(p.hs.on_oob(hello.data(), hello.size()) ==
        fcp::HandshakeStatus::kProtocolFailure);
  CHECK(p.hs.error() == fcp::HandshakeError::kBadNonce);

  // A TLV peer gets the reason back instead of running out the retry table.
  CHECK_EQ(p.sent.size(), 1u);
  if (p.sent.empty()) {
    return;
  }
  CHECK(fcp::is_hello_ack(p.sent[0].data(), p.sent[0].size()));
  std::vector<fcp::HandshakeTlv> tlvs;
  CHECK(fcp::hello_tlvs(p.sent[0].data(), p.sent[0].size(), true, &tlvs));
  CHECK_EQ(tlvs.size(), 1u);
  CHECK_EQ(tlvs[0].type, fcp::kTlvTypeError);
  CHECK_EQ(tlvs[0].value.size(), 1u);
  CHECK_EQ(tlvs[0].value[0],
           static_cast<uint8_t>(fcp::HandshakeError::kBadNonce));
}

void TestPeerErrorCodeNormalises() {
  Peer c(fcp::HandshakeRole::kClient, 0x55);
  c.hs.start(0);
  c.hs.on_tick(0);  // HELLO leaves; sent[0]
  Bytes s_nonce(16, 0x66);
  Bytes ack(fcp::kHelloAckLen + fcp::kTlvBlockLenBytes + 3, 0);
  fcp::build_hello_ack({1, 10, 3, fcp::kLocalFlagsM1 | fcp::kCapTlv},
                       c.nonce.data(), s_nonce.data(), ack.data());
  ack[fcp::kHelloAckLen] = 0x03;  // block length
  ack[fcp::kHelloAckLen + 2] = fcp::kTlvTypeError;
  ack[fcp::kHelloAckLen + 3] = 0x01;
  ack[fcp::kHelloAckLen + 4] = 9;  // not a code this build knows

  CHECK(c.hs.on_oob(ack.data(), ack.size()) ==
        fcp::HandshakeStatus::kProtocolFailure);
  // Only BadCaps / BadNonce cross the boundary; anything else is reported as
  // BadCaps so a peer cannot invent error classes here.
  CHECK(c.hs.peer_error() == fcp::HandshakeError::kBadCaps);
  CHECK(c.hs.error() == fcp::HandshakeError::kBadCaps);
}

void TestAckWithoutFramingFails() {
  Peer c(fcp::HandshakeRole::kClient, 0x77);
  c.hs.start(0);
  c.hs.on_tick(0);
  Bytes s_nonce(16, 0x78);
  Bytes ack(fcp::kHelloAckLen, 0);
  // FECSTAT without FRAMING: the required pair is not met, so negotiate fails
  // on the ACK path instead of leaving a half-configured session.
  fcp::build_hello_ack({1, 10, 3, fcp::kCapFecstat}, c.nonce.data(), s_nonce.data(),
                       ack.data());
  CHECK(c.hs.on_oob(ack.data(), ack.size()) ==
        fcp::HandshakeStatus::kProtocolFailure);
  CHECK(c.hs.error() == fcp::HandshakeError::kMissingCapability);
}

// ---- envelope: boundaries ordinary traffic never reaches ----

void TestEnvelopeEdges() {
  const uint8_t payload[3] = {1, 2, 3};
  fcp::Envelope client(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
  fcp::Envelope server(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  std::vector<uint8_t> wire;
  std::vector<uint8_t> plain;

  // An explicit-counter seal with no output buffer is refused, not written to.
  CHECK(!client.seal_at(0, payload, sizeof(payload), nullptr));

  // A counter far above the receiver's window re-bases it instead of shifting
  // a 1024-bit window by thousands of positions.
  CHECK(client.seal_at(5000, payload, sizeof(payload), &wire));
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
  CHECK_EQ(server.send_nonce(), 0u);  // receive state never touches send state

  // A sealed reset whose payload is not the reset magic is refused: the tag
  // being valid is not enough, the content has to say "reset".
  const uint8_t not_reset[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0};
  fcp::Envelope boot(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
  CHECK(boot.seal_at(0, not_reset, sizeof(not_reset), &wire));
  CHECK_EQ(wire.size(), fcp::Envelope::kOverhead + fcp::Envelope::kResetMagicLen);
  CHECK(!server.open_reset(wire.data(), wire.size(), &plain));

  // And a reset sealed under a different salt is refused by the salt check.
  fcp::Envelope stranger(kKey, kSaltB, fcp::Direction::kC2S, fcp::Direction::kS2C);
  const uint8_t reset[8] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
  CHECK(stranger.seal_at(0, reset, sizeof(reset), &wire));
  CHECK(!server.open_reset(wire.data(), wire.size(), &plain));
  // The honest reset still opens on this instance.
  CHECK(boot.seal_at(0, reset, sizeof(reset), &wire));
  CHECK(server.open_reset(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), fcp::Envelope::kResetMagicLen);
}

// ---- session: pre-negotiation paths and host-callable edges ----

fcp::SessionConfig MakeConfig(const uint8_t salt[8]) {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, kKey, sizeof(kKey));
  std::memcpy(cfg.salt, salt, fcp::Envelope::kSaltLen);
  return cfg;
}

// Seals as the peer would: the session under test is a C2S sender, so its
// receive key is the S2C direction key.
Bytes SealFrame(const uint8_t* plain, size_t len, uint64_t nonce) {
  fcp::Envelope env(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  std::vector<uint8_t> wire;
  CHECK(env.seal_at(nonce, plain, len, &wire));
  return wire;
}

Bytes FrameWire(uint64_t nonce, uint32_t set_id, uint8_t index, uint8_t type_k,
                const Bytes& symbol) {
  std::vector<uint8_t> plain(fcp::kFecHdrLen);
  fcp::pack_hdr(fcp::FecHdr{set_id, index, type_k}, plain.data());
  plain.insert(plain.end(), symbol.begin(), symbol.end());
  return SealFrame(plain.data(), plain.size(), nonce);
}

Bytes OobWire(uint64_t nonce, const uint8_t* body, size_t len) {
  std::vector<uint8_t> plain(fcp::kFecHdrLen);
  fcp::pack_hdr(fcp::FecHdr{0, 0, fcp::pack_type_k(0, 0, 2)}, plain.data());  // oob
  plain.insert(plain.end(), body, body + len);
  return SealFrame(plain.data(), plain.size(), nonce);
}

void TestSessionHostEdges() {
  fcp::SessionConfig cfg = MakeConfig(kSalt);
  std::vector<std::string> logs;
  fcp::Session s(cfg,
                 [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {},
                 [&logs](const std::string& line) { logs.push_back(line); });

  // A null segment with a non-zero length is a host bug: refuse it rather
  // than building a copy out of nullptr.
  s.on_kcp_output(nullptr, 4, 0);
  // No reporter exists before negotiation, so these are no-ops.
  s.flush_report(0);
  // srtt <= 0 carries no information and must not move the baseline.
  s.on_rtt_sample(0, 0);
  CHECK_EQ(s.srtt_ms(), fcp::kDefaultSrttMs);
  CHECK(!s.established());
  CHECK(s.config_valid());
}

void TestSessionPreNegotiationFrames() {
  fcp::SessionConfig cfg = MakeConfig(kSalt);
  std::vector<std::string> logs;
  fcp::Session s(cfg,
                 [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {},
                 [&logs](const std::string& line) { logs.push_back(line); });
  const uint32_t failures_before = s.struct_fail();

  // Data framing rejections before any codec exists.
  Bytes wire;
  // 1) symbol shorter than the 2-byte declared-length field.
  wire = FrameWire(1, 0, 0, fcp::pack_type_k(2, 0, 0), Bytes{0});
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  // 2) declared length disagrees with the symbol.
  wire = FrameWire(2, 0, 0, fcp::pack_type_k(2, 0, 0), Bytes{5, 0});
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  // 3) type 3 was retired by erratum #25 and must not be classified.
  wire = FrameWire(3, 0, 0, fcp::pack_type_k(2, 0, 3), Bytes{2, 0});
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(s.struct_fail() - failures_before, 3u);

  // 4) parity before negotiation: structurally fine, simply dropped (no codec).
  wire = FrameWire(4, 0, 0, fcp::pack_type_k(2, 0, 1), Bytes{2, 0});
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(s.struct_fail() - failures_before, 3u);
}

void TestSessionPreNegotiationOob() {
  fcp::SessionConfig cfg = MakeConfig(kSalt);
  std::vector<std::string> logs;
  fcp::Session s(cfg,
                 [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {},
                 [&logs](const std::string& line) { logs.push_back(line); });

  // NAT keepalive: consumed before the FECSTAT validator can count it.
  const uint8_t keepalive[8] = {'F', 'C', 'P', 'K', 'A', 'L', '1', 0};
  Bytes wire = OobWire(1, keepalive, sizeof(keepalive));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(logs.size(), 0u);

  // Stateless reset: the client flags the session dead and says so once.
  const uint8_t reset[8] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
  wire = OobWire(2, reset, sizeof(reset));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK(s.peer_dead());
  CHECK_EQ(logs.size(), 1u);
  CHECK(logs[0].find("stateless reset") != std::string::npos);
  // A second reset is consumed silently (the flag is already set).
  wire = OobWire(3, reset, sizeof(reset));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(logs.size(), 1u);

  // A valid FECSTAT before negotiation: the peer's report has no strategy to
  // feed yet, so it is counted and dropped instead of being applied.
  fcp::FecstatPacket stat = fcp::MakeFecstatPacket(kSalt);
  uint8_t body[fcp::kFecstatLen];
  fcp::encode_fecstat(stat, body);
  wire = OobWire(4, body, sizeof(body));
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(s.fecstat_rx(), 0u);  // only accepted reports count as rx
}

void TestSessionFailedHandshakeStopsOutput() {
  fcp::SessionConfig cfg = MakeConfig(kSalt);
  std::vector<std::string> logs;
  fcp::Session s(cfg,
                 [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {},
                 [&logs](const std::string& line) { logs.push_back(line); });

  // A HELLO this build cannot accept fails the handshake and is logged.
  Bytes hello(fcp::kHelloLen, 0);
  const uint8_t nonce[16] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
  fcp::build_hello({2, 10, 3, fcp::kLocalFlagsM1}, nonce, hello.data());
  Bytes wire = OobWire(1, hello.data(), hello.size());
  CHECK(s.on_wire(wire.data(), wire.size(), 0));
  CHECK_EQ(s.state(), fcp::HandshakeState::kFailed);
  CHECK_EQ(logs.size(), 1u);
  CHECK(logs[0].find("FEC handshake failed") != std::string::npos);

  // Once failed, KCP output is dropped on the floor: no codec will ever exist.
  const uint8_t seg[6] = {1, 2, 3, 4, 5, 6};
  s.on_kcp_output(seg, sizeof(seg), 0);
}

void TestSessionTableEdges() {
  fcp::SessionTable table;
  CHECK(!table.add(nullptr));
  table.remove(nullptr);  // no-op
  CHECK(table.find(nullptr) == nullptr);

  fcp::SessionConfig cfg_a = MakeConfig(kSalt);
  fcp::SessionConfig cfg_b = MakeConfig(kSaltB);
  fcp::Session a(cfg_a, [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {}, {});
  fcp::Session a2(cfg_a, [](const uint8_t*, size_t, fcp::SymbolType) {},
                  [](const uint8_t*, size_t) {}, {});
  fcp::Session b(cfg_b, [](const uint8_t*, size_t, fcp::SymbolType) {},
                 [](const uint8_t*, size_t) {}, {});

  CHECK(table.add(&a));
  CHECK(!table.add(&a2));  // one salt, one session
  CHECK_EQ(table.find(kSalt), &a);
  CHECK(table.find(kSaltB) == nullptr);

  // Removing a different session bound to the same salt must not unbind `a`.
  table.remove(&a2);
  CHECK_EQ(table.find(kSalt), &a);
  table.remove(&a);
  CHECK(table.find(kSalt) == nullptr);

  CHECK(table.add(&b));
  CHECK_EQ(table.find(kSaltB), &b);
  CHECK_EQ(table.size(), 1u);
}

// ---- frame rx: window bookkeeping edges ----

void TestFrameRxEdges() {
  std::vector<Bytes> delivered;
  fcp::FrameRx rx(
      10, 3, [&delivered](const uint8_t* p, size_t n) { delivered.emplace_back(p, p + n); },
      [](const uint8_t*, size_t, int64_t) {}, fcp::FrameRx::SnFn());

  // The caller-owned list form accepts a null pointer as "nothing to report".
  rx.active_set_ids(nullptr);
  CHECK(rx.active_set_ids().empty());

  auto feed_data = [&rx](uint32_t set_id) {
    std::vector<uint8_t> dg(fcp::kFecHdrLen);
    fcp::pack_hdr(fcp::FecHdr{set_id, 0, fcp::pack_type_k(2, 0, 0)}, dg.data());
    dg.push_back(2);  // declared symbol length
    dg.push_back(0);
    rx.on_datagram(dg.data(), dg.size(), 0);
  };
  feed_data(0);
  // A jump past kMaxGapPlaceholders is dropped outright: one forged far-future
  // id must not materialise (or re-anchor) hundreds of sets.
  feed_data(100);
  CHECK_EQ(rx.struct_fail(), 0u);
  CHECK_EQ(rx.active_sets(), 1u);
  CHECK_EQ(rx.ahead_dropped(), 1u);
}

}  // namespace

int main() {
  TestErrorText();
  TestExtBuilderRejects();
  TestHelloFraming();
  TestFailedHandshakeIgnoresHello();
  TestBadNonceGetsErrorAck();
  TestPeerErrorCodeNormalises();
  TestAckWithoutFramingFails();
  TestEnvelopeEdges();
  TestSessionHostEdges();
  TestSessionPreNegotiationFrames();
  TestSessionPreNegotiationOob();
  TestSessionFailedHandshakeStopsOutput();
  TestSessionTableEdges();
  TestFrameRxEdges();
  return fcp_test::finish();
}
