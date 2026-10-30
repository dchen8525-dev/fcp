#include "fcp/envelope.h"

#include <cstring>
#include <vector>

#include "fcp/gcm.h"
#include "test_util.h"

namespace {

const uint8_t kKey[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
const uint8_t kSalt[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

fcp::Envelope MakeClient() {
  return fcp::Envelope(kKey, kSalt, fcp::Direction::kC2S, fcp::Direction::kS2C);
}
fcp::Envelope MakeServer() {
  return fcp::Envelope(kKey, kSalt, fcp::Direction::kS2C, fcp::Direction::kC2S);
}

void TestEmptyAndRoundTrip() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();

  std::vector<uint8_t> wire;
  CHECK(client.seal(nullptr, 0, &wire));
  CHECK_EQ(wire.size(), fcp::Envelope::kOverhead);
  CHECK_EQ(wire.size(), static_cast<size_t>(28));
  CHECK_EQ(fcp_test::hex(wire.data(), 8), fcp_test::hex(kSalt, 8));

  std::vector<uint8_t> plain;
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK(plain.empty());
  CHECK_EQ(client.send_nonce(), 1u);

  std::vector<uint8_t> payload(5);
  for (int i = 0; i < 5; ++i) {
    payload[static_cast<size_t>(i)] = static_cast<uint8_t>(0xA0 + i);
  }
  CHECK(client.seal(payload.data(), payload.size(), &wire));
  CHECK_EQ(wire.size(), payload.size() + 28);
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(fcp_test::hex(plain.data(), plain.size()),
           fcp_test::hex(payload.data(), payload.size()));

  // Same plaintext sealed by the other direction must differ (separate IV byte).
  std::vector<uint8_t> client_wire;
  std::vector<uint8_t> server_wire;
  CHECK(client.seal_at(100, payload.data(), payload.size(), &client_wire));
  CHECK(server.seal_at(100, payload.data(), payload.size(), &server_wire));
  CHECK(client_wire != server_wire);
}

void TestTamperAndSalt() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  std::vector<uint8_t> wire;
  const uint8_t payload[4] = {1, 2, 3, 4};
  CHECK(client.seal(payload, sizeof(payload), &wire));

  std::vector<uint8_t> tampered = wire;
  tampered[16] ^= 0x01;  // first ciphertext byte
  std::vector<uint8_t> plain;
  CHECK(!server.open(tampered.data(), tampered.size(), &plain));

  tampered = wire;
  tampered.back() ^= 0x01;  // tag
  CHECK(!server.open(tampered.data(), tampered.size(), &plain));

  tampered = wire;
  tampered[0] ^= 0x01;  // salt
  CHECK(!server.open(tampered.data(), tampered.size(), &plain));

  CHECK(!server.open(wire.data(), 27, &plain));
  // Failed attempts above must not burn the counter: the intact packet still opens.
  CHECK(server.open(wire.data(), wire.size(), &plain));

  const uint8_t other_salt[8] = {9, 9, 9, 9, 9, 9, 9, 9};
  fcp::Envelope stranger(kKey, other_salt, fcp::Direction::kS2C, fcp::Direction::kC2S);
  CHECK(!stranger.open(wire.data(), wire.size(), &plain));
}

void TestReplay() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  const uint8_t payload[3] = {7, 8, 9};
  std::vector<uint8_t> first;
  std::vector<uint8_t> plain;
  CHECK(client.seal(payload, sizeof(payload), &first));
  CHECK(server.open(first.data(), first.size(), &plain));
  // Immediate replay is rejected.
  CHECK(!server.open(first.data(), first.size(), &plain));

  std::vector<uint8_t> second;
  CHECK(client.seal(payload, sizeof(payload), &second));
  CHECK(server.open(second.data(), second.size(), &plain));
  // Replaying an older counter is rejected.
  CHECK(!server.open(first.data(), first.size(), &plain));

  // Reordered-but-fresh packets inside the replay window are still accepted.
  std::vector<uint8_t> third;
  std::vector<uint8_t> fourth;
  CHECK(client.seal_at(10, payload, sizeof(payload), &third));
  CHECK(client.seal_at(11, payload, sizeof(payload), &fourth));
  CHECK(server.open(third.data(), third.size(), &plain));
  CHECK(server.open(fourth.data(), fourth.size(), &plain));
  CHECK(server.open(third.data(), third.size(), &plain) == false);
}

void TestNonceLimit() {
  fcp::Envelope client = MakeClient();
  CHECK(client.set_send_nonce(fcp::Envelope::kNonceLimit - 1));
  CHECK(!client.exhausted());
  const uint8_t payload[1] = {0x42};
  std::vector<uint8_t> wire;
  CHECK(client.seal(payload, sizeof(payload), &wire));
  CHECK_EQ(client.send_nonce(), fcp::Envelope::kNonceLimit);
  CHECK(client.exhausted());
  CHECK(!client.seal(payload, sizeof(payload), &wire));

  std::vector<uint8_t> at_limit;
  CHECK(!client.seal_at(fcp::Envelope::kNonceLimit, payload, sizeof(payload), &at_limit));
  CHECK(client.seal_at(fcp::Envelope::kNonceLimit - 1, payload, sizeof(payload), &at_limit));
  CHECK(!client.set_send_nonce(fcp::Envelope::kNonceLimit));
}

// A hand-built (validly authenticated) packet at or past the nonce limit must be
// rejected by the receiver, not just by the sender: a misbehaving peer could
// otherwise push the replay window to the wrap point.
//
// #26②: the envelope seals/opens with direction keys derived from the
// per-session key (#28①), so hand-built wires must use the same derived key to
// count as "validly authenticated".
void TestRecvNonceLimit() {
  const uint8_t payload[2] = {0xAA, 0x55};

  uint8_t session_key[16];
  uint8_t key_c2s[16];
  uint8_t key_s2c[16];
  fcp::derive_session_key(kKey, kSalt, session_key);
  fcp::derive_direction_keys(session_key, key_c2s, key_s2c);

  auto make_wire = [&](uint64_t nonce) {
    std::vector<uint8_t> wire(fcp::Envelope::kOverhead + sizeof(payload));
    std::memcpy(wire.data(), kSalt, 8);
    uint8_t iv[fcp::kGcmIvLen] = {};
    for (int i = 0; i < 8; ++i) {
      wire[8 + i] = static_cast<uint8_t>(nonce >> (8 * i));
      iv[i] = static_cast<uint8_t>(nonce >> (8 * i));
    }
    iv[8] = static_cast<uint8_t>(fcp::Direction::kC2S);  // client -> server
    uint8_t* cipher = wire.data() + 16;
    uint8_t* tag = cipher + sizeof(payload);
    CHECK(fcp::gcm_seal(key_c2s, iv, nullptr, 0, payload, sizeof(payload), cipher, tag));
    return wire;
  };

  fcp::Envelope server = MakeServer();
  std::vector<uint8_t> plain;
  std::vector<uint8_t> past = make_wire(fcp::Envelope::kNonceLimit);
  CHECK(!server.open(past.data(), past.size(), &plain));

  std::vector<uint8_t> last = make_wire(fcp::Envelope::kNonceLimit - 1);
  CHECK(server.open(last.data(), last.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
  CHECK_EQ(plain[0], 0xAA);
}

// #26②: direction keys are isolated (T19) and derivation is deterministic
// (T25). Also proves a hand-built wire sealed with the raw session key no
// longer opens — the old single-key behavior is gone.
void TestDirectionKeyIsolation() {
  uint8_t c2s_a[16];
  uint8_t s2c_a[16];
  uint8_t c2s_b[16];
  uint8_t s2c_b[16];
  fcp::derive_direction_keys(kKey, c2s_a, s2c_a);
  fcp::derive_direction_keys(kKey, c2s_b, s2c_b);
  CHECK(std::memcmp(c2s_a, c2s_b, 16) == 0);  // deterministic
  CHECK(std::memcmp(s2c_a, s2c_b, 16) == 0);
  CHECK(std::memcmp(c2s_a, s2c_a, 16) != 0);  // directions differ
  CHECK(std::memcmp(c2s_a, kKey, 16) != 0);   // not the raw session key
  CHECK(std::memcmp(s2c_a, kKey, 16) != 0);

  // Cross-direction open must fail: a c2s-sealed packet under the s2c key.
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  const uint8_t payload[3] = {1, 2, 3};
  std::vector<uint8_t> wire;
  CHECK(client.seal(payload, sizeof(payload), &wire));

  uint8_t iv[fcp::kGcmIvLen] = {};
  for (int i = 0; i < 8; ++i) {
    iv[i] = wire[8 + i];
  }
  iv[8] = static_cast<uint8_t>(fcp::Direction::kC2S);
  uint8_t s2c_cipher[3];
  uint8_t s2c_tag[12];
  CHECK(fcp::gcm_seal(s2c_a, iv, nullptr, 0, payload, sizeof(payload),
                      s2c_cipher, s2c_tag));
  std::vector<uint8_t> cross(wire);
  std::memcpy(cross.data() + 16, s2c_cipher, sizeof(payload));
  std::memcpy(cross.data() + 16 + sizeof(payload), s2c_tag, 12);
  std::vector<uint8_t> plain;
  CHECK(!server.open(cross.data(), cross.size(), &plain));

  // The honest wire still opens.
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
}

// #28① (T27): the session key is derived per session from (PSK, salt), so two
// sessions sharing a PSK no longer share GCM keys. Before this fix the
// derivation below collapsed to the PSK and the salt-isolation assertions
// failed — the bug this test pins.
void TestSessionKeyDerivation() {
  const uint8_t kSaltB[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
  const uint8_t kKeyB[16] = {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78,
                             0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70};

  // Deterministic: same PSK + same salt -> identical session key (both ends
  // compute it locally with no extra wire exchange).
  uint8_t sk_a1[16];
  uint8_t sk_a2[16];
  fcp::derive_session_key(kKey, kSalt, sk_a1);
  fcp::derive_session_key(kKey, kSalt, sk_a2);
  CHECK(std::memcmp(sk_a1, sk_a2, 16) == 0);

  // Salt isolation (the P0 property): same PSK, different salt -> different
  // session key, hence different direction keys.
  uint8_t sk_b[16];
  fcp::derive_session_key(kKey, kSaltB, sk_b);
  CHECK(std::memcmp(sk_a1, sk_b, 16) != 0);

  // PSK isolation: different PSK, same salt -> different session key.
  uint8_t sk_c[16];
  fcp::derive_session_key(kKeyB, kSalt, sk_c);
  CHECK(std::memcmp(sk_a1, sk_c, 16) != 0);

  // The session key must not be the PSK itself.
  CHECK(std::memcmp(sk_a1, kKey, 16) != 0);

  // Direction keys follow the session key, not the PSK: deriving them from
  // sk_a1 vs sk_b (same PSK, different salts) gives different results.
  uint8_t c2s_a[16];
  uint8_t s2c_a[16];
  uint8_t c2s_b[16];
  uint8_t s2c_b[16];
  fcp::derive_direction_keys(sk_a1, c2s_a, s2c_a);
  fcp::derive_direction_keys(sk_b, c2s_b, s2c_b);
  CHECK(std::memcmp(c2s_a, c2s_b, 16) != 0);
  CHECK(std::memcmp(s2c_a, s2c_b, 16) != 0);

  // Behavioral: a hand-built wire sealed under the OLD scheme (direction keys
  // straight from the PSK) must no longer open — the raw PSK never
  // encrypts traffic now.
  fcp::Envelope server = MakeServer();
  uint8_t legacy_c2s[16];
  fcp::derive_direction_keys(kKey, legacy_c2s, s2c_a);
  const uint8_t payload[3] = {4, 5, 6};
  std::vector<uint8_t> wire(fcp::Envelope::kOverhead + sizeof(payload));
  std::memcpy(wire.data(), kSalt, 8);
  uint8_t iv[fcp::kGcmIvLen] = {};
  iv[8] = static_cast<uint8_t>(fcp::Direction::kC2S);
  uint8_t* cipher = wire.data() + 16;
  uint8_t* tag = cipher + sizeof(payload);
  CHECK(fcp::gcm_seal(legacy_c2s, iv, nullptr, 0, payload, sizeof(payload),
                      cipher, tag));
  std::vector<uint8_t> plain;
  CHECK(!server.open(wire.data(), wire.size(), &plain));

  // The same wire sealed under the derived session key opens.
  CHECK(fcp::gcm_seal(c2s_a, iv, nullptr, 0, payload, sizeof(payload),
                      cipher, tag));
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
  CHECK_EQ(plain[0], 4);
}

}  // namespace

int main() {
  TestEmptyAndRoundTrip();
  TestTamperAndSalt();
  TestReplay();
  TestNonceLimit();
  TestRecvNonceLimit();
  TestDirectionKeyIsolation();
  TestSessionKeyDerivation();
  return fcp_test::finish();
}
