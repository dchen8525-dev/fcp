#include "fcp/envelope.h"

#include <cstring>
#include <vector>

#include "fcp/gcm.h"
#include "fcp/random.h"
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

// R3-1: the v7 session key must bind fresh material from both ends.
//
// Every constant below was computed independently of this implementation with
// `openssl enc -aes-128-ecb -nopad -K <psk>` over the three chained blocks, so
// the test cannot pass just because the code agrees with itself.
void TestV7KeyVector() {
  uint8_t psk[16];
  uint8_t salt[8];
  uint8_t c_nonce[16];
  uint8_t s_nonce[16];
  CHECK(fcp_test::unhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0", psk, 16));
  CHECK(fcp_test::unhex("1122334455667788", salt, 8));
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));

  // Block 0 is the v6 value; v7 must not stop there.
  uint8_t v6[16];
  fcp::derive_session_key(psk, salt, v6);
  CHECK_EQ(fcp_test::hex(v6, 16), "18e6cda19e4e7799e2f2e18874e4c2d6");

  uint8_t key[16];
  fcp::derive_session_key_v7(psk, salt, c_nonce, s_nonce, key);
  CHECK_EQ(fcp_test::hex(key, 16), "54986bbc5ccc12b8666f56c7a5d6eb8d");
  CHECK(std::memcmp(key, v6, 16) != 0);

  // The two nonces are not interchangeable: which side contributes which is
  // fixed by Direction, and a swapped pair must not collide.
  uint8_t swapped[16];
  fcp::derive_session_key_v7(psk, salt, s_nonce, c_nonce, swapped);
  CHECK_EQ(fcp_test::hex(swapped, 16), "fce3349c24a2ee4b0a0a4c096c1f55af");

  // An all-zero pair (a peer that sent no freshness) is still not the v6 key.
  const uint8_t zero[16] = {};
  uint8_t degenerate[16];
  fcp::derive_session_key_v7(psk, salt, zero, zero, degenerate);
  CHECK_EQ(fcp_test::hex(degenerate, 16), "7363d57e850ce2d2f301b80bae264112");
  CHECK(std::memcmp(degenerate, v6, 16) != 0);

  // Same nonces under a different salt is a different session, as before.
  uint8_t salt2[8];
  CHECK(fcp_test::unhex("8877665544332211", salt2, 8));
  uint8_t other[16];
  fcp::derive_session_key_v7(psk, salt2, c_nonce, s_nonce, other);
  CHECK(std::memcmp(other, key, 16) != 0);
}

// A rekeyed envelope must restart at counter 0 under the new key, and the
// bootstrap instance must keep opening the pre-rekey datagrams -- that is what
// makes a retried HELLO readable after the data epoch moved on.
void TestRekey() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();

  uint8_t c_nonce[16];
  uint8_t s_nonce[16];
  uint8_t session_key[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c_nonce, s_nonce, session_key);

  const uint8_t payload[4] = {1, 2, 3, 4};
  std::vector<uint8_t> before;
  CHECK(client.seal(payload, sizeof(payload), &before));
  CHECK_EQ(client.send_nonce(), 1u);

  client.rekey(session_key);
  server.rekey(session_key);
  CHECK_EQ(client.send_nonce(), 0u);
  CHECK_EQ(server.send_nonce(), 0u);

  // The bootstrap-epoch datagram no longer authenticates under the new key.
  std::vector<uint8_t> plain;
  CHECK(!server.open(before.data(), before.size(), &plain));

  // The new epoch round-trips from counter 0, so the wire is reused only with a
  // new key (never the same (key, IV) pair twice).
  std::vector<uint8_t> after;
  CHECK(client.seal(payload, sizeof(payload), &after));
  CHECK(server.open(after.data(), after.size(), &plain));
  CHECK_EQ(plain.size(), sizeof(payload));
  CHECK_EQ(plain[0], 1);

  // A fresh bootstrap instance still opens the old datagram.
  fcp::Envelope bootstrap = MakeServer();
  CHECK(bootstrap.open(before.data(), before.size(), &plain));
  CHECK_EQ(plain[0], 1);
}

// Rekeying twice (a future key rotation does exactly this) must leave every
// earlier epoch dead on the current receiver, not just the immediately
// previous one: epoch0 died at the first rekey, epoch1 at the second.
void TestRekeyTwice() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();

  uint8_t c1[16], s1[16], c2[16], s2[16], key1[16], key2[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c1, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s1, 16));
  CHECK(fcp_test::unhex("0102030405060708090a0b0c0d0e0f10", c2, 16));
  CHECK(fcp_test::unhex("e0d0c0b0a090807060504030201000f0", s2, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c1, s1, key1);
  fcp::derive_session_key_v7(kKey, kSalt, c2, s2, key2);
  CHECK(std::memcmp(key1, key2, 16) != 0);

  const uint8_t payload[4] = {9, 8, 7, 6};
  std::vector<uint8_t> wire, plain;

  CHECK(client.seal(payload, sizeof(payload), &wire));  // bootstrap epoch
  const std::vector<uint8_t> epoch0 = wire;
  client.rekey(key1);
  server.rekey(key1);
  CHECK(client.seal(payload, sizeof(payload), &wire));
  const std::vector<uint8_t> epoch1 = wire;

  client.rekey(key2);
  server.rekey(key2);
  CHECK_EQ(client.send_nonce(), 0u);  // counters restart with every key change
  CHECK(client.seal(payload, sizeof(payload), &wire));
  CHECK(server.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain[0], 9);

  CHECK(!server.open(epoch1.data(), epoch1.size(), &plain));
  CHECK(!server.open(epoch0.data(), epoch0.size(), &plain));
}

// A broken CSPRNG can hand both ends the same draw. The schedule must not
// collapse onto the v6 bootstrap key (that would silently undo R3-1), and the
// two ends must still agree on the key they derive.
void TestV7IdenticalNonces() {
  uint8_t same[16], other[16], x0[16], key[16], key_again[16], key_other[16];
  CHECK(fcp_test::unhex("0a0b0c0d0e0f10111213141516171819", same, 16));
  CHECK(fcp_test::unhex("0a0b0c0d0e0f1011121314151617181a", other, 16));
  fcp::derive_session_key(kKey, kSalt, x0);
  fcp::derive_session_key_v7(kKey, kSalt, same, same, key);
  CHECK(std::memcmp(key, x0, 16) != 0);  // no shortcut back to the v6 key
  fcp::derive_session_key_v7(kKey, kSalt, same, same, key_again);
  CHECK(std::memcmp(key_again, key, 16) == 0);  // c == s: both ends still agree
  fcp::derive_session_key_v7(kKey, kSalt, other, same, key_other);
  CHECK(std::memcmp(key_other, key, 16) != 0);  // one differing draw re-splits
}

// R3-1/F-1: the bootstrap envelope draws a 64-bit start, so two session
// instances built from the same (PSK, salt) — which a replayed HELLO creates —
// never seal their first ACK under the same (key, IV).
void TestBootstrapNonceStart() {
  fcp::Envelope a = MakeClient();
  fcp::Envelope b = MakeClient();
  // Two session instances replaying one HELLO each have their own peer side.
  fcp::Envelope peer_a = MakeServer();
  fcp::Envelope peer_b = MakeServer();

  // Both envelopes must have drawn; without init both sit at 0.
  CHECK(a.send_nonce() == 0);
  CHECK(a.init_bootstrap_nonce(1u << 16));
  CHECK(peer_a.init_bootstrap_nonce(1u << 16));
  CHECK(b.init_bootstrap_nonce(1u << 16));
  CHECK(peer_b.init_bootstrap_nonce(1u << 16));
  // A 64-bit draw colliding across two instances: 2^-64. The old 32-bit start
  // collided after ~65k sessions under one salt.
  CHECK(a.send_nonce() != b.send_nonce());

  // Each peer accepts a start far above the 2^32 data-envelope ceiling: the
  // receive ceiling widens with the draw, otherwise the first bootstrap packet
  // would be rejected outright.
  const uint8_t payload[2] = {0x5A, 0xA5};
  std::vector<uint8_t> wire;
  std::vector<uint8_t> plain;
  CHECK(a.seal(payload, sizeof(payload), &wire));
  CHECK(peer_a.open(wire.data(), wire.size(), &plain));
  CHECK_EQ(plain[0], 0x5A);
  CHECK(b.seal(payload, sizeof(payload), &wire));
  CHECK(peer_b.open(wire.data(), wire.size(), &plain));

  // The budget bounds the packet count, and the counter never wraps: the last
  // legal counter is below UINT64_MAX.
  fcp::Envelope bounded = MakeClient();
  CHECK(bounded.init_bootstrap_nonce(8));
  CHECK(bounded.send_nonce() < UINT64_MAX - 9);
  for (int i = 0; i < 9; ++i) {
    CHECK(bounded.seal(nullptr, 0, &wire));
  }
  CHECK(bounded.exhausted());
  CHECK(!bounded.seal(nullptr, 0, &wire));

  // A data envelope (no bootstrap draw) keeps the 2^32 ceiling on both sides.
  fcp::Envelope data = MakeClient();
  CHECK(data.send_nonce() == 0);
  CHECK(data.set_send_nonce(fcp::Envelope::kNonceLimit - 1));
  CHECK(data.seal(nullptr, 0, &wire));
  CHECK(data.exhausted());
}

// The OS CSPRNG is the only source of salts/nonces/counter seeds; a silent
// failure there would seed a session from zeros.
void TestRandomSource() {
  uint8_t a[32];
  uint8_t b[32];
  CHECK(fcp::random_bytes(a, sizeof(a)));
  CHECK(fcp::random_bytes(b, sizeof(b)));
  CHECK(std::memcmp(a, b, sizeof(a)) != 0);
  int acc = 0;
  for (size_t i = 0; i < sizeof(a); ++i) {
    acc |= a[i];
  }
  CHECK(acc != 0);  // 32 zero bytes from a CSPRNG: never happens legitimately
  CHECK(fcp::random_bytes(a, 0));  // empty request is a no-op, not a failure
  CHECK(!fcp::random_bytes(nullptr, 4));
}

}  // namespace

// ---- key update / epoch rolling (#84) ----

// Rolling drives the 101st seal into epoch 1 (the first roll exercises the
// mechanism at kFirstRollAt); the receiver follows from the nonce's high bits
// alone; the frozen epoch-0 window keeps accepting late arrivals while
// rejecting both replays and the never-sent counters above its highest.
void TestKeyUpdateRollover() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  uint8_t c_nonce[16], s_nonce[16], session_key[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c_nonce, s_nonce, session_key);
  client.rekey(session_key);
  server.rekey(session_key);
  client.set_key_update(true);
  server.set_key_update(true);

  const uint8_t payload[4] = {1, 2, 3, 4};
  std::vector<std::vector<uint8_t>> epoch0;
  for (int i = 0; i < 100; ++i) {
    std::vector<uint8_t> wire;
    CHECK(client.seal(payload, sizeof(payload), &wire));
    epoch0.push_back(std::move(wire));
  }
  CHECK_EQ(client.send_epoch(), 0u);
  std::vector<uint8_t> first_epoch1;
  CHECK(client.seal(payload, sizeof(payload), &first_epoch1));
  CHECK_EQ(client.send_epoch(), 1u);
  CHECK_EQ(client.send_nonce(), fcp::Envelope::kEpochSpan + 1u);

  // Everything but the last epoch-0 datagram opens before the roll is seen.
  std::vector<uint8_t> plain;
  for (size_t i = 0; i + 1 < epoch0.size(); ++i) {
    CHECK(server.open(epoch0[i].data(), epoch0[i].size(), &plain));
    CHECK_EQ(plain.size(), sizeof(payload));
  }
  // The epoch-1 datagram makes the receiver follow; the late epoch-0 tail
  // still opens under the frozen window afterwards.
  CHECK(server.open(first_epoch1.data(), first_epoch1.size(), &plain));
  CHECK(server.open(epoch0.back().data(), epoch0.back().size(), &plain));
  // Replays die in both epochs.
  CHECK(!server.open(first_epoch1.data(), first_epoch1.size(), &plain));
  CHECK(!server.open(epoch0.back().data(), epoch0.back().size(), &plain));

  // The exercise roll is one-shot: the next seals stay in epoch 1 until
  // kEpochSpan, and the receiver keeps opening them under the epoch-1 key.
  std::vector<uint8_t> again;
  CHECK(client.seal(payload, sizeof(payload), &again));
  CHECK_EQ(client.send_epoch(), 1u);
  CHECK(server.open(again.data(), again.size(), &plain));
  std::vector<uint8_t> third;
  CHECK(client.seal(payload, sizeof(payload), &third));
  CHECK(server.open(third.data(), third.size(), &plain));

  // A counter in epoch 0 that was never sent (100..kEpochSpan) still opens
  // under the frozen key — the window slides like any other, gated by the tag;
  // what matters is that its replay dies.
  fcp::Envelope forged = MakeClient();
  forged.rekey(session_key);  // key_update stays off: epoch-0 key
  std::vector<uint8_t> evil;
  CHECK(forged.seal_at(5000, payload, sizeof(payload), &evil));
  CHECK(server.open(evil.data(), evil.size(), &plain));
  CHECK(!server.open(evil.data(), evil.size(), &plain));
  // A packet from the future epoch (seen + 2) is refused outright.
  CHECK(forged.seal_at(2 * fcp::Envelope::kEpochSpan, payload, sizeof(payload), &evil));
  CHECK(!server.open(evil.data(), evil.size(), &plain));
}

// A forged datagram may claim the next epoch (salt and nonce are plaintext),
// but it must not advance the receiver: two such datagrams used to move
// recv_epoch_seen_ past the live epoch and black-hole every legitimate packet
// until the sender completed a roll.
void TestKeyUpdateForgedRollDoesNotCommit() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  uint8_t c_nonce[16], s_nonce[16], session_key[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c_nonce, s_nonce, session_key);
  client.rekey(session_key);
  server.rekey(session_key);
  client.set_key_update(true);
  server.set_key_update(true);

  const uint8_t payload[4] = {1, 2, 3, 4};
  // One genuine epoch-0 packet, sealed before the attack.
  std::vector<uint8_t> legit;
  CHECK(client.seal(payload, sizeof(payload), &legit));

  // Same salt, same nonce layout, wrong key: the tag must fail.
  fcp::Envelope forger = MakeClient();
  std::vector<uint8_t> forged1, forged2, plain;
  CHECK(forger.seal_at(fcp::Envelope::kEpochSpan + 7, payload, sizeof(payload), &forged1));
  CHECK(forger.seal_at(2 * fcp::Envelope::kEpochSpan + 7, payload, sizeof(payload),
                       &forged2));
  CHECK(!server.open(forged1.data(), forged1.size(), &plain));
  CHECK(!server.open(forged2.data(), forged2.size(), &plain));

  // The failed roll attempts committed nothing: epoch 0 still opens.
  CHECK(server.open(legit.data(), legit.size(), &plain));
  CHECK_EQ(fcp_test::hex(plain.data(), plain.size()),
           fcp_test::hex(payload, sizeof(payload)));
}

// The v7-peer path: key update off keeps the flat single-key envelope — no
// roll at the 100-packet mark, the 2^32 ceiling (and its disconnect) intact.
void TestKeyUpdateOffNeverRolls() {
  fcp::Envelope client = MakeClient();
  fcp::Envelope server = MakeServer();
  uint8_t c_nonce[16], s_nonce[16], session_key[16];
  CHECK(fcp_test::unhex("000102030405060708090a0b0c0d0e0f", c_nonce, 16));
  CHECK(fcp_test::unhex("f0e0d0c0b0a090807060504030201000", s_nonce, 16));
  fcp::derive_session_key_v7(kKey, kSalt, c_nonce, s_nonce, session_key);
  client.rekey(session_key);
  server.rekey(session_key);
  // set_key_update is never called.

  const uint8_t payload[4] = {1, 2, 3, 4};
  for (int i = 0; i < 150; ++i) {
    std::vector<uint8_t> wire;
    CHECK(client.seal(payload, sizeof(payload), &wire));
    std::vector<uint8_t> plain;
    CHECK(server.open(wire.data(), wire.size(), &plain));
  }
  CHECK_EQ(client.send_epoch(), 0u);
  CHECK_EQ(client.send_nonce(), 150u);
}

int main() {
  TestEmptyAndRoundTrip();
  TestTamperAndSalt();
  TestReplay();
  TestNonceLimit();
  TestRecvNonceLimit();
  TestDirectionKeyIsolation();
  TestSessionKeyDerivation();
  TestV7KeyVector();
  TestRekey();
  TestRekeyTwice();
  TestV7IdenticalNonces();
  TestBootstrapNonceStart();
  TestRandomSource();
  TestKeyUpdateRollover();
  TestKeyUpdateForgedRollDoesNotCommit();
  TestKeyUpdateOffNeverRolls();
  return fcp_test::finish();
}
