#include "fcp/gcm.h"

#include <cstring>
#include <vector>

#include "fcp/aes.h"
#include "test_util.h"

namespace {

struct GcmVector {
  const char* name;
  uint8_t key[16];
  uint8_t iv[12];
  std::vector<uint8_t> aad;
  std::vector<uint8_t> plain;
  std::vector<uint8_t> cipher;
  uint8_t tag[12];
};

std::vector<GcmVector> Vectors() {
  std::vector<GcmVector> vectors(3);

  // NIST GCM test case 1 (empty message).
  vectors[0].name = "tc1";
  std::memset(vectors[0].key, 0, 16);
  std::memset(vectors[0].iv, 0, 12);
  static const uint8_t kTag1[12] = {0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E,
                                    0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57};
  std::memcpy(vectors[0].tag, kTag1, 12);

  // NIST GCM test case 2 (one zero block).
  vectors[1].name = "tc2";
  std::memset(vectors[1].key, 0, 16);
  std::memset(vectors[1].iv, 0, 12);
  vectors[1].plain.assign(16, 0);
  static const uint8_t kCipher2[16] = {0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
                                       0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78};
  vectors[1].cipher.assign(kCipher2, kCipher2 + 16);
  static const uint8_t kTag2[12] = {0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC,
                                    0x13, 0xBD, 0xF5, 0x3A, 0x67, 0xB2};
  std::memcpy(vectors[1].tag, kTag2, 12);

  // NIST GCM test case 3 (60 bytes, 20 bytes of AAD).
  vectors[2].name = "tc3";
  static const uint8_t kKey3[16] = {0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C,
                                    0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08};
  static const uint8_t kIv3[12] = {0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
                                   0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88};
  static const uint8_t kAad3[20] = {0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                                    0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                                    0xAB, 0xAD, 0xDA, 0xD2};
  static const uint8_t kPlain3[60] = {
      0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5,
      0xAF, 0xF5, 0x26, 0x9A, 0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA,
      0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72, 0x1C, 0x3C, 0x0C, 0x95,
      0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
      0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39};
  static const uint8_t kCipher3[60] = {
      0x42, 0x83, 0x1E, 0xC2, 0x21, 0x77, 0x74, 0x24, 0x4B, 0x72, 0x21, 0xB7,
      0x84, 0xD0, 0xD4, 0x9C, 0xE3, 0xAA, 0x21, 0x2F, 0x2C, 0x02, 0xA4, 0xE0,
      0x35, 0xC1, 0x7E, 0x23, 0x29, 0xAC, 0xA1, 0x2E, 0x21, 0xD5, 0x14, 0xB2,
      0x54, 0x66, 0x93, 0x1C, 0x7D, 0x8F, 0x6A, 0x5A, 0xAC, 0x84, 0xAA, 0x05,
      0x1B, 0xA3, 0x0B, 0x39, 0x6A, 0x0A, 0xAC, 0x97, 0x3D, 0x58, 0xE0, 0x91};
  static const uint8_t kTag3[12] = {0x5B, 0xC9, 0x4F, 0xBC, 0x32, 0x21,
                                    0xA5, 0xDB, 0x94, 0xFA, 0xE9, 0x5A};
  std::memcpy(vectors[2].key, kKey3, 16);
  std::memcpy(vectors[2].iv, kIv3, 12);
  vectors[2].aad.assign(kAad3, kAad3 + 20);
  vectors[2].plain.assign(kPlain3, kPlain3 + 60);
  vectors[2].cipher.assign(kCipher3, kCipher3 + 60);
  std::memcpy(vectors[2].tag, kTag3, 12);
  return vectors;
}

void TestNistVectors() {
  for (const GcmVector& vector : Vectors()) {
    std::vector<uint8_t> cipher(vector.plain.size());
    uint8_t tag[12];
    CHECK(fcp::gcm_seal(vector.key, vector.iv, vector.aad.empty() ? nullptr : vector.aad.data(),
                        vector.aad.size(), vector.plain.empty() ? nullptr : vector.plain.data(),
                        vector.plain.size(), cipher.data(), tag));
    CHECK_EQ(fcp_test::hex(cipher.data(), cipher.size()),
             fcp_test::hex(vector.cipher.data(), vector.cipher.size()));
    CHECK_EQ(fcp_test::hex(tag, 12), fcp_test::hex(vector.tag, 12));

    std::vector<uint8_t> plain(vector.cipher.size());
    CHECK(fcp::gcm_open(vector.key, vector.iv,
                        vector.aad.empty() ? nullptr : vector.aad.data(), vector.aad.size(),
                        vector.cipher.data(), vector.cipher.size(), vector.tag, plain.data()));
    CHECK_EQ(fcp_test::hex(plain.data(), plain.size()),
             fcp_test::hex(vector.plain.data(), vector.plain.size()));
  }
}

void TestRoundTripAndTamper() {
  for (int trial = 0; trial < 100; ++trial) {
    uint8_t key[16];
    uint8_t iv[12];
    for (int i = 0; i < 16; ++i) {
      key[i] = fcp_test::random_byte();
    }
    for (int i = 0; i < 12; ++i) {
      iv[i] = fcp_test::random_byte();
    }
    const size_t len = fcp_test::rng()() % 300;
    std::vector<uint8_t> plain(len);
    for (auto& byte : plain) {
      byte = fcp_test::random_byte();
    }
    std::vector<uint8_t> aad(fcp_test::rng()() % 40);
    for (auto& byte : aad) {
      byte = fcp_test::random_byte();
    }
    std::vector<uint8_t> cipher(len);
    uint8_t tag[12];
    CHECK(fcp::gcm_seal(key, iv, aad.empty() ? nullptr : aad.data(), aad.size(),
                        plain.empty() ? nullptr : plain.data(), len, cipher.data(), tag));

    std::vector<uint8_t> decoded(len);
    CHECK(fcp::gcm_open(key, iv, aad.empty() ? nullptr : aad.data(), aad.size(),
                        cipher.empty() ? nullptr : cipher.data(), len, tag, decoded.data()));
    CHECK_EQ(fcp_test::hex(decoded.data(), len), fcp_test::hex(plain.data(), len));

    if (len != 0) {
      cipher[trial % len] ^= 0x01;
      CHECK(!fcp::gcm_open(key, iv, aad.empty() ? nullptr : aad.data(), aad.size(),
                           cipher.data(), len, tag, decoded.data()));
      cipher[trial % len] ^= 0x01;
    }
    tag[trial % 12] ^= 0x80;
    CHECK(!fcp::gcm_open(key, iv, aad.empty() ? nullptr : aad.data(), aad.size(),
                         cipher.empty() ? nullptr : cipher.data(), len, tag, decoded.data()));
  }
}

// The GcmKey API (per-session key pre-expansion) must be byte-identical to the
// one-shot wrappers: same ciphertext, same truncated tag, and one expanded key
// stays valid across many seals with differing IVs and lengths.
void TestKeyedApi() {
  for (const GcmVector& vector : Vectors()) {
    fcp::GcmKey keyed;
    fcp::gcm_key_init(vector.key, &keyed);

    // H = E_K(0) is the GHASH multiplier cached by gcm_key_init; recomputing it
    // through the AES primitive proves the cached value is the right one.
    fcp::Aes128Key round_keys;
    fcp::aes128_expand_key(vector.key, &round_keys);
    uint8_t zero[16] = {};
    uint8_t h[16];
    fcp::aes128_encrypt_block(round_keys, zero, h);
    CHECK_EQ(fcp_test::hex(keyed.h, 16), fcp_test::hex(h, 16));

    std::vector<uint8_t> cipher(vector.plain.size());
    uint8_t tag[12];
    CHECK(fcp::gcm_seal_keyed(keyed, vector.iv,
                              vector.aad.empty() ? nullptr : vector.aad.data(),
                              vector.aad.size(),
                              vector.plain.empty() ? nullptr : vector.plain.data(),
                              vector.plain.size(), cipher.data(), tag));
    CHECK_EQ(fcp_test::hex(cipher.data(), cipher.size()),
             fcp_test::hex(vector.cipher.data(), vector.cipher.size()));
    CHECK_EQ(fcp_test::hex(tag, 12), fcp_test::hex(vector.tag, 12));

    std::vector<uint8_t> plain(vector.cipher.size());
    CHECK(fcp::gcm_open_keyed(keyed, vector.iv,
                              vector.aad.empty() ? nullptr : vector.aad.data(),
                              vector.aad.size(), vector.cipher.data(),
                              vector.cipher.size(), vector.tag, plain.data()));
    CHECK_EQ(fcp_test::hex(plain.data(), plain.size()),
             fcp_test::hex(vector.plain.data(), vector.plain.size()));
  }

  // One expanded key, many IVs and lengths: every result must match the
  // one-shot path, and a key differing by one bit cannot open the other's
  // output.
  uint8_t key[16];
  for (auto& byte : key) {
    byte = fcp_test::random_byte();
  }
  fcp::GcmKey keyed;
  fcp::gcm_key_init(key, &keyed);
  uint8_t wrong_key[16];
  std::memcpy(wrong_key, key, sizeof(wrong_key));
  wrong_key[0] ^= 0x01;
  fcp::GcmKey other;
  fcp::gcm_key_init(wrong_key, &other);

  for (int trial = 0; trial < 100; ++trial) {
    uint8_t iv[12];
    for (auto& byte : iv) {
      byte = fcp_test::random_byte();
    }
    const size_t len = fcp_test::rng()() % 300;
    std::vector<uint8_t> plain(len);
    for (auto& byte : plain) {
      byte = fcp_test::random_byte();
    }
    const uint8_t* in = len == 0 ? nullptr : plain.data();

    std::vector<uint8_t> keyed_cipher(len);
    uint8_t keyed_tag[12];
    CHECK(fcp::gcm_seal_keyed(keyed, iv, nullptr, 0, in, len,
                              len == 0 ? nullptr : keyed_cipher.data(), keyed_tag));

    std::vector<uint8_t> cipher(len);
    uint8_t tag[12];
    CHECK(fcp::gcm_seal(key, iv, nullptr, 0, in, len,
                        len == 0 ? nullptr : cipher.data(), tag));
    CHECK_EQ(fcp_test::hex(keyed_cipher.data(), len),
             fcp_test::hex(cipher.data(), len));
    CHECK_EQ(fcp_test::hex(keyed_tag, 12), fcp_test::hex(tag, 12));

    std::vector<uint8_t> decoded(len);
    CHECK(fcp::gcm_open_keyed(keyed, iv, nullptr, 0,
                              len == 0 ? nullptr : keyed_cipher.data(), len,
                              keyed_tag, len == 0 ? nullptr : decoded.data()));
    CHECK_EQ(fcp_test::hex(decoded.data(), len), fcp_test::hex(plain.data(), len));

    CHECK(!fcp::gcm_open_keyed(other, iv, nullptr, 0,
                               len == 0 ? nullptr : keyed_cipher.data(), len,
                               keyed_tag, len == 0 ? nullptr : decoded.data()));
  }

  // In-place seal (cipher aliases plain), as the header documents.
  std::vector<uint8_t> buf(37);
  for (auto& byte : buf) {
    byte = fcp_test::random_byte();
  }
  const std::vector<uint8_t> before = buf;
  uint8_t iv[12] = {};
  uint8_t tag[12];
  CHECK(fcp::gcm_seal_keyed(keyed, iv, nullptr, 0, buf.data(), buf.size(),
                            buf.data(), tag));
  std::vector<uint8_t> round(buf.size());
  CHECK(fcp::gcm_open_keyed(keyed, iv, nullptr, 0, buf.data(), buf.size(), tag,
                            round.data()));
  CHECK_EQ(fcp_test::hex(round.data(), round.size()),
           fcp_test::hex(before.data(), before.size()));
}

}  // namespace

int main() {
  TestNistVectors();
  TestRoundTripAndTamper();
  TestKeyedApi();
  return fcp_test::finish();
}
