#include "fcp/gcm.h"

#include <cstring>

#include "fcp/aes.h"
#include "fcp/ghash.h"

namespace fcp {
namespace {

void increment_counter(uint8_t counter[16]) {
  for (int i = 15; i >= 12; --i) {
    if (++counter[i] != 0) {
      return;
    }
  }
}

void make_j0(const uint8_t iv[kGcmIvLen], uint8_t j0[16]) {
  std::memcpy(j0, iv, kGcmIvLen);
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;
}

void compute_tag(const Aes128Key& key, const uint8_t j0[16], const uint8_t* aad,
                 size_t aad_len, const uint8_t* cipher, size_t cipher_len,
                 uint8_t tag[16]) {
  uint8_t h[16];
  uint8_t zero[16] = {};
  aes128_encrypt_block(key, zero, h);

  Ghash ghash(h);
  ghash.update_padded(aad, aad_len);
  ghash.update_padded(cipher, cipher_len);
  ghash.update_lengths(aad_len, cipher_len);

  uint8_t s[16];
  uint8_t ek[16];
  ghash.finalize(s);
  aes128_encrypt_block(key, j0, ek);
  for (int i = 0; i < 16; ++i) {
    tag[i] = static_cast<uint8_t>(s[i] ^ ek[i]);
  }
}

void ctr_xor(const Aes128Key& key, const uint8_t j0[16], const uint8_t* in, size_t len,
             uint8_t* out) {
  uint8_t counter[16];
  std::memcpy(counter, j0, 16);
  size_t off = 0;
  while (off < len) {
    increment_counter(counter);
    uint8_t stream[16];
    aes128_encrypt_block(key, counter, stream);
    const size_t take = (len - off < 16) ? len - off : 16;
    for (size_t i = 0; i < take; ++i) {
      out[off + i] = static_cast<uint8_t>(in[off + i] ^ stream[i]);
    }
    off += take;
  }
}

}  // namespace

bool gcm_seal(const uint8_t key[16], const uint8_t iv[kGcmIvLen], const uint8_t* aad,
              size_t aad_len, const uint8_t* plain, size_t len, uint8_t* cipher,
              uint8_t tag[kGcmTagLen]) {
  Aes128Key round_keys;
  aes128_expand_key(key, &round_keys);
  uint8_t j0[16];
  make_j0(iv, j0);
  ctr_xor(round_keys, j0, plain, len, cipher);

  uint8_t full_tag[16];
  compute_tag(round_keys, j0, aad, aad_len, cipher, len, full_tag);
  std::memcpy(tag, full_tag, kGcmTagLen);
  return true;
}

bool gcm_open(const uint8_t key[16], const uint8_t iv[kGcmIvLen], const uint8_t* aad,
              size_t aad_len, const uint8_t* cipher, size_t len,
              const uint8_t tag[kGcmTagLen], uint8_t* plain) {
  Aes128Key round_keys;
  aes128_expand_key(key, &round_keys);
  uint8_t j0[16];
  make_j0(iv, j0);

  uint8_t expected[16];
  compute_tag(round_keys, j0, aad, aad_len, cipher, len, expected);

  uint8_t diff = 0;
  for (size_t i = 0; i < kGcmTagLen; ++i) {
    diff = static_cast<uint8_t>(diff | (expected[i] ^ tag[i]));
  }
  if (diff != 0) {
    return false;
  }

  ctr_xor(round_keys, j0, cipher, len, plain);
  return true;
}

}  // namespace fcp
