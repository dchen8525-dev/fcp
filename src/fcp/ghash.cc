#include "fcp/ghash.h"

#include <cstring>

namespace fcp {

void gf128_mul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
  uint8_t z[16] = {};
  uint8_t v[16];
  std::memcpy(v, b, 16);

  for (int i = 0; i < 128; ++i) {
    if ((a[i >> 3] >> (7 - (i & 7))) & 1) {
      for (int j = 0; j < 16; ++j) {
        z[j] ^= v[j];
      }
    }
    const uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
    for (int j = 15; j > 0; --j) {
      v[j] = static_cast<uint8_t>((v[j] >> 1) | (v[j - 1] << 7));
    }
    v[0] = static_cast<uint8_t>(v[0] >> 1);
    if (lsb != 0) {
      v[0] ^= 0xE1;
    }
  }
  std::memcpy(out, z, 16);
}

Ghash::Ghash(const uint8_t h[16]) : h_{}, y_{} { std::memcpy(h_, h, 16); }

void Ghash::update_block(const uint8_t block[16]) {
  for (int i = 0; i < 16; ++i) {
    y_[i] ^= block[i];
  }
  uint8_t product[16];
  gf128_mul(y_, h_, product);
  std::memcpy(y_, product, 16);
}

void Ghash::update_padded(const uint8_t* data, size_t len) {
  while (len >= 16) {
    update_block(data);
    data += 16;
    len -= 16;
  }
  if (len != 0) {
    uint8_t tail[16] = {};
    std::memcpy(tail, data, len);
    update_block(tail);
  }
}

void Ghash::update_lengths(uint64_t aad_bytes, uint64_t cipher_bytes) {
  uint8_t block[16];
  const uint64_t aad_bits = aad_bytes * 8;
  const uint64_t cipher_bits = cipher_bytes * 8;
  for (int i = 0; i < 8; ++i) {
    block[i] = static_cast<uint8_t>(aad_bits >> (56 - 8 * i));
    block[8 + i] = static_cast<uint8_t>(cipher_bits >> (56 - 8 * i));
  }
  update_block(block);
}

void Ghash::finalize(uint8_t out[16]) const { std::memcpy(out, y_, 16); }

}  // namespace fcp
