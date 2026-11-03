#include "fcp/ghash.h"

#include <cstring>

namespace fcp {
namespace {

// One application of the "multiply by alpha" step of the bit-serial routine:
// shift the whole 128-bit register right by one bit and, when the bit that fell
// off the end was set, fold the reduction polynomial back into the top byte.
inline void mul_x(uint8_t v[16]) {
  const uint8_t carry = static_cast<uint8_t>(v[15] & 1);
  for (int j = 15; j > 0; --j) {
    v[j] = static_cast<uint8_t>((v[j] >> 1) | (v[j - 1] << 7));
  }
  v[0] = static_cast<uint8_t>(v[0] >> 1);
  if (carry != 0) {
    v[0] ^= 0xE1;
  }
}

inline void xor_into(uint8_t dst[16], const uint8_t src[16]) {
  for (int i = 0; i < 16; ++i) {
    dst[i] ^= src[i];
  }
}

}  // namespace

// The reference implementation, kept as the definition of the field arithmetic:
// ghash_test.cc checks the table path against this one. a*b is a linear
// combination of R^i(b) over the set bits of a, where R is mul_x; that identity
// is exactly what the tables below precompute.
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

// NIST bit ordering: bit i of a block is bit (7 - i % 8) of byte i / 8, so the
// high nibble of byte j holds bits 8j..8j+3 and the low nibble holds 8j+4..8j+7.
// Nibble position p is therefore worth R^(4p) for its top bit, which is what the
// per-position table is built from: one lookup then replaces three multiplies
// by alpha and a scatter of XORs.
void ghash_init_table(const uint8_t h[16], GhashTable* table) {
  uint8_t base[16];  // R^(4p)(H)
  std::memcpy(base, h, 16);
  for (int pos = 0; pos < kGhashNibbles; ++pos) {
    if (pos != 0) {
      for (int k = 0; k < 4; ++k) {
        mul_x(base);
      }
    }
    // Contributions of the nibble's four bits, most significant first:
    // comp[0] weighs 8, comp[1] weighs 4, comp[2] weighs 2, comp[3] weighs 1.
    uint8_t comp[4][16];
    std::memcpy(comp[0], base, 16);
    for (int j = 1; j < 4; ++j) {
      std::memcpy(comp[j], comp[j - 1], 16);
      mul_x(comp[j]);
    }
    std::memset(table->t[pos][0], 0, 16);
    for (int n = 1; n < 16; ++n) {
      uint8_t acc[16] = {};
      for (int j = 0; j < 4; ++j) {
        if ((n & (8 >> j)) != 0) {
          xor_into(acc, comp[j]);
        }
      }
      std::memcpy(table->t[pos][n], acc, 16);
    }
  }
}

Ghash::Ghash(const GhashTable& table) : table_(&table), y_{} {}

void Ghash::update_block(const uint8_t block[16]) {
  // y = (y ^ block) * H. 只有第一块的操作数是纯公开数据（y 从 0 起）；从第二
  // 块起 y 已是先前 (块, H) 乘积的函数，因此下面对 8 KiB 表的索引本身就依赖
  // 密钥——本路径会泄漏 H 相关的缓存时序，并不比被换下的逐比特 gf128_mul
  // 更"常数时间"。这与已接受的风险 A12/R3-27 是同一条（docs/对抗分析报告.md：
  // 部署前提为受控链路 + PSK 不泄露），不要把本注释读成已消除该风险。
  for (int i = 0; i < 16; ++i) {
    y_[i] ^= block[i];
  }
  uint64_t z0 = 0;
  uint64_t z1 = 0;
  for (int i = 0; i < 16; ++i) {
    const uint8_t* hi = table_->t[2 * i][y_[i] >> 4];
    const uint8_t* lo = table_->t[2 * i + 1][y_[i] & 0x0F];
    uint64_t w0;
    uint64_t w1;
    std::memcpy(&w0, hi, 8);
    std::memcpy(&w1, hi + 8, 8);
    z0 ^= w0;
    z1 ^= w1;
    std::memcpy(&w0, lo, 8);
    std::memcpy(&w1, lo + 8, 8);
    z0 ^= w0;
    z1 ^= w1;
  }
  std::memcpy(y_, &z0, 8);
  std::memcpy(y_ + 8, &z1, 8);
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
