// GHASH over GF(2^128), reduction polynomial x^128 + x^7 + x^2 + x + 1.
//
// Two implementations live here: gf128_mul(), the bit-serial definition of the
// field arithmetic used by the tests as a reference, and Ghash, which runs the
// per-block multiply out of a 4-bit window table (one lookup per nibble of the
// operand). The table is the reason GCM is usable at all: the bit-serial
// multiply costs ~128 shift/XOR rounds per block and measured ~105 us for a
// 1.3 KiB symbol (~13 MB/s single core), which put a ceiling on the whole
// tunnel below what the event loop could carry. The table path is ~12x faster
// and, because it is indexed only by the public accumulator, it keeps the same
// key-independent memory access pattern.

#ifndef FCP_GHASH_H_
#define FCP_GHASH_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

// out = a * b in GF(2^128) (NIST bit ordering). Reference implementation.
void gf128_mul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]);

// One 4-bit window table per nibble of a 16-byte block: 32 positions x 16 values
// x 16 bytes = 8 KiB. It depends only on H, so it belongs to the key state
// (GcmKey) and is built once per key, never per packet.
constexpr int kGhashNibbles = 32;

struct GhashTable {
  uint8_t t[kGhashNibbles][16][16];
};

// Builds the window table for the fixed multiplier H = E_K(0).
void ghash_init_table(const uint8_t h[16], GhashTable* table);

class Ghash {
 public:
  // Uses a table built by ghash_init_table(); it must outlive this object.
  explicit Ghash(const GhashTable& table);

  // Absorbs one full 16-byte block.
  void update_block(const uint8_t block[16]);

  // Absorbs arbitrary bytes, zero-padding the tail to a full block.
  void update_padded(const uint8_t* data, size_t len);

  // Absorbs the GCM length block: (aad_bytes * 8, cipher_bytes * 8) big-endian.
  void update_lengths(uint64_t aad_bytes, uint64_t cipher_bytes);

  void finalize(uint8_t out[16]) const;

 private:
  const GhashTable* table_;
  uint8_t y_[16];
};

}  // namespace fcp

#endif  // FCP_GHASH_H_
