// GHASH over GF(2^128), reduction polynomial x^128 + x^7 + x^2 + x + 1.

#ifndef FCP_GHASH_H_
#define FCP_GHASH_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

// out = a * b in GF(2^128) (NIST bit ordering).
void gf128_mul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]);

class Ghash {
 public:
  explicit Ghash(const uint8_t h[16]);

  // Absorbs one full 16-byte block.
  void update_block(const uint8_t block[16]);

  // Absorbs arbitrary bytes, zero-padding the tail to a full block.
  void update_padded(const uint8_t* data, size_t len);

  // Absorbs the GCM length block: (aad_bytes * 8, cipher_bytes * 8) big-endian.
  void update_lengths(uint64_t aad_bytes, uint64_t cipher_bytes);

  void finalize(uint8_t out[16]) const;

 private:
  uint8_t h_[16];
  uint8_t y_[16];
};

}  // namespace fcp

#endif  // FCP_GHASH_H_
