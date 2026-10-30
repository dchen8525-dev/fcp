// AES-128 block cipher: AES-NI fast path with a T-table software fallback.
//
// The two paths must produce identical bytes (verified by tests).

#ifndef FCP_AES_H_
#define FCP_AES_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

constexpr size_t kAesBlockLen = 16;
constexpr size_t kAes128RoundKeyLen = 176;  // 11 round keys of 16 bytes

struct Aes128Key {
  uint8_t round_key[kAes128RoundKeyLen];
};

void aes128_expand_key(const uint8_t key[kAesBlockLen], Aes128Key* out);

bool aesni_available();

// Software T-table implementation; always available.
void aes128_encrypt_block_ttable(const Aes128Key& key, const uint8_t in[kAesBlockLen],
                                 uint8_t out[kAesBlockLen]);

// AES-NI implementation; falls back to the T-table path when AES-NI is absent.
void aes128_encrypt_block_hw(const Aes128Key& key, const uint8_t in[kAesBlockLen],
                             uint8_t out[kAesBlockLen]);

// Uses AES-NI when available, otherwise the T-table path.
void aes128_encrypt_block(const Aes128Key& key, const uint8_t in[kAesBlockLen],
                          uint8_t out[kAesBlockLen]);

}  // namespace fcp

#endif  // FCP_AES_H_
