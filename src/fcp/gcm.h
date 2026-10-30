// AES-128-GCM with a 12-byte IV and a 12-byte tag (NIST SP 800-38D).
//
// FCP never sends the 16-byte tag: the envelope truncates it to 96 bits
// (forgery probability 2^-96, see FCP_PROTOCOL_V6.md §4.1/§14.7).

#ifndef FCP_GCM_H_
#define FCP_GCM_H_

#include <cstddef>
#include <cstdint>

namespace fcp {

constexpr size_t kGcmIvLen = 12;
constexpr size_t kGcmTagLen = 12;

// Encrypts `plain` into `cipher` and writes the truncated tag. `cipher` and
// `plain` may alias; both may be null when len == 0.
bool gcm_seal(const uint8_t key[16], const uint8_t iv[kGcmIvLen], const uint8_t* aad,
              size_t aad_len, const uint8_t* plain, size_t len, uint8_t* cipher,
              uint8_t tag[kGcmTagLen]);

// Verifies the tag before decrypting. On failure returns false and leaves
// `plain` untouched. `plain` and `cipher` may alias.
bool gcm_open(const uint8_t key[16], const uint8_t iv[kGcmIvLen], const uint8_t* aad,
              size_t aad_len, const uint8_t* cipher, size_t len,
              const uint8_t tag[kGcmTagLen], uint8_t* plain);

}  // namespace fcp

#endif  // FCP_GCM_H_
