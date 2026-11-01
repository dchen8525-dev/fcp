// AES-128-GCM with a 12-byte IV and a 12-byte tag (NIST SP 800-38D).
//
// FCP never sends the 16-byte tag: the envelope truncates it to 96 bits
// (forgery probability 2^-96, see 协议规格.md §4.1/§14.7).

#ifndef FCP_GCM_H_
#define FCP_GCM_H_

#include <cstddef>
#include <cstdint>

#include "fcp/aes.h"
#include "fcp/ghash.h"

namespace fcp {

constexpr size_t kGcmIvLen = 12;
constexpr size_t kGcmTagLen = 12;

// Per-key GCM state: the AES key schedule, the GHASH multiplier H = E_K(0) and
// the 4-bit window table derived from it. All of it depends only on the key, so
// a session that seals many datagrams with one key builds this once instead of
// per packet -- the table costs 8 KiB and about 2000 multiply steps to build,
// which would dominate a single packet.
struct GcmKey {
  Aes128Key round_keys;
  uint8_t h[kAesBlockLen];
  GhashTable ghash;
};

void gcm_key_init(const uint8_t key[16], GcmKey* out);

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

// Same operations on pre-expanded key state (see GcmKey). Identical output;
// the key argument of the two functions above is just expanded on the fly.
bool gcm_seal_keyed(const GcmKey& key, const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                    size_t aad_len, const uint8_t* plain, size_t len, uint8_t* cipher,
                    uint8_t tag[kGcmTagLen]);
bool gcm_open_keyed(const GcmKey& key, const uint8_t iv[kGcmIvLen], const uint8_t* aad,
                    size_t aad_len, const uint8_t* cipher, size_t len,
                    const uint8_t tag[kGcmTagLen], uint8_t* plain);

}  // namespace fcp

#endif  // FCP_GCM_H_
