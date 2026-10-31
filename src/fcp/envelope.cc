#include "fcp/envelope.h"

#include <cstring>

#include "fcp/aes.h"
#include "fcp/gcm.h"

namespace fcp {
namespace {

void store_le64(uint64_t value, uint8_t out[8]) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<uint8_t>(value >> (8 * i));
  }
}

uint64_t load_le64(const uint8_t in[8]) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(in[i]) << (8 * i);
  }
  return value;
}

void make_iv(uint64_t nonce_ctr, Direction direction, uint8_t iv[kGcmIvLen]) {
  store_le64(nonce_ctr, iv);
  iv[8] = static_cast<uint8_t>(direction);
  iv[9] = 0;
  iv[10] = 0;
  iv[11] = 0;
}

// NIST SP 800-108 Rev.1 §4.1: counter-mode KDF with AES-128 as the PRF.
//
//   K(i) = AES(K_mr, [i]1 | label | 0x00 | [L]8)
//
// The session key plays the role of the key-derivation key; the label binds
// each output to its purpose. The AES block is 16 bytes, which fixes the
// label budget at 6 bytes: 1 + 6 + 1 + 8 = 16 exactly ("fcp-c2" / "fcp-s2").
// Blocks are independent, so both direction keys come from one invocation
// with two counters. This avoids pulling a hash implementation into the
// envelope: AES here is the same primitive already verified against FIPS 197
// vectors by aes_test.cc.
void kdf_ctr_aes128(const uint8_t key[16], const char* label, size_t label_len,
                    uint8_t* out, size_t out_len) {
  Aes128Key aes_key;
  aes128_expand_key(key, &aes_key);

  uint8_t l_be[8];
  const uint64_t bits = static_cast<uint64_t>(out_len) * 8;
  for (int i = 0; i < 8; ++i) {
    l_be[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
  }

  size_t done = 0;
  uint8_t counter = 1;
  while (done < out_len) {
    uint8_t block[16];
    block[0] = counter;
    std::memcpy(block + 1, label, label_len);
    block[1 + label_len] = 0x00;
    std::memcpy(block + 2 + label_len, l_be, 8);
    uint8_t stream[kAesBlockLen];
    aes128_encrypt_block(aes_key, block, stream);
    const size_t n = (out_len - done) < kAesBlockLen ? (out_len - done) : kAesBlockLen;
    std::memcpy(out + done, stream, n);
    done += n;
    ++counter;
  }
}

}  // namespace

// #28①: session_key = AES128-Encrypt(psk, salt || 0x00 x 8). The salt is the
// fresh per-session value carried in the clear, so distinct sessions under one
// PSK get distinct session keys; the PSK itself never encrypts traffic.
void derive_session_key(const uint8_t psk[16], const uint8_t salt[8],
                        uint8_t out[16]) {
  Aes128Key aes_key;
  aes128_expand_key(psk, &aes_key);
  uint8_t block[16];
  static_assert(Envelope::kSaltLen == 8, "derive_session_key assumes 8B salt");
  std::memcpy(block, salt, Envelope::kSaltLen);
  std::memset(block + Envelope::kSaltLen, 0, 16 - Envelope::kSaltLen);
  aes128_encrypt_block(aes_key, block, out);
}

void derive_direction_keys(const uint8_t session_key[16],
                           uint8_t key_c2s[16], uint8_t key_s2c[16]) {
  // Spec §14.9 (#26②): direction keys must be independent; the label makes
  // them so. L = 128 bits each, counter i = 1. ikm is the per-session key
  // derived by derive_session_key (#28①), not the configured PSK.
  kdf_ctr_aes128(session_key, "fcp-c2", 6, key_c2s, 16);
  kdf_ctr_aes128(session_key, "fcp-s2", 6, key_s2c, 16);
}

// R3-1: see envelope.h. CBC-MAC over (salt || 0^8, client_nonce, server_nonce)
// keyed by the PSK. Only the AES primitive is used -- no hash is pulled in, and
// the chain is three fixed-size blocks so no padding rule exists to get wrong.
void derive_session_key_v7(const uint8_t psk[16], const uint8_t salt[8],
                           const uint8_t client_nonce[16],
                           const uint8_t server_nonce[16], uint8_t out[16]) {
  Aes128Key aes_key;
  aes128_expand_key(psk, &aes_key);

  uint8_t block[16];
  static_assert(Envelope::kSaltLen == 8, "derive_session_key_v7 assumes 8B salt");
  std::memcpy(block, salt, Envelope::kSaltLen);
  std::memset(block + Envelope::kSaltLen, 0, 16 - Envelope::kSaltLen);
  uint8_t chain[16];
  aes128_encrypt_block(aes_key, block, chain);  // X0, == derive_session_key()

  for (int i = 0; i < 16; ++i) {
    block[i] = static_cast<uint8_t>(chain[i] ^ client_nonce[i]);
  }
  aes128_encrypt_block(aes_key, block, chain);  // X1

  for (int i = 0; i < 16; ++i) {
    block[i] = static_cast<uint8_t>(chain[i] ^ server_nonce[i]);
  }
  aes128_encrypt_block(aes_key, block, out);  // X2
}

Envelope::Envelope(const uint8_t key[16], const uint8_t salt[kSaltLen],
                   Direction send_direction, Direction recv_direction)
    : send_key_{},
      recv_key_{},
      salt_{},
      send_direction_(send_direction),
      recv_direction_(recv_direction),
      send_nonce_(0),
      recv_has_nonce_(false),
      recv_highest_(0),
      recv_seen_() {
  // #28①: derive the per-session key from (PSK, salt), then the direction
  // keys from it — same computation on both ends, zero wire change.
  uint8_t session_key[16];
  derive_session_key(key, salt, session_key);
  install_keys(session_key);
  std::memcpy(salt_, salt, kSaltLen);
}

void Envelope::install_keys(const uint8_t session_key[16]) {
  uint8_t key_c2s[16];
  uint8_t key_s2c[16];
  derive_direction_keys(session_key, key_c2s, key_s2c);
  std::memcpy(send_key_, send_direction_ == Direction::kC2S ? key_c2s : key_s2c, 16);
  std::memcpy(recv_key_, recv_direction_ == Direction::kC2S ? key_c2s : key_s2c, 16);
  send_nonce_ = 0;
  recv_has_nonce_ = false;
  recv_highest_ = 0;
  recv_seen_.reset();
}

void Envelope::rekey(const uint8_t session_key[16]) {
  install_keys(session_key);
}

bool Envelope::seal(const uint8_t* plain, size_t len, std::vector<uint8_t>* wire) {
  if (send_nonce_ >= kNonceLimit) {
    return false;
  }
  if (!seal_at(send_nonce_, plain, len, wire)) {
    return false;
  }
  ++send_nonce_;
  return true;
}

bool Envelope::seal_at(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
                       std::vector<uint8_t>* wire) const {
  if (wire == nullptr || nonce_ctr >= kNonceLimit) {
    return false;
  }
  wire->resize(kOverhead + len);
  std::memcpy(wire->data(), salt_, kSaltLen);
  store_le64(nonce_ctr, wire->data() + kSaltLen);

  uint8_t iv[kGcmIvLen];
  make_iv(nonce_ctr, send_direction_, iv);
  uint8_t* cipher = wire->data() + kSaltLen + kNonceLen;
  uint8_t* tag = cipher + len;
  return gcm_seal(send_key_, iv, nullptr, 0, plain, len, cipher, tag);
}

bool Envelope::open(const uint8_t* wire, size_t len, std::vector<uint8_t>* plain) {
  if (wire == nullptr || plain == nullptr || len < kOverhead) {
    return false;
  }
  if (std::memcmp(wire, salt_, kSaltLen) != 0) {
    return false;
  }
  const uint64_t nonce_ctr = load_le64(wire + kSaltLen);
  // Reject counters at or past the limit before touching GCM: a sender that
  // crossed the block budget is a protocol violation, not a replay candidate.
  if (nonce_ctr >= kNonceLimit) {
    return false;
  }
  uint8_t iv[kGcmIvLen];
  make_iv(nonce_ctr, recv_direction_, iv);

  const size_t cipher_len = len - kOverhead;
  const uint8_t* cipher = wire + kSaltLen + kNonceLen;
  const uint8_t* tag = cipher + cipher_len;

  std::vector<uint8_t> decoded(cipher_len);
  if (!gcm_open(recv_key_, iv, nullptr, 0, cipher, cipher_len, tag, decoded.data())) {
    plain->clear();
    return false;
  }
  if (!accept_nonce(nonce_ctr)) {
    plain->clear();
    return false;
  }
  *plain = std::move(decoded);
  return true;
}

bool Envelope::set_send_nonce(uint64_t value) {
  if (value >= kNonceLimit) {
    return false;
  }
  send_nonce_ = value;
  return true;
}

bool Envelope::accept_nonce(uint64_t nonce_ctr) {
  if (!recv_has_nonce_) {
    recv_has_nonce_ = true;
    recv_highest_ = nonce_ctr;
    recv_seen_.reset();
    recv_seen_[0] = true;
    return true;
  }
  if (nonce_ctr > recv_highest_) {
    const uint64_t delta = nonce_ctr - recv_highest_;
    if (delta >= recv_seen_.size()) {
      recv_seen_.reset();
    } else {
      recv_seen_ <<= static_cast<size_t>(delta);
    }
    recv_seen_[0] = true;
    recv_highest_ = nonce_ctr;
    return true;
  }
  const uint64_t delta = recv_highest_ - nonce_ctr;
  if (delta >= recv_seen_.size() || recv_seen_[static_cast<size_t>(delta)]) {
    return false;
  }
  recv_seen_[static_cast<size_t>(delta)] = true;
  return true;
}

}  // namespace fcp
