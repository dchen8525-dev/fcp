// FCP v6 wire envelope: salt(8) | nonce_ctr(8, LE) | AES-GCM ciphertext | tag(12).
//
// The 12-byte GCM IV is expanded locally as counter(8, LE) | direction(1) | 0x00 x 3;
// the direction byte never goes on the wire (FCP_PROTOCOL_V6.md §4.1).
//
// #26: send and receive use two direction keys derived from the session key
// (SP 800-108 counter KDF, labels "fcp-c2" / "fcp-s2"), so each direction has
// its own GCM block budget. The session must retire a direction key once its
// nonce counter reaches kNonceLimit = 2^32 packets: a full-size packet is ~84
// AES blocks, so 2^32 packets ≈ 2^36.1 blocks < 2^39 - 256 (NIST SP 800-38D).
// The old 2^48 limit exceeded the budget by ~65000x (spec errata #26①).
//
// #28①: the session key is no longer the configured PSK itself. Both sides
// derive it per session as session_key = AES128(psk, salt || 0x00 x 8), where
// salt is the fresh per-session value carried in the clear. Without this, any
// two sessions sharing a PSK (reconnects, or multiple clients on one config)
// would hold identical direction keys while their IVs (counter|dir|0x3) both
// start at zero — a cross-session GCM (key, IV) reuse (spec §6.0). Zero wire
// change: derivation is local on both ends.

#ifndef FCP_ENVELOPE_H_
#define FCP_ENVELOPE_H_

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace fcp {

enum class Direction : uint8_t {
  kC2S = 0x01,
  kS2C = 0x02,
};

// #28①: derives the per-session key from the configured PSK and the on-wire
// salt: out = AES128-Encrypt(psk, salt(8) || 0x00 x 8). Deterministic, so both
// ends compute the same value; distinct salts yield distinct session keys.
// salt length is Envelope::kSaltLen (8).
void derive_session_key(const uint8_t psk[16], const uint8_t salt[8],
                        uint8_t out[16]);

// Derives the two direction keys from the 16-byte session key (the ikm is the
// per-session key from derive_session_key, not the configured PSK). Labels are
// fixed by spec §14.9 (#26②); both sides must agree on which direction is which.
void derive_direction_keys(const uint8_t session_key[16],
                           uint8_t key_c2s[16], uint8_t key_s2c[16]);

class Envelope {
 public:
  static constexpr size_t kSaltLen = 8;
  static constexpr size_t kNonceLen = 8;
  static constexpr size_t kTagLen = 12;
  static constexpr size_t kOverhead = kSaltLen + kNonceLen + kTagLen;  // 28
  // #26①: GCM block budget caps a direction at 2^32 packets (was 2^48).
  static constexpr uint64_t kNonceLimit = 1ull << 32;
  // #26③: per-direction anti-replay window (was 64; 256 covers ~13-19 Mbps x
  // 200ms BDP at 1312B MSS — spec #28② corrected the "25 Mbps" figure).
  static constexpr size_t kReplayWindow = 256;

  // `key` is the configured 16-byte PSK; the effective session key is derived
  // from it and the salt (see derive_session_key, #28①).
  Envelope(const uint8_t key[16], const uint8_t salt[kSaltLen],
           Direction send_direction, Direction recv_direction);

  // Appends the sealed datagram to `wire` and advances the nonce counter.
  // Returns false once the counter reaches 2^32 (the session must disconnect).
  bool seal(const uint8_t* plain, size_t len, std::vector<uint8_t>* wire);

  // Seals with an explicit counter without touching send state (tests/replay).
  bool seal_at(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
               std::vector<uint8_t>* wire) const;

  // Authenticates and decrypts one datagram. Replayed or too-old counters are
  // rejected. Returns false on any failure.
  bool open(const uint8_t* wire, size_t len, std::vector<uint8_t>* plain);

  // Restores the send counter (must be < 2^32).
  bool set_send_nonce(uint64_t value);

  uint64_t send_nonce() const { return send_nonce_; }
  bool exhausted() const { return send_nonce_ >= kNonceLimit; }

 private:
  bool accept_nonce(uint64_t nonce_ctr);

  uint8_t send_key_[16];
  uint8_t recv_key_[16];
  uint8_t salt_[kSaltLen];
  Direction send_direction_;
  Direction recv_direction_;
  uint64_t send_nonce_;
  bool recv_has_nonce_;
  uint64_t recv_highest_;
  std::bitset<kReplayWindow> recv_seen_;
};

}  // namespace fcp

#endif  // FCP_ENVELOPE_H_
