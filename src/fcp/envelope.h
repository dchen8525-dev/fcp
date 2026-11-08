// FCP v6 wire envelope: salt(8) | nonce_ctr(8, LE) | AES-GCM ciphertext | tag(12).
//
// The 12-byte GCM IV is expanded locally as counter(8, LE) | direction(1) | 0x00 x 3;
// the direction byte never goes on the wire (协议规格.md §4.1).
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

#include "fcp/gcm.h"

namespace fcp {

enum class Direction : uint8_t {
  kC2S = 0x01,
  kS2C = 0x02,
};

// #28①: derives the per-session key from the configured PSK and the on-wire
// salt: out = AES128-Encrypt(psk, salt(8) || 0x00 x 8). Deterministic, so both
// ends compute the same value; distinct salts yield distinct session keys.
// salt length is Envelope::kSaltLen (8).
//
// v6 only: this is the *bootstrap* value for the handshake envelope (v7 keeps
// using it for HELLO/HELLO_ACK). It is NOT a session key any more — a value
// derived from public wire bytes alone is replayable, which is exactly the R3-1
// defect. Data symbols use derive_session_key_v7().
void derive_session_key(const uint8_t psk[16], const uint8_t salt[8],
                        uint8_t out[16]);

// R3-1: the v7 session key binds fresh material from both ends, so replaying a
// recorded handshake cannot rebuild the same key (the responder's nonce is new).
//
//   X0 = AES128-Encrypt(psk, salt(8) || 0x00 x 8)   // == derive_session_key
//   X1 = AES128-Encrypt(psk, X0 xor client_nonce)
//   X2 = AES128-Encrypt(psk, X1 xor server_nonce)   // == out
//
// Three fixed-size blocks, no padding: CBC-MAC has no length-extension
// ambiguity when every message has the same known length, and block 0 can never
// be confused with a nonce block because its position is fixed. All-zero
// nonces do not degenerate to the v6 key (X2 != X0), so the two derivations
// stay separated. client_nonce is the C2S side's draw, server_nonce the S2C
// side's; the roles are fixed by Direction, not by who spoke first, so a
// simultaneous handshake still converges on one key.
void derive_session_key_v7(const uint8_t psk[16], const uint8_t salt[8],
                           const uint8_t client_nonce[16],
                           const uint8_t server_nonce[16], uint8_t out[16]);

// Derives the two direction keys from the 16-byte session key (the ikm is the
// per-session key from derive_session_key, not the configured PSK). Labels are
// fixed by spec §14.9 (#26②); both sides must agree on which direction is which.
void derive_direction_keys(const uint8_t session_key[16],
                           uint8_t key_c2s[16], uint8_t key_s2c[16]);

// #84 (key update): the per-epoch direction key for epoch >= 1. Epoch 0 keeps
// the #26② derivation byte-for-byte, so v7 golden vectors and v7 peers are
// untouched. The PRF is the same AES-128 the envelope already verifies (the
// derive_session_key construction is the precedent); the input block binds the
// direction label and the epoch, so every epoch of every direction lands on a
// distinct key.
void derive_epoch_direction_key(const uint8_t session_key[16], Direction dir,
                                uint16_t epoch, uint8_t out[16]);

class Envelope {
 public:
  static constexpr size_t kSaltLen = 8;
  static constexpr size_t kNonceLen = 8;
  static constexpr size_t kTagLen = 12;
  static constexpr size_t kOverhead = kSaltLen + kNonceLen + kTagLen;  // 28
  // #26①: GCM block budget caps a direction at 2^32 packets (was 2^48).
  static constexpr uint64_t kNonceLimit = 1ull << 32;
  // #26③: per-direction anti-replay window (was 64; 256 covered ~13-19 Mbps x
  // 200ms BDP at 1312B MSS — spec #28② corrected the "25 Mbps" figure).
  // #84 raises it to 1024 (~54 Mbps x 200ms), removing the speed ceiling the
  // 256-slot window put on high-BDP paths.
  static constexpr size_t kReplayWindow = 1024;
  // #84 (key update): the 64-bit wire nonce is split into
  //   nonce = epoch * kEpochSpan + counter
  // and the direction key is re-derived per epoch, so one key never seals more
  // than kEpochSpan packets (2^24 ≈ 2^30.6 GCM blocks, far under the 2^39
  // budget) while the session as a whole never exhausts: the epoch field spans
  // the rest of the 64-bit nonce space. Epoch 0 occupies [0, kEpochSpan) with
  // the #26② key, which keeps the v7 wire behavior byte-identical until the
  // first roll (rolling itself is only enabled for TLV-negotiated peers).
  static constexpr uint64_t kEpochSpan = 1ull << 24;
  // quic-go exercises the key-update mechanism almost immediately
  // (FirstKeyUpdateInterval = 100 packets): the first roll is cheap and a
  // latent bug in the rollover surfaces in the first seconds, not mid-transfer
  // weeks later. After the exercise roll, the interval is kEpochSpan.
  static constexpr uint64_t kFirstRollAt = 100;

  // `key` is the configured 16-byte PSK; the effective session key is derived
  // from it and the salt (see derive_session_key, #28①).
  Envelope(const uint8_t key[16], const uint8_t salt[kSaltLen],
           Direction send_direction, Direction recv_direction);
  // 零化两头 GcmKey（轮密钥 + H）。析构后密钥不得再留在自由堆里
  // （PSK 是长期静态配置的，派生方向密钥本属"逐会话即弃"）。
  ~Envelope();
  Envelope(const Envelope&) = delete;
  Envelope& operator=(const Envelope&) = delete;

  // Appends the sealed datagram to `wire` and advances the nonce counter.
  // Returns false once the counter reaches the ceiling (the session must
  // disconnect). With key update enabled the counter never gets there: the
  // key rolls and the epoch base jumps.
  bool seal(const uint8_t* plain, size_t len, std::vector<uint8_t>* wire);

  // Seals with an explicit counter without touching send state (tests/replay).
  bool seal_at(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
               std::vector<uint8_t>* wire) const;

  // Authenticates and decrypts one datagram. Replayed or too-old counters are
  // rejected. Returns false on any failure.
  bool open(const uint8_t* wire, size_t len, std::vector<uint8_t>* plain);

  // Restores the send counter inside the current packet budget (must be below
  // both the counter ceiling and this envelope's send limit).
  bool set_send_nonce(uint64_t value);

  // R3-1, bootstrap envelope only: draws a 64-bit start for the send counter
  // from the OS CSPRNG and caps this envelope at `budget` more packets. Two
  // session instances built from the same salt (a replayed HELLO creates one)
  // would otherwise seal their first ACK under the same (key, IV) - which is
  // the keystream reuse #31 exists to remove. NIST SP 800-38D bounds the
  // number of invocations under a key, not the counter value, so a high start
  // costs nothing as long as `budget` stays far below 2^32.
  //
  // The receive ceiling opens to the full counter range at the same time: the
  // peer draws its own start, so a 2^32 receive ceiling would reject the very
  // first bootstrap packet. The data envelope (start 0) keeps the 2^32 ceiling.
  //
  // Returns false when the CSPRNG is unavailable. Callers must fail the
  // session there - falling back to a fixed start reintroduces the defect.
  bool init_bootstrap_nonce(uint32_t budget);

  // R3-1: switches this envelope to an explicit session key and restarts both
  // directions from counter 0 with an empty replay window. Called exactly once
  // per session, when the handshake has produced the nonce pair; the caller
  // must not use the envelope for data before that (nothing does: symbols are
  // prepared after negotiation and handshake traffic has its own envelope).
  // Restarting the counter is safe here only because the key changes with it.
  void rekey(const uint8_t session_key[16]);

  // #84: enables epoch rolling (send side) and multi-epoch receive keys. Only
  // meaningful on the data envelope, only after rekey(), and only for a
  // TLV-negotiated peer — a v7 peer keeps the byte-identical epoch-0 behavior.
  // The receive side follows the peer's rolls by reading the epoch out of the
  // nonce's high bits; no negotiation beyond the capability bit is needed.
  void set_key_update(bool enabled) { key_update_ = enabled; }
  bool key_update() const { return key_update_; }
  uint64_t send_epoch() const { return send_nonce_ / kEpochSpan; }

  uint64_t send_nonce() const { return send_nonce_; }
  bool exhausted() const { return send_nonce_ >= send_limit_; }

 private:
  // The value-level work of seal_at, without either ceiling check.
  bool seal_unchecked(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
                      std::vector<uint8_t>* wire) const;
  // 布尔纯成员测试："这条计数器按当前窗口会不会被收下"，不落任何状态。
  // open() 在跑 AES 前用它廉价拒掉重放；真正的窗口更新仍只由
  // accept_nonce() 在 tag 验证通过后做（窗口绝不被未认证包污染）。
  bool nonce_window_may_accept(uint64_t nonce_ctr) const;
  bool accept_nonce(uint64_t nonce_ctr);
  // Derives both direction keys from a session key and resets all per-key state.
  void install_keys(const uint8_t session_key[16]);
  // #84: roll the send epoch — re-derive the send key, jump the nonce base.
  // Returns false when the u16 epoch space is exhausted (seal() then fails).
  bool roll_send_epoch();
  // #84: per-epoch receive window state (epoch 0 keeps the flat-64-bit shape:
  // with no roll the counter IS the nonce and the epoch is always 0).
  struct RecvEpoch {
    bool has_nonce = false;
    uint64_t highest = 0;  // highest counter within this epoch
    std::bitset<kReplayWindow> seen;
  };
  // Per-epoch replay pre-check (the may-accept mirror of the window owner).
  bool epoch_window_may_accept(RecvEpoch& win, uint64_t counter) const;
  bool epoch_accept(RecvEpoch& win, uint64_t counter);
  // #84: the open() path for key-update mode (epoch decomposition, key and
  // window selection, freeze-on-roll).
  bool open_epoch(uint64_t nonce_ctr, const uint8_t* wire, size_t len,
                  std::vector<uint8_t>* plain);

  // Expanded once per key (install_keys): the AES schedule and GHASH's H are
  // key-only state, so a per-datagram re-expansion is pure waste (~2% of the
  // AES work at MTU 1400, and it multiplies the observable samples on the
  // GHASH side channel, R3-27).
  GcmKey send_key_;
  GcmKey recv_key_;
  // #84: the frozen key of recv_epoch_seen_ - 1 (key-update mode only).
  GcmKey prev_recv_key_;
  uint8_t salt_[kSaltLen];
  Direction send_direction_;
  Direction recv_direction_;
  // Two bounds on the 64-bit wire counter, both defaulting to kNonceLimit:
  //   counter_ceiling_ - values at or past it are refused on both directions
  //     (protocol violation / block budget). The bootstrap envelope raises it
  //     to the full 64-bit space (init_bootstrap_nonce); key-update mode
  //     raises it too — the per-key budget is what kEpochSpan enforces now.
  //   send_limit_ - where this envelope's own budget ends: the start plus the
  //     packets it was allowed to seal. exhausted() and seal() use this one.
  uint64_t counter_ceiling_;
  uint64_t send_limit_;
  uint64_t send_nonce_;
  bool recv_has_nonce_;
  uint64_t recv_highest_;
  std::bitset<kReplayWindow> recv_seen_;

  // #84 key-update state (all inert until set_key_update(true)).
  bool key_update_ = false;
  uint64_t send_epoch_ = 0;  // base of the current send epoch
  bool rolled_once_ = false;
  uint64_t recv_epoch_seen_ = 0;  // highest epoch the peer has used
  RecvEpoch recv_cur_;            // window of recv_epoch_seen_
  RecvEpoch recv_prev_;           // frozen window of recv_epoch_seen_ - 1
  uint8_t session_key_[16];       // kept for per-epoch re-derivation
};

}  // namespace fcp

#endif  // FCP_ENVELOPE_H_
