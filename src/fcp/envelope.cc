#include "fcp/envelope.h"

#include <cstring>

#include "fcp/aes.h"
#include "fcp/gcm.h"
#include "fcp/random.h"
#include "fcp/wire.h"

namespace fcp {
namespace {

void make_iv(uint64_t nonce_ctr, Direction direction, uint8_t iv[kGcmIvLen]) {
  put_le64(nonce_ctr, iv);
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
    // 离开本次迭代的中间值（普通字节栈变量，防优化喂给 volatile 抹除）。
    secure_zero(block, sizeof(block));
    secure_zero(stream, sizeof(stream));
    done += n;
    ++counter;
  }

  // 展开的轮密钥属于密钥材料，离开作用域前抹除。
  secure_zero(&aes_key, sizeof(aes_key));
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
  secure_zero(&aes_key, sizeof(aes_key));
  secure_zero(block, sizeof(block));
}

void derive_direction_keys(const uint8_t session_key[16],
                           uint8_t key_c2s[16], uint8_t key_s2c[16]) {
  // Spec §14.9 (#26②): direction keys must be independent; the label makes
  // them so. L = 128 bits each, counter i = 1. ikm is the per-session key
  // derived by derive_session_key (#28①), not the configured PSK.
  kdf_ctr_aes128(session_key, "fcp-c2", 6, key_c2s, 16);
  kdf_ctr_aes128(session_key, "fcp-s2", 6, key_s2c, 16);
}

void derive_epoch_direction_key(const uint8_t session_key[16], Direction dir,
                                uint16_t epoch, uint8_t out[16]) {
  // #84: epoch >= 1 keys live in a fresh domain so the #26② epoch-0 keys stay
  // byte-identical (v7 golden vectors, v7 peers). The PRF is the AES-128 the
  // envelope already relies on; the input block binds direction + epoch:
  //   out = AES128(session_key, label(2) | epoch(2 LE) | 0x00 x 12)
  // with "c2" / "s2" as the direction labels — same family as
  // derive_session_key's AES(psk, salt || 0^8) construction.
  Aes128Key aes_key;
  aes128_expand_key(session_key, &aes_key);
  uint8_t block[16];
  block[0] = dir == Direction::kC2S ? 'c' : 's';
  block[1] = dir == Direction::kC2S ? '2' : '2';
  block[2] = static_cast<uint8_t>(epoch);
  block[3] = static_cast<uint8_t>(epoch >> 8);
  std::memset(block + 4, 0, 12);
  aes128_encrypt_block(aes_key, block, out);
  secure_zero(&aes_key, sizeof(aes_key));
  secure_zero(block, sizeof(block));
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

  secure_zero(&aes_key, sizeof(aes_key));
  secure_zero(block, sizeof(block));
  secure_zero(chain, sizeof(chain));
}

Envelope::Envelope(const uint8_t key[16], const uint8_t salt[kSaltLen],
                   Direction send_direction, Direction recv_direction)
    : send_key_{0},
      recv_key_{0},
      salt_{},
      send_direction_(send_direction),
      recv_direction_(recv_direction),
      counter_ceiling_(kNonceLimit),  // both overwritten by install_keys()
      send_limit_(kNonceLimit),
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

Envelope::~Envelope() {
  // 会话退出后，轮密钥与 H 不得留在已释放的堆页上。salt 本身就是明文
  // wire 字段，无需抹除。
  secure_zero(&send_key_, sizeof(send_key_));
  secure_zero(&recv_key_, sizeof(recv_key_));
  secure_zero(&prev_recv_key_, sizeof(prev_recv_key_));
  // #84: 会话密钥是全部 epoch 派生的根，同样即弃。
  secure_zero(session_key_, sizeof(session_key_));
}

void Envelope::install_keys(const uint8_t session_key[16]) {
  uint8_t key_c2s[16];
  uint8_t key_s2c[16];
  derive_direction_keys(session_key, key_c2s, key_s2c);
  // Expanded into locals and committed together, so the two directions can
  // never be left on different generations if anything above fails.
  GcmKey send_key;
  GcmKey recv_key;
  gcm_key_init(send_direction_ == Direction::kC2S ? key_c2s : key_s2c, &send_key);
  gcm_key_init(recv_direction_ == Direction::kC2S ? key_c2s : key_s2c, &recv_key);
  secure_zero(key_c2s, sizeof(key_c2s));
  secure_zero(key_s2c, sizeof(key_s2c));
  send_key_ = send_key;
  recv_key_ = recv_key;
  secure_zero(&send_key, sizeof(send_key));
  secure_zero(&recv_key, sizeof(recv_key));
  // #26①: a fresh data key starts at 0, so its packet budget is exactly the
  // 2^32 ceiling on both directions.
  send_nonce_ = 0;
  counter_ceiling_ = kNonceLimit;
  send_limit_ = kNonceLimit;
  recv_has_nonce_ = false;
  recv_highest_ = 0;
  recv_seen_.reset();
  // #84: keep the root for per-epoch re-derivation and reset the rolling
  // state. set_key_update() is (re)applied by the session after rekey().
  std::memcpy(session_key_, session_key, sizeof(session_key_));
  send_epoch_ = 0;
  rolled_once_ = false;
  recv_epoch_seen_ = 0;
  recv_cur_ = RecvEpoch{};
  recv_prev_ = RecvEpoch{};
  secure_zero(&prev_recv_key_, sizeof(prev_recv_key_));
}

void Envelope::rekey(const uint8_t session_key[16]) {
  install_keys(session_key);
}

bool Envelope::seal(const uint8_t* plain, size_t len, std::vector<uint8_t>* wire) {
  // #84: roll the send key at the threshold. The first roll happens at
  // kFirstRollAt so the rollover path is exercised in the first seconds of
  // every session (quic-go's FirstKeyUpdateInterval rationale); afterwards
  // once per kEpochSpan. The counter never reaches kNonceLimit while rolling
  // is on, which is what retires the 2^32 disconnect.
  if (key_update_) {
    const uint64_t in_epoch = send_nonce_ - send_epoch_;
    const uint64_t threshold = rolled_once_ ? kEpochSpan : kFirstRollAt;
    if (in_epoch >= threshold && !roll_send_epoch()) {
      return false;  // epoch space exhausted (~1.4 PB per direction)
    }
  }
  if (send_nonce_ >= send_limit_) {
    return false;
  }
  if (!seal_unchecked(send_nonce_, plain, len, wire)) {
    return false;
  }
  ++send_nonce_;
  return true;
}

bool Envelope::roll_send_epoch() {
  // #84: the epoch number rides the nonce's high bits and feeds the KDF as a
  // u16; 65535 epochs x 2^24 packets ≈ 1.1 PB per direction. Past that the
  // session must reconnect — seal() reports false and the host disconnects.
  const uint64_t epoch_num = send_epoch_ / kEpochSpan + 1;
  if (epoch_num > 65535) {
    return false;
  }
  uint8_t out[16];
  derive_epoch_direction_key(session_key_, send_direction_,
                             static_cast<uint16_t>(epoch_num), out);
  GcmKey k;
  gcm_key_init(out, &k);
  secure_zero(out, sizeof(out));
  secure_zero(&send_key_, sizeof(send_key_));
  send_key_ = k;
  secure_zero(&k, sizeof(k));
  // Jump the nonce to the new epoch's base: the fresh key has never sealed
  // anything, so (key, IV) uniqueness holds with the counter restarting at 0
  // within the epoch. The 64-bit wire counter stays monotonic overall.
  send_epoch_ = epoch_num * kEpochSpan;
  send_nonce_ = send_epoch_;
  rolled_once_ = true;
  return true;
}

bool Envelope::seal_at(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
                       std::vector<uint8_t>* wire) const {
  // Test/replay primitive: an explicit counter never advances the send state,
  // so it is bounded by the counter ceiling rather than this envelope's packet
  // budget (a bootstrap envelope may name any value in the 64-bit space).
  if (nonce_ctr >= counter_ceiling_) {
    return false;
  }
  return seal_unchecked(nonce_ctr, plain, len, wire);
}

bool Envelope::seal_unchecked(uint64_t nonce_ctr, const uint8_t* plain, size_t len,
                             std::vector<uint8_t>* wire) const {
  if (wire == nullptr) {
    return false;
  }
  wire->resize(kOverhead + len);
  std::memcpy(wire->data(), salt_, kSaltLen);
  put_le64(nonce_ctr, wire->data() + kSaltLen);

  uint8_t iv[kGcmIvLen];
  make_iv(nonce_ctr, send_direction_, iv);
  uint8_t* cipher = wire->data() + kSaltLen + kNonceLen;
  uint8_t* tag = cipher + len;
  return gcm_seal_keyed(send_key_, iv, nullptr, 0, plain, len, cipher, tag);
}

// 见 envelope.h：纯判定，先于 AES。状态只由 accept_nonce() 落。
bool Envelope::nonce_window_may_accept(uint64_t nonce_ctr) const {
  if (!recv_has_nonce_) {
    return true;
  }
  if (nonce_ctr > recv_highest_) {
    // 前跳无论 delta 大小都会被接受（reset 或左移，见 accept_nonce）。
    return true;
  }
  const uint64_t delta = recv_highest_ - nonce_ctr;
  return delta < recv_seen_.size() && !recv_seen_[static_cast<size_t>(delta)];
}

bool Envelope::open(const uint8_t* wire, size_t len, std::vector<uint8_t>* plain) {
  if (wire == nullptr || plain == nullptr || len < kOverhead) {
    return false;
  }
  if (std::memcmp(wire, salt_, kSaltLen) != 0) {
    return false;
  }
  const uint64_t nonce_ctr = get_le64(wire + kSaltLen);
  // Reject counters at or past this direction's ceiling before touching GCM: a
  // sender that crossed the block budget is a protocol violation, not a replay
  // candidate.
  if (nonce_ctr >= counter_ceiling_) {
    return false;
  }
  if (key_update_) {
    return open_epoch(nonce_ctr, wire, len, plain);
  }
  // Replay pre-check, also before AES: a replay of an authentic datagram is
  // guaranteed to die at accept_nonce(), so it must not pay the full CTR +
  // GHASH bill first（重放洪泛的 CPU 放大就此关闭）。判定不落状态，窗口仍
  // 只在 tag 验证通过后由 accept_nonce() 更新，未认证包无法污染窗口。
  if (!nonce_window_may_accept(nonce_ctr)) {
    return false;
  }
  uint8_t iv[kGcmIvLen];
  make_iv(nonce_ctr, recv_direction_, iv);

  const size_t cipher_len = len - kOverhead;
  const uint8_t* cipher = wire + kSaltLen + kNonceLen;
  const uint8_t* tag = cipher + cipher_len;

  std::vector<uint8_t> decoded(cipher_len);
  if (!gcm_open_keyed(recv_key_, iv, nullptr, 0, cipher, cipher_len, tag, decoded.data())) {
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

// #84 receive path: the epoch rides the nonce's high bits, so the peer's rolls
// are followed without any extra negotiation — pick the key for the epoch,
// then run the same pre-check / decrypt / accept sequence against that epoch's
// window. At most two epochs are live (current + the frozen previous one): the
// replay window is far smaller than an epoch, so a datagram older than one
// epoch is unrecoverable by design.
bool Envelope::open_epoch(uint64_t nonce_ctr, const uint8_t* wire, size_t len,
                          std::vector<uint8_t>* plain) {
  const uint64_t epoch = nonce_ctr / kEpochSpan;
  const uint64_t counter = nonce_ctr % kEpochSpan;
  const GcmKey* key = nullptr;
  RecvEpoch* win = nullptr;
  if (epoch == recv_epoch_seen_) {
    key = &recv_key_;
    win = &recv_cur_;
  } else if (epoch + 1 == recv_epoch_seen_) {
    // The frozen previous epoch (epoch 0 included — the guard is epoch arithmetic,
    // not "epoch must be positive": with seen == 1 the previous epoch IS 0).
    // "Frozen" refers to the key, not the window: the window slides exactly
    // like the current one. A counter above the seen-highest from a key-holding
    // peer is either a legal late tail (the roll happened before it arrived)
    // or a misbehaving peer — both are safe to admit, because the tag gates
    // every window update and the old key's nonce space is untouched by it.
    key = &prev_recv_key_;
    win = &recv_prev_;
  } else if (epoch == recv_epoch_seen_ + 1) {
    // The peer rolled: freeze the current window and key as "previous", then
    // derive the new epoch's receive key. This runs before any AES, but the
    // only thing it commits is bookkeeping — an attacker forcing the advance
    // costs one failed GCM and cannot resurrect an old key (the previous
    // epoch's window and key both stay live).
    recv_prev_ = recv_cur_;
    prev_recv_key_ = recv_key_;
    recv_epoch_seen_ = epoch;
    uint8_t out[16];
    derive_epoch_direction_key(session_key_, recv_direction_,
                               static_cast<uint16_t>(epoch), out);
    GcmKey k;
    gcm_key_init(out, &k);
    secure_zero(out, sizeof(out));
    recv_key_ = k;
    secure_zero(&k, sizeof(k));
    recv_cur_ = RecvEpoch{};
    key = &recv_key_;
    win = &recv_cur_;
  } else {
    return false;  // too old (below the frozen window) or from the future
  }
  if (counter >= counter_ceiling_) {
    return false;
  }
  if (!epoch_window_may_accept(*win, counter)) {
    return false;
  }
  uint8_t iv[kGcmIvLen];
  make_iv(nonce_ctr, recv_direction_, iv);
  const size_t cipher_len = len - kOverhead;
  const uint8_t* cipher = wire + kSaltLen + kNonceLen;
  const uint8_t* tag = cipher + cipher_len;
  std::vector<uint8_t> decoded(cipher_len);
  if (!gcm_open_keyed(*key, iv, nullptr, 0, cipher, cipher_len, tag, decoded.data())) {
    plain->clear();
    return false;
  }
  if (!epoch_accept(*win, counter)) {
    plain->clear();
    return false;
  }
  *plain = std::move(decoded);
  return true;
}

bool Envelope::epoch_window_may_accept(RecvEpoch& win, uint64_t counter) const {
  if (!win.has_nonce) {
    return true;
  }
  if (counter > win.highest) {
    return true;
  }
  const uint64_t delta = win.highest - counter;
  return delta < win.seen.size() && !win.seen[static_cast<size_t>(delta)];
}

bool Envelope::epoch_accept(RecvEpoch& win, uint64_t counter) {
  if (!win.has_nonce) {
    win.has_nonce = true;
    win.highest = counter;
    win.seen.reset();
    win.seen[0] = true;
    return true;
  }
  if (counter > win.highest) {
    const uint64_t delta = counter - win.highest;
    if (delta >= win.seen.size()) {
      win.seen.reset();
    } else {
      win.seen <<= static_cast<size_t>(delta);
    }
    win.seen[0] = true;
    win.highest = counter;
    return true;
  }
  const uint64_t delta = win.highest - counter;
  if (delta >= win.seen.size() || win.seen[static_cast<size_t>(delta)]) {
    return false;
  }
  win.seen[static_cast<size_t>(delta)] = true;
  return true;
}

bool Envelope::open_reset(const uint8_t* wire, size_t len,
                          std::vector<uint8_t>* plain) {
  if (wire == nullptr || plain == nullptr || len != kOverhead + kResetMagicLen) {
    return false;
  }
  if (std::memcmp(wire, salt_, kSaltLen) != 0) {
    return false;
  }
  uint8_t iv[kGcmIvLen];
  make_iv(get_le64(wire + kSaltLen), recv_direction_, iv);
  static const uint8_t kReset[kResetMagicLen] = {'F', 'C', 'P', 'R', 'S', 'T', '1', 0};
  uint8_t decoded[kResetMagicLen];
  if (!gcm_open_keyed(recv_key_, iv, nullptr, 0, wire + kSaltLen + kNonceLen,
                      kResetMagicLen, wire + kSaltLen + kNonceLen + kResetMagicLen,
                      decoded)) {
    return false;
  }
  if (std::memcmp(decoded, kReset, kResetMagicLen) != 0) {
    return false;
  }
  plain->assign(kReset, kReset + kResetMagicLen);
  return true;
}

bool Envelope::set_send_nonce(uint64_t value) {
  if (value >= counter_ceiling_ || value >= send_limit_) {
    return false;
  }
  send_nonce_ = value;
  return true;
}

bool Envelope::init_bootstrap_nonce(uint32_t budget) {
  uint64_t draw = 0;
  if (!random_bytes(&draw, sizeof(draw))) {
    return false;
  }
  // Leave `budget` increments plus one spare below UINT64_MAX, so neither
  // seal() nor the peer's replay window can see the counter wrap.
  const uint64_t span = static_cast<uint64_t>(budget) + 1;
  send_nonce_ = draw % (UINT64_MAX - span);
  send_limit_ = send_nonce_ + span;  // <= UINT64_MAX - 1
  // The peer draws its own landing zone and only handshake frames travel this
  // epoch, so the 2^32 invocation budget cannot apply to a counter value here.
  counter_ceiling_ = UINT64_MAX;
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
