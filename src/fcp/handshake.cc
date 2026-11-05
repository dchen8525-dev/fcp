#include "fcp/handshake.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "fcp/random.h"

namespace fcp {
namespace {

constexpr uint8_t kMaxParityField = 7;  // 3-bit k field
constexpr uint16_t kMaxCodeLen = 256;   // D + P, compared as u16 (erratum #7)

bool caps_valid(const HandshakeCaps& caps) {
  if (caps.ver != kCapsVersion || caps.data < 1 || caps.parity > kMaxParityField) {
    return false;
  }
  if (static_cast<uint16_t>(caps.data) + caps.parity > kMaxCodeLen) {
    return false;
  }
  return (caps.flags & ~kCapKnownMask) == 0;
}

HandshakeCaps parse_caps(const uint8_t* in) {
  HandshakeCaps caps;
  caps.ver = in[0];
  caps.data = in[1];
  caps.parity = in[2];
  caps.flags = in[3];
  return caps;
}

void write_caps(const HandshakeCaps& caps, uint8_t* out) {
  out[0] = caps.ver;
  out[1] = caps.data;
  out[2] = caps.parity;
  out[3] = caps.flags;
}

// An all-zero nonce is what a peer that never drew one sends, and it is what an
// attacker can put in a forgery without guessing anything. It contributes no
// freshness, so it is rejected instead of being folded into the key schedule.
bool nonce_valid(const uint8_t nonce[kHandshakeNonceLen]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < kHandshakeNonceLen; ++i) {
    acc |= nonce[i];
  }
  return acc != 0;
}

}  // namespace

const char* handshake_error_text(HandshakeError error) {
  switch (error) {
    case HandshakeError::kNone:
      return "none";
    case HandshakeError::kNoAck:
      return "no ACK after 3 tries";
    case HandshakeError::kBadCaps:
      return "invalid caps";
    case HandshakeError::kMissingCapability:
      return "missing required capability";
    case HandshakeError::kCacheOverflow:
      return "pre-negotiation data cache overflow";
    case HandshakeError::kBadNonce:
      return "invalid handshake nonce";
  }
  return "unknown";
}

void build_hello(const HandshakeCaps& caps, const uint8_t sender_nonce[16],
                 uint8_t out[kHelloLen]) {
  std::memcpy(out, kHelloMagic, kHelloMagicLen);
  std::memcpy(out + kHelloMagicLen, sender_nonce, kHandshakeNonceLen);
  write_caps(caps, out + kHelloMagicLen + kHandshakeNonceLen);
}

void build_hello_ack(const HandshakeCaps& caps, const uint8_t client_nonce[16],
                     const uint8_t server_nonce[16], uint8_t out[kHelloAckLen]) {
  std::memcpy(out, kHelloAckMagic, kHelloAckMagicLen);
  std::memcpy(out + kHelloAckMagicLen, client_nonce, kHandshakeNonceLen);
  std::memcpy(out + kHelloAckMagicLen + kHandshakeNonceLen, server_nonce,
              kHandshakeNonceLen);
  write_caps(caps, out + kHelloAckMagicLen + 2 * kHandshakeNonceLen);
}

bool is_hello(const uint8_t* data, size_t len) {
  return data != nullptr && len == kHelloLen &&
         std::memcmp(data, kHelloMagic, kHelloMagicLen) == 0;
}

bool is_hello_ack(const uint8_t* data, size_t len) {
  return data != nullptr && len == kHelloAckLen &&
         std::memcmp(data, kHelloAckMagic, kHelloAckMagicLen) == 0;
}

Handshake::Handshake(uint8_t local_d, uint8_t local_p, SendFn send,
                     HandshakeRole role, const uint8_t* local_nonce,
                     uint8_t local_flags, size_t max_cached_segments,
                     size_t max_cached_bytes)
    : local_d_(local_d),
      local_p_(local_p),
      local_flags_(local_flags),
      send_(std::move(send)),
      role_(role),
      max_cached_segments_(max_cached_segments),
      max_cached_bytes_(max_cached_bytes),
      local_nonce_{},
      peer_nonce_{} {
  if (local_nonce != nullptr) {
    std::memcpy(local_nonce_, local_nonce, kHandshakeNonceLen);
  } else if (!random_bytes(local_nonce_, kHandshakeNonceLen)) {
    // A predictable or zero nonce is precisely what R3-1 is about, so a failed
    // CSPRNG fails the handshake instead of falling back to something weaker.
    fail(HandshakeError::kBadNonce);
  }
  if (!nonce_valid(local_nonce_)) {
    fail(HandshakeError::kBadNonce);
  }
}

Handshake::~Handshake() {
  // 两侧 nonce 是 v7 会话密钥的派生输入，生命周期结束后不留明文
  // （会话拆除 = 密钥纪元即弃）。
  secure_zero(local_nonce_, sizeof(local_nonce_));
  secure_zero(peer_nonce_, sizeof(peer_nonce_));
}

void Handshake::start(int64_t now_ms) {
  if (state_ != HandshakeState::kIdle) {
    return;
  }
  if (error_ == HandshakeError::kBadNonce) {
    return;  // construction already failed; nothing to send
  }
  state_ = HandshakeState::kHelloSent;
  retries_ = 0;
  next_retry_ms_ = now_ms;
}

void Handshake::on_tick(int64_t now_ms) {
  if (state_ != HandshakeState::kHelloSent || now_ms < next_retry_ms_) {
    return;
  }
  if (retries_ >= kHandshakeMaxRetries) {
    fail(HandshakeError::kNoAck);
    return;
  }
  send_hello();
  ++retries_;
  // Exponential backoff (#27①): the gap after send n is 300 << (n-1) ms, i.e.
  // 300/600/1200ms. With the 3-HELLO cap the handshake fails at ~2.1s, which
  // covers RTT <= ~700ms links; the old fixed 300ms budget failed at 900ms.
  next_retry_ms_ = now_ms + (kHandshakeRetryMs << (retries_ - 1));
}

HandshakeStatus Handshake::on_oob(const uint8_t* data, size_t len) {
  if (is_hello(data, len)) {
    if (state_ == HandshakeState::kFailed) {
      return HandshakeStatus::kConsumed;
    }
    const uint8_t* sender_nonce = data + kHelloMagicLen;
    const HandshakeCaps peer = parse_caps(data + kHelloMagicLen + kHandshakeNonceLen);
    if (!caps_valid(peer)) {
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
    }
    if (!nonce_valid(sender_nonce)) {
      fail(HandshakeError::kBadNonce);
      return HandshakeStatus::kProtocolFailure;
    }
    if (state_ == HandshakeState::kEstablished) {
      // Duplicate HELLO (our ACK was lost): repeat it, unchanged.
      if (have_peer_nonce_ &&
          std::memcmp(peer_nonce_, sender_nonce, kHandshakeNonceLen) == 0) {
        send_hello_ack();
        return HandshakeStatus::kConsumed;
      }
      // R3-24: a different nonce means "restart the session". A replay of an
      // old handshake looks identical, and honouring it would let one packet
      // kill a live session. Refuse and leave every bit of state alone; the
      // peer times out and reconnects with a fresh salt.
      ++hello_refused_;
      return HandshakeStatus::kConsumed;
    }
    // Idle / HelloSent: the peer's draw is immutable for the life of this
    // object, or an injected HELLO could move the key out from under datagrams
    // that are already in flight.
    if (have_peer_nonce_) {
      if (std::memcmp(peer_nonce_, sender_nonce, kHandshakeNonceLen) != 0) {
        ++hello_refused_;
        return HandshakeStatus::kConsumed;
      }
    } else {
      std::memcpy(peer_nonce_, sender_nonce, kHandshakeNonceLen);
      have_peer_nonce_ = true;
    }
    if (!negotiate(peer)) {
      return HandshakeStatus::kProtocolFailure;
    }
    send_hello_ack();
    return HandshakeStatus::kConsumed;
  }

  if (is_hello_ack(data, len)) {
    if (state_ != HandshakeState::kHelloSent) {
      return HandshakeStatus::kConsumed;  // duplicate, or stray in Idle/Failed
    }
    const uint8_t* c_nonce = data + kHelloAckMagicLen;
    const uint8_t* s_nonce = c_nonce + kHandshakeNonceLen;
    const HandshakeCaps peer = parse_caps(s_nonce + kHandshakeNonceLen);
    if (!caps_valid(peer)) {
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
    }
    if (!nonce_valid(c_nonce) || !nonce_valid(s_nonce)) {
      fail(HandshakeError::kBadNonce);
      return HandshakeStatus::kProtocolFailure;
    }
    // The ACK must answer *our* challenge: `own_echo` is the field that has to
    // repeat our draw, `peer_draw` the one that has to carry the peer's.
    const uint8_t* own_echo = role_ == HandshakeRole::kClient ? c_nonce : s_nonce;
    const uint8_t* peer_draw = role_ == HandshakeRole::kClient ? s_nonce : c_nonce;
    if (std::memcmp(own_echo, local_nonce_, kHandshakeNonceLen) != 0) {
      // A recorded ACK replayed at a fresh client echoes the wrong challenge.
      ++nonce_mismatch_;
      return HandshakeStatus::kConsumed;
    }
    if (have_peer_nonce_) {
      if (std::memcmp(peer_nonce_, peer_draw, kHandshakeNonceLen) != 0) {
        ++hello_refused_;
        return HandshakeStatus::kConsumed;
      }
    } else {
      std::memcpy(peer_nonce_, peer_draw, kHandshakeNonceLen);
      have_peer_nonce_ = true;
    }
    if (!negotiate(peer)) {
      return HandshakeStatus::kProtocolFailure;
    }
    return HandshakeStatus::kConsumed;
  }

  return HandshakeStatus::kNotHandshake;
}

bool Handshake::negotiate(const HandshakeCaps& peer) {
  const uint8_t flags = static_cast<uint8_t>(local_flags_ & peer.flags);
  const uint8_t required = static_cast<uint8_t>(kCapFraming | kCapFecstat);
  if ((flags & required) != required) {
    fail(HandshakeError::kMissingCapability);
    return false;
  }
  params_.d = std::min(local_d_, peer.data);
  params_.p = std::min(local_p_, peer.parity);
  params_.flags = flags;
  params_.mode = params_.p == 0 ? SessionMode::kFramedStats : SessionMode::kFramedRepair;
  state_ = HandshakeState::kEstablished;
  error_ = HandshakeError::kNone;
  return true;
}

void Handshake::fail(HandshakeError error) {
  state_ = HandshakeState::kFailed;
  error_ = error;
  cached_.clear();
  cached_bytes_ = 0;
}

void Handshake::send_hello() {
  if (!send_) {
    return;
  }
  uint8_t msg[kHelloLen];
  build_hello(HandshakeCaps{kCapsVersion, local_d_, local_p_, local_flags_},
              local_nonce_, msg);
  send_(msg, sizeof(msg));
}

void Handshake::send_hello_ack() {
  if (!send_ || !have_peer_nonce_) {
    return;
  }
  uint8_t msg[kHelloAckLen];
  build_hello_ack(HandshakeCaps{kCapsVersion, local_d_, local_p_, local_flags_},
                  client_nonce(), server_nonce(), msg);
  send_(msg, sizeof(msg));
}

bool Handshake::cache_data(std::vector<uint8_t> segment) {
  if (!buffering_data()) {
    return false;
  }
  if (cached_.size() + 1 > max_cached_segments_ ||
      cached_bytes_ + segment.size() > max_cached_bytes_) {
    fail(HandshakeError::kCacheOverflow);
    return false;
  }
  cached_bytes_ += segment.size();
  cached_.push_back(std::move(segment));
  return true;
}

std::vector<std::vector<uint8_t>> Handshake::take_cached_data() {
  std::vector<std::vector<uint8_t>> out;
  if (state_ != HandshakeState::kEstablished) {
    return out;
  }
  out = std::move(cached_);
  cached_.clear();
  cached_bytes_ = 0;
  return out;
}

}  // namespace fcp
