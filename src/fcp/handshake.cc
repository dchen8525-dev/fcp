#include "fcp/handshake.h"

#include <algorithm>
#include <cstring>
#include <utility>

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

}  // namespace

const char* handshake_error_text(HandshakeError error) {
  switch (error) {
    case HandshakeError::kNone:
      return "none";
    case HandshakeError::kNoAck:
      return "V3 no ACK after 3 tries";
    case HandshakeError::kBadCaps:
      return "invalid caps";
    case HandshakeError::kMissingCapability:
      return "missing required capability";
    case HandshakeError::kCacheOverflow:
      return "pre-negotiation data cache overflow";
  }
  return "unknown";
}

void build_hello(const HandshakeCaps& caps, uint8_t out[kHelloLen]) {
  std::memcpy(out, kHelloMagic, kHelloMagicLen);
  write_caps(caps, out + kHelloMagicLen);
}

void build_hello_ack(const HandshakeCaps& caps, uint8_t out[kHelloAckLen]) {
  std::memcpy(out, kHelloAckMagic, kHelloAckMagicLen);
  write_caps(caps, out + kHelloAckMagicLen);
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
                     uint8_t local_flags, size_t max_cached_segments,
                     size_t max_cached_bytes)
    : local_d_(local_d),
      local_p_(local_p),
      local_flags_(local_flags),
      send_(std::move(send)),
      max_cached_segments_(max_cached_segments),
      max_cached_bytes_(max_cached_bytes) {}

void Handshake::start(int64_t now_ms) {
  if (state_ != HandshakeState::kIdle) {
    return;
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
    const HandshakeCaps peer = parse_caps(data + kHelloMagicLen);
    if (!caps_valid(peer)) {
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
    }
    // Duplicate HELLOs are swallowed, but the ACK is repeated: the peer may
    // still be retrying because our previous ACK was lost.
    if (state_ == HandshakeState::kEstablished) {
      send_hello_ack();
      return HandshakeStatus::kConsumed;
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
    const HandshakeCaps peer = parse_caps(data + kHelloAckMagicLen);
    if (!caps_valid(peer)) {
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
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
  build_hello(HandshakeCaps{kCapsVersion, local_d_, local_p_, local_flags_}, msg);
  send_(msg, sizeof(msg));
}

void Handshake::send_hello_ack() {
  if (!send_) {
    return;
  }
  uint8_t msg[kHelloAckLen];
  build_hello_ack(HandshakeCaps{kCapsVersion, local_d_, local_p_, local_flags_}, msg);
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
