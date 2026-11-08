#include "fcp/handshake.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "fcp/random.h"
#include "fcp/wire.h"

namespace fcp {
namespace {

constexpr uint8_t kMaxParityField = 7;  // 3-bit k field
constexpr uint16_t kMaxCodeLen = 256;   // D + P, compared as u16 (erratum #7)

// Offset of caps.flags inside a HELLO / HELLO_ACK (the last of the 4 caps
// bytes, right after the fixed nonce field(s)).
constexpr size_t kHelloFlagsOff = kHelloMagicLen + kHandshakeNonceLen + kCapsLen - 1;
constexpr size_t kHelloAckFlagsOff =
    kHelloAckMagicLen + 2 * kHandshakeNonceLen + kCapsLen - 1;

// A handshake message is either the fixed size, or the fixed size plus a
// length-consistent TLV block when the caps carry kCapTlv (#77). Anything
// else is not a handshake message -- junk must keep out of the key schedule.
// A fixed-size message WITH kCapTlv set still passes here: the block it
// claims is missing, and on_oob() reports that as kBadCaps (the H2 error-ACK
// path needs the message to reach the caps check, not die in dispatch).
bool handshake_msg_ok(const uint8_t* data, size_t len, size_t fixed_len,
                      const char* magic) {
  if (data == nullptr || len < fixed_len ||
      std::memcmp(data, magic, kHelloMagicLen) != 0) {
    return false;
  }
  if ((data[fixed_len - 1] & kCapTlv) == 0) {
    return len == fixed_len;
  }
  if (len == fixed_len) {
    return true;  // block claimed but absent: on_oob() -> kBadCaps
  }
  if (len < fixed_len + kTlvBlockLenBytes) {
    return false;
  }
  const size_t block = get_le16(data + fixed_len);
  return len == fixed_len + kTlvBlockLenBytes + block;
}

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
      return "no ACK before the retry budget ran out";
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
  return handshake_msg_ok(data, len, kHelloLen, kHelloMagic);
}

bool is_hello_ack(const uint8_t* data, size_t len) {
  return handshake_msg_ok(data, len, kHelloAckLen, kHelloAckMagic);
}

size_t tlv_encode(const std::vector<HandshakeTlv>& tlvs, uint8_t* out, size_t cap) {
  size_t total = 0;
  for (const auto& t : tlvs) {
    if (t.type == 0 || t.value.size() > kTlvMaxValueLen) {
      return 0;
    }
    total += kTlvOverhead + t.value.size();
  }
  if (total > kTlvBlockMaxLen || cap < kTlvBlockLenBytes + total) {
    return 0;
  }
  put_le16(static_cast<uint32_t>(total), out);
  size_t off = kTlvBlockLenBytes;
  for (const auto& t : tlvs) {
    out[off++] = t.type;
    out[off++] = static_cast<uint8_t>(t.value.size());
    if (!t.value.empty()) {
      std::memcpy(out + off, t.value.data(), t.value.size());
      off += t.value.size();
    }
  }
  return off;
}

bool tlv_parse(const uint8_t* block, size_t len, std::vector<HandshakeTlv>* out) {
  out->clear();
  size_t off = 0;
  while (off < len) {
    if (len - off < kTlvOverhead) {
      return false;
    }
    const uint8_t type = block[off];
    const size_t vlen = block[off + 1];
    // Type 0 is reserved; a value must fit inside the block it claims.
    if (type == 0 || len - off - kTlvOverhead < vlen) {
      return false;
    }
    out->push_back(HandshakeTlv{
        type, std::vector<uint8_t>(block + off + kTlvOverhead,
                                   block + off + kTlvOverhead + vlen)});
    off += kTlvOverhead + vlen;
  }
  return true;
}

size_t build_hello_ext(const HandshakeCaps& caps, const uint8_t sender_nonce[16],
                       const std::vector<HandshakeTlv>& tlvs, uint8_t* out,
                       size_t cap) {
  if ((caps.flags & kCapTlv) == 0 || cap < kHelloLen) {
    return 0;
  }
  const size_t n = tlv_encode(tlvs, out + kHelloLen, cap - kHelloLen);
  if (n == 0) {
    return 0;
  }
  build_hello(caps, sender_nonce, out);
  return kHelloLen + n;
}

size_t build_hello_ack_ext(const HandshakeCaps& caps, const uint8_t client_nonce[16],
                           const uint8_t server_nonce[16],
                           const std::vector<HandshakeTlv>& tlvs, uint8_t* out,
                           size_t cap) {
  if ((caps.flags & kCapTlv) == 0 || cap < kHelloAckLen) {
    return 0;
  }
  const size_t n = tlv_encode(tlvs, out + kHelloAckLen, cap - kHelloAckLen);
  if (n == 0) {
    return 0;
  }
  build_hello_ack(caps, client_nonce, server_nonce, out);
  return kHelloAckLen + n;
}

bool hello_tlvs(const uint8_t* data, size_t len, bool is_ack,
                std::vector<HandshakeTlv>* tlvs) {
  const size_t fixed = is_ack ? kHelloAckLen : kHelloLen;
  tlvs->clear();
  if (len < fixed || (data[fixed - 1] & kCapTlv) == 0) {
    return true;  // no block claimed
  }
  if (len == fixed) {
    return false;  // block claimed but absent
  }
  const size_t block = get_le16(data + fixed);
  if (block > kTlvBlockMaxLen || len != fixed + kTlvBlockLenBytes + block) {
    return false;
  }
  return tlv_parse(data + fixed + kTlvBlockLenBytes, block, tlvs);
}

Handshake::Handshake(uint8_t local_d, uint8_t local_p, SendFn send,
                     HandshakeRole role, const uint8_t* local_nonce,
                     uint8_t local_flags, size_t max_cached_segments,
                     size_t max_cached_bytes, int64_t rtt_seed_ms)
    : local_d_(local_d),
      local_p_(local_p),
      local_flags_(local_flags),
      send_(std::move(send)),
      role_(role),
      max_cached_segments_(max_cached_segments),
      max_cached_bytes_(max_cached_bytes),
      local_nonce_{},
      peer_nonce_{} {
  if (rtt_seed_ms > 0) {
    first_gap_ms_ = std::clamp(2 * rtt_seed_ms, kHandshakeRetryMs,
                               kHandshakeRetryCapMs);
  }
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
  // #77 downgrade probe: two TLV-carrying HELLOs went out unanswered (this
  // tick fires the third). A peer that predates the bit rejects kCapTlv as a
  // reserved flag and never ACKs, so finish the schedule in the plain v7
  // shape.
  if (!local_tlvs_.empty() && !tlv_downgraded_ && retries_ >= 2) {
    tlv_downgraded_ = true;
  }
  send_hello();
  ++retries_;
  // Exponential backoff (#27①, #76): the gap after send n is
  // min(first_gap_ms_ << (n-1), 8s). Base 250ms puts the 9 sends at
  // 0/250/750/1750/.../31750 ms and the failure check one cap interval later
  // (~39.7s of coverage), so a multi-second blackout (WiFi roaming, cellular
  // handover) no longer kills an otherwise healthy handshake; a prewarm RTT
  // prior seeds first_gap_ms_ instead of the base.
  next_retry_ms_ =
      now_ms + std::min(first_gap_ms_ << (retries_ - 1), kHandshakeRetryCapMs);
}

HandshakeStatus Handshake::on_oob(const uint8_t* data, size_t len) {
  if (is_hello(data, len)) {
    if (state_ == HandshakeState::kFailed) {
      return HandshakeStatus::kConsumed;
    }
    const uint8_t* sender_nonce = data + kHelloMagicLen;
    // #77: split the optional TLV block first. A kCapTlv HELLO with a
    // missing/malformed block is rejected through the error-ACK channel; a
    // valid block rides along into negotiate().
    std::vector<HandshakeTlv> tlvs;
    const bool tlv_ok = hello_tlvs(data, len, /*is_ack=*/false, &tlvs);
    const HandshakeCaps peer = parse_caps(data + kHelloMagicLen + kHandshakeNonceLen);
    // #77: "the peer knows the TLV bit" is caps-level, not framing-level --
    // a fixed-size HELLO that claims the block also goes through the error
    // channel (it is exactly the malformed case worth explaining).
    const bool knows_tlv = (peer.flags & kCapTlv) != 0;
    if (!caps_valid(peer) || !tlv_ok) {
      if (knows_tlv) {
        send_error_ack(HandshakeError::kBadCaps, sender_nonce);
      }
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
    }
    if (!nonce_valid(sender_nonce)) {
      if (knows_tlv) {
        send_error_ack(HandshakeError::kBadNonce, sender_nonce);
      }
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
      // #77: the re-ACKed duplicate keeps the same shape as the first ACK.
      peer_tlv_hello_ = knows_tlv;
      if (knows_tlv) {
        peer_tlvs_ = std::move(tlvs);
      }
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
    // The ACK must answer *our* challenge before anything in it is
    // interpreted: `own_echo` is the field that has to repeat our draw,
    // `peer_draw` the one that has to carry the peer's. Binding first is what
    // keeps a replayed error ACK from another session from killing this
    // handshake (#77).
    const uint8_t* own_echo = role_ == HandshakeRole::kClient ? c_nonce : s_nonce;
    const uint8_t* peer_draw = role_ == HandshakeRole::kClient ? s_nonce : c_nonce;
    if (std::memcmp(own_echo, local_nonce_, kHandshakeNonceLen) != 0) {
      // A recorded ACK replayed at a fresh client echoes the wrong challenge.
      ++nonce_mismatch_;
      return HandshakeStatus::kConsumed;
    }
    // #77 (H2): the peer's rejection rides a kTlvTypeError TLV. It means the
    // peer parsed our HELLO and refused -- retrying cannot help, so fail with
    // the peer's code immediately instead of running out the retry table.
    std::vector<HandshakeTlv> tlvs;
    const bool tlv_ack = hello_tlvs(data, len, /*is_ack=*/true, &tlvs);
    if (tlv_ack) {
      for (const auto& t : tlvs) {
        if (t.type == kTlvTypeError && t.value.size() == 1) {
          const auto code = static_cast<HandshakeError>(t.value[0]);
          peer_error_ = code == HandshakeError::kBadCaps ||
                                code == HandshakeError::kBadNonce
                            ? code
                            : HandshakeError::kBadCaps;
          fail(peer_error_);
          return HandshakeStatus::kProtocolFailure;
        }
      }
    }
    const HandshakeCaps peer = parse_caps(s_nonce + kHandshakeNonceLen);
    if (!caps_valid(peer) || !tlv_ack) {
      fail(HandshakeError::kBadCaps);
      return HandshakeStatus::kProtocolFailure;
    }
    if (!nonce_valid(c_nonce) || !nonce_valid(s_nonce)) {
      fail(HandshakeError::kBadNonce);
      return HandshakeStatus::kProtocolFailure;
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
    if (peer.flags & kCapTlv) {
      peer_tlvs_ = std::move(tlvs);
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
  // #77: kCapTlv survives only when both ends actually used the extension on
  // this exchange. The plain flags-AND cannot express that, because
  // local_flags_ never carries the bit -- the outgoing HELLO/ACK ORs it in
  // from the TLV state instead. The peer's bit alone is proof enough of the
  // other side (the server echoes the bit only for a TLV HELLO, and the
  // client's ACK can only carry it if our HELLO offered), but requiring our
  // own side too keeps the negotiation symmetric.
  const bool both_tlv = (peer.flags & kCapTlv) != 0 &&
                        (role_ == HandshakeRole::kClient ? tlv_offered_
                                                         : peer_tlv_hello_);
  params_.d = std::min(local_d_, peer.data);
  params_.p = std::min(local_p_, peer.parity);
  params_.flags = static_cast<uint8_t>(flags | (both_tlv ? kCapTlv : 0));
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

void Handshake::set_local_tlvs(std::vector<HandshakeTlv> tlvs) {
  local_tlvs_ = std::move(tlvs);
}

void Handshake::send_hello() {
  if (!send_) {
    return;
  }
  // #77: offer the TLV block until the downgrade probe flips (see on_tick);
  // the offered caps are derived, local_flags_ itself never carries the bit.
  const bool offer = !local_tlvs_.empty() && !tlv_downgraded_;
  const uint8_t flags = offer ? static_cast<uint8_t>(local_flags_ | kCapTlv)
                              : static_cast<uint8_t>(local_flags_ & ~kCapTlv);
  const HandshakeCaps caps{kCapsVersion, local_d_, local_p_, flags};
  if (offer) {
    tlv_offered_ = true;
    std::vector<uint8_t> msg(kHelloLen + kTlvBlockLenBytes + kTlvBlockMaxLen);
    const size_t n =
        build_hello_ext(caps, local_nonce_, local_tlvs_, msg.data(), msg.size());
    if (n != 0) {
      send_(msg.data(), n);
      return;
    }
    // Unencodable block: a programming error in the caller's TLVs. Fall
    // through to the plain shape rather than sending caps that claim a block
    // the message does not carry.
  }
  uint8_t msg[kHelloLen];
  build_hello(caps, local_nonce_, msg);
  send_(msg, sizeof(msg));
}

void Handshake::send_hello_ack() {
  if (!send_ || !have_peer_nonce_) {
    return;
  }
  // #77: the ACK echoes the kCapTlv bit exactly when the establishing HELLO
  // carried it (the re-ACKed duplicate keeps the same shape). The block may
  // be empty -- the bit then just says "this end speaks TLV".
  const bool offer = peer_tlv_hello_;
  const uint8_t flags = offer ? static_cast<uint8_t>(local_flags_ | kCapTlv)
                              : static_cast<uint8_t>(local_flags_ & ~kCapTlv);
  const HandshakeCaps caps{kCapsVersion, local_d_, local_p_, flags};
  if (offer) {
    std::vector<uint8_t> msg(kHelloAckLen + kTlvBlockLenBytes + kTlvBlockMaxLen);
    const size_t n = build_hello_ack_ext(caps, client_nonce(), server_nonce(),
                                         local_tlvs_, msg.data(), msg.size());
    if (n != 0) {
      send_(msg.data(), n);
      return;
    }
  }
  uint8_t msg[kHelloAckLen];
  build_hello_ack(caps, client_nonce(), server_nonce(), msg);
  send_(msg, sizeof(msg));
}

void Handshake::send_error_ack(HandshakeError error, const uint8_t client_nonce[16]) {
  if (!send_ || role_ != HandshakeRole::kServer) {
    return;
  }
  const HandshakeCaps caps{
      kCapsVersion, local_d_, local_p_,
      static_cast<uint8_t>((local_flags_ & ~kCapTlv) | kCapTlv)};
  std::vector<HandshakeTlv> tlvs;
  tlvs.push_back(
      HandshakeTlv{kTlvTypeError, std::vector<uint8_t>{static_cast<uint8_t>(error)}});
  std::vector<uint8_t> msg(kHelloAckLen + kTlvBlockLenBytes + kTlvBlockMaxLen);
  const size_t n =
      build_hello_ack_ext(caps, client_nonce, local_nonce_, tlvs, msg.data(), msg.size());
  if (n != 0) {
    send_(msg.data(), n);
  }
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
