// HELLO / HELLO_ACK handshake and capability negotiation
// (协议规格.md §6, design doc §10).
//
// Both messages travel as oob frames (type=2, erratum #25): the session wraps
// them in the AEAD envelope and the receiver dispatches by their 16-byte magic.
// Retransmission belongs to the handshake's own exponential-backoff timer
// (300/600/1200ms, #27①), so there is no KCP-level retransmit window. Both
// sides may send HELLO simultaneously: every
// valid HELLO is ACKed, and the first side to receive either message negotiates
// once.
//
// v4 (R3-1): every handshake message now carries a 16-byte nonce drawn from the
// local CSPRNG, and the session key binds both draws
// (derive_session_key_v7). Without it, a recorded HELLO/HELLO_ACK pair could be
// replayed to rebuild the very same (key, IV) pair on both ends, and the
// per-session replay window would happily accept the recorded data as new.
//
//   HELLO     = magic16 | sender_nonce16 | caps4              (36)
//   HELLO_ACK = magic16 | client_nonce16 | server_nonce16 | caps4  (52)
//
// HELLO carries only the sender's own draw; the reader maps it by ROLE (the
// C2S side's draw is the client nonce, the S2C side's is the server nonce), so
// a simultaneous open still converges on one key. HELLO_ACK carries both, which
// lets the client that sent a HELLO establish on the ACK alone.
//
// The ACK echoes the client nonce on purpose: it is the only binding between
// "this ACK" and "my challenge". A recorded ACK replayed at a fresh client
// echoes the wrong nonce and is dropped, and because the server's nonce is
// drawn per session object, the replayed pair also produces a different key.

#ifndef FCP_HANDSHAKE_H_
#define FCP_HANDSHAKE_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace fcp {

constexpr size_t kCapsLen = 4;
constexpr uint8_t kCapsVersion = 1;

constexpr uint8_t kCapFraming = 1u << 0;   // required
constexpr uint8_t kCapFecstat = 1u << 1;   // required
constexpr uint8_t kCapPerSetK = 1u << 2;   // optional
constexpr uint8_t kCapDeadline = 1u << 3;  // optional, M2
// PMTUD (pmtu.h): the peer may send path-MTU probes and expects acks. The
// flag is only advertised when the session is configured for it; a peer that
// does not know the bit rejects the caps (reserved bits are a hard gate), so
// both ends must be updated together for PMTUD to be usable.
constexpr uint8_t kCapPmtud = 1u << 4;     // optional, M2
constexpr uint8_t kCapKnownMask = 0x1F;    // bits 5..7 must be zero

// M1 advertises framing + FECSTAT + per-set k.
constexpr uint8_t kLocalFlagsM1 = kCapFraming | kCapFecstat | kCapPerSetK;

// oob magic (§4.7): fixed 16 bytes, and it doubles as the handshake version --
// byte-for-byte equality is the gate, so a message that does not carry our
// magic exactly is not a HELLO/HELLO_ACK and can never enter the key
// schedule.
constexpr char kHelloMagic[] = "FCP_HELLO_V1\0\0\0\0";
constexpr char kHelloAckMagic[] = "FCP_HELLO_ACK_V1";
constexpr size_t kHelloMagicLen = 16;
constexpr size_t kHelloAckMagicLen = sizeof(kHelloAckMagic) - 1;  // 16
static_assert(kHelloMagicLen == sizeof(kHelloMagic) - 1, "HELLO magic must be 16 bytes");
static_assert(kHelloAckMagicLen == 16, "HELLO_ACK magic must be 16 bytes");

constexpr size_t kHandshakeNonceLen = 16;
constexpr size_t kHelloLen = kHelloMagicLen + kHandshakeNonceLen + kCapsLen;  // 36
constexpr size_t kHelloAckLen =
    kHelloAckMagicLen + 2 * kHandshakeNonceLen + kCapsLen;  // 52

constexpr int kHandshakeMaxRetries = 3;
// Base timeout before the first retry. The gap doubles after every send, so
// the three gaps are 300/600/1200ms and the handshake fails at ~2.1s total
// (spec §6.2 #27①: a fixed 900ms budget falsely kills RTT > 450ms links).
constexpr int64_t kHandshakeRetryMs = 300;
// #28③ (F2): pre-negotiation cache limits, raised from 64 segs / 64 KiB and
// made configurable. The 2.1s worst-case handshake at a sustained 8 Mbit/s
// sender fills 64 segs in ~80ms and disconnected the session; 512 segs /
// 512 KiB buffers ~0.5s of full-rate data and covers the RTT <= ~500ms
// handshake class. Heavier BDP links override via SessionConfig.
constexpr size_t kHandshakeMaxCachedSegments = 512;
constexpr size_t kHandshakeMaxCachedBytes = 512 * 1024;

// Which end of the session this is. It decides which of the two nonces this
// side contributes, and it is fixed by Direction -- never by who sent HELLO
// first, so a simultaneous open cannot fork the key.
enum class HandshakeRole : uint8_t {
  kClient = 0,  // C2S: contributes the client nonce
  kServer = 1,  // S2C: contributes the server nonce
};

struct HandshakeCaps {
  uint8_t ver = kCapsVersion;
  uint8_t data = 0;
  uint8_t parity = 0;
  uint8_t flags = kLocalFlagsM1;
};

enum class SessionMode : uint8_t {
  kFramedRepair = 0,  // P' >= 1
  kFramedStats,       // P' == 0, no RS codec
};

enum class HandshakeState : uint8_t {
  kIdle = 0,
  kHelloSent,
  kEstablished,
  kFailed,
};

enum class HandshakeError : uint8_t {
  kNone = 0,
  kNoAck,             // 3 HELLOs, no answer
  kBadCaps,           // version / bounds / reserved flags
  kMissingCapability, // negotiated framing or FECSTAT bit is 0
  kCacheOverflow,     // over the (configurable) cache limits before negotiation
  kBadNonce,          // all-zero or otherwise unusable handshake nonce
};

// Reason text for the §11 log line.
const char* handshake_error_text(HandshakeError error);

struct NegotiatedParams {
  uint8_t d = 0;
  uint8_t p = 0;
  uint8_t flags = 0;
  SessionMode mode = SessionMode::kFramedStats;
};

void build_hello(const HandshakeCaps& caps, const uint8_t sender_nonce[16],
                 uint8_t out[kHelloLen]);
void build_hello_ack(const HandshakeCaps& caps, const uint8_t client_nonce[16],
                     const uint8_t server_nonce[16], uint8_t out[kHelloAckLen]);

bool is_hello(const uint8_t* data, size_t len);
bool is_hello_ack(const uint8_t* data, size_t len);

// Handshake messages arrive as oob frames; the session dispatches by magic
// before handing the payload here.
enum class HandshakeStatus : uint8_t {
  kNotHandshake = 0,  // no HELLO/ACK magic, the caller keeps routing
  kConsumed,
  kProtocolFailure,   // state moved to kFailed
};

class Handshake {
 public:
  using SendFn = std::function<void(const uint8_t* data, size_t len)>;

  // `local_nonce` is the caller's draw; nullptr means "take it from the OS
  // CSPRNG", which is what production always does. It is injectable only so a
  // test can pin a vector.
  Handshake(uint8_t local_d, uint8_t local_p, SendFn send, HandshakeRole role,
            const uint8_t* local_nonce = nullptr,
            uint8_t local_flags = kLocalFlagsM1,
            size_t max_cached_segments = kHandshakeMaxCachedSegments,
            size_t max_cached_bytes = kHandshakeMaxCachedBytes);
  // 两侧 nonce 一旦生命周期结束就零化：它们绑定了 v7 会话密钥的派生输入。
  ~Handshake();
  Handshake(const Handshake&) = delete;
  Handshake& operator=(const Handshake&) = delete;

  // Idle -> HelloSent; the first HELLO goes out on the next on_tick().
  void start(int64_t now_ms);
  void on_tick(int64_t now_ms);

  HandshakeStatus on_oob(const uint8_t* data, size_t len);

  HandshakeState state() const { return state_; }
  HandshakeError error() const { return error_; }
  bool established() const { return state_ == HandshakeState::kEstablished; }
  const NegotiatedParams& params() const { return params_; }
  HandshakeRole role() const { return role_; }

  int retries() const { return retries_; }
  int64_t next_retry_ms() const { return next_retry_ms_; }

  // This end's draw (the client nonce on the C2S side, the server nonce on the
  // S2C side). Valid from construction.
  const uint8_t* local_nonce() const { return local_nonce_; }
  bool have_peer_nonce() const { return have_peer_nonce_; }
  const uint8_t* peer_nonce() const { return peer_nonce_; }

  // The pair the session key is bound to, valid once have_peer_nonce().
  const uint8_t* client_nonce() const {
    return role_ == HandshakeRole::kClient ? local_nonce_ : peer_nonce_;
  }
  const uint8_t* server_nonce() const {
    return role_ == HandshakeRole::kServer ? local_nonce_ : peer_nonce_;
  }

  // Diagnostics: an ACK that did not echo our nonce (stale, replayed, or a peer
  // that mixed up the roles), and a HELLO that asked to restart a live session
  // (R3-24: refused, the peer must reconnect with a fresh salt).
  uint32_t nonce_mismatch() const { return nonce_mismatch_; }
  uint32_t hello_refused() const { return hello_refused_; }

  // True while data segments must be buffered (Idle / HelloSent).
  bool buffering_data() const {
    return state_ == HandshakeState::kIdle || state_ == HandshakeState::kHelloSent;
  }

  // Buffers one KCP segment until negotiation completes. Returns false when
  // the segment cannot be buffered (overflow fails the handshake, or the
  // handshake is already over and the caller must route normally).
  bool cache_data(std::vector<uint8_t> segment);

  // Drains the cache in send order; empty unless Established.
  std::vector<std::vector<uint8_t>> take_cached_data();

  size_t cached_segments() const { return cached_.size(); }
  size_t cached_bytes() const { return cached_bytes_; }

 private:
  bool negotiate(const HandshakeCaps& peer);
  void fail(HandshakeError error);
  void send_hello();
  void send_hello_ack();

  uint8_t local_d_;
  uint8_t local_p_;
  uint8_t local_flags_;
  SendFn send_;
  HandshakeRole role_;
  size_t max_cached_segments_;
  size_t max_cached_bytes_;

  // Immutable once drawn: the session key is bound to this exact pair, so a
  // second draw would silently desync from any datagram already in flight.
  uint8_t local_nonce_[kHandshakeNonceLen];
  uint8_t peer_nonce_[kHandshakeNonceLen];
  bool have_peer_nonce_ = false;

  uint32_t nonce_mismatch_ = 0;
  uint32_t hello_refused_ = 0;

  HandshakeState state_ = HandshakeState::kIdle;
  HandshakeError error_ = HandshakeError::kNone;
  NegotiatedParams params_;

  int retries_ = 0;
  int64_t next_retry_ms_ = 0;

  std::vector<std::vector<uint8_t>> cached_;
  size_t cached_bytes_ = 0;
};

}  // namespace fcp

#endif  // FCP_HANDSHAKE_H_
