// HELLO / HELLO_ACK handshake and capability negotiation
// (FCP_PROTOCOL_V6.md §6, design doc §10).
//
// Both messages travel as oob frames (type=2, erratum #25): the session wraps
// them in the AEAD envelope and the receiver dispatches by their 16-byte magic.
// Retransmission belongs to the handshake's own exponential-backoff timer
// (300/600/1200ms, #27①), so there is no KCP-level retransmit window. Both
// sides may send HELLO simultaneously: every
// valid HELLO is ACKed, and the first side to receive either message negotiates
// once.

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
constexpr uint8_t kCapKnownMask = 0x0F;    // bits 4..7 must be zero

// M1 advertises framing + FECSTAT + per-set k.
constexpr uint8_t kLocalFlagsM1 = kCapFraming | kCapFecstat | kCapPerSetK;

// oob magic (§4.7): fixed 16 bytes. HELLO pads its 12-byte ASCII name with
// 4 NULs; HELLO_ACK's name is exactly 16 bytes. Both messages are magic(16) |
// caps(4) = 20 bytes on the wire.
constexpr char kHelloMagic[] = "FCP_HELLO_V3\0\0\0\0";
constexpr char kHelloAckMagic[] = "FCP_HELLO_ACK_V3";
constexpr size_t kHelloMagicLen = 16;
constexpr size_t kHelloAckMagicLen = sizeof(kHelloAckMagic) - 1;  // 16
static_assert(kHelloMagicLen == sizeof(kHelloMagic) - 1, "HELLO magic must be 16 bytes");
static_assert(kHelloAckMagicLen == 16, "HELLO_ACK magic must be 16 bytes");
constexpr size_t kHelloLen = kHelloMagicLen + kCapsLen;           // 20
constexpr size_t kHelloAckLen = kHelloAckMagicLen + kCapsLen;     // 20

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
};

// Reason text for the §11 log line.
const char* handshake_error_text(HandshakeError error);

struct NegotiatedParams {
  uint8_t d = 0;
  uint8_t p = 0;
  uint8_t flags = 0;
  SessionMode mode = SessionMode::kFramedStats;
};

void build_hello(const HandshakeCaps& caps, uint8_t out[kHelloLen]);
void build_hello_ack(const HandshakeCaps& caps, uint8_t out[kHelloAckLen]);

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

  Handshake(uint8_t local_d, uint8_t local_p, SendFn send,
            uint8_t local_flags = kLocalFlagsM1,
            size_t max_cached_segments = kHandshakeMaxCachedSegments,
            size_t max_cached_bytes = kHandshakeMaxCachedBytes);

  // Idle -> HelloSent; the first HELLO goes out on the next on_tick().
  void start(int64_t now_ms);
  void on_tick(int64_t now_ms);

  HandshakeStatus on_oob(const uint8_t* data, size_t len);

  HandshakeState state() const { return state_; }
  HandshakeError error() const { return error_; }
  bool established() const { return state_ == HandshakeState::kEstablished; }
  const NegotiatedParams& params() const { return params_; }

  int retries() const { return retries_; }
  int64_t next_retry_ms() const { return next_retry_ms_; }

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
  size_t max_cached_segments_;
  size_t max_cached_bytes_;

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
