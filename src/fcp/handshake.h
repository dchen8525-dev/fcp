// HELLO / HELLO_ACK handshake and capability negotiation
// (协议规格.md §6, design doc §10).
//
// Both messages travel as oob frames (type=2, erratum #25): the session wraps
// them in the AEAD envelope and the receiver dispatches by their 16-byte magic.
// Retransmission belongs to the handshake's own exponential-backoff timer
// (250ms doubling, capped at 8s -- 9 sends over ~39.7s; #27①, extended by
// 施工单 step 1 / #76), so there is no KCP-level retransmit window. Both
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
// #77 adds an optional TLV block after caps4 whenever caps.flags carries
// kCapTlv: [block_len(2 LE)][type(1)|len(1)|value]... -- the extension
// channel future parameters negotiate through (see the TLV section below
// is_hello).
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
// TLV extension (#77, 施工单 step 2): the caps carry a TLV block after the
// fixed fields. Unknown TLV types are ignored by both sides (forward
// compatibility -- future parameters ride this without another handshake
// format change); a peer that does not know the BIT still rejects it, which
// is why the client probes: two unanswered TLV-carrying HELLOs and it
// downgrades to the plain v7 shape for the rest of the handshake.
constexpr uint8_t kCapTlv = 1u << 5;       // optional, #77
constexpr uint8_t kCapKnownMask = 0x3F;    // bits 6..7 must be zero

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
// TLV block (#77): [block_len(2 LE)][type(1) | len(1) | value]... The block
// rides after the fixed caps4 in HELLO/HELLO_ACK whenever caps.flags carries
// kCapTlv; a fixed-size message with kCapTlv set (block claimed, absent) is a
// caps error. Unknown types parse through and are ignored by the caller.
constexpr size_t kTlvBlockLenBytes = 2;
constexpr size_t kTlvOverhead = 2;         // type + len per TLV
constexpr size_t kTlvMaxValueLen = 255;
constexpr size_t kTlvBlockMaxLen = 1024;
// TLV types. 0 is reserved (a parsed type of 0 is malformed). kTlvTypeError
// carries one byte: the sender's HandshakeError. It is the H2 channel -- the
// peer parsed our handshake and refused it, so retrying cannot help and the
// client fails immediately instead of running out the retry table.
constexpr uint8_t kTlvTypeError = 1;

// Total sends before the handshake is declared dead (initial HELLO + retries).
constexpr int kHandshakeMaxRetries = 9;
// Base gap before the first retry. The gap doubles after every send and caps
// at kHandshakeRetryCapMs, so the sends land at 0/250/750/1750/3750/7750/
// 15750/23750/31750 ms and the handshake fails at ~39.7s total -- the last
// send gets one full cap interval of grace, matching the STUN request
// lifecycle (spec §6.2 #27① fixed the false-fail on RTT > 450ms links; #76
// extends it further: the old 3-send/2.1s budget declared death inside any
// >2.1s blackout -- WiFi roaming, cellular handover -- on a link that was
// fine). With a prewarm RTT prior (SessionConfig::initial_srtt_ms) the first
// gap is seeded to clamp(2*srtt, base, cap) instead, so a known-fast path
// does not wait out a 250ms first gap and a known-slow one does not give up
// early.
constexpr int64_t kHandshakeRetryMs = 250;
constexpr int64_t kHandshakeRetryCapMs = 8000;
// #28③ (F2): pre-negotiation cache limits, raised from 64 segs / 64 KiB and
// made configurable. A sustained 8 Mbit/s sender fills 64 segs in ~80ms and
// disconnected the session; 512 segs / 512 KiB buffers ~0.5s of full-rate
// data and covers the RTT <= ~500ms handshake class (the cache bounds how
// long a busy sender can wait out a blackout regardless of the retry table,
// which is why the two budgets are documented apart). Heavier BDP links
// override via SessionConfig.
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

// One capability TLV. Type 0 and value lengths over kTlvMaxValueLen cannot be
// encoded; the block as a whole is capped at kTlvBlockMaxLen.
struct HandshakeTlv {
  uint8_t type = 0;
  std::vector<uint8_t> value;
};

// Encodes [block_len(2 LE)][tlv]...; returns the bytes written, 0 when `tlvs`
// is empty (callers then send the fixed-size message) or the block would
// exceed kTlvBlockMaxLen / out_cap.
size_t tlv_encode(const std::vector<HandshakeTlv>& tlvs, uint8_t* out, size_t cap);
// Parses a block (without the 2-byte length prefix). Unknown types come back;
// type 0, truncation, or a value length past the buffer returns false.
bool tlv_parse(const uint8_t* block, size_t len, std::vector<HandshakeTlv>* out);

// Fixed-size builders with a TLV block appended (#77): the caps in `caps` must
// already carry kCapTlv (the caller's decision). Returns 0 when `tlvs` is
// empty, the block does not fit kTlvBlockMaxLen, or `cap` is too small --
// callers fall back to the fixed-size builders above.
size_t build_hello_ext(const HandshakeCaps& caps, const uint8_t sender_nonce[16],
                       const std::vector<HandshakeTlv>& tlvs, uint8_t* out,
                       size_t cap);
size_t build_hello_ack_ext(const HandshakeCaps& caps, const uint8_t client_nonce[16],
                           const uint8_t server_nonce[16],
                           const std::vector<HandshakeTlv>& tlvs, uint8_t* out,
                           size_t cap);

// Splits the optional TLV block off a HELLO (is_ack=false) or HELLO_ACK
// (is_ack=true) that already passed is_hello()/is_hello_ack(). *tlvs is
// cleared then populated (possibly empty). Returns false when the caps claim
// a block (kCapTlv) but the framing is missing or malformed -- the caller
// treats that as kBadCaps.
bool hello_tlvs(const uint8_t* data, size_t len, bool is_ack,
                std::vector<HandshakeTlv>* tlvs);

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
            size_t max_cached_bytes = kHandshakeMaxCachedBytes,
            int64_t rtt_seed_ms = 0);
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

  // TLV extension (#77). `set_local_tlvs` arms the client-side downgrade
  // probe: the first two HELLOs carry the block (kCapTlv), and if nothing
  // answers by the third send the rest go out in the plain v7 shape -- a peer
  // that predates the bit rejects the caps outright and never ACKs. The
  // negotiated bit is params().flags & kCapTlv (set only when BOTH sides
  // carried it). `peer_error()` is the H2 channel: the peer parsed our
  // handshake and refused it (error TLV in the ACK), so the handshake failed
  // immediately instead of running out the retry table.
  void set_local_tlvs(std::vector<HandshakeTlv> tlvs);
  bool tlv_downgraded() const { return tlv_downgraded_; }
  bool tlv_negotiated() const { return (params_.flags & kCapTlv) != 0; }
  const std::vector<HandshakeTlv>& peer_tlvs() const { return peer_tlvs_; }
  HandshakeError peer_error() const { return peer_error_; }

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
  // The rejection channel (H2): one HELLO_ACK carrying kTlvTypeError, sent
  // before a kBadCaps failure so the peer learns why instead of timing out.
  void send_error_ack(HandshakeError error, const uint8_t client_nonce[16]);

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
  // First backoff gap: kHandshakeRetryMs, or clamp(2*rtt_seed, base, cap)
  // when a prewarm prior was passed in. Every later gap doubles this one.
  int64_t first_gap_ms_ = kHandshakeRetryMs;

  // TLV extension state (#77). `tlv_downgraded_` flips once two TLV-carrying
  // HELLOs went out unanswered; `peer_tlv_hello_` remembers whether the HELLO
  // that established us carried the bit, so a re-ACKed duplicate keeps the
  // same shape as the first ACK.
  std::vector<HandshakeTlv> local_tlvs_;
  std::vector<HandshakeTlv> peer_tlvs_;
  bool tlv_downgraded_ = false;
  bool tlv_offered_ = false;  // sticky: an ext-shape HELLO went out (#77)
  bool peer_tlv_hello_ = false;
  HandshakeError peer_error_ = HandshakeError::kNone;

  std::vector<std::vector<uint8_t>> cached_;
  size_t cached_bytes_ = 0;
};

}  // namespace fcp

#endif  // FCP_HANDSHAKE_H_
