// Per-session assembly: envelope -> handshake -> frame tx/rx -> settle ->
// reporter -> strategy (design doc §2, §10, §11).
//
// One logical thread per session; no internal locks. The owner feeds inbound
// datagrams with on_wire(), KCP output with on_kcp_output(), and drives
// on_tick() from a 25ms poll. Modules are created lazily once handshake
// negotiation fixes (D', P'); until then only oob (including HELLO/ACK) is
// actionable, outbound data segments are buffered by the handshake (erratum
// #4), and inbound data/parity is dropped.
// Handshake messages travel as oob frames (erratum #25): there is no content
// classification anywhere on the KCP paths.

#ifndef FCP_SESSION_H_
#define FCP_SESSION_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "fcp/envelope.h"
#include "fcp/fecstat.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "fcp/reporter.h"
#include "fcp/settle.h"
#include "fcp/trace.h"
#include "fcp/strategy.h"

namespace fcp {

// Poll interval for T_flush, settlement and the FECSTAT cadence.
constexpr int64_t kSessionTickMs = 25;

// srtt assumed until the first RTT sample arrives, i.e. what a session without
// a prewarm value starts from.
constexpr int64_t kDefaultSrttMs = 200;

// The frame layer's cross-set duplicate check needs a replayable id out of the
// payload. §4 assumed the payload to be a KCP segment, whose sn sits at offset
// 12; that is what this reads. Payloads shorter than a KCP header carry no sn
// and skip the check.
//
// This is the only place in the code base that knows the KCP header layout:
// the Qt bench's receive check and the test fixtures go through it too, so a
// change to the offset changes every reader at once.
constexpr size_t kKcpSnOffset = 12;
constexpr size_t kKcpSnLen = kKcpSnOffset + 4;
bool kcp_sn_of(const uint8_t* payload, size_t len, uint32_t* sn);

struct SessionConfig {
  uint8_t key[16] = {};
  uint8_t salt[Envelope::kSaltLen] = {};
  Direction send_direction = Direction::kC2S;
  Direction recv_direction = Direction::kS2C;
  uint8_t d = 10;
  uint8_t p = 3;
  uint8_t p_max = kDefaultPmax;
  uint16_t mtu = 1400;
  size_t ip_hdr_len = 20;
  int pinned_k = -1;  // --fec-parity-pinned; >= 0 bypasses the strategy
  // Link warm-up (M2代理设计.md §5), both optional and both defaulting to
  // the cold M1 behaviour. initial_srtt_ms == 0 keeps the internal 200ms, so
  // T_flush, the settlement tombstones and the §8 queue guardrail all start
  // from the peer's history instead of from the first converged sample.
  int64_t initial_srtt_ms = 0;
  // >= 1 enters the FEC state machine already ON at this k (still clamped by
  // the negotiated P' and p_max). -1 starts OFF, which cannot pick a k until
  // the first FECSTAT report lands.
  int initial_k = -1;
  // M3 byte budget (M3控制设计.md §2): ceiling on the interval's
  // parity_bytes/data_bytes ratio seen by the peer's FECSTAT; 0 disables.
  // Exceeding it enters the kCapped state (one parity per report down, floor
  // 1) until a report measures back under the ceiling.
  double fec_budget = 0.50;
  // #28③ (F2): pre-negotiation data cache limits (see handshake.h defaults).
  size_t handshake_cache_segments = kHandshakeMaxCachedSegments;
  size_t handshake_cache_bytes = kHandshakeMaxCachedBytes;
  // R3-1: our handshake nonce. All-zero means "draw it from the OS CSPRNG",
  // which is what every host wants; a test can pin it to reproduce a vector.
  uint8_t handshake_nonce[16] = {};
  // Dedup key for delivered payloads, or empty to switch the cross-set dedup
  // off. FCP-STREAM must run with an empty one: it numbers bytes, so a
  // retransmission deliberately repeats an id the peer has to see in order to
  // re-ack it, and suppressing that at this layer stalls the sender's window.
  FrameRx::SnFn sn_of = &kcp_sn_of;
  // #28 controller trace sink (M3控制设计.md §5): invoked once per
  // accepted FECSTAT report with the report, the config snapshot and the
  // decision just made. Empty = no recording.
  using TraceFn = std::function<void(const TraceEntry&)>;
  TraceFn trace;
};

class Session {
 public:
  // Sealed datagram plus its symbol type, so the transport can account bytes
  // and test harnesses can drop data/parity without decrypting.
  using SendFn = std::function<void(const uint8_t* wire, size_t len, SymbolType type)>;
  using DeliverFn = std::function<void(const uint8_t* payload, size_t len)>;
  using LogFn = std::function<void(const std::string& line)>;

  Session(const SessionConfig& config, SendFn send, DeliverFn deliver, LogFn log = {});
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  void start(int64_t now_ms);

  // Authenticates and routes one inbound datagram. Returns true only when the
  // envelope authenticated: a false result means the datagram carried no valid
  // GCM tag (wrong key, corrupted, or a replayed counter) and changed nothing
  // except the auth_fail counter. Hosts that route by the plaintext salt use
  // this to keep unauthenticated traffic away from any peer binding (A1).
  bool on_wire(const uint8_t* wire, size_t len, int64_t now_ms);

  // One KCP output segment; every segment is data (handshake traffic uses oob).
  void on_kcp_output(const uint8_t* seg, size_t len, int64_t now_ms);

  // Timer pump: handshake retries, T_flush, settlement, FECSTAT cadence.
  void on_tick(int64_t now_ms);

  void on_rtt_sample(int64_t srtt_ms);

  // §14.6 (#30): emit the interval's FECSTAT now if it holds anything.
  // Called once at teardown so the peer's controller sees the final stretch
  // of traffic instead of losing it to the < 60s cadence tail.
  void flush_report(int64_t now_ms);

  // #26①/T25: restores the send counter below the 2^32 block-budget line
  // (tests; a live session starts at 0). Once exhausted() turns true, seal()
  // refuses and nothing more leaves -- the host must disconnect the session.
  bool set_send_nonce(uint64_t value) { return env_.set_send_nonce(value); }
  bool nonce_exhausted() const { return env_.exhausted(); }

  bool established() const { return hs_.established(); }
  HandshakeState state() const { return hs_.state(); }
  HandshakeError error() const { return hs_.error(); }
  const NegotiatedParams& params() const { return hs_.params(); }
  SessionMode mode() const { return hs_.params().mode; }
  uint8_t k() const { return strategy_ ? strategy_->k() : 0; }

  const uint8_t* salt() const { return cfg_.salt; }
  // R3-1: this end's handshake draw. Diagnostics, and the handle a test needs
  // to build the ACK that answers this session's challenge (the echo check
  // rejects anything else, which is the point).
  const uint8_t* handshake_nonce() const { return hs_.local_nonce(); }
  // R3-1: ACKs whose echoed nonce did not match the challenge this end issued
  // (a replayed or cross-session ACK). Non-zero means the echo check is what
  // kept the session from establishing on someone else's transcript.
  uint32_t nonce_mismatch() const { return hs_.nonce_mismatch(); }
  const MtuLimits& mtu_limits() const { return limits_; }
  bool config_valid() const { return limits_.valid; }

  size_t cached_segments() const { return hs_.cached_segments(); }
  int64_t srtt_ms() const { return srtt_ms_; }

  uint32_t auth_fail() const { return auth_fail_; }
  uint32_t struct_fail() const { return pre_struct_fail_ + (rx_ ? rx_->struct_fail() : 0); }
  // #31 (M4 trigger metric): FEC/ARQ waste — retransmissions that lost the
  // race to parity. Summed into the proxy stats line for the WAN calibration.
  uint32_t dup_after_recovered() const { return rx_ ? rx_->dup_after_recovered() : 0; }
  uint32_t fecstat_dropped() const { return fecstat_dropped_; }
  uint32_t fecstat_stale() const { return fecstat_stale_; }
  // #28⑤ (F3): second copies of double-sent FECSTATs, ignored via the
  // monotonic key. Kept apart from stale/dropped so diagnostics stay clean.
  uint32_t fecstat_dup() const { return fecstat_dup_; }

  // Fields the host appends to its "stats ..." line (spec §10).
  uint32_t fecstat_rx() const { return fecstat_rx_; }
  uint32_t last_pre_ppm() const { return last_pre_ppm_; }
  uint32_t last_usable_ppm() const { return last_usable_ppm_; }
  // Cumulative received data-symbol payload bytes (wire length minus the
  // envelope/FEC header and the 2-byte symbol length). Benchmarks need this to
  // separate real payload from parity: both datagram types share one wire
  // length, so counting by size alone inflated every `--k > 0` run by 1+k/D.
  uint64_t data_payload_rx() const { return data_payload_rx_; }

  const FrameTx* tx() const { return tx_.get(); }
  const FrameRx* rx() const { return rx_.get(); }
  const FcpSettle* settle() const { return settle_.get(); }
  const FcpReporter* reporter() const { return reporter_.get(); }
  const FecStrategy* strategy() const { return strategy_.get(); }

 private:
  bool ensure_configured(int64_t now_ms);
  void configure(int64_t now_ms);
  // Oob dispatch: HELLO/HELLO_ACK magic -> handshake, else FECSTAT/KEEPALIVE.
  void on_oob(const uint8_t* payload, size_t len, int64_t now_ms);
  void sync_report_counters();

  void emit_symbol(const TxSymbol& symbol, bool bootstrap = false);
  // `bootstrap` routes the frame through the handshake envelope instead of the
  // data envelope (HELLO/HELLO_ACK only).
  void send_oob(const uint8_t* msg, size_t len, bool bootstrap = false);

  void log(const std::string& line) const {
    if (log_) {
      log_(line);
    }
  }

  SessionConfig cfg_;
  MtuLimits limits_;
  // #28: the strategy's effective config, captured at construction for the
  // trace sink (negotiated D / P' included — replaying with the configured
  // values instead would drift whenever negotiation clamps them).
  TraceConfigSnapshot trace_cfg_{};
  // R3-1: two key epochs. `hs_env_` is keyed by (PSK, salt) and carries only
  // HELLO/HELLO_ACK, for the whole life of the session -- that is what keeps a
  // retried HELLO readable after the data epoch moved on. `env_` carries
  // everything else and is rekeyed once, at handshake completion, onto the
  // nonce-bound session key.
  Envelope env_;
  Envelope hs_env_;
  // R3-1: init_bootstrap_nonce() result. A session whose handshake counter
  // start could not be drawn must not run — see Session::start().
  bool bootstrap_seed_ok_ = false;
  SendFn send_;
  DeliverFn deliver_;
  LogFn log_;
  Handshake hs_;

  // Seeded from SessionConfig::initial_srtt_ms (0 = kDefaultSrttMs), then
  // replaced by every on_rtt_sample(). Only srtt_ms_ is warmed: min_srtt_ms_
  // stays 0 until a real sample, so the §8 queue guardrail cannot fire on a
  // cached baseline that no longer describes this path.
  int64_t srtt_ms_ = kDefaultSrttMs;
  // Minimum RTT observed via on_rtt_sample(); 0 = no sample yet, so the §8
  // queue guardrail stays inactive instead of firing on the default srtt.
  int64_t min_srtt_ms_ = 0;

  std::unique_ptr<FrameTx> tx_;
  std::unique_ptr<FrameRx> rx_;
  std::unique_ptr<FcpSettle> settle_;
  std::unique_ptr<FcpReporter> reporter_;
  std::unique_ptr<FecStrategy> strategy_;
  FecstatValidator validator_;

  uint32_t auth_fail_ = 0;
  uint32_t pre_struct_fail_ = 0;
  uint64_t data_payload_rx_ = 0;
  uint32_t fecstat_dropped_ = 0;
  uint32_t fecstat_stale_ = 0;
  uint32_t fecstat_dup_ = 0;
  uint32_t fecstat_rx_ = 0;
  uint32_t last_pre_ppm_ = 0;
  uint32_t last_usable_ppm_ = 0;
  uint32_t data_tx_since_fecstat_ = 0;
  int64_t last_fecstat_ms_ = 0;
  bool fecstat_rx_pending_ = false;
  bool fecstat_missing_warned_ = false;
  uint32_t auth_fail_synced_ = 0;
  uint32_t struct_fail_synced_ = 0;
  bool nonce_exhausted_logged_ = false;
};

// Server-side salt lookup. Sessions are owned by the caller.
class SessionTable {
 public:
  // Returns false when the salt is already bound to another session.
  bool add(Session* session);
  void remove(const Session* session);
  Session* find(const uint8_t salt[Envelope::kSaltLen]) const;
  size_t size() const { return by_salt_.size(); }

 private:
  std::unordered_map<std::string, Session*> by_salt_;
};

}  // namespace fcp

#endif  // FCP_SESSION_H_
