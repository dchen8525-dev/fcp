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
  // Link warm-up (FCP_M2_PROXY.md §5), both optional and both defaulting to
  // the cold M1 behaviour. initial_srtt_ms == 0 keeps the internal 200ms, so
  // T_flush, the settlement tombstones and the §8 queue guardrail all start
  // from the peer's history instead of from the first converged sample.
  int64_t initial_srtt_ms = 0;
  // >= 1 enters the FEC state machine already ON at this k (still clamped by
  // the negotiated P' and p_max). -1 starts OFF, which cannot pick a k until
  // the first FECSTAT report lands.
  int initial_k = -1;
  // M3 byte budget (FCP_M3_CONTROL.md §2): ceiling on the interval's
  // parity_bytes/data_bytes ratio seen by the peer's FECSTAT; 0 disables.
  // Exceeding it enters the kCapped state (one parity per report down, floor
  // 1) until a report measures back under the ceiling.
  double fec_budget = 0.40;
  // #28③ (F2): pre-negotiation data cache limits (see handshake.h defaults).
  size_t handshake_cache_segments = kHandshakeMaxCachedSegments;
  size_t handshake_cache_bytes = kHandshakeMaxCachedBytes;
  // Dedup key for delivered payloads, or empty to switch the cross-set dedup
  // off. FCP-STREAM must run with an empty one: it numbers bytes, so a
  // retransmission deliberately repeats an id the peer has to see in order to
  // re-ack it, and suppressing that at this layer stalls the sender's window.
  FrameRx::SnFn sn_of = &kcp_sn_of;
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

  // Authenticates and routes one inbound datagram.
  void on_wire(const uint8_t* wire, size_t len, int64_t now_ms);

  // One KCP output segment; every segment is data (handshake traffic uses oob).
  void on_kcp_output(const uint8_t* seg, size_t len, int64_t now_ms);

  // Timer pump: handshake retries, T_flush, settlement, FECSTAT cadence.
  void on_tick(int64_t now_ms);

  void on_rtt_sample(int64_t srtt_ms);

  bool established() const { return hs_.established(); }
  HandshakeState state() const { return hs_.state(); }
  HandshakeError error() const { return hs_.error(); }
  const NegotiatedParams& params() const { return hs_.params(); }
  SessionMode mode() const { return hs_.params().mode; }
  uint8_t k() const { return strategy_ ? strategy_->k() : 0; }

  const uint8_t* salt() const { return cfg_.salt; }
  const MtuLimits& mtu_limits() const { return limits_; }
  bool config_valid() const { return limits_.valid; }

  size_t cached_segments() const { return hs_.cached_segments(); }
  int64_t srtt_ms() const { return srtt_ms_; }

  uint32_t auth_fail() const { return auth_fail_; }
  uint32_t struct_fail() const { return pre_struct_fail_ + (rx_ ? rx_->struct_fail() : 0); }
  uint32_t fecstat_dropped() const { return fecstat_dropped_; }
  uint32_t fecstat_stale() const { return fecstat_stale_; }
  // #28⑤ (F3): second copies of double-sent FECSTATs, ignored via the
  // monotonic key. Kept apart from stale/dropped so diagnostics stay clean.
  uint32_t fecstat_dup() const { return fecstat_dup_; }

  // Fields the host appends to its "stats ..." line (spec §10).
  uint32_t fecstat_rx() const { return fecstat_rx_; }
  uint32_t last_pre_ppm() const { return last_pre_ppm_; }
  uint32_t last_usable_ppm() const { return last_usable_ppm_; }

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

  void emit_symbol(const TxSymbol& symbol);
  void send_oob(const uint8_t* msg, size_t len);

  void log(const std::string& line) const {
    if (log_) {
      log_(line);
    }
  }

  SessionConfig cfg_;
  MtuLimits limits_;
  Envelope env_;
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
