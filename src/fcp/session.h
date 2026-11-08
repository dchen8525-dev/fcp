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

#include "fcp/defaults.h"
#include "fcp/envelope.h"
#include "fcp/fecstat.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/handshake.h"
#include "fcp/hdr.h"
#include "fcp/pmtu.h"
#include "fcp/reporter.h"
#include "fcp/settle.h"
#include "fcp/strategy.h"
#include "fcp/trace.h"

namespace fcp {

// Poll interval for T_flush, settlement and the FECSTAT cadence.
constexpr int64_t kSessionTickMs = 25;

// srtt assumed until the first RTT sample arrives: the value lives in
// defaults.h (单一定义，对抗分析第九轮), alongside the other collected
// operator-default constants this header used to duplicate.

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
  uint8_t d = kDefaultD;
  uint8_t p = kDefaultP;
  uint8_t p_max = kDefaultPmax;
  uint16_t mtu = kDefaultMtu;
  size_t ip_hdr_len = kDefaultIpHeaderLen;
  // PMTUD (pmtu.h): probe upward from `mtu` to at most pmtu_max_mtu. Off by
  // default at the library level -- tests and embedders get exactly the wire
  // they asked for -- while the proxy engine turns it on. The capability is
  // negotiated, so a peer that did not advertise kCapPmtud is never probed.
  bool pmtud = false;
  uint16_t pmtu_max_mtu = kDefaultPmtuMaxMtu;
  int pinned_k = -1;  // --fec-parity-pinned; >= 0 bypasses the strategy
  // Link warm-up (M2代理设计.md §5), both optional and both defaulting to
  // the cold M1 behaviour. initial_srtt_ms == 0 keeps the internal 200ms, so
  // T_flush, the settlement tombstones and the §8 queue guardrail all start
  // from the peer's history instead of from the first converged sample.
  // It also seeds the handshake's first backoff gap to clamp(2*srtt, 250,
  // 8000) ms (#76): the prewarm prior is the same link knowledge, so a
  // known-fast path skips the 250ms base gap and a known-slow one retries
  // patiently instead of dying early.
  int64_t initial_srtt_ms = 0;
  // >= 1 enters the FEC state machine already ON at this k (still clamped by
  // the negotiated P' and p_max). -1 starts OFF, which cannot pick a k until
  // the first FECSTAT report lands.
  int initial_k = -1;
  // M3 byte budget (M3控制设计.md §2): ceiling on the interval's
  // parity_bytes/data_bytes ratio seen by the peer's FECSTAT; 0 disables.
  // Exceeding it enters the kCapped state (one parity per report down, floor
  // 1) until a report measures back under the ceiling.
  double fec_budget = kDefaultFecBudget;
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
  // #78: offer FCP-STREAM ACK v2 through the handshake TLV extension. On by
  // default; a peer that predates the TLV bit costs one 750ms downgrade probe
  // (two unanswered HELLOs) and then negotiates without it, so mixed-version
  // deployments pay that once per connection while the roll-out crosses.
  bool stream_ack_v2 = true;
  // #84: envelope key update (epoch rolling) — offered to TLV peers only; a
  // v7 peer keeps the single-key 2^32-packet lifetime with its disconnect
  // semantics. With rolling on, one key never seals more than kEpochSpan
  // packets and the session never hits the counter ceiling.
  bool key_update = true;
  // #87 (H8): the peer prewarm ticket rides the same TLV block; on by default
  // (it costs 2 + 11 bytes in the HELLO/ACK, both directions).
  bool prewarm_tlv = true;
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

  // Why start() refused. A refusal must reach the caller: logging it and
  // returning as if the session had begun left an unstarted session that an
  // inbound HELLO could still establish (B-04).
  enum class StartStatus : uint8_t {
    kOk = 0,
    kNoEntropy,  // the OS CSPRNG could not draw the handshake nonce start
    kBadConfig,  // MTU / caps cannot carry a data symbol or a FECSTAT oob
  };
  StartStatus start(int64_t now_ms);

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

  // `now_ms` drives the expiry of min_srtt_ms_ (0 = caller has no clock, in
  // which case the baseline simply stays put -- tests only).
  void on_rtt_sample(int64_t srtt_ms, int64_t now_ms = 0);

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
  // #87 (H8): the local link profile this end wants the peer to see, encoded
  // as a kTlvTypePrewarm TLV which the peer feeds to its own prewarm cache.
  // Must be called before start(): the local TLV block is assembled there, so
  // a ticket staged afterwards never leaves. Ignored once the handshake is
  // under way rather than pretending it went out.
  void set_prewarm_tlv(const std::vector<uint8_t>& value) {
    if (hs_.state() != HandshakeState::kIdle) {
      return;
    }
    prewarm_tlv_ = value;
  }

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
  // #87 (H8) the negotiated result the host feeds into StreamConfig::ack_v2 --
  // both ends had to offer the capability (Handshake::tlv_agreed).
  bool stream_ack_v2() const {
    return cfg_.stream_ack_v2 && hs_.tlv_agreed(kTlvTypeAckV2);
  }
  // #87 (H8): the peer's prewarm ticket from the handshake TLV, if any (empty
  // when the peer sent none or did not speak TLV).
  std::vector<uint8_t> peer_prewarm_tlv() const {
    if (!hs_.tlv_negotiated()) {
      return {};
    }
    for (const auto& t : hs_.peer_tlvs()) {
      if (t.type == kTlvTypePrewarm) {
        return t.value;
      }
    }
    return {};
  }

  // PMTUD: the proven send MTU (starts at the configured value, climbs on an
  // ack, and steps below the configured floor only on kernel EMSGSIZE
  // evidence, see on_kernel_send_too_big) and the payload size the stream
  // layer must arm itself with. The host polls payload_max() and re-arms the
  // stream when it moves, either way.
  uint16_t path_mtu() const { return pmtu_mtu_; }
  size_t payload_max() const { return limits_.payload_max; }
  // The kernel refused an outbound datagram of udp_len bytes with EMSGSIZE:
  // its ICMP-learned path-MTU cache sits below the refused IP size, so every
  // datagram of that size dies inside send() without reaching the wire.
  // Authoritative, immediate evidence -- lower the send bound at once (see
  // session.cc) instead of waiting out the reachability watchdog. Safe to
  // call at any rate; each call descends at most one kPmtuMaxDiffMtu step.
  void on_kernel_send_too_big(size_t udp_len, int64_t now_ms);
  // Largest symbol the receive side has proven (the peer's probes, capped by
  // our own ceiling). Diagnostics and tests: the host never polls this for
  // sizing, because only the sender learns the bound from the peer's ack.
  size_t recv_symbol_max() const { return recv_symbol_max_; }
  uint32_t pmtu_probes_sent() const { return pmtu_probes_sent_; }
  uint32_t pmtu_probes_acked() const { return pmtu_probes_acked_; }
  uint32_t pmtu_probes_lost() const { return pmtu_probes_lost_; }
  // True once the search interval has narrowed inside kPmtuMaxDiffMtu: no
  // further probing this session (the size is within 20 bytes of the path's
  // ceiling on the evidence available). Diagnostics and tests.
  bool pmtu_search_done() const { return pmtu_done(); }

  size_t cached_segments() const { return hs_.cached_segments(); }
  int64_t srtt_ms() const { return srtt_ms_; }

  uint32_t auth_fail() const { return auth_fail_; }
  // Amplification-bound drops (see the member comment): outbound datagrams
  // suppressed by the 3x rule before the handshake confirmed. Zero on every
  // legitimate deployment; non-zero means the peer (or the path) kept
  // provoking replies without ever completing a handshake.
  uint32_t amp_limited_drops() const { return amp_limited_drops_; }
  // Tests only: the liveness clock's raw stamp (0 = no authenticated inbound
  // datagram ever).
  int64_t last_peer_in_ms() const { return last_peer_in_ms_; }
  // H5 (#85): session-level liveness. True once the peer has been
  // authenticated-traffic silent for kPeerAliveGraceMs (three keepalive probe
  // periods) on an established session; the keepalive probe doubles as the
  // ping, so the answer window is the probe period itself. The host polls
  // this from its tick and tears the session down — deterministic dead-peer
  // discovery instead of waiting out the stream idle clock.
  // H6 (#86): a stateless reset (the peer holds the PSK but lost the session)
  // sets it immediately.
  bool peer_dead() const { return peer_dead_ || reset_by_peer_; }
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
  // Raw loss of our outbound direction as the peer reported it in its last
  // FECSTAT (expected data symbols and those that never arrived, before FEC
  // recovery). The proxy aggregates these into loss_out_* on the stats line.
  uint32_t last_peer_expected() const { return last_peer_expected_; }
  uint32_t last_peer_lost() const { return last_peer_lost_; }
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
  // Returns true when the payload was a handshake message and has been fed to
  // hs_; false means "not ours", so on_oob can fall through to FECSTAT.
  bool dispatch_handshake(const uint8_t* payload, size_t len, int64_t now_ms);
  // Validate -> feed the strategy -> record trace -> log (session_log.cc).
  void handle_fecstat(const uint8_t* payload, size_t len, int64_t now_ms);
  void sync_report_counters();

  // The two key epochs of on_wire() after authentication: HELLO/HELLO_ACK only
  // under the bootstrap key, everything else through the frame layer once the
  // codec exists.
  bool on_wire_bootstrap(const std::vector<uint8_t>& plain, int64_t now_ms);
  bool on_wire_data(const std::vector<uint8_t>& plain, size_t wire_len, int64_t now_ms);

  // PMTUD (pmtu.h): the binary search over [min, lost-ledger max], the probe/
  // ack codec, and the two bounds it moves. All of it is inert until
  // configure() sees the peer's capability. Structure mirrors quic-go's
  // mtuFinder one-to-one; see the pmtu.h header for the mapping.
  void pmtu_tick(int64_t now_ms);
  void pmtu_send(uint8_t type, uint16_t mtu, uint32_t token);
  bool pmtu_handle(const std::vector<uint8_t>& plain, size_t wire_len, int64_t now_ms);
  bool is_pmtu_frame(const std::vector<uint8_t>& plain) const;
  uint16_t pmtu_search_max() const;  // mtuFinder.max(): ledger-derived ceiling
  bool pmtu_done() const;            // mtuFinder.done(): interval <= maxMTUDiff
  uint16_t pmtu_next_size() const;   // mtuFinder.GetPing(): candidate size
  // mtuFinder's OnLost / OnAcked for the single in-flight probe.
  void pmtu_probe_lost(int64_t now_ms);
  void pmtu_probe_acked(uint16_t size, int64_t now_ms);
  // Ascending loss-ledger insert (mtuFinder's ledger): entries shift right,
  // the largest is pushed out when the ledger is full. Shared by the probe
  // loss path and the black-hole fallback.
  void pmtu_ledger_insert(int size);
  // Raised-size black-hole fallback (fired by the reachability watchdog): the
  // send bound reverts to cfg_.mtu in-session and the dead size enters the
  // ledger, so the paced search re-probes upward beneath it.
  void pmtu_blackhole(int64_t now_ms);
  // Probe pacing: one probe every kPmtuProbeDelayRtt x srtt, and an
  // unacknowledged probe is resolved as lost after 2 x srtt (see pmtu.h).
  int64_t pmtu_spacing_ms() const;
  int64_t pmtu_resolve_ms() const;
  void pmtu_raise_recv(uint16_t mtu);
  void pmtu_raise_send(uint16_t mtu);

  void emit_symbol(const TxSymbol& symbol, bool bootstrap = false);
  // True when this datagram must not leave: the amplification bound above.
  bool amp_limited(size_t wire_len) const;
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
  // Budget for AEAD attempts on the bootstrap envelope after negotiation. That
  // key can then only carry a retried HELLO/ACK, which the handshake sends at
  // >=250ms intervals, so a handful per second is plenty. Without the budget
  // every forged datagram that failed the data envelope bought a second
  // decrypt; the window caps that at kBootstrapProbesPerSecond per session.
  int64_t bootstrap_window_ms_ = -1;
  uint32_t bootstrap_probes_ = 0;
  // Pre-establishment amplification bound (施工单 step 1 / #76, quic-go
  // sent_packet_handler.go:1156): until the handshake confirms, this session
  // may not have sent more than 3x the bytes it received. The initiator's
  // unsolicited first HELLO is exempt (the QUIC client-Initial analogue), so
  // the bound arms on the first inbound byte and lifts at establishment --
  // the ACK that completed the handshake already proved the peer decrypts
  // and reaches us. Legitimate traffic never trips it (a HELLO_ACK is 52B
  // against a 36B HELLO, ratio 1.44); what it caps is a peer that answers
  // nothing yet keeps provoking replies.
  uint64_t amp_recv_bytes_ = 0;
  uint64_t amp_sent_bytes_ = 0;
  uint32_t amp_limited_drops_ = 0;
  bool amp_limited_warned_ = false;
  SendFn send_;
  DeliverFn deliver_;
  LogFn log_;
  Handshake hs_;
  // #87 (H8): the ticket payload staged by set_prewarm_tlv() before start().
  std::vector<uint8_t> prewarm_tlv_;

  // Seeded from SessionConfig::initial_srtt_ms (0 = kDefaultSrttMs), then
  // replaced by every on_rtt_sample(). Only srtt_ms_ is warmed: min_srtt_ms_
  // stays 0 until a real sample, so the §8 queue guardrail cannot fire on a
  // cached baseline that no longer describes this path.
  int64_t srtt_ms_ = kDefaultSrttMs;
  // Minimum RTT observed via on_rtt_sample(); 0 = no sample yet, so the §8
  // queue guardrail stays inactive instead of firing on the default srtt.
  // The baseline expires after kMinSrttExpiryMs so a route change to a slower
  // path does not leave the guardrail permanently closed (srtt - min >= 40ms)
  // and the FEC rate pinned at the ceiling.
  int64_t min_srtt_ms_ = 0;
  int64_t min_srtt_stamp_ms_ = 0;

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
  uint32_t last_peer_expected_ = 0;
  uint32_t last_peer_lost_ = 0;
  uint32_t data_tx_since_fecstat_ = 0;
  int64_t last_fecstat_ms_ = 0;
  bool fecstat_rx_pending_ = false;
  bool fecstat_missing_warned_ = false;
  uint32_t auth_fail_synced_ = 0;
  uint32_t struct_fail_synced_ = 0;
  bool nonce_exhausted_logged_ = false;

  // NAT keepalive bookkeeping (session.cc on_tick): cumulative sealed-wire
  // bytes, the snapshot compared against them each tick, and the wall time
  // the mapping was last refreshed by an outbound datagram.
  uint64_t wire_out_bytes_ = 0;
  uint64_t keepalive_snapshot_ = 0;
  int64_t last_wire_out_ms_ = 0;
  // Session liveness (H5, #85): the last authenticated inbound datagram and
  // the verdict it feeds. The host tears the session down via peer_dead().
  int64_t last_peer_in_ms_ = 0;
  bool peer_dead_ = false;
  bool peer_dead_logged_ = false;
  // H6 (#86): a stateless reset arrived — the peer holds the PSK but has no
  // session for this salt (it restarted). Immediate teardown signal.
  bool reset_by_peer_ = false;

  // PMTUD state, quic-go mtuFinder shape. `pmtu_mtu_` (their `min`) is the
  // largest size the *send* direction has proven -- it starts at the
  // configured MTU and only an ack moves it. `recv_symbol_max_` is the
  // largest symbol the *receive* direction has proven. They are separate
  // because a path can be asymmetric, and each side's probe proves only its
  // own direction. `pmtu_lost_` (their `lost`) holds the sizes of resolved
  // probe losses in ascending order; the configured ceiling occupies the
  // first slot at start (= quic-go treating the maximum as the first "lost"
  // packet), an ack removes every entry <= the proven size, and
  // `pmtu_search_max()` reads the effective ceiling off the ledger.
  bool pmtud_on_ = false;          // capability negotiated (accept/answer probes)
  uint16_t pmtu_mtu_ = 0;          // proven send MTU (mtuFinder.min)
  // Black-hole fallback state (pmtu_blackhole). `pmtu_clamp_` caps what the
  // search may re-climb to until `pmtu_clamp_until_ms_`: probes keep getting
  // acked on a rate-policing path even at sizes the path drops in bulk, so
  // without the clamp the search would walk straight back into the rung the
  // watchdog just reverted. 0 = no clamp.
  uint16_t pmtu_clamp_ = 0;
  int64_t pmtu_clamp_until_ms_ = 0;
  uint16_t pmtu_max_mtu_ = 0;      // configured ceiling, clamped to the hard cap
  int16_t pmtu_lost_[kPmtuMaxLostProbes] = {-1, -1, -1};  // ascending, -1 = empty
  bool pmtu_probe_was_lost_ = false;  // last probe resolved as lost
  uint16_t pmtu_probe_mtu_ = 0;    // outstanding probe IP size, 0 = none
  // Echoed by the ack; matched back by token. One probe is in flight at a
  // time and there is no same-size resend (quic-go also does not resend the
  // PING), so the token is unique meanwhile and a late ack from an earlier
  // probe can never be mistaken for this one.
  uint32_t pmtu_token_ = 0;
  int64_t pmtu_last_probe_ms_ = -1;      // spacing origin: last probe send
  int64_t pmtu_probe_deadline_ms_ = 0;   // unacked-probe resolution deadline
  // Raised-size reachability watchdog: one WARN per episode. Reset on any
  // inbound FECSTAT (progress); re-arms if the path dies again while the
  // session is still held at the raised size.
  bool pmtu_unreachable_warned_ = false;
  size_t recv_symbol_max_ = 0;
  uint32_t pmtu_probes_sent_ = 0;
  uint32_t pmtu_probes_acked_ = 0;
  uint32_t pmtu_probes_lost_ = 0;
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
