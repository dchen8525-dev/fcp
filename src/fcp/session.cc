#include "fcp/session.h"

#include "fcp/log_level.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

#include "fcp/pmtu.h"
#include "fcp/random.h"
#include "fcp/session_log.h"
#include "fcp/wire.h"

namespace fcp {
namespace {

uint32_t ppm_of(uint64_t part, uint64_t whole) {
  if (whole == 0) {
    return 0;
  }
  return static_cast<uint32_t>(part * 1000000ull / whole);
}

// Local D/P must satisfy the same caps bounds the handshake enforces on the
// peer (§6.2), or negotiation can yield a zero-D codec.
bool local_caps_valid(const SessionConfig& cfg) {
  if (cfg.d < 1 || cfg.p > 7) {
    return false;
  }
  return static_cast<uint16_t>(cfg.d) + cfg.p <= 256;
}

// §4.6/T2: oob frames obey the same path-MTU budget as data and parity, and
// the largest defined oob is the frozen 128-byte FECSTAT. At a smaller MTU our
// reports would exceed the path and the peer's post-auth MTU guard would drop
// every inbound one, so the session must refuse the configuration instead of
// negotiating a codec whose feedback path cannot carry a single report.
bool mtu_fits_largest_oob(const SessionConfig& cfg) {
  const size_t oob_wire =
      kFecHdrLen + kFecstatLen + Envelope::kOverhead + cfg.ip_hdr_len + 8;
  return cfg.mtu >= oob_wire;
}

// R3-1: how many packets the handshake epoch may seal under the (PSK, salt)
// key. A handshake spends a handful (HELLO/HELLO_ACK plus retries); 2^16 is
// three orders of magnitude of headroom and still leaves the per-key GCM
// invocation count far below the 2^32 bound.
constexpr uint32_t kHandshakeSendBudget = 1u << 16;

// After negotiation, the bootstrap envelope is only worth trying for a retried
// HELLO/HELLO_ACK. The handshake retries at 300/600/1200ms, so this ceiling is
// far above what a real peer needs; it only stops an unauthenticated flood
// from making every failing datagram cost a second AEAD attempt.
constexpr uint32_t kBootstrapProbesPerSecond = 64;

// How long the §8 queue guardrail's min-RTT baseline stays valid. Mirrors Bbr's
// min_rtt_expiry_ms; both controllers read the same "is this a standing queue"
// question and must not disagree for long.
constexpr int64_t kMinSrttExpiryMs = 10000;

// R3-1: an all-zero configured nonce means "let the handshake draw one". The
// distinction only exists so a test can pin the value.
const uint8_t* nonce_or_null(const uint8_t nonce[16]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < 16; ++i) {
    acc |= nonce[i];
  }
  return acc == 0 ? nullptr : nonce;
}

// PMTUD (pmtu.h): how long one probe may stay unanswered before it is retried,
// and how many attempts a size gets before the ladder stops. A size that is
// one step too large is a black hole -- the datagram is dropped by the path,
// never by the peer -- so the only signal is the missing ack.
constexpr int64_t kPmtuRetryMs = 1000;
constexpr int kPmtuAttempts = 3;

uint8_t handshake_flags(const SessionConfig& cfg) {
  return static_cast<uint8_t>(kLocalFlagsM1 | (cfg.pmtud ? kCapPmtud : 0));
}

// The ceiling from configuration, floored at the configured MTU (nothing to
// probe upward to) and capped at the hard jumbo bound.
uint16_t pmtu_ceiling(const SessionConfig& cfg) {
  if (cfg.pmtu_max_mtu <= cfg.mtu) {
    return cfg.mtu;
  }
  return std::min<uint16_t>(cfg.pmtu_max_mtu, kPmtuAbsoluteMaxMtu);
}

}  // namespace

// See session.h: the default dedup key, read out of a KCP segment header.
bool kcp_sn_of(const uint8_t* payload, size_t len, uint32_t* sn) {
  if (payload == nullptr || sn == nullptr || len < kKcpSnLen) {
    return false;
  }
  *sn = get_le32(payload + kKcpSnOffset);
  return true;
}

Session::Session(const SessionConfig& config, SendFn send, DeliverFn deliver, LogFn log)
    : cfg_(config),
      limits_(compute_mtu_limits(config.mtu, config.ip_hdr_len)),
      env_(config.key, config.salt, config.send_direction, config.recv_direction),
      hs_env_(config.key, config.salt, config.send_direction, config.recv_direction),
      send_(std::move(send)),
      deliver_(std::move(deliver)),
      log_(std::move(log)),
      hs_(config.d, config.p,
          [this](const uint8_t* data, size_t len) { send_oob(data, len, true); },
          config.send_direction == Direction::kC2S ? HandshakeRole::kClient
                                                   : HandshakeRole::kServer,
          nonce_or_null(config.handshake_nonce), handshake_flags(config),
          config.handshake_cache_segments, config.handshake_cache_bytes),
      srtt_ms_(config.initial_srtt_ms > 0 ? config.initial_srtt_ms : kDefaultSrttMs),
      pmtu_mtu_(config.mtu),
      pmtu_max_mtu_(pmtu_ceiling(config)),
      recv_symbol_max_(limits_.symbol_max) {
  // R3-1: the handshake envelope keeps the (PSK, salt) key for the whole life
  // of the session, so its counter must not restart at 0. A replayed HELLO
  // makes a *new* session seal a fresh ACK under that same key; with a fixed
  // start that would be a GCM (key, IV) reuse with a known plaintext prefix.
  // A 64-bit random start makes every session's landing zone distinct, and the
  // packet budget (kHandshakeSendBudget) keeps the per-key invocation count
  // far below 2^32. A failed draw is fatal: start() refuses the session rather
  // than falling back to a predictable start.
  bootstrap_seed_ok_ = hs_env_.init_bootstrap_nonce(kHandshakeSendBudget);
}

Session::StartStatus Session::start(int64_t now_ms) {
  if (!bootstrap_seed_ok_) {
    log(std::string(kTagError) + "FCP session refused: OS CSPRNG unavailable for the handshake nonce start");
    return StartStatus::kNoEntropy;
  }
  // The Handshake constructor draws its own nonce and fails closed on a CSPRNG
  // error. A failed object must not be started either: it would sit in kIdle
  // forever while looking like a live session.
  if (hs_.state() == HandshakeState::kFailed) {
    log(std::string(kTagWarn) + "FCP handshake refused: " + handshake_error_text(hs_.error()));
    return hs_.error() == HandshakeError::kBadNonce ? StartStatus::kNoEntropy
                                                    : StartStatus::kBadConfig;
  }
  if (!limits_.valid) {
    log(std::string(kTagError) + "FCP config invalid: MTU leaves no room for a data symbol");
    return StartStatus::kBadConfig;
  }
  if (!mtu_fits_largest_oob(cfg_)) {
    log(std::string(kTagError) + "FCP config invalid: MTU too small for a 128-byte FECSTAT oob");
    return StartStatus::kBadConfig;
  }
  if (!local_caps_valid(cfg_)) {
    log(std::string(kTagError) + "FCP config invalid: local D/P out of range");
    return StartStatus::kBadConfig;
  }
  hs_.start(now_ms);
  return StartStatus::kOk;
}

bool Session::on_wire(const uint8_t* wire, size_t len, int64_t now_ms) {
  // R3-1: two key epochs reach this entry point. Data symbols use the rekeyed
  // envelope; HELLO/HELLO_ACK still travel under the (PSK, salt) bootstrap key
  // so a retried handshake stays readable after the data epoch moved on. The
  // second attempt only runs when the first fails, so a steady-state datagram
  // is authenticated exactly once.
  std::vector<uint8_t> plain;
  bool bootstrap = false;
  bool opened = env_.open(wire, len, &plain);
  if (!opened) {
    // Past negotiation the bootstrap key can only carry a retried
    // HELLO/HELLO_ACK (its ACK was lost). Probing it is budgeted because any
    // unauthenticated datagram that fails the data envelope otherwise bought a
    // second AEAD attempt: an attacker set the decrypt budget for free. Before
    // negotiation the session lives for a handshake, so every datagram is tried
    // against the bootstrap epoch too -- that is the path that reaches
    // on_oob().
    bool may_probe = true;
    if (hs_.established()) {
      if (bootstrap_window_ms_ < 0 || now_ms - bootstrap_window_ms_ >= 1000) {
        bootstrap_window_ms_ = now_ms;
        bootstrap_probes_ = 0;
      }
      may_probe = bootstrap_probes_ < kBootstrapProbesPerSecond;
      if (may_probe) {
        ++bootstrap_probes_;
      }
    }
    opened = may_probe && hs_env_.open(wire, len, &plain);
    bootstrap = opened;
  }
  if (!opened) {
    ++auth_fail_;
    sync_report_counters();
    return false;
  }

  // Authenticated but outside the MTU budget every conforming peer obeys
  // (§4.5): reject before it can inflate a set's symbol_max, the decode
  // buffers, or the pre-negotiation data cache. A PMTUD probe is the single
  // exception -- being larger than the current bound is its whole job -- and
  // pmtu_handle() re-checks it against the size the receiver actually got, so
  // an oversized frame that merely claims to be a probe cannot move anything.
  const bool pmtu_frame = is_pmtu_frame(plain);
  if (limits_.valid && plain.size() > kFecHdrLen + recv_symbol_max_ && !pmtu_frame) {
    ++pre_struct_fail_;
    sync_report_counters();
    return true;
  }

  if (bootstrap) {
    return on_wire_bootstrap(plain, now_ms);
  }

  // Handled before the frame layer: a probe that is within the current bound
  // would otherwise reach FECSTAT validation and be counted as a drop.
  if (pmtu_frame) {
    pmtu_handle(plain, len, now_ms);
    return true;
  }

  if (rx_) {
    return on_wire_data(plain, len, now_ms);
  }

  // Before negotiation only oob (including HELLO/ACK) is actionable (§6.2).
  // Inbound data cannot be framed yet (D' is not fixed) and must be dropped:
  // the handshake cache holds *our* outbound KCP segments and is replayed into
  // the transmitter, never into the receiver (erratum #4). KCP below recovers.
  FecHdr hdr{};
  if (!parse_hdr(plain.data(), plain.size(), &hdr)) {
    ++pre_struct_fail_;
    sync_report_counters();
    return true;
  }
  const uint8_t* symbol = plain.data() + kFecHdrLen;
  const size_t symbol_len = plain.size() - kFecHdrLen;

  switch (hdr_type(hdr.type_k)) {
    case SymbolType::kOob:
      on_oob(symbol, symbol_len, now_ms);
      break;
    case SymbolType::kData: {
      if (hs_.state() == HandshakeState::kFailed) {
        break;
      }
      if (symbol_len < 2) {
        ++pre_struct_fail_;
        break;
      }
      const size_t declared = static_cast<size_t>(symbol[0]) |
                              (static_cast<size_t>(symbol[1]) << 8);
      if (declared != symbol_len) {
        ++pre_struct_fail_;
        break;
      }
      // Structurally valid, but the local codec does not exist yet: drop it
      // rather than feeding it to hs_.cache_data(), which would echo the
      // peer's segment back as our own outbound data at negotiation time.
      break;
    }
    case SymbolType::kParity:
      break;  // no negotiated codec yet: drop
    default:
      // Type 3 is undefined since erratum #25; it must not be classified.
      ++pre_struct_fail_;
      break;
  }
  sync_report_counters();
  return true;
}

bool Session::on_wire_bootstrap(const std::vector<uint8_t>& plain, int64_t now_ms) {
  // Only handshake messages may travel under the bootstrap key. Anything
  // else that authenticates with it is a peer that never left the handshake
  // epoch (or a sealing bug); it is dropped rather than fed to the frame
  // layer, which would accept data the session key never protected.
  if (plain.size() < kFecHdrLen) {
    ++pre_struct_fail_;
    sync_report_counters();
    return true;
  }
  const uint8_t* symbol = plain.data() + kFecHdrLen;
  const size_t symbol_len = plain.size() - kFecHdrLen;
  FecHdr hdr{};
  if (parse_hdr(plain.data(), plain.size(), &hdr) &&
      hdr_type(hdr.type_k) == SymbolType::kOob &&
      (is_hello(symbol, symbol_len) || is_hello_ack(symbol, symbol_len))) {
    on_oob(symbol, symbol_len, now_ms);
  } else {
    // §4.1: only HELLO/HELLO_ACK may ride the bootstrap key. Anything else
    // that authenticates with it comes from a peer that never left the
    // handshake epoch (or from a sealing bug). Counting it as a structural
    // failure is what makes that visible: dropping it silently put the
    // symptom in a gap between auth_fail and struct_fail, so an operator saw
    // an idle tunnel with flat counters and no clue which side was stale.
    ++pre_struct_fail_;
  }
  sync_report_counters();
  return true;
}

bool Session::on_wire_data(const std::vector<uint8_t>& plain, size_t wire_len,
                           int64_t now_ms) {
  FecHdr hdr{};
  if (parse_hdr(plain.data(), plain.size(), &hdr)) {
    const SymbolType type = hdr_type(hdr.type_k);
    // Reuse the shared constant from frame_tx.h instead of shadowing it:
    // compute_mtu_limits() derives payload_max from the same value, so the two
    // must never drift apart.
    if (type == SymbolType::kData) {
      data_payload_rx_ += wire_len > kDataWireOverhead ? wire_len - kDataWireOverhead : 0;
      if (reporter_ != nullptr) {
        reporter_->add_data_bytes(static_cast<uint32_t>(wire_len));
      }
    } else if (type == SymbolType::kParity && reporter_ != nullptr) {
      reporter_->add_parity_bytes(static_cast<uint32_t>(wire_len));
    }
  }
  rx_->on_datagram(plain.data(), plain.size(), now_ms);
  sync_report_counters();
  return true;
}

void Session::on_kcp_output(const uint8_t* seg, size_t len, int64_t now_ms) {
  if (hs_.state() == HandshakeState::kFailed) {
    return;
  }
  // Erratum #25: every KCP output segment is data; handshake traffic travels
  // as oob frames sent by the handshake module directly.
  if (!ensure_configured(now_ms)) {
    if (seg == nullptr && len != 0) {
      return;
    }
    std::vector<uint8_t> copy;
    if (len != 0) {
      copy.assign(seg, seg + len);
    }
    if (!hs_.cache_data(std::move(copy)) &&
        hs_.state() == HandshakeState::kFailed) {
      log(std::string(kTagWarn) + "FEC handshake failed: " + handshake_error_text(hs_.error()));
    }
    return;
  }
  tx_->on_kcp_output(seg, len, now_ms);
}

void Session::on_tick(int64_t now_ms) {
  const HandshakeState before = hs_.state();
  hs_.on_tick(now_ms);
  if (before != HandshakeState::kFailed && hs_.state() == HandshakeState::kFailed) {
    log(std::string(kTagWarn) + "FEC handshake failed: " + handshake_error_text(hs_.error()));
  }
  if (!ensure_configured(now_ms)) {
    return;
  }
  tx_->on_tick(now_ms);
  pmtu_tick(now_ms);
  settle_->tick(now_ms, srtt_ms_);
  reporter_->on_tick(now_ms);
  sync_report_counters();

  // §8 "无报告": three expected report periods without an inbound FECSTAT mean
  // the feedback path is dead. The peer reports every 2s only while it accounts
  // >= 256 packets per interval; below ~128 pkt/s it falls back to the 60s
  // forced cadence. Pick the period from our own send rate since the last
  // report, so slow flows do not trip a false alarm. k is already frozen
  // because no reports drive it. Warn once.
  if (fecstat_rx_pending_) {
    fecstat_rx_pending_ = false;
    last_fecstat_ms_ = now_ms;
    data_tx_since_fecstat_ = 0;
  }
  const int64_t since_fecstat_ms = now_ms - last_fecstat_ms_;
  if (!fecstat_missing_warned_ && !strategy_->pinned() && data_tx_since_fecstat_ > 0 &&
      since_fecstat_ms > 0) {
    const bool two_second_cadence =
        static_cast<uint64_t>(data_tx_since_fecstat_) * kFecstatMinIntervalMs >=
        static_cast<uint64_t>(kFecstatMinSamples) * static_cast<uint64_t>(since_fecstat_ms);
    const int64_t period =
        two_second_cadence ? kFecstatMinIntervalMs : kFecstatMaxIntervalMs;
    if (since_fecstat_ms >= 3 * period) {
      fecstat_missing_warned_ = true;
      char line[160];
      std::snprintf(line, sizeof(line),
                    "FEC WARNING: no FECSTAT for 3 report periods, keeping k=%u",
                    strategy_->k());
      log(std::string(kTagWarn) + line);
    }
  }
}

// §14.6 (#30): see session.h. A teardown report rides the peer's tombstone
// window if its own session already died.
void Session::flush_report(int64_t now_ms) {
  if (reporter_) {
    reporter_->flush(now_ms);
  }
}

void Session::on_rtt_sample(int64_t srtt_ms, int64_t now_ms) {
  if (srtt_ms <= 0) {
    return;
  }
  srtt_ms_ = srtt_ms;
  // Baseline for the §8 queue guardrail is the minimum *observed* RTT. A fixed
  // initial value would make srtt - min_rtt >= 40ms permanent on any link
  // whose RTT exceeds it (satellite/cross-continental), silently pinning k.
  // A route change has the same effect from the other side: a floor from a
  // faster path keeps the guardrail closed forever, so it expires after
  // kMinSrttExpiryMs and follows the current path again.
  const bool expired =
      min_srtt_ms_ > 0 && now_ms > 0 && now_ms - min_srtt_stamp_ms_ >= kMinSrttExpiryMs;
  if (min_srtt_ms_ <= 0 || srtt_ms < min_srtt_ms_ || expired) {
    min_srtt_ms_ = srtt_ms;
    if (now_ms > 0) {
      min_srtt_stamp_ms_ = now_ms;
    }
  }
  if (tx_) {
    tx_->set_srtt_ms(srtt_ms);
  }
}

bool Session::ensure_configured(int64_t now_ms) {
  if (tx_) {
    return true;
  }
  if (!hs_.established() || !limits_.valid || !mtu_fits_largest_oob(cfg_) ||
      !local_caps_valid(cfg_)) {
    return false;
  }
  configure(now_ms);
  return true;
}

void Session::configure(int64_t now_ms) {
  const NegotiatedParams np = hs_.params();

  // R3-1: from here on the data epoch is bound to both handshake draws. The
  // rekey resets the counters, which is only sound because the key changes
  // with them; the bootstrap envelope keeps running untouched.
  uint8_t session_key[16];
  derive_session_key_v7(cfg_.key, cfg_.salt, hs_.client_nonce(), hs_.server_nonce(),
                        session_key);
  env_.rekey(session_key);

  tx_ = std::make_unique<FrameTx>(np.d, limits_,
                                  [this](const TxSymbol& symbol) { emit_symbol(symbol); });
  tx_->set_srtt_ms(srtt_ms_);

  rx_ = std::make_unique<FrameRx>(
      np.d, np.p,
      [this](const uint8_t* payload, size_t len) {
        if (deliver_) {
          deliver_(payload, len);
        }
      },
      [this](const uint8_t* payload, size_t len, int64_t now_ms) { on_oob(payload, len, now_ms); }, cfg_.sn_of);

  settle_ = std::make_unique<FcpSettle>(np.d);
  settle_->attach(rx_.get());
  settle_->set_observer([this](RxEvent event, uint32_t repair_ms) {
    if (reporter_ != nullptr &&
        (event == RxEvent::kRecovered || event == RxEvent::kRecoveredLate)) {
      reporter_->record_repair_latency(repair_ms);
    }
  });

  reporter_ = std::make_unique<FcpReporter>(
      settle_.get(), [this](const uint8_t* packet, size_t len) {
        // 与 send_oob() 同一构造（§4.7 oob 头 set_id = index = 0）：不再
        // 手搭第二份帧组装（对抗分析第九轮——两份 §4.7 注释曾各自跟踪自己）。
        send_oob(packet, len);
      });
  reporter_->set_salt(cfg_.salt);

  const bool stats = np.mode == SessionMode::kFramedStats;
  // A pinned k can never exceed the negotiated P'; the operator flag is only a
  // request, negotiation wins.
  int pinned = stats ? 0 : cfg_.pinned_k;
  if (pinned > static_cast<int>(np.p)) {
    pinned = static_cast<int>(np.p);
  }
  FecStrategyConfig strategy_config;
  strategy_config.d = np.d;
  // k <= P' (§2): exceeding the negotiated parity budget pushes the last
  // parity index to n + P' >= S, which the peer must reject as malformed.
  strategy_config.p_max =
      stats ? 0 : std::min<uint8_t>(cfg_.p_max, np.p);
  strategy_config.pinned_k = pinned;
  // FecStrategy clamps this against p_max_ the same way it clamps pinned_k, and
  // p_max_ is already min(p_max, P') -- 0 in stats mode, where the clamp drops
  // the seed and the machine stays OFF.
  strategy_config.initial_k = cfg_.initial_k;
  strategy_config.budget_ratio = cfg_.fec_budget;
  strategy_ = std::make_unique<FecStrategy>(strategy_config);
  tx_->set_k(strategy_->k());
  trace_cfg_ = TraceConfigSnapshot{np.d, strategy_config.p_max,
                                   strategy_->target_recovery(), cfg_.fec_budget,
                                   cfg_.initial_k, pinned};

  // PMTUD: only when both ends advertised the capability and there is room
  // above the configured MTU. The first tick (not now) starts the ladder --
  // probing from inside configure() would race the peer's own setup.
  pmtud_on_ = cfg_.pmtud && (np.flags & kCapPmtud) != 0 && pmtu_max_mtu_ > cfg_.mtu;
  if (pmtud_on_) {
    pmtu_next_ms_ = now_ms;
  }

  sync_report_counters();

  char line[192];
  std::snprintf(line, sizeof(line),
                "FCP v6 negotiated: data=%u parity=%u pmax=%u flags=framed,stats (peer V3)",
                np.d, np.p, cfg_.p_max);
  log(std::string(kTagInfo) + line);
  if (strategy_config.pinned_k > 0) {
    std::snprintf(line, sizeof(line), "FEC pinned: k=%d (operator)", strategy_config.pinned_k);
    log(std::string(kTagInfo) + line);
  } else if (strategy_->initial_k() > 0) {
    // The value shown is post-clamp: what the session actually started with.
    std::snprintf(line, sizeof(line), "FEC warmed: k=%d (prewarm)", strategy_->initial_k());
    log(std::string(kTagInfo) + line);
  }

  reporter_->on_tick(now_ms);  // first tick only sets the interval baseline
  last_fecstat_ms_ = now_ms;
  for (auto& seg : hs_.take_cached_data()) {
    tx_->on_kcp_output(seg.data(), seg.size(), now_ms);
  }
}

void Session::on_oob(const uint8_t* payload, size_t len, int64_t now_ms) {
  if (dispatch_handshake(payload, len, now_ms)) {
    return;
  }
  handle_fecstat(payload, len, now_ms);
}

bool Session::dispatch_handshake(const uint8_t* payload, size_t len, int64_t now_ms) {
  // Erratum #25: HELLO/HELLO_ACK arrive as oob frames and are dispatched by
  // their 16-byte magic before the FECSTAT validator ever sees them. The length
  // gate must be the *shortest* handshake message: HELLO (36) is shorter than
  // HELLO_ACK (52) since R3-1 added the nonce pair, and gating on the ACK size
  // silently dropped every HELLO that arrived on the data-envelope path.
  if (len < kHelloLen || payload == nullptr ||
      (!is_hello(payload, len) && !is_hello_ack(payload, len))) {
    return false;
  }
  if (hs_.on_oob(payload, len) == HandshakeStatus::kProtocolFailure) {
    log(std::string(kTagWarn) + "FEC handshake failed: " + handshake_error_text(hs_.error()));
  }
  ensure_configured(now_ms);
  return true;
}

void Session::handle_fecstat(const uint8_t* payload, size_t len, int64_t now_ms) {
  FecstatPacket stat{};
  const FecstatStatus status = validator_.validate(payload, len, cfg_.salt, &stat);
  if (status == FecstatStatus::kDuplicate) {
    // #28⑤ (F3): second copy of a double-sent report. Counted separately so
    // `stale` keeps meaning "genuinely behind"; nothing is logged — this is
    // the healthy path whenever the first copy arrived.
    ++fecstat_dup_;
    return;
  }
  if (status != FecstatStatus::kOk) {
    ++fecstat_dropped_;
    if (status == FecstatStatus::kStale) {
      ++fecstat_stale_;
    }
    log_fecstat_dropped(log_, status);
    return;
  }
  if (strategy_ == nullptr) {
    return;  // peer reports its view of our traffic; meaningless before setup
  }
  ++fecstat_rx_;
  fecstat_rx_pending_ = true;

  const bool queued =
      min_srtt_ms_ > 0 && srtt_ms_ - min_srtt_ms_ >= kQueueGuardrailGapMs;
  const FecState before = strategy_->state();
  strategy_->on_report(stat, queued);
  if (tx_) {
    tx_->set_k(strategy_->k());
  }
  // Keep the raw numbers behind loss_out_* even when the sample gates below
  // suppress the log line: the desktop speed test samples this between stats
  // ticks and a small but valid report is still better than a stale zero.
  last_peer_expected_ = stat.data_expected;
  last_peer_lost_ = stat.data_expected > stat.data_rx_orig
                        ? stat.data_expected - stat.data_rx_orig
                        : 0;
  if (cfg_.trace) {
    TraceEntry entry;
    entry.now_ms = now_ms;
    entry.window_queued = queued;
    entry.stat = stat;
    entry.snapshot = trace_cfg_;
    entry.k_after = strategy_->k();
    entry.state_after = strategy_->state();
    entry.last_loss = strategy_->last_loss();
    cfg_.trace(entry);
  }
  // Same measure the strategy acted on (§2); for the budget log lines only.
  const double ratio = stat.data_bytes_rx > 0
                           ? static_cast<double>(stat.parity_bytes_rx) /
                                 static_cast<double>(stat.data_bytes_rx)
                           : 0.0;

  // The two sample gates run after the strategy was fed on purpose: a report
  // that is too lossy to trust still moves the machine off the raw numbers,
  // and only the *log* line is suppressed. 同 strategy 样本门一阈值：
  // kUntrustedKUnknownPct 是唯一定义。
  if (k_unknown_untrusted(stat.sets_expected, stat.sets_k_unknown)) {
    log_fecstat_untrusted(log_, stat);
    return;
  }
  if (stat.data_expected < kMinSamplePackets) {
    log_fecstat_too_small(log_, stat);
    return;
  }

  const int64_t lost_signed = static_cast<int64_t>(stat.data_expected) -
                              stat.data_rx_orig - stat.data_recovered_dl -
                              stat.data_late_rx;
  const uint32_t pre = ppm_of(stat.data_expected > stat.data_rx_orig
                                  ? stat.data_expected - stat.data_rx_orig
                                  : 0,
                              stat.data_expected);
  // Sum in 64 bits: both fields are peer-supplied and the 32-bit sum wraps.
  // With data_rx_orig = 0x80000000 and data_recovered_dl = 0x80000001 the sum
  // is 1, so the old test claimed 299 usable bytes out of 300 while the peer
  // had in fact delivered nothing -- a self-contradicting `pre=0ppm
  // usable=996666ppm` log line and a poisoned last_usable_ppm_.
  const uint64_t rx_total =
      static_cast<uint64_t>(stat.data_rx_orig) + stat.data_recovered_dl;
  const uint32_t usable_part =
      stat.data_expected > rx_total ? stat.data_expected - static_cast<uint32_t>(rx_total) : 0;
  FecSampleRates rates;
  rates.lost = lost_signed > 0 ? static_cast<uint32_t>(lost_signed) : 0;
  rates.pre_ppm = pre;
  rates.usable_ppm = ppm_of(usable_part, stat.data_expected);
  last_pre_ppm_ = rates.pre_ppm;
  last_usable_ppm_ = rates.usable_ppm;

  log_fecstat_report(log_, stat, rates, strategy_->k(), strategy_->state());

  // M3 R(k) correction (M3控制设计.md §1.2): peer's ledger lifted the
  // loss input; own line keeps the §10 format untouched.
  if (strategy_->ledger_active()) {
    FecLedgerView view;
    view.k = ledger_k(stat);
    view.p_eff = strategy_->last_p_eff();
    view.loss = strategy_->last_loss();
    view.reports = strategy_->ledger_reports();
    view.skipped = strategy_->ledger_skipped();
    log_fec_ledger(log_, stat, view);
  }

  // M3 byte budget transitions (§2), greppable for WAN calibration.
  log_fec_budget_transitions(log_, before, strategy_->state(), ratio, cfg_.fec_budget,
                             strategy_->k(), strategy_->last_loss());
}

// ---- PMTUD (pmtu.h) ----

bool Session::is_pmtu_frame(const std::vector<uint8_t>& plain) const {
  if (!pmtud_on_ || plain.size() < kFecHdrLen + kPmtuHeaderLen) {
    return false;
  }
  FecHdr hdr{};
  if (!parse_hdr(plain.data(), plain.size(), &hdr) ||
      hdr_type(hdr.type_k) != SymbolType::kOob) {
    return false;
  }
  PmtuMessage msg;
  return pmtu_parse(plain.data() + kFecHdrLen, plain.size() - kFecHdrLen, &msg);
}

uint16_t Session::pmtu_next_candidate() const {
  if (pmtu_mtu_ >= pmtu_max_mtu_) {
    return 0;
  }
  // Two rungs cover the useful cases without spending RTTs on sizes nothing
  // uses: the standard Ethernet size first, then the configured ceiling
  // (jumbo is a LAN property and has to be asked for).
  if (pmtu_mtu_ < 1500 && pmtu_max_mtu_ >= 1500) {
    return 1500;
  }
  return pmtu_max_mtu_;
}

void Session::pmtu_tick(int64_t now_ms) {
  if (!pmtud_on_ || pmtu_next_ms_ < 0 || now_ms < pmtu_next_ms_) {
    return;
  }
  if (pmtu_probe_mtu_ != 0) {
    pmtu_probe_mtu_ = 0;
    if (++pmtu_attempts_ >= kPmtuAttempts) {
      ++pmtu_probes_lost_;
      pmtu_next_ms_ = -1;
      char line[112];
      std::snprintf(line, sizeof(line),
                    "FCP PMTUD: %u-byte path did not answer, staying at %u",
                    static_cast<unsigned>(pmtu_max_mtu_),
                    static_cast<unsigned>(pmtu_mtu_));
      log(std::string(kTagWarn) + line);
      return;
    }
  }
  const uint16_t candidate = pmtu_next_candidate();
  if (candidate == 0) {
    pmtu_next_ms_ = -1;
    return;
  }
  // The token ties the ack to this probe. The ack itself is authenticated, so
  // the token's job is to reject a late ack from an earlier rung and any
  // reordering inside the session, not an off-path attacker.
  uint8_t token_bytes[4] = {};
  if (!random_bytes(token_bytes, sizeof(token_bytes))) {
    pmtu_next_ms_ = -1;
    return;
  }
  pmtu_token_ = get_le32(token_bytes);
  pmtu_probe_mtu_ = candidate;
  pmtu_send(kPmtuProbe, candidate, pmtu_token_);
  ++pmtu_probes_sent_;
  pmtu_next_ms_ = now_ms + kPmtuRetryMs;
}

void Session::pmtu_send(uint8_t type, uint16_t mtu, uint32_t token) {
  const size_t len =
      type == kPmtuProbe ? pmtu_probe_len(mtu, cfg_.ip_hdr_len) : kPmtuHeaderLen;
  if (len == 0) {
    return;
  }
  std::vector<uint8_t> msg(len, 0);
  pmtu_build(PmtuMessage{type, token, mtu}, msg.data(), msg.size());
  send_oob(msg.data(), msg.size());
}

bool Session::pmtu_handle(const std::vector<uint8_t>& plain, size_t wire_len,
                          int64_t now_ms) {
  PmtuMessage msg;
  if (!pmtu_parse(plain.data() + kFecHdrLen, plain.size() - kFecHdrLen, &msg)) {
    return false;
  }
  // Above the configured base and below the local ceiling is the only range
  // that can move anything; everything else is a stale or misconfigured probe
  // and is consumed silently. The ceiling is ours, not the peer's: a peer
  // running --pmtu-max=9000 against a receiver configured for 1500 must not be
  // able to inflate our receive bound (an 8 KB symbol times D per set times 256
  // sets is real memory, and the probe may simply have crossed a path that
  // accepts jumbo in one direction).
  if (msg.mtu <= cfg_.mtu || msg.mtu > pmtu_max_mtu_) {
    return true;
  }
  if (msg.type == kPmtuProbe) {
    // The ack exists to say "this datagram arrived at the size it aimed for".
    // The IP length is the outer bound on the way in, so a probe cannot be
    // padded up by the path -- only truncated or dropped. Compare the envelope
    // length actually received, not the message's own claim. (The ack itself
    // is deliberately small, so only probes are size-checked.)
    const size_t expect_wire = pmtu_udp_payload(msg.mtu, cfg_.ip_hdr_len);
    if (wire_len != expect_wire) {
      ++pre_struct_fail_;
      sync_report_counters();
      return true;
    }
    // Raise the receive bound first: the ack below is what authorizes the peer
    // to send symbols this large.
    pmtu_raise_recv(msg.mtu);
    pmtu_send(kPmtuAck, msg.mtu, msg.token);
  } else if (pmtu_probe_mtu_ == msg.mtu) {
    // The rung is identified by its size, not the token: the ladder is strictly
    // increasing, so an ack carrying the outstanding size can only belong to
    // it. Requiring the token as well broke exactly the slow paths PMTUD is
    // meant to help -- with a 1.2 s RTT the first ack arrives after the next
    // retry already replaced the token, so every ack was ignored and the rung
    // gave up after three tries even though the path had answered each probe.
    pmtu_probe_mtu_ = 0;
    pmtu_attempts_ = 0;
    ++pmtu_probes_acked_;
    pmtu_raise_send(msg.mtu);
    pmtu_next_ms_ = pmtu_next_candidate() == 0 ? -1 : now_ms + kPmtuRetryMs;
  }
  return true;
}

void Session::pmtu_raise_recv(uint16_t mtu) {
  const size_t wire = pmtu_udp_payload(mtu, cfg_.ip_hdr_len);
  if (wire <= Envelope::kOverhead + kFecHdrLen) {
    return;
  }
  const size_t symbol = wire - Envelope::kOverhead - kFecHdrLen;
  recv_symbol_max_ = std::max(recv_symbol_max_, symbol);
}

void Session::pmtu_raise_send(uint16_t mtu) {
  const MtuLimits next = compute_mtu_limits(mtu, cfg_.ip_hdr_len);
  if (!next.valid || next.payload_max <= limits_.payload_max) {
    return;
  }
  const uint16_t before = pmtu_mtu_;
  limits_ = next;
  pmtu_mtu_ = mtu;
  if (tx_) {
    tx_->raise_limits(next);
  }
  char line[96];
  std::snprintf(line, sizeof(line), "FCP PMTUD: path MTU %u -> %u",
                static_cast<unsigned>(before), static_cast<unsigned>(mtu));
  log(std::string(kTagDebug) + line);
}

void Session::sync_report_counters() {
  if (reporter_ == nullptr) {
    return;
  }
  if (auth_fail_ != auth_fail_synced_) {
    reporter_->add_auth_fail(auth_fail_ - auth_fail_synced_);
    auth_fail_synced_ = auth_fail_;
  }
  const uint32_t total = struct_fail();
  if (total != struct_fail_synced_) {
    reporter_->add_struct_fail(total - struct_fail_synced_);
    struct_fail_synced_ = total;
  }
}

void Session::emit_symbol(const TxSymbol& symbol, bool bootstrap) {
  if (!send_) {
    return;
  }
  if (hdr_type(symbol.type_k) == SymbolType::kData &&
      data_tx_since_fecstat_ < 0xFFFFFFFFu) {
    ++data_tx_since_fecstat_;
  }
  std::vector<uint8_t> plain(kFecHdrLen + symbol.symbol.size());
  pack_hdr(FecHdr{symbol.set_id, symbol.index, symbol.type_k}, plain.data());
  if (!symbol.symbol.empty()) {
    std::memcpy(plain.data() + kFecHdrLen, symbol.symbol.data(), symbol.symbol.size());
  }
  Envelope& env = bootstrap ? hs_env_ : env_;
  std::vector<uint8_t> wire;
  if (!env.seal(plain.data(), plain.size(), &wire)) {
    if (!nonce_exhausted_logged_) {
      nonce_exhausted_logged_ = true;
      log(std::string(kTagError) + "FCP session exhausted nonce space");
    }
    return;
  }
  send_(wire.data(), wire.size(), hdr_type(symbol.type_k));
}

void Session::send_oob(const uint8_t* msg, size_t len, bool bootstrap) {
  if (msg == nullptr && len != 0) {
    return;
  }
  TxSymbol symbol;
  symbol.set_id = 0;  // §4.7: oob headers carry set_id = 0, index = 0
  symbol.index = 0;
  symbol.type_k = pack_type_k(0, 0, static_cast<uint8_t>(SymbolType::kOob));
  if (len != 0) {
    symbol.symbol.assign(msg, msg + len);
  }
  emit_symbol(symbol, bootstrap);
}

bool SessionTable::add(Session* session) {
  if (session == nullptr) {
    return false;
  }
  const std::string key(reinterpret_cast<const char*>(session->salt()),
                        Envelope::kSaltLen);
  return by_salt_.emplace(key, session).second;
}

void SessionTable::remove(const Session* session) {
  if (session == nullptr) {
    return;
  }
  const std::string key(reinterpret_cast<const char*>(session->salt()),
                        Envelope::kSaltLen);
  const auto it = by_salt_.find(key);
  if (it != by_salt_.end() && it->second == session) {
    by_salt_.erase(it);
  }
}

Session* SessionTable::find(const uint8_t salt[Envelope::kSaltLen]) const {
  if (salt == nullptr) {
    return nullptr;
  }
  const std::string key(reinterpret_cast<const char*>(salt), Envelope::kSaltLen);
  const auto it = by_salt_.find(key);
  return it == by_salt_.end() ? nullptr : it->second;
}

}  // namespace fcp
