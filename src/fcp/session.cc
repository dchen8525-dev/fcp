#include "fcp/session.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

namespace fcp {
namespace {

const char* fecstat_reason(FecstatStatus status) {
  switch (status) {
    case FecstatStatus::kOk:
      return "ok";
    case FecstatStatus::kBadLength:
      return "bad_length";
    case FecstatStatus::kBadMagic:
      return "bad_magic";
    case FecstatStatus::kBadSalt:
      return "bad_salt";
    case FecstatStatus::kBadVer:
      return "bad_ver";
    case FecstatStatus::kStale:
      return "stale";
    case FecstatStatus::kDuplicate:
      return "duplicate";
  }
  return "unknown";
}

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

}  // namespace

// See session.h: the default dedup key, read out of a KCP segment header.
bool kcp_sn_of(const uint8_t* payload, size_t len, uint32_t* sn) {
  if (len < 16) {
    return false;
  }
  *sn = static_cast<uint32_t>(payload[12]) |
        (static_cast<uint32_t>(payload[13]) << 8) |
        (static_cast<uint32_t>(payload[14]) << 16) |
        (static_cast<uint32_t>(payload[15]) << 24);
  return true;
}

Session::Session(const SessionConfig& config, SendFn send, DeliverFn deliver, LogFn log)
    : cfg_(config),
      limits_(compute_mtu_limits(config.mtu, config.ip_hdr_len)),
      env_(config.key, config.salt, config.send_direction, config.recv_direction),
      send_(std::move(send)),
      deliver_(std::move(deliver)),
      log_(std::move(log)),
      hs_(config.d, config.p,
          [this](const uint8_t* data, size_t len) { send_oob(data, len); },
          kLocalFlagsM1, config.handshake_cache_segments,
          config.handshake_cache_bytes),
      srtt_ms_(config.initial_srtt_ms > 0 ? config.initial_srtt_ms : kDefaultSrttMs) {}

void Session::start(int64_t now_ms) {
  if (!limits_.valid) {
    log("FCP config invalid: MTU leaves no room for a data symbol");
    return;
  }
  if (!mtu_fits_largest_oob(cfg_)) {
    log("FCP config invalid: MTU too small for a 128-byte FECSTAT oob");
    return;
  }
  if (!local_caps_valid(cfg_)) {
    log("FCP config invalid: local D/P out of range");
    return;
  }
  hs_.start(now_ms);
}

void Session::on_wire(const uint8_t* wire, size_t len, int64_t now_ms) {
  std::vector<uint8_t> plain;
  if (!env_.open(wire, len, &plain)) {
    ++auth_fail_;
    sync_report_counters();
    return;
  }

  // Authenticated but outside the MTU budget every conforming peer obeys
  // (§4.5): reject before it can inflate a set's symbol_max, the decode
  // buffers, or the pre-negotiation data cache.
  if (limits_.valid && plain.size() > kFecHdrLen + limits_.symbol_max) {
    ++pre_struct_fail_;
    sync_report_counters();
    return;
  }

  if (rx_) {
    if (reporter_ != nullptr) {
      FecHdr hdr{};
      if (parse_hdr(plain.data(), plain.size(), &hdr)) {
        const SymbolType type = hdr_type(hdr.type_k);
        if (type == SymbolType::kData) {
          reporter_->add_data_bytes(static_cast<uint32_t>(len));
        } else if (type == SymbolType::kParity) {
          reporter_->add_parity_bytes(static_cast<uint32_t>(len));
        }
      }
    }
    rx_->on_datagram(plain.data(), plain.size(), now_ms);
    sync_report_counters();
    return;
  }

  // Before negotiation only oob (including HELLO/ACK) is actionable (§6.2).
  // Inbound data cannot be framed yet (D' is not fixed) and must be dropped:
  // the handshake cache holds *our* outbound KCP segments and is replayed into
  // the transmitter, never into the receiver (erratum #4). KCP below recovers.
  FecHdr hdr{};
  if (!parse_hdr(plain.data(), plain.size(), &hdr)) {
    ++pre_struct_fail_;
    sync_report_counters();
    return;
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
      log(std::string("FEC handshake failed: ") + handshake_error_text(hs_.error()));
    }
    return;
  }
  tx_->on_kcp_output(seg, len, now_ms);
}

void Session::on_tick(int64_t now_ms) {
  const HandshakeState before = hs_.state();
  hs_.on_tick(now_ms);
  if (before != HandshakeState::kFailed && hs_.state() == HandshakeState::kFailed) {
    log(std::string("FEC handshake failed: ") + handshake_error_text(hs_.error()));
  }
  if (!ensure_configured(now_ms)) {
    return;
  }
  tx_->on_tick(now_ms);
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
      log(line);
    }
  }
}

void Session::on_rtt_sample(int64_t srtt_ms) {
  if (srtt_ms <= 0) {
    return;
  }
  srtt_ms_ = srtt_ms;
  // Baseline for the §8 queue guardrail is the minimum *observed* RTT. A fixed
  // initial value would make srtt - min_rtt >= 40ms permanent on any link
  // whose RTT exceeds it (satellite/cross-continental), silently pinning k.
  if (min_srtt_ms_ <= 0 || srtt_ms < min_srtt_ms_) {
    min_srtt_ms_ = srtt_ms;
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
      [this](const uint8_t* payload, size_t len) { on_oob(payload, len, 0); }, cfg_.sn_of);

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
        TxSymbol symbol;
        symbol.set_id = 0;  // §4.7: oob headers carry set_id = 0, index = 0
        symbol.index = 0;
        symbol.type_k = pack_type_k(0, 0, static_cast<uint8_t>(SymbolType::kOob));
        symbol.symbol.assign(packet, packet + len);
        emit_symbol(symbol);
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
  strategy_ = std::make_unique<FecStrategy>(strategy_config);
  tx_->set_k(strategy_->k());

  sync_report_counters();

  char line[192];
  std::snprintf(line, sizeof(line),
                "FCP v6 negotiated: data=%u parity=%u pmax=%u flags=framed,stats (peer V3)",
                np.d, np.p, cfg_.p_max);
  log(line);
  if (strategy_config.pinned_k > 0) {
    std::snprintf(line, sizeof(line), "FEC pinned: k=%d (operator)", strategy_config.pinned_k);
    log(line);
  } else if (strategy_->initial_k() > 0) {
    // The value shown is post-clamp: what the session actually started with.
    std::snprintf(line, sizeof(line), "FEC warmed: k=%d (prewarm)", strategy_->initial_k());
    log(line);
  }

  reporter_->on_tick(now_ms);  // first tick only sets the interval baseline
  last_fecstat_ms_ = now_ms;
  for (auto& seg : hs_.take_cached_data()) {
    tx_->on_kcp_output(seg.data(), seg.size(), now_ms);
  }
}

void Session::on_oob(const uint8_t* payload, size_t len, int64_t now_ms) {
  // Erratum #25: HELLO/HELLO_ACK arrive as oob frames and are dispatched by
  // their 16-byte magic before the FECSTAT validator ever sees them.
  if (len >= kHelloAckLen && payload != nullptr &&
      (is_hello(payload, len) || is_hello_ack(payload, len))) {
    if (hs_.on_oob(payload, len) == HandshakeStatus::kProtocolFailure) {
      log(std::string("FEC handshake failed: ") + handshake_error_text(hs_.error()));
    }
    ensure_configured(now_ms);
    return;
  }

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
    char line[96];
    std::snprintf(line, sizeof(line), "FECSTAT dropped: reason=%s count=1",
                  fecstat_reason(status));
    log(line);
    return;
  }
  if (strategy_ == nullptr) {
    return;  // peer reports its view of our traffic; meaningless before setup
  }
  ++fecstat_rx_;
  fecstat_rx_pending_ = true;

  const bool queued = min_srtt_ms_ > 0 && srtt_ms_ - min_srtt_ms_ >= 40;
  const FecState before = strategy_->state();
  strategy_->on_report(stat, queued);
  if (tx_) {
    tx_->set_k(strategy_->k());
  }

  const uint32_t sets = stat.sets_expected;
  if (static_cast<uint64_t>(stat.sets_k_unknown) * 10 > std::max<uint32_t>(1, sets)) {
    char line[96];
    std::snprintf(line, sizeof(line), "FEC sample untrusted: k_unknown=%u/%u (>10%%)",
                  stat.sets_k_unknown, sets);
    log(line);
    return;
  }
  if (stat.data_expected < kMinSamplePackets) {
    char line[96];
    std::snprintf(line, sizeof(line), "FEC sample too small: expected=%u",
                  stat.data_expected);
    log(line);
    return;
  }

  const int64_t lost_signed = static_cast<int64_t>(stat.data_expected) -
                              stat.data_rx_orig - stat.data_recovered_dl -
                              stat.data_late_rx;
  const uint32_t lost = lost_signed > 0 ? static_cast<uint32_t>(lost_signed) : 0;
  const uint32_t pre = ppm_of(stat.data_expected > stat.data_rx_orig
                                  ? stat.data_expected - stat.data_rx_orig
                                  : 0,
                              stat.data_expected);
  const uint32_t usable_part =
      stat.data_expected > stat.data_rx_orig + stat.data_recovered_dl
          ? stat.data_expected - stat.data_rx_orig - stat.data_recovered_dl
          : 0;
  const uint32_t usable = ppm_of(usable_part, stat.data_expected);
  last_pre_ppm_ = pre;
  last_usable_ppm_ = usable;

  char line[512];
  std::snprintf(line, sizeof(line),
                "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u pre=%uppm "
                "usable=%uppm -> k=%u state=%s",
                stat.sets_expected, stat.data_expected, stat.data_rx_orig,
                stat.data_recovered_dl, stat.data_late_rx, lost, pre, usable,
                strategy_->k(), strategy_->state() == FecState::kOn ? "ON" : "OFF");
  log(line);

  if (before == FecState::kOn && strategy_->state() == FecState::kOff) {
    std::snprintf(line, sizeof(line),
                  "FEC off: pre<0.30%% for 5 reports (last %.2f%%)",
                  strategy_->last_loss() * 100.0);
    log(line);
  }
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

void Session::emit_symbol(const TxSymbol& symbol) {
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
  std::vector<uint8_t> wire;
  if (!env_.seal(plain.data(), plain.size(), &wire)) {
    if (!nonce_exhausted_logged_) {
      nonce_exhausted_logged_ = true;
      log("FCP session exhausted nonce space");
    }
    return;
  }
  send_(wire.data(), wire.size(), hdr_type(symbol.type_k));
}

void Session::send_oob(const uint8_t* msg, size_t len) {
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
  emit_symbol(symbol);
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
