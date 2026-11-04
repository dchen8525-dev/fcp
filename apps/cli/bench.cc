#include "bench.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <thread>

#include "fcp/frame_tx.h"
#include "fcp/random.h"
#include "fcp/wire.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fcp {
namespace bench {

const uint8_t kMagic[kMagicLen] = {'F', 'C', 'P', 'S', 'T', 'E', 'S', 'T'};

namespace {

int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void SleepMs(int64_t ms) {
  if (ms > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  }
}

double WireBytesPerSegment() {
  // Data symbol on the wire = envelope/FEC overhead + payload (frame_tx.h).
  return static_cast<double>(kDataPayloadLen + kDataWireOverhead);
}

}  // namespace

bool EncodeRendezvous(const uint8_t salt[kSaltLen], uint16_t seconds,
                      uint8_t out[kRendezvousLen]) {
  if (salt == nullptr || out == nullptr) {
    return false;
  }
  std::memcpy(out, kMagic, kMagicLen);
  put_le16(kVersion, out + kMagicLen);
  put_le16(seconds, out + kMagicLen + 2);
  std::memcpy(out + kMagicLen + 4, salt, kSaltLen);
  return true;
}

bool DecodeRendezvous(const uint8_t* data, size_t len, uint8_t salt[kSaltLen],
                      uint16_t* seconds) {
  if (!IsMagicPrefix(data, len) || len != kRendezvousLen ||
      get_le16(data + kMagicLen) != kVersion || salt == nullptr || seconds == nullptr) {
    return false;
  }
  *seconds = get_le16(data + kMagicLen + 2);
  std::memcpy(salt, data + kMagicLen + 4, kSaltLen);
  return true;
}

bool IsMagicPrefix(const uint8_t* data, size_t len) {
  return data != nullptr && len >= kMagicLen && std::memcmp(data, kMagic, kMagicLen) == 0;
}

bool IsMagic(const uint8_t* data, size_t len) {
  return len == kMagicLen && IsMagicPrefix(data, len);
}

void EncodeData(uint32_t sn, uint8_t* out, size_t len) {
  if (out == nullptr || len < kHeaderLen) {
    return;
  }
  std::memset(out, 0, len);
  std::memcpy(out, kMagic, kMagicLen);
  put_le16(kVersion, out + kMagicLen);
  out[kMagicLen + 2] = static_cast<uint8_t>(PayloadType::kData);
  out[kMagicLen + 3] = 0;
  put_le32(sn, out + 12);
}

void EncodeReport(uint32_t sn, uint64_t delivered, uint64_t best_bps, uint8_t* out,
                  size_t len) {
  if (out == nullptr || len < kReportPayloadLen) {
    return;
  }
  EncodeData(sn, out, len);
  out[kMagicLen + 2] = static_cast<uint8_t>(PayloadType::kReport);
  put_le64(delivered, out + kHeaderLen);
  put_le64(best_bps, out + kHeaderLen + 8);
}

bool DecodePayload(const uint8_t* payload, size_t len, DecodedPayload* out) {
  if (out == nullptr || !IsMagicPrefix(payload, len) || len < kHeaderLen) {
    return false;
  }
  if (get_le16(payload + kMagicLen) != kVersion) {
    return false;
  }
  const uint8_t type = payload[kMagicLen + 2];
  if (type != static_cast<uint8_t>(PayloadType::kData) &&
      type != static_cast<uint8_t>(PayloadType::kReport)) {
    return false;
  }
  out->type = static_cast<PayloadType>(type);
  out->sn = get_le32(payload + 12);
  out->delivered = 0;
  out->best_bps = 0;
  if (out->type == PayloadType::kReport) {
    if (len < kReportPayloadLen) {
      return false;
    }
    out->delivered = get_le64(payload + kHeaderLen);
    out->best_bps = get_le64(payload + kHeaderLen + 8);
  }
  return true;
}

void Ramp::Advance() {
  bps_ = std::min(kMaxBps, bps_ * 1.5);
}

// One bench at a time per process: two sessions would interleave on the same
// UDP socket, and the reactor's UDP receive buffer is shared with the proxy.
std::atomic<int>& BenchOwner() {
  static std::atomic<int> owner{0};
  return owner;
}

bool BenchGate(std::string* error) {
  if (BenchOwner().exchange(1) == 0) {
    return true;
  }
  if (error != nullptr) {
    *error = "已有测速会话在进行（同一进程同一时间只跑一个）";
  }
  return false;
}

void BenchRelease() { BenchOwner().store(0); }

void RateWindow::Add(int64_t now_ms, uint64_t bytes) {
  const int64_t index = now_ms / kSlotMs;
  if (slots_.empty() || slots_.back().index != index) {
    slots_.push_back(Slot{index, 0});
    while (slots_.size() > kMaxSlots) {
      slots_.pop_front();
    }
  }
  slots_.back().bytes += bytes;
  total_ += bytes;

  // The trailing one-second window, measured over the slots that actually
  // hold data. A gap means the sender was silent, so the span stays one slot
  // wide and the rate is not divided by time it never had traffic in.
  const int64_t oldest_allowed = index - (static_cast<int64_t>(kSlotsPerWindow) - 1);
  uint64_t sum = 0;
  int64_t oldest = index;
  for (auto it = slots_.rbegin(); it != slots_.rend(); ++it) {
    if (it->index < oldest_allowed) {
      break;
    }
    sum += it->bytes;
    oldest = it->index;
  }
  const int64_t span_slots = index - oldest + 1;
  // A window narrower than half a second is a burst, not a rate; letting it
  // set the best would turn the very first datagrams into a fake peak.
  if (span_slots < static_cast<int64_t>(kSlotsPerWindow) / 2) {
    return;
  }
  const uint64_t bps =
      sum * 8 * 1000 / static_cast<uint64_t>(span_slots * kSlotMs);
  best_bps_ = std::max(best_bps_, bps);
}

void RateWindow::Reset() {
  slots_.clear();
  total_ = 0;
  best_bps_ = 0;
}

namespace {

#ifdef _WIN32
using Sock = SOCKET;
constexpr Sock kBadSock = INVALID_SOCKET;
void CloseSock(Sock sock) { closesocket(sock); }
#else
using Sock = int;
constexpr Sock kBadSock = -1;
void CloseSock(Sock sock) { ::close(sock); }
#endif

bool SetNonBlocking(Sock sock) {
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
  const int flags = fcntl(sock, F_GETFL, 0);
  return flags >= 0 && fcntl(sock, F_SETFL, flags | O_NONBLOCK) >= 0;
#endif
}

void TuneBuffers(Sock sock) {
  const int size = 4 * 1024 * 1024;
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&size),
             sizeof(size));
  setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&size),
             sizeof(size));
}

// SleepMs(1) is 15.6ms on Windows unless the timer resolution was raised, and
// a 15.6ms stall between drain batches caps receive throughput at a few
// hundred Mbps regardless of CPU headroom. Wait on readability instead: it
// returns immediately while data is flowing and only parks the loop when the
// socket is genuinely empty.
bool WaitReadable(Sock sock, int64_t timeout_ms) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(sock, &set);
  timeval tv{};
  tv.tv_sec = static_cast<long>(timeout_ms / 1000);
  tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
  return ::select(static_cast<int>(sock + 1), &set, nullptr, nullptr, &tv) > 0;
}

// Opens a connected UDP socket to an IPv4 literal. The proxy CLI already
// requires IPv4 for --host, so the speed test keeps the same contract instead
// of growing a resolver.
Sock OpenClient(const ClientOptions& opt, std::string* error) {
  Sock sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == kBadSock) {
    *error = "speedtest: socket() failed";
    return kBadSock;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(opt.port);
  if (opt.host.empty() || inet_pton(AF_INET, opt.host.c_str(), &addr.sin_addr) != 1) {
    *error = "speedtest: --host must be an IPv4 address (got '" + opt.host + "')";
    CloseSock(sock);
    return kBadSock;
  }
  if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    *error = "speedtest: udp connect failed";
    CloseSock(sock);
    return kBadSock;
  }
  TuneBuffers(sock);
  if (!SetNonBlocking(sock)) {
    *error = "speedtest: cannot make the socket non-blocking";
    CloseSock(sock);
    return kBadSock;
  }
  return sock;
}

}  // namespace

bool RunClient(const ClientOptions& opt, const ProgressFn& progress, Result* out) {
  if (out == nullptr) {
    return false;
  }
  *out = Result{};
  if (opt.seconds < kMinSeconds || opt.seconds > kMaxSeconds) {
    out->error = "测速时长必须在 3..30 秒";
    return false;
  }
  std::string gate_error;
  if (!BenchGate(&gate_error)) {
    out->error = gate_error;
    return false;
  }
  // RAII so every early return below releases the gate; hand it over as the
  // last thing the function does.
  struct GateGuard {
    ~GateGuard() {
      if (held) {
        BenchRelease();
      }
    }
    bool held = true;
  } gate;
#ifdef _WIN32
  WSADATA wsa{};
  const bool wsa_owned = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  if (!wsa_owned) {
    out->error = "speedtest: WSAStartup 失败";
    return false;
  }
#endif
  auto cleanup = [&]() {
#ifdef _WIN32
    WSACleanup();
#endif
  };

  std::string error;
  Sock sock = OpenClient(opt, &error);
  if (sock == kBadSock) {
    out->error = error;
    cleanup();
    return false;
  }

  // Every run gets a fresh salt; the server adopts it from the rendezvous.
  uint8_t salt[kSaltLen] = {};
  if (!random_bytes(salt, sizeof(salt))) {
    out->error = "speedtest: 系统熵源不可用";
    CloseSock(sock);
    cleanup();
    return false;
  }
  uint8_t rendezvous[kRendezvousLen];
  EncodeRendezvous(salt, opt.seconds, rendezvous);

  // Rendezvous before the session: the FCP handshake only retries for ~2.1s,
  // so both ends must start within that window. The server echoes the magic
  // once it has created the bench session.
  bool met = false;
  int64_t meet_start = NowMs();
  int64_t next_meet = 0;
  while (NowMs() - meet_start < 5000) {
    const int64_t now = NowMs();
    if (now >= next_meet) {
      ::send(sock, reinterpret_cast<const char*>(rendezvous), sizeof(rendezvous), 0);
      next_meet = now + 50;
    }
    uint8_t buf[2048];
    for (int drained = 0; drained < 64; ++drained) {
      const int n = static_cast<int>(
          ::recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0));
      if (n <= 0) {
        break;
      }
      if (IsMagic(buf, static_cast<size_t>(n))) {
        met = true;
        break;
      }
    }
    if (met) {
      break;
    }
    SleepMs(2);
  }
  if (!met) {
    out->error =
        "服务端没有响应测速（确认服务端以 --speedtest 启动，且地址/端口正确）";
    CloseSock(sock);
    cleanup();
    return false;
  }

  // Client caps are deliberately loose so the *server's* deployed geometry
  // wins the min() negotiation: --fec=20:4 on the server then measures 20:4,
  // not the client's default 10:3.
  SessionConfig cfg;
  std::memcpy(cfg.key, opt.key, sizeof(cfg.key));
  std::memcpy(cfg.salt, salt, sizeof(cfg.salt));
  cfg.send_direction = Direction::kC2S;
  cfg.recv_direction = Direction::kS2C;
  cfg.d = 249;
  cfg.p = 7;
  cfg.p_max = 7;
  cfg.mtu = opt.mtu;
  cfg.ip_hdr_len = opt.ip_hdr_len;
  cfg.fec_budget = kDefaultFecBudget;

  Result result;
  enum class Phase { kHandshake, kDownload, kWarmup, kUpload, kDrain };
  Phase phase = Phase::kHandshake;
  uint64_t down_bytes = 0;
  uint64_t up_sent = 0;
  uint64_t up_reported = 0;
  uint64_t up_best_bps = 0;
  bool have_report = false;
  RateWindow down_window;
  int64_t first_down_ms = 0;
  int64_t last_down_ms = 0;
  int64_t phase_start = 0;
  int64_t next_ramp = 0;

  Session session(
      cfg,
      [sock](const uint8_t* wire, size_t len, SymbolType) {
        ::send(sock, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0);
      },
      [&](const uint8_t* payload, size_t len) {
        DecodedPayload decoded;
        if (!DecodePayload(payload, len, &decoded)) {
          return;
        }
        if (decoded.type == PayloadType::kData) {
          if (phase != Phase::kDownload) {
            return;
          }
          const uint64_t user = UserBytes(len);
          const int64_t now = NowMs();
          down_bytes += user;
          down_window.Add(now, user);
          if (first_down_ms == 0) {
            first_down_ms = now;
          }
          last_down_ms = now;
        } else if (decoded.delivered >= up_reported) {
          // Reports are cumulative and can arrive late; never let a stale one
          // walk the upload count back (that would look like lost data).
          up_reported = decoded.delivered;
          up_best_bps = decoded.best_bps;
          have_report = true;
        }
      },
      [](const std::string&) {});

  const int64_t session_start = NowMs();
  if (session.start(session_start) != Session::StartStatus::kOk) {
    out->error = "speedtest: FCP 会话启动失败（熵源或 MTU 配置）";
    CloseSock(sock);
    cleanup();
    return false;
  }
  session.on_tick(session_start);

  uint8_t payload[kDataPayloadLen] = {};
  EncodeData(0, payload, sizeof(payload));
  uint32_t sn = 1;
  double tokens = 0.0;
  int64_t token_ms = NowMs();
  Ramp ramp;
  int64_t next_tick = 0;
  int64_t next_progress = NowMs() + 200;
  bool fatal = false;

  for (;;) {
    const int64_t now = NowMs();
    uint8_t buf[2048];
    int drained_any = 0;
    // 1024 is a starvation bound, not a throughput target: at 1 Gbps the whole
    // socket buffer holds about 3400 symbols, so a full drain still finishes
    // well inside one tick.
    for (int drained = 0; drained < 1024; ++drained) {
      const int n = static_cast<int>(
          ::recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0));
      if (n <= 0) {
        break;
      }
      drained_any = 1;
      session.on_wire(buf, static_cast<size_t>(n), now);
      if (session.state() == HandshakeState::kFailed) {
        break;
      }
    }
    if (now >= next_tick) {
      session.on_tick(now);
      next_tick = now + kSessionTickMs;
    }
    if (session.state() == HandshakeState::kFailed) {
      result.error = "测速握手失败";
      fatal = true;
      break;
    }

    switch (phase) {
      case Phase::kHandshake:
        if (session.established()) {
          phase = Phase::kDownload;
          phase_start = now;
        } else if (now - session_start > kSetupTimeoutMs) {
          result.error = "测速握手超时";
          fatal = true;
        }
        break;
      case Phase::kDownload:
        if (down_bytes > 0 && now - last_down_ms >= kSilenceMs) {
          phase = Phase::kWarmup;
          phase_start = now;
        } else if (now - phase_start > (static_cast<int64_t>(opt.seconds) + 4) * 1000) {
          result.error = "测速下行没有收到数据";
          fatal = true;
        }
        break;
      case Phase::kWarmup:
        if (now - phase_start >= kSettleBeforePhaseMs) {
          phase = Phase::kUpload;
          phase_start = now;
          next_ramp = now + kRampMs;
          token_ms = now;
          tokens = 0.0;
        }
        break;
      case Phase::kUpload: {
        if (now >= next_ramp) {
          ramp.Advance();
          next_ramp = now + kRampMs;
        }
        const double dt = static_cast<double>(now - token_ms) / 1000.0;
        token_ms = now;
        // Tokens are bits; one segment costs its wire size in bits. The cap is
        // 50ms of budget, so a coarse tick (the reactor's 25ms) never throws
        // away offered rate before it can be spent.
        const double wire_per_seg = WireBytesPerSegment() * 8.0;
        tokens = std::min(tokens + ramp.bps() * dt,
                          std::max(ramp.bps() * 0.05, wire_per_seg));
        int burst = 0;
        while (tokens >= wire_per_seg && burst < 4096) {
          put_le32(sn++, payload + 12);
          session.on_kcp_output(payload, sizeof(payload), now);
          up_sent += UserBytes(sizeof(payload));
          tokens -= wire_per_seg;
          ++burst;
        }
        if (now - phase_start >= static_cast<int64_t>(opt.seconds) * 1000) {
          // The timer stops the offered load; leftover tokens must not turn
          // into one final burst after the measurement window closed.
          tokens = 0.0;
          phase = Phase::kDrain;
          phase_start = now;
        }
        break;
      }
      case Phase::kDrain:
        if (now - phase_start >= kDrainMs) {
          fatal = false;
          goto done;
        }
        break;
    }
    if (fatal) {
      break;
    }
    if (progress && now >= next_progress) {
      next_progress = now + 200;
      if (phase == Phase::kDownload || phase == Phase::kWarmup) {
        progress("down", down_bytes, now - (first_down_ms != 0 ? first_down_ms : now));
      } else if (phase == Phase::kUpload || phase == Phase::kDrain) {
        progress("up", have_report ? up_reported : up_sent, now - phase_start);
      }
    }
    if (!drained_any) {
      WaitReadable(sock, 1);
    }
  }
 done:;

  // Publish the last interval before reading the loss counters, so an 8s test
  // does not report the loss of a window that ended several seconds early.
  session.flush_report(NowMs());

  if (down_bytes > 0) {
    result.download.bytes = down_bytes;
    result.download.mbps = static_cast<double>(down_window.best_bps()) / 1e6;
    result.download.seconds =
        first_down_ms != 0 ? static_cast<double>(last_down_ms - first_down_ms) / 1000.0
                           : 0.0;
    result.download.acked = true;
    if (session.reporter() != nullptr) {
      const uint32_t expected = session.reporter()->last_expected();
      const uint32_t lost = session.reporter()->last_lost();
      result.download.loss_n = expected;
      result.download.loss_ppm =
          expected > 0
              ? static_cast<uint32_t>((static_cast<uint64_t>(lost) * 1000000ull +
                                       expected / 2) /
                                      expected)
              : 0;
    }
    result.have_download = true;
  } else if (result.error.empty()) {
    result.error = "测速下行没有收到数据";
  }

  if (have_report) {
    result.upload.bytes = up_reported;
    result.upload.mbps = static_cast<double>(up_best_bps) / 1e6;
    result.upload.seconds = static_cast<double>(opt.seconds);
    result.upload.acked = true;
    // The server counts what arrived, not what we handed to the framer. It
    // can only report at least as much as we sent (we stop sending first and
    // wait out the drain), so a smaller number is FEC/ARQ loss the upload
    // could not recover -- never report that as confirmed.
    if (up_reported < up_sent) {
      result.upload.acked = false;
      result.upload.lost_bytes = up_sent - up_reported;
      if (result.error.empty()) {
        const double pct = up_sent > 0
                               ? 100.0 * static_cast<double>(result.upload.lost_bytes) /
                                     static_cast<double>(up_sent)
                               : 0.0;
        char line[96];
        std::snprintf(line, sizeof(line), "上行有 %.1f%% 未到达服务端", pct);
        result.error = line;
      }
    }
    result.have_upload = true;
  } else if (result.error.empty()) {
    result.error = "没有收到服务端的上传确认";
  }

  *out = result;
  CloseSock(sock);
  cleanup();
  gate.held = false;
  bench::BenchRelease();
  return result.have_download;
}

}  // namespace bench

// ---------------------------------------------------------------------------
// BenchServer

fcp::BenchServer::BenchServer(const bench::Options& options, SendFn send, LogFn log)
    : opt_(options), send_(std::move(send)), log_(std::move(log)) {
  // The data payload is constant apart from its sn; build it once and patch
  // the sn per segment instead of memsetting 1.2 KiB in the hot loop.
  bench::EncodeData(0, payload_, sizeof(payload_));
}

BenchServer::~BenchServer() { Reset(); }

void BenchServer::Reset() {
  // Destroy the session first: its destructor flushes the last FECSTAT through
  // send_, which still needs peer_ to be valid.
  session_.reset();
  bench::BenchRelease();
  // sn_ deliberately survives: the frame layer's cross-set dedup remembers
  // the last kSnWindow sequence numbers, so restarting at 1 would make the next
  // client's first payloads collide with the previous session's and vanish.
  have_peer_ = false;
  phase_ = Phase::kWaitEstablished;
  outcome_logged_ = false;
  std::memset(salt_, 0, sizeof(salt_));
  upload_bytes_ = 0;
  upload_window_.Reset();
  tokens_ = 0.0;
  token_ms_ = 0;
  last_ramp_ms_ = 0;
  // last_echo_ms_ is not reset: it throttles the "busy slot" echo path too,
  // and StartSession replies to its own rendezvous explicitly.
}

void BenchServer::StartSession(const Peer& from, const uint8_t salt[bench::kSaltLen],
                               uint16_t seconds, int64_t now_ms) {
  Reset();
  peer_ = from;
  have_peer_ = true;
  std::memcpy(salt_, salt, sizeof(salt_));
  seconds_ = static_cast<uint16_t>(
      std::min<int>(bench::kMaxSeconds, std::max<int>(bench::kMinSeconds, seconds)));
  created_ms_ = now_ms;
  if (!bench::BenchGate(nullptr)) {
    // A previous session's tick never released the gate; the slot has to be
    // reclaimable or the responder locks up on a stale claim.
    bench::BenchRelease();
    if (!bench::BenchGate(nullptr)) {
      return;
    }
  }

  SessionConfig cfg;
  std::memcpy(cfg.key, opt_.key, sizeof(cfg.key));
  std::memcpy(cfg.salt, salt_, sizeof(cfg.salt));
  cfg.send_direction = Direction::kS2C;
  cfg.recv_direction = Direction::kC2S;
  cfg.d = opt_.d;
  cfg.p = opt_.p;
  cfg.p_max = opt_.p_max;
  cfg.mtu = opt_.mtu;
  cfg.ip_hdr_len = opt_.ip_hdr_len;
  cfg.fec_budget = opt_.fec_budget;

  session_ = std::make_unique<Session>(
      cfg,
      [this](const uint8_t* wire, size_t len, SymbolType) {
        return send_(peer_, wire, len);
      },
      [this](const uint8_t* payload, size_t len) {
        OnDelivered(payload, len, bench::NowMs());
      },
      [this](const std::string& line) {
        if (log_) {
          log_("[bench] " + line);
        }
      });

  if (session_->start(now_ms) != Session::StartStatus::kOk) {
    if (log_) {
      log_("[bench] session start failed");
    }
    Reset();
    return;
  }
  session_->on_tick(now_ms);
  phase_ = Phase::kWaitEstablished;
  // Reply unconditionally: last_echo_ms_ deliberately survives a Reset (it is
  // shared with the busy-slot path) and would otherwise swallow the echo for a
  // client that arrives inside the previous session's echo window.
  last_echo_ms_ = now_ms;
  send_(peer_, bench::kMagic, bench::kMagicLen);
  if (log_) {
    log_("[bench] session started, " + std::to_string(seconds_) + "s per direction");
  }
}

void BenchServer::SendRendezvousEcho(int64_t now_ms) {
  if (!have_peer_ || now_ms - last_echo_ms_ < 50) {
    return;
  }
  last_echo_ms_ = now_ms;
  send_(peer_, bench::kMagic, bench::kMagicLen);
}

bool BenchServer::OnDatagram(const Peer& from, const uint8_t* data, size_t len,
                             int64_t now_ms) {
  if (!have_peer_) {
    uint8_t salt[bench::kSaltLen];
    uint16_t seconds = 0;
    if (!bench::DecodeRendezvous(data, len, salt, &seconds)) {
      return false;
    }
    StartSession(from, salt, seconds, now_ms);
    return true;
  }
  if (std::memcmp(from.bytes, peer_.bytes, sizeof(peer_.bytes)) == 0) {
    if (bench::IsMagic(data, len)) {
      SendRendezvousEcho(now_ms);  // rendezvous echo lost: tell the client again
      return true;
    }
    if (session_ != nullptr) {
      // Session's return value is the auth/parse verdict. False is expected for
      // a duplicate or corrupt datagram; it must not be retried, and it must
      // not fall through as "not ours" either -- every datagram from the peer
      // belongs to the bench session while the slot is held.
      (void)session_->on_wire(data, len, now_ms);
    }
    return true;
  }
  // Not the bench peer. A datagram that merely *starts* with the magic is not
  // necessarily ours: the tunnel envelope header is arbitrary ciphertext
  // bytes, so a real proxy datagram draws the 8-byte magic with probability
  // 2^-64. Among ~500k datagrams per second that is once in 40 years, but a
  // bug that writes the magic at offset 0 (the old bench code did) would turn
  // every such datagram into one here -- so only full bench shapes are
  // consumed, and an incomplete rendezvous still gets the echo (the client
  // may be retrying after a lost echo) instead of being parsed or forwarded.
  if (bench::IsMagic(data, len)) {
    return true;
  }
  uint8_t salt[bench::kSaltLen];
  uint16_t seconds = 0;
  if (bench::DecodeRendezvous(data, len, salt, &seconds) ||
      (bench::IsMagicPrefix(data, len) && len < bench::kRendezvousLen)) {
    SendRendezvousEcho(now_ms);
    return true;
  }
  return false;
}

void BenchServer::OnDelivered(const uint8_t* payload, size_t len, int64_t now_ms) {
  bench::DecodedPayload decoded;
  if (!bench::DecodePayload(payload, len, &decoded)) {
    return;
  }
  if (decoded.type != bench::PayloadType::kData) {
    return;  // the client does not send reports
  }
  if (phase_ == Phase::kAwaitUpload) {
    phase_ = Phase::kUpload;
    phase_start_ms_ = now_ms;
    upload_bytes_ = 0;
    upload_window_.Reset();
    last_report_ms_ = 0;
  }
  if (phase_ != Phase::kUpload) {
    return;
  }
  const uint64_t user = bench::UserBytes(len);
  upload_bytes_ += user;
  upload_window_.Add(now_ms, user);
  last_upload_data_ms_ = now_ms;
}

void BenchServer::SendReport(int64_t now_ms, bool final) {
  if (session_ == nullptr) {
    return;
  }
  uint8_t report[bench::kReportPayloadLen] = {};
  bench::EncodeReport(sn_++, upload_bytes_, upload_window_.best_bps(), report,
                      sizeof(report));
  session_->on_kcp_output(report, sizeof(report), now_ms);
  last_report_ms_ = now_ms;
  // final is true for every repeat of the final report; log the outcome once.
  if (final && log_ && upload_bytes_ > 0 && !outcome_logged_) {
    outcome_logged_ = true;
    char line[160];
    std::snprintf(line, sizeof(line), "[bench] upload %llu bytes delivered, best %.1f Mbps",
                  static_cast<unsigned long long>(upload_bytes_),
                  static_cast<double>(upload_window_.best_bps()) / 1e6);
    log_(line);
  }
}

void BenchServer::ApplyTokens(int64_t now_ms) {
  if (session_ == nullptr || now_ms < phase_start_ms_) {
    return;
  }
  if (last_ramp_ms_ == 0) {
    last_ramp_ms_ = now_ms;
    token_ms_ = now_ms;
  }
  if (now_ms - last_ramp_ms_ >= bench::kRampMs) {
    ramp_.Advance();
    last_ramp_ms_ = now_ms;
  }
  const double dt = static_cast<double>(now_ms - token_ms_) / 1000.0;
  token_ms_ = now_ms;
  // Bits in, bits out: one segment costs its wire size in bits (see the
  // client's bucket). The reactor ticks every 25ms, so the 50ms cap is what
  // keeps the offered rate intact between ticks.
  const double wire_per_seg = bench::WireBytesPerSegment() * 8.0;
  tokens_ = std::min(tokens_ + ramp_.bps() * dt,
                     std::max(ramp_.bps() * 0.05, wire_per_seg));
  int burst = 0;
  while (tokens_ >= wire_per_seg && burst < 4096) {
    put_le32(sn_++, payload_ + 12);
    session_->on_kcp_output(payload_, sizeof(payload_), now_ms);
    tokens_ -= wire_per_seg;
    ++burst;
  }
}

void BenchServer::OnTick(int64_t now_ms) {
  if (session_ == nullptr) {
    return;
  }
  session_->on_tick(now_ms);
  if (session_->state() == HandshakeState::kFailed) {
    if (log_) {
      log_("[bench] handshake failed");
    }
    Reset();
    return;
  }
  // A stuck client must not pin the one bench slot.
  if (now_ms - created_ms_ >
      (static_cast<int64_t>(seconds_) * 2 + 20) * 1000) {
    Reset();
    return;
  }

  switch (phase_) {
    case Phase::kWaitEstablished:
      if (session_->established()) {
        phase_ = Phase::kDownload;
        phase_start_ms_ = now_ms + bench::kSettleBeforePhaseMs;
        download_end_ms_ = phase_start_ms_ + static_cast<int64_t>(seconds_) * 1000;
        tokens_ = 0.0;
        token_ms_ = phase_start_ms_;
        last_ramp_ms_ = 0;
        ramp_.Reset();
      }
      break;
    case Phase::kDownload:
      ApplyTokens(now_ms);
      if (now_ms >= download_end_ms_) {
        phase_ = Phase::kAwaitUpload;
        phase_start_ms_ = now_ms;
      }
      break;
    case Phase::kAwaitUpload:
      // The client detects this direction's end by 700ms of silence and then
      // starts uploading; give it a wide margin before giving up.
      if (now_ms - phase_start_ms_ > 5000) {
        Reset();
      }
      break;
    case Phase::kUpload:
      if (now_ms - last_report_ms_ >= bench::kReportMs) {
        SendReport(now_ms, false);
      }
      if (now_ms - last_upload_data_ms_ >= bench::kSilenceMs) {
        SendReport(now_ms, true);
        phase_ = Phase::kDraining;
        phase_start_ms_ = now_ms;
        // Stay addressable long enough to swallow the client's teardown
        // FECSTAT; otherwise it reaches the proxy engine as an unknown salt.
        drain_end_ms_ = now_ms + 2500;
      }
      break;
    case Phase::kDraining:
      if (now_ms - phase_start_ms_ < bench::kFinalReportsMs &&
          now_ms - last_report_ms_ >= 150) {
        SendReport(now_ms, true);  // repeat the final report; payloads can drop
      }
      if (now_ms >= drain_end_ms_) {
        Reset();
      }
      break;
  }
}

}  // namespace fcp
