#include "reactor.h"

#include <algorithm>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <thread>
#include <utility>

#include <chrono>
#include <ctime>

#include "bench.h"
#include "fcp/session.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <unistd.h>
#else
#include <timeapi.h>
#endif

#ifdef __linux__
// UDP GSO segmentation cmsg (kernel >= 4.18; older glibc headers lack it, the
// socket setup below degrades to plain sends when the kernel rejects it).
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
// Receive aggregation socket option (kernel >= 5.0). The same-numbered cmsg
// on recvmsg names the segment size of a coalesced read; see drain_gro().
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#endif

namespace fcp {
namespace {

#ifdef _WIN32
int SockErr() { return static_cast<int>(WSAGetLastError()); }
bool WouldBlock(int err) { return err == WSAEWOULDBLOCK; }
bool Interrupted(int err) { return err == WSAEINTR; }
bool Connecting(int err) { return err == WSAEWOULDBLOCK || err == WSAEALREADY || err == WSAEINPROGRESS; }
void CloseSock(SOCKET s) { closesocket(s); }
std::string ErrText(int err) {
  char buf[48];
  std::snprintf(buf, sizeof(buf), "winsock error %d", err);
  return buf;
}
// Windows select() quantizes its timeout to the system timer tick (~15.6 ms),
// unless the process raises the timer resolution. Everything in the reactor
// below one tick -- the pacer's token release, delayed ACKs, TLP/PMTU probes --
// then arrives at whole ~15 ms quanta, which is the Windows-only slice of the
// quic-go pacer gap. timeGivePeriod requests 1 ms around the whole run loop.
struct TimerResolution {
  explicit TimerResolution(bool want) {
    if (want) {
      timeBeginPeriod(1);
      active_ = true;
    }
  }
  ~TimerResolution() {
    if (active_) {
      timeEndPeriod(1);
    }
  }
  TimerResolution(const TimerResolution&) = delete;
  TimerResolution& operator=(const TimerResolution&) = delete;

 private:
  bool active_ = false;
};
#else
using SOCKET = int;
int SockErr() { return errno; }
bool WouldBlock(int err) { return err == EAGAIN || err == EWOULDBLOCK; }
bool Interrupted(int err) { return err == EINTR; }
bool Connecting(int err) { return err == EINPROGRESS || err == EALREADY; }
void CloseSock(SOCKET s) { ::close(s); }
std::string ErrText(int err) { return std::strerror(err); }
#endif

// 日志行里的小数秒，统一一位小数（%.1f），别让 to_string 的 6 位尾巴进档。
std::string Secs(double v) {
  char b[24];
  std::snprintf(b, sizeof(b), "%.1f", v);
  return b;
}

// --log-file 目录形式下的文件名后缀：fcp-<角色>-<pid>.log，避免两个实例互踩。
uint32_t ThisPid() {
#ifdef _WIN32
  return GetCurrentProcessId();
#else
  return static_cast<uint32_t>(getpid());
#endif
}

// Same underlying type as Reactor::Sock, so the helpers below and the members
// hand each other descriptors without casts.
using Sock = SOCKET;

#ifdef _WIN32
constexpr int kErrRefused = WSAECONNREFUSED;
constexpr int kErrTimeout = WSAETIMEDOUT;
#else
constexpr int kErrRefused = ECONNREFUSED;
constexpr int kErrTimeout = ETIMEDOUT;
#endif

// A target that is not listening and a target that never answers are different
// failures and the client owes the application a different reply code (RFC 1928
// rep 0x05 versus 0x06), so the socket error has to reach the engine as the
// matching OpenError rather than as one lump of "could not connect".
OpenError open_error_for(int err) {
  return err == kErrTimeout ? OpenError::kTargetTimeout : OpenError::kRefused;
}

bool SetNonBlocking(SOCKET s) {
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  const int flags = fcntl(s, F_GETFL, 0);
  return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) >= 0;
#endif
}

// Borrowed from quic-go's sys_conn (7 MiB receive buffer): on an untuned
// kernel even ~1 KB/MTU packets queue up exactly no room at all on a
// multi-hundred-Mbps link, and the reactor's single-threaded select() loop
// makes the socket the only buffer between the NIC and sessions. The Linux
// *_FORCE setsockopts ask the kernel to go past rmem_max/wmem_max (quic-go
// does the same via GSO-capable socket setup); without CAP_NET_ADMIN they
// fail and we fall back to the plain options, which are capped at the sysctl.
#ifdef _WIN32
void TuneUdp(SOCKET s) {
  const int size = 7 * 1024 * 1024;
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&size), sizeof(size));
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&size), sizeof(size));
}
#else
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif
#ifndef SO_SNDBUFFORCE
#define SO_SNDBUFFORCE 34
#endif
static bool SockBufForceOrPlain(SOCKET s, int force_opt, int plain_opt, int size) {
  if (setsockopt(s, SOL_SOCKET, force_opt, &size, sizeof(size)) == 0) {
    return true;
  }
  return setsockopt(s, SOL_SOCKET, plain_opt, &size, sizeof(size)) == 0;
}
void TuneUdp(SOCKET s) {
  const int size = 7 * 1024 * 1024;
  SockBufForceOrPlain(s, SO_RCVBUFFORCE, SO_RCVBUF, size);
  SockBufForceOrPlain(s, SO_SNDBUFFORCE, SO_SNDBUF, size);
}
#endif

// PMTUD (pmtu.h) is only sound when the kernel refuses to fragment: a router
// that fragments an oversized probe lets it arrive, and the session would then
// raise its MTU to a size the path cannot carry whole. Linux's default
// (IP_PMTUDISC_WANT) only sets DF above the cached path MTU, so be explicit;
// Windows needs IP_DONTFRAGMENT.
bool SetDontFragment(SOCKET s) {
#ifdef _WIN32
#ifdef IP_DONTFRAGMENT
  const int on = 1;
  return setsockopt(s, IPPROTO_IP, IP_DONTFRAGMENT,
                    reinterpret_cast<const char*>(&on), sizeof(on)) == 0;
#else
  (void)s;
  return false;
#endif
#else
  const int mode = IP_PMTUDISC_DO;
  return setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode)) == 0;
#endif
}

void EnableReuse(SOCKET s) {
  const int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
}

std::string ip_text(const sockaddr_in& a) {
  char buf[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
  return buf;
}

std::string host_port(const std::string& host, int port) {
  return host + ":" + std::to_string(port);
}

int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::atomic<bool> g_signalled{false};

void OnSignal(int) { g_signalled.store(true); }

}  // namespace

Reactor::Reactor(const EngineConfig& engine_config, const ReactorOptions& options)
    : opt_(options),
      base_config_(engine_config),
      engine_(engine_config, make_host(this)),
      max_sessions_(engine_config.max_sessions) {}

EngineHost Reactor::make_host(Reactor* self) {
  // The callbacks are installed before the engine is constructed, but nothing
  // can invoke them until the constructor has returned, so `self` is fully
  // built by the time any of these run.
  EngineHost host;
  host.app_send = [self](uint64_t conn, const uint8_t* data, size_t len) {
    return self->app_send(conn, data, len);
  };
  host.app_close = [self](uint64_t conn) { self->app_close(conn); };
  host.app_abort = [self](uint64_t conn) { self->app_abort(conn); };
  host.app_shutdown = [self](uint64_t conn) { self->app_shutdown(conn); };
  host.wire_send = [self](uint64_t peer, const uint8_t* wire, size_t len) {
    return self->wire_send(peer, wire, len);
  };
  host.dial = [self](uint64_t conn, const ProxyTarget& target) {
    self->dial(conn, target);
  };
  host.peer_key = [self](uint64_t peer) { return self->peer_key(peer); };
  host.peer_bound = [self](uint64_t peer) { self->peer_bound(peer); };
  host.peer_retired = [self](uint64_t peer) { self->peer_retired(peer); };
  host.log = [self](const std::string& line) {
    // 等级是全局裁决者：阈值外的行 stderr 与文件都不落。
    self->log_line(line);
  };
  return host;
}

Reactor::~Reactor() {
  // The resolver threads hold their own reference to the queue, so a
  // getaddrinfo() still in flight at shutdown writes into memory that is
  // still alive. They exit at their next wake once stopping is visible.
  {
    const std::lock_guard<std::mutex> lock(resolve_->mutex);
    resolve_->stopping = true;
  }
  resolve_->wake.notify_all();
  // Winsock forbids WSACleanup() while another thread is still inside a
  // Winsock call (getaddrinfo here), and a detached thread could also outlive
  // the queue. Join every worker before the cleanup below (A-01). A worker
  // blocked in getaddrinfo delays shutdown by that lookup, which is the
  // correct trade.
  for (std::thread& t : workers_) {
    if (t.joinable()) {
      t.join();
    }
  }
  workers_.clear();
  // Restore the process-wide handlers this instance replaced, so a second
  // Reactor (tests, an embedded run) does not inherit a stale callback.
  if (prev_int_ != nullptr) {
    std::signal(SIGINT, prev_int_);
  }
  if (prev_term_ != nullptr) {
    std::signal(SIGTERM, prev_term_);
  }
#ifndef _WIN32
  if (prev_pipe_ != nullptr) {
    std::signal(SIGPIPE, prev_pipe_);
  }
#endif
  for (const auto& e : locals_) {
    CloseSock(e.second);
  }
  for (const auto& e : targets_) {
    CloseSock(e.second);
  }
  for (const auto& e : pending_) {
    CloseSock(e.second.sock);
  }
  // The socket tables are cleared as well as closed: ~ProxyEngine runs after
  // this body (it is declared before them, so it is destroyed last) and a
  // teardown hook that sends or looks up a connection must find a consistent,
  // empty world -- not a closed descriptor or a dangling entry.
  locals_.clear();
  targets_.clear();
  pending_.clear();
  dial_addrs_.clear();
  // The bench session's teardown flushes through the UDP socket, so retire it
  // before the descriptor goes away.
  bench_.reset();
  if (udp_ != kBadSock) {
    CloseSock(udp_);
    udp_ = kBadSock;
  }
  if (listener_ != kBadSock) {
    CloseSock(listener_);
    listener_ = kBadSock;
  }
#ifdef _WIN32
  if (wsa_owner_) {
    WSACleanup();
  }
#endif
}

bool Reactor::open_udp(std::string* error) {
  udp_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (udp_ == kBadSock) {
    *error = "udp socket: " + ErrText(SockErr());
    return false;
  }
  TuneUdp(udp_);
#ifdef __linux__
  // P1-4 receive arena, allocated only on Linux. The slot bound has to cover
  // the largest GRO bundle: 64 segments within the biggest datagram this
  // socket can carry — the PMTUD ceiling when probing is on (a raised receive
  // size is how that ladder works), else --mtu.
  const size_t wire_cap =
      base_config_.pmtud && base_config_.pmtu_max_mtu > base_config_.mtu
          ? static_cast<size_t>(base_config_.pmtu_max_mtu)
          : static_cast<size_t>(base_config_.mtu);
  udp_slot_bytes_ = 64 * wire_cap;
  udp_batch_.resize(static_cast<size_t>(kRecvBatchMsgs) * udp_slot_bytes_);
  // Receive aggregation: same-size same-flow datagrams coalesce in-kernel and
  // the read names its segment size via cmsg. On by default (--no-udp-gro to
  // retire it); a kernel without UDP_GRO (or a sandbox that says no) keeps the
  // plain loop below.
  if (opt_.udp_gro) {
    const int one = 1;
    if (setsockopt(udp_, SOL_UDP, UDP_GRO, &one, sizeof(one)) != 0) {
      gro_ok_ = false;
    }
  } else {
    gro_ok_ = false;
  }
#endif
  // DF is socket-wide, so it also covers the configured-size data path. Only
  // ask for it when PMTUD is actually on: with --no-pmtud (or when the CLI
  // disabled it because --mtu exceeds the local interface) the old behaviour --
  // the kernel fragments an oversized datagram -- is what keeps the tunnel
  // working, and turning DF on would replace it with EMSGSIZE on every send.
  if (base_config_.pmtud) {
    if (!SetDontFragment(udp_)) {
      // Without DF an oversized probe is fragmented and arrives, so an ack
      // stops being evidence that the path can carry that size. Stay at the
      // configured MTU instead of measuring a lie.
      engine_.set_pmtud(false);
      // Not verbose-gated: this silently changes what the tunnel can discover,
      // and the operator should see it exactly once at startup.
      note("UDP socket has no DF mode; PMTUD disabled",
           Severity(LogLevel::kWarn));
    }
  }
  // P5-09: a failed start must not leak the descriptor it already created.
  auto fail = [this, error](std::string message) {
    *error = std::move(message);
    if (udp_ != kBadSock) {
      CloseSock(udp_);
      udp_ = kBadSock;
    }
    return false;
  };
  if (opt_.role == EngineRole::kClient) {
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(static_cast<uint16_t>(opt_.remote_port));
    if (inet_pton(AF_INET, opt_.remote_host.c_str(), &remote.sin_addr) != 1) {
      return fail("--remote must be an IPv4 address, got '" + opt_.remote_host + "'");
    }
    if (::connect(udp_, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
      return fail("udp connect: " + ErrText(SockErr()));
    }
    // Peer id 0, the only one a client has. No session is ever released on
    // this side, so the slot is marked in use permanently.
    PeerSlot slot;
    slot.addr = remote;
    slot.used = true;
    peers_.push_back(slot);
  } else {
    EnableReuse(udp_);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(static_cast<uint16_t>(opt_.bind_port));
    if (opt_.bind_addr.empty() || opt_.bind_addr == "0.0.0.0") {
      local.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, opt_.bind_addr.c_str(), &local.sin_addr) != 1) {
      return fail("--bind must be an IPv4 address, got '" + opt_.bind_addr + "'");
    }
    if (::bind(udp_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
      return fail("udp bind " + host_port(opt_.bind_addr, opt_.bind_port) + ": " +
                  ErrText(SockErr()));
    }
  }
  if (!SetNonBlocking(udp_)) {
    return fail("udp nonblocking: " + ErrText(SockErr()));
  }
  return true;
}

bool Reactor::open_listener(std::string* error) {
  listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener_ == kBadSock) {
    *error = "listener: " + ErrText(SockErr());
    return false;
  }
  EnableReuse(listener_);
  auto fail = [this, error](std::string message) {
    *error = std::move(message);
    if (listener_ != kBadSock) {
      CloseSock(listener_);
      listener_ = kBadSock;
    }
    return false;
  };
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(opt_.listen_port));
  if (inet_pton(AF_INET, opt_.listen_addr.c_str(), &addr.sin_addr) != 1) {
    return fail("--listen must be an IPv4 address, got '" + opt_.listen_addr + "'");
  }
  if (::bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    return fail("listener bind " + host_port(opt_.listen_addr, opt_.listen_port) + ": " +
                ErrText(SockErr()));
  }
  if (::listen(listener_, 64) != 0) {
    return fail("listen: " + ErrText(SockErr()));
  }
  if (!SetNonBlocking(listener_)) {
    return fail("listener nonblocking: " + ErrText(SockErr()));
  }
  return true;
}

bool Reactor::start(std::string* error) {
  // select()/fd_set can only watch FD_SETSIZE descriptors (and on POSIX only
  // descriptors whose value is below it). Each session needs one TCP socket
  // plus the UDP socket and, on the client, the listener; past the limit
  // build_sets() drops sockets silently, so refuse the configuration up front
  // rather than accept connections that can never move (M-01).
  const size_t need = max_sessions_ + 16;
  if (need > FD_SETSIZE) {
    *error = "--max-sessions " + std::to_string(max_sessions_) +
             " needs " + std::to_string(need) + " descriptors, but fd_set holds " +
             std::to_string(FD_SETSIZE) + "; lower --max-sessions";
    return false;
  }
#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    *error = "WSAStartup failed";
    return false;
  }
  wsa_owner_ = true;
#endif
  // Startup phase timing: the console/one-shot companions of the desktop
  // launcher (P-启动快照). Measured here, printed once below the endpoint echo.
  const int64_t started_at = NowMs();
  // --log-file 尽早开：后面每一步（socket、握手、tick）都该有一行落档。
  open_log_file();
  if (!open_udp(error)) {
    return false;
  }
  const int64_t udp_done = NowMs();
  int64_t listener_done = udp_done;
  if (opt_.role == EngineRole::kServer && opt_.speedtest) {
    // The responder's send callback goes straight to ::sendto and thus bypasses
    // the shaper on purpose: the bench measures raw link throughput (--rate-limit
    // shapes the tunnels this server also serves, which this socket is not).
    bench::Options bench_options;
    std::memcpy(bench_options.key, base_config_.key, sizeof(bench_options.key));
    bench_options.d = base_config_.d;
    bench_options.p = base_config_.p;
    bench_options.p_max = base_config_.p_max;
    bench_options.mtu = base_config_.mtu;
    bench_options.ip_hdr_len = base_config_.ip_hdr_len;
    bench_options.fec_budget = base_config_.fec_budget;
    bench_ = std::make_unique<BenchServer>(
        bench_options,
        [this](const BenchServer::Peer& peer, const uint8_t* data, size_t len) {
          sockaddr_in to{};
          static_assert(sizeof(to) == sizeof(peer.bytes),
                        "the bench peer key is a raw sockaddr_in");
          std::memcpy(&to, peer.bytes, sizeof(to));
          const int n =
              ::sendto(udp_, reinterpret_cast<const char*>(data), static_cast<int>(len), 0,
                       reinterpret_cast<const sockaddr*>(&to), sizeof(to));
          return n > 0 ? static_cast<size_t>(n) : 0;
        },
        [this](const std::string& line) { log_line(line); });
  }
  if (opt_.role == EngineRole::kClient && !open_listener(error)) {
    if (udp_ != kBadSock) {
      CloseSock(udp_);
      udp_ = kBadSock;
    }
    return false;
  }
  listener_done = NowMs();
  workers_.reserve(kResolverWorkers);
  for (size_t i = 0; i < kResolverWorkers; ++i) {
    workers_.emplace_back([queue = resolve_]() { resolve_worker(queue); });
  }
  const int64_t workers_done = NowMs();
  if (opt_.role == EngineRole::kClient) {
    note("client: socks5/http on " + host_port(opt_.listen_addr, opt_.listen_port) +
         " -> fcp " + host_port(opt_.remote_host, opt_.remote_port));
  } else {
    note("server: fcp on " + host_port(opt_.bind_addr, opt_.bind_port));
    if (bench_ != nullptr) {
      note("server: speedtest responder on the same UDP port");
    }
  }
  // One-line config echo for support tickets. Never prints key material: the
  // PSK lives in a file or an environment variable and stays there (C-18).
  if (opt_.psk_from_default_env) {
    note("key: environment variable FCP_PSK (implicit; no --key* argument given)");
  }
  {
    const EngineConfig& ec = base_config_;
    std::string where = opt_.role == EngineRole::kClient
                            ? host_port(opt_.listen_addr, opt_.listen_port) + " -> " +
                                  host_port(opt_.remote_host, opt_.remote_port)
                            : host_port(opt_.bind_addr, opt_.bind_port);
    char echo[512];
    std::snprintf(
        echo, sizeof(echo),
        "config: %s mtu=%u pmtud=%s pmtu_max=%u fec=%u:%u p_max=%u k=%d budget=%.2f "
        "window=%s:%zuK bbr=v%d probe=%s ackx%u idle=%.0fs stall=%lldms rate=%.1fMbps",
        where.c_str(), static_cast<unsigned>(ec.mtu), ec.pmtud ? "on" : "off",
        static_cast<unsigned>(ec.pmtu_max_mtu), static_cast<unsigned>(ec.d),
        static_cast<unsigned>(ec.p), static_cast<unsigned>(ec.p_max), ec.pinned_k,
        ec.fec_budget, ec.auto_window ? "auto" : "fixed",
        ec.send_window_bytes / 1024, ec.bbr_version, ec.window_probe ? "on" : "off",
        static_cast<unsigned>(ec.ack_every), ec.idle_timeout_ms / 1000.0,
        static_cast<long long>(opt_.role == EngineRole::kClient ? opt_.stall_ms : 0),
        static_cast<double>(shaper_bytes_per_sec()) * 8.0 / 1e6);
    note(echo);
  }
  // The "startup" line names bytes/s as Mbps because it is what the shaper
  // was handed; --rate-limit halves that do not apply to this role read 0.
  char startup[128];
  std::snprintf(startup, sizeof(startup),
                "startup: udp=%dms listen=%dms workers=%dms total=%dms",
                static_cast<int>(udp_done - started_at),
                static_cast<int>(listener_done - udp_done),
                static_cast<int>(workers_done - listener_done),
                static_cast<int>(workers_done - started_at));
  note(startup);
  // Save the handlers this instance replaces: they are process-wide, and a
  // second Reactor in the same process must not inherit a stale callback.
  SignalHandler prev = std::signal(SIGINT, OnSignal);
  if (prev != SIG_ERR) {
    prev_int_ = prev;
  }
  prev = std::signal(SIGTERM, OnSignal);
  if (prev != SIG_ERR) {
    prev_term_ = prev;
  }
#ifndef _WIN32
  // A7: a local application that closes its TCP socket turns the next send()
  // into EPIPE plus SIGPIPE, whose default action kills the whole proxy (and
  // every other tunnel with it). app_send already treats the -1 as a fatal
  // socket error; the signal just must not terminate the process.
  prev = std::signal(SIGPIPE, SIG_IGN);
  if (prev != SIG_ERR) {
    prev_pipe_ = prev;
  }
#endif
  started_ms_ = NowMs();
  next_tick_ms_ = started_ms_;
  next_stats_ms_ = opt_.stats_ms != 0 ? started_ms_ + opt_.stats_ms : 0;
  // The watchdog measures "no inbound since X"; without a seed, a tunnel that
  // has never received a byte would look dark since epoch 0 and the first
  // outbound datagram would instantly declare a stall. Start both clocks at
  // startup so the first stall can only be a real silence after real traffic.
  stall_last_rx_ms_ = started_ms_;
  stall_last_tx_ms_ = started_ms_;
  return true;
}

void Reactor::run() {
  // The flag is process-wide (the signal handler cannot capture `this`); a
  // Reactor that was stopped and started again must not exit on the first
  // loop iteration because of the previous run's signal (A-13).
  g_signalled.store(false);
  // Sub-tick wakeups need the 1 ms timer resolution; see TimerResolution. A
  // server that would rather trade latency for CPU is out of scope here: the
  // pacer fires under this resolution by design (P1-1).
#ifdef _WIN32
  TimerResolution timer(true);
#endif
  while (!g_signalled.load()) {
    int64_t now = NowMs();

    flush_dead_apps(now);
    flush_wire_deferred(now);
    drain_resolves(now);
    drain_udp(now);
    expire_connects(now);

    fd_set read_set;
    fd_set write_set;
    fd_set except_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);
    sel_read_.clear();
    sel_connect_.clear();
    sel_write_.clear();
    sel_except_.clear();
    const int nfds = build_sets(&read_set, &write_set, &except_set, &sel_read_, &sel_connect_,
                                &sel_write_, &sel_except_);

    timeval tv{};
    // Sub-tick deadline: a pending coalesced ACK or the pacer releasing the
    // next segment. Without it the token bucket and delayed ACKs would only
    // move on the 25 ms tick, which is what turned BBR pacing into a burst
    // emitter and delayed a short exchange's ACK by up to a tick.
#ifdef __linux__
    // The engine's sends during this iteration (ACK repairs, pacer releases,
    // app reads) pulled from UDP buffers: ship the batch now, before the loop
    // can wait in select() with data still buffered.
    flush_udp_batch();
#endif
    const int64_t wake = engine_.next_wake_ms(now);
    const int64_t wait = wait_ms(now, wake);
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(wait / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((wait % 1000) * 1000);
    const int ready = ::select(nfds, &read_set, &write_set, &except_set, &tv);
    if (ready < 0) {
      const int err = SockErr();
#ifdef _WIN32
      note("select: " + ErrText(err), Severity(LogLevel::kError));
#else
      if (err != EINTR) {
        note("select: " + ErrText(err), Severity(LogLevel::kError));
        break;
      }
#endif
    }

    now = NowMs();
    if (ready > 0) {
      if (udp_ != kBadSock && FD_ISSET(udp_, &read_set)) {
        drain_udp(now);
      }
      if (listener_ != kBadSock && FD_ISSET(listener_, &read_set)) {
        accept_local(now);
      }
      for (const auto& e : sel_connect_) {
        if (FD_ISSET(e.first, &write_set)) {
          connect_event(e.first, e.second, now);
        }
      }
      for (const auto& e : sel_read_) {
        if (FD_ISSET(e.first, &read_set)) {
          read_socket(e.first, e.second, targets_.count(e.second) != 0, now);
        }
      }
      for (const auto& e : sel_write_) {
        if (FD_ISSET(e.first, &write_set)) {
          flush_conn(e.second, now);
        }
      }
      for (const auto& e : sel_except_) {
        if (FD_ISSET(e.first, &except_set)) {
          except_event(e.first, e.second, now);
        }
      }
    }

    // Sockets build_sets() could not fit are read here instead of being starved
    // until a restart. read_socket is non-blocking and stops at the first
    // would-block, so a skipped socket costs one recv per loop.
    for (uint64_t conn : unmonitored_) {
      const auto lt = locals_.find(conn);
      if (lt != locals_.end()) {
        read_socket(lt->second, conn, false, now);
        continue;
      }
      const auto tt = targets_.find(conn);
      if (tt != targets_.end()) {
        read_socket(tt->second, conn, true, now);
      }
    }
    if (skipped_this_pass_ != 0) {
      skipped_total_ += skipped_this_pass_;
      if (now >= next_skip_log_ms_) {
        next_skip_log_ms_ = now + 5000;
        char msg[128];
        std::snprintf(msg, sizeof(msg),
                      "reactor: %zu socket(s) could not be watched by select "
                      "(total %llu); lower --max-sessions",
                      skipped_this_pass_,
                      static_cast<unsigned long long>(skipped_total_));
        note(msg, Severity(LogLevel::kWarn));
      }
    }

    if (now < next_tick_ms_ && wake != 0 && now >= wake) {
      // Woke early for the pacer / a coalesced ACK. Only the engine has work to
      // do; the per-tick application flush below is left for the real tick so
      // a sub-tick wake stays cheap. next_tick_ms_ is untouched.
      engine_.on_tick(now);
    }
    if (now >= next_tick_ms_) {
      next_tick_ms_ = now + kReactorTickMs;
      engine_.on_tick(now);
      if (bench_ != nullptr) {
        bench_->OnTick(now);
      }
      check_stall(now);
      check_high_loss(now);
      // Anything the engine still owes an application socket gets another try
      // here, whether or not select reported it: the pending byte count is the
      // engine's, so this is the only place a stalled write can be retried.
      // Same hazard as A5 in the Qt host: flush_conn can synchronously reach
      // app_close(), which erases from these maps. Walk an id snapshot and
      // re-find each entry (the reactor has no nested loop today, but the
      // invariant should not rest on that).
      scratch_local_ids_.clear();
      scratch_local_ids_.reserve(locals_.size());
      for (const auto& e : locals_) {
        scratch_local_ids_.push_back(e.first);
      }
      for (uint64_t id : scratch_local_ids_) {
        if (locals_.find(id) != locals_.end() && engine_.pending_app_bytes(id) != 0) {
          flush_conn(id, now);
        }
      }
      scratch_target_ids_.clear();
      scratch_target_ids_.reserve(targets_.size());
      for (const auto& e : targets_) {
        scratch_target_ids_.push_back(e.first);
      }
      for (uint64_t id : scratch_target_ids_) {
        if (targets_.find(id) != targets_.end() && engine_.pending_app_bytes(id) != 0) {
          flush_conn(id, now);
        }
      }
    }
    if (next_stats_ms_ != 0 && now >= next_stats_ms_) {
      next_stats_ms_ = now + opt_.stats_ms;
      print_stats(now);
    }
  }
  // One last tick so the teardown logs and the final counters are complete.
  engine_.on_tick(NowMs());
  // The last tick's and the teardown's own datagrams may still sit in the
  // GSO batch or the shaper hold queue (engine counters already claim them
  // as accepted): drain both before the watchdog calls the process goodbye,
  // or the session-closing FECSTAT rides nowhere.
  flush_wire_deferred(NowMs(), /*force=*/true);
#ifdef __linux__
  flush_udp_batch();
#endif
  print_stats(NowMs());
}

int64_t Reactor::wait_ms(int64_t now_ms, int64_t wake_ms) const {
  int64_t wait = next_tick_ms_ > now_ms ? next_tick_ms_ - now_ms : 1;
  if (wake_ms > 0) {
    const int64_t left = wake_ms - now_ms;
    wait = std::min(wait, left > 0 ? left : 1);
  }
  for (const auto& e : pending_) {
    const int64_t left = e.second.deadline_ms - now_ms;
    if (left > 0) {
      wait = std::min(wait, left);
    }
  }
  return std::max<int64_t>(1, std::min(wait, static_cast<int64_t>(kReactorTickMs)));
}

int Reactor::build_sets(fd_set* read_set, fd_set* write_set, fd_set* except_set,
                        std::unordered_map<Sock, uint64_t>* read_conn,
                        std::unordered_map<Sock, uint64_t>* connect_conn,
                        std::unordered_map<Sock, uint64_t>* write_conn,
                        std::unordered_map<Sock, uint64_t>* except_conn) {
  int nfds = 0;
  // Each set holds at most FD_SETSIZE descriptors. On Windows that is a count
  // bound only (fd_set is an array of SOCKET handles), but on POSIX fd_set is a
  // bitmap indexed by descriptor value: a descriptor >= FD_SETSIZE overruns it
  // no matter how few entries the set holds, so the value has to be checked
  // there too. A socket that does not fit stays unmonitored for this iteration
  // and the tick retries it.
  size_t nread = 0;
  size_t nwrite = 0;
  size_t nexcept = 0;
  skipped_this_pass_ = 0;
  unmonitored_.clear();
  auto fits = [](Sock s) {
#ifdef _WIN32
    (void)s;
    return true;
#else
    return s >= 0 && s < FD_SETSIZE;
#endif
  };
  auto bump = [&nfds](Sock s) {
    if (static_cast<int>(s) + 1 > nfds) {
      nfds = static_cast<int>(s) + 1;
    }
  };
  auto add_read = [&](Sock s, uint64_t conn) {
    if (!fits(s) || nread >= FD_SETSIZE) {
      ++skipped_this_pass_;
      if (conn != 0) {
        unmonitored_.push_back(conn);
      }
      return;
    }
    ++nread;
    FD_SET(s, read_set);
    read_conn->emplace(s, conn);
    bump(s);
  };
  auto add_write = [&](Sock s, uint64_t conn, std::unordered_map<Sock, uint64_t>* into) {
    if (!fits(s) || nwrite >= FD_SETSIZE) {
      ++skipped_this_pass_;  // ticks already retry these writes
      return;
    }
    ++nwrite;
    FD_SET(s, write_set);
    into->emplace(s, conn);
    bump(s);
  };
  auto add_except = [&](Sock s, uint64_t conn) {
    if (!fits(s) || nexcept >= FD_SETSIZE) {
      ++skipped_this_pass_;
      return;
    }
    ++nexcept;
    FD_SET(s, except_set);
    except_conn->emplace(s, conn);
    bump(s);
  };
  if (udp_ != kBadSock) {
    // Reserved in the count but not in read_conn: the loop services the UDP
    // socket by descriptor, since it belongs to no connection.
    if (fits(udp_) && nread < FD_SETSIZE) {
      ++nread;
      FD_SET(udp_, read_set);
      bump(udp_);
    } else {
      ++skipped_this_pass_;
    }
  }
  if (listener_ != kBadSock) {
    if (fits(listener_) && nread < FD_SETSIZE) {
      ++nread;
      FD_SET(listener_, read_set);
      bump(listener_);
    } else {
      ++skipped_this_pass_;
    }
  }
  for (const auto& e : locals_) {
    if (engine_.wants_local_read(e.first)) {
      add_read(e.second, e.first);
    }
    // Every TCP socket is watched for an exception: a target whose connect was
    // refused only ever becomes ready there.
    add_except(e.second, e.first);
  }
  for (const auto& e : targets_) {
    if (engine_.wants_target_read(e.first)) {
      add_read(e.second, e.first);
    }
    add_except(e.second, e.first);
  }
  for (const auto& e : pending_) {
    // Writable means the connect resolved -- SO_ERROR says whether it succeeded.
    add_write(e.second.sock, e.first, connect_conn);
    add_except(e.second.sock, e.first);
  }
  // Sockets the engine is still trying to feed. These are also retried on the
  // tick, so a lost readiness edge costs one tick, not a stalled connection.
  for (const auto& e : locals_) {
    if (engine_.pending_app_bytes(e.first) != 0) {
      add_write(e.second, e.first, write_conn);
    }
  }
  for (const auto& e : targets_) {
    if (engine_.pending_app_bytes(e.first) != 0) {
      add_write(e.second, e.first, write_conn);
    }
  }
  return nfds;
}

void Reactor::drain_udp(int64_t now_ms) {
  if (udp_ == kBadSock) {
    return;
  }
#ifdef __linux__
  // P1-4: one syscall per batch of up to 8 reads. No fallback: recvmmsg
  // predates every feature this build needs (UDP_SEGMENT is 4.18+, GRO 5.0+).
  drain_udp_mmsg(now_ms);
#else
  for (int i = 0; i < 128; ++i) {  // bounded: a flood must not starve the tick
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const int n = ::recvfrom(udp_, reinterpret_cast<char*>(udp_buf_.data()),
                             static_cast<int>(udp_buf_.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) {
      return;
    }
    drain_datagram(from, udp_buf_.data(), static_cast<size_t>(n), now_ms);
  }
#endif
}

void Reactor::drain_datagram(const sockaddr_in& from, const uint8_t* data,
                             size_t len, int64_t now_ms) {
  if (len == 0) {
    return;
  }
  if (bench_ != nullptr) {
    BenchServer::Peer key{};
    static_assert(sizeof(key.bytes) == sizeof(from),
                  "the bench peer key is a raw sockaddr_in");
    std::memcpy(key.bytes, &from, sizeof(from));
    if (bench_->OnDatagram(key, data, len, now_ms)) {
      return;  // answered in the same pass; do not hand it to a session
    }
  }
  uint64_t peer = 0;
  if (opt_.role == EngineRole::kServer) {
    const auto it = peer_ids_.find(addr_key(reinterpret_cast<const sockaddr*>(&from)));
    if (it != peer_ids_.end()) {
      peer = it->second;
    } else if (!add_peer(from, &peer)) {
      return;  // every slot is bound to a live session: drop, do not track
    }
  }
  engine_.on_wire(peer, data, len, now_ms);
}

#ifdef __linux__
void Reactor::drain_gro(const sockaddr_in& from, const uint8_t* data, size_t len,
                        int gro_seg, int64_t now_ms) {
  // The kernel names a coalesced read's segment size and guarantees the whole
  // bundle came from that size; splitting it is exact, not a guess. A cmsg
  // whose arithmetic does not add up (or a zero/negative one) is treated as a
  // single arrival: the engine's own frame validation is the safety net.
  if (gro_seg > 0 && static_cast<size_t>(gro_seg) < len &&
      len % static_cast<size_t>(gro_seg) == 0) {
    for (size_t off = 0; off < len; off += static_cast<size_t>(gro_seg)) {
      drain_datagram(from, data + off, static_cast<size_t>(gro_seg), now_ms);
    }
    return;
  }
  drain_datagram(from, data, len, now_ms);
}

void Reactor::drain_udp_mmsg(int64_t now_ms) {
  mmsghdr msgs[kRecvBatchMsgs];
  iovec iov[kRecvBatchMsgs];
  sockaddr_in from[kRecvBatchMsgs];
  // Per-slot ancillary space for the kernel's UDP_GRO cmsg (absent on every
  // single-datagram arrival).
  alignas(cmsghdr) char cbuf[kRecvBatchMsgs][CMSG_SPACE(sizeof(int))];
  // The pass is bounded twice on purpose: by bytes (with GRO one read can
  // carry up to 64 datagrams, so the old per-datagram count bound no longer
  // represents the engine work) and by rounds (an empty datagram costs no
  // bytes, so a zero-length flood is a count problem only). 128 KiB/16 reads
  // per pass keeps the 25ms tick comfortable at multi-hundred-Mbps waves.
  size_t budget = kUdpRecvBytes * 2;
  int rounds_left = 128 / kRecvBatchMsgs;
  while (rounds_left-- > 0) {
    for (int i = 0; i < kRecvBatchMsgs; ++i) {
      std::memset(&msgs[i], 0, sizeof(msgs[i]));
      std::memset(&from[i], 0, sizeof(from[i]));
      iov[i].iov_base = udp_batch_.data() + static_cast<size_t>(i) * udp_slot_bytes_;
      iov[i].iov_len = udp_slot_bytes_;
      msgs[i].msg_hdr.msg_iov = &iov[i];
      msgs[i].msg_hdr.msg_iovlen = 1;
      msgs[i].msg_hdr.msg_name = &from[i];
      msgs[i].msg_hdr.msg_namelen = sizeof(from[i]);
      msgs[i].msg_hdr.msg_control = cbuf[i];
      msgs[i].msg_hdr.msg_controllen = sizeof(cbuf[i]);
    }
    const int got = ::recvmmsg(udp_, msgs, kRecvBatchMsgs, MSG_DONTWAIT, nullptr);
    if (got <= 0) {
      return;  // drained (or EAGAIN): the next readiness edge re-enters
    }
    for (int i = 0; i < got; ++i) {
      const size_t len = static_cast<size_t>(msgs[i].msg_len);
      int gro_seg = 0;
      if (gro_ok_ && len > 0 && msgs[i].msg_hdr.msg_controllen >= sizeof(cmsghdr)) {
        for (cmsghdr* cm = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cm != nullptr;
             cm = CMSG_NXTHDR(&msgs[i].msg_hdr, cm)) {
          if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO &&
              cm->cmsg_len == CMSG_LEN(sizeof(int))) {
            std::memcpy(&gro_seg, CMSG_DATA(cm), sizeof(gro_seg));
            break;
          }
        }
      }
      drain_gro(from[i], udp_batch_.data() + static_cast<size_t>(i) * udp_slot_bytes_,
                len, gro_seg, now_ms);
      budget = budget > len ? budget - len : 0;
    }
    if (budget == 0 || got < kRecvBatchMsgs) {
      return;  // budget spent, or the socket emptied for now
    }
  }
}
#endif

void Reactor::accept_local(int64_t now_ms) {
  for (int i = 0; i < 32; ++i) {
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const Sock s = ::accept(listener_, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (s == kBadSock) {
      return;
    }
    // P5' N3: a blocking accepted socket would stall the single-threaded
    // reactor inside the next recv(), letting one client freeze every tunnel.
    if (!SetNonBlocking(s)) {
      CloseSock(s);
      continue;
    }
    const uint64_t conn = next_local_conn_++;
    locals_.emplace(conn, s);
    engine_.on_local_open(conn, 0, now_ms);
  }
}

void Reactor::read_socket(Sock sock, uint64_t conn, bool target, int64_t now_ms) {
  uint8_t buf[kReactorMaxReadBytes];
  for (int i = 0; i < 16; ++i) {
    if (!engine_.has_connection(conn)) {
      return;
    }
    const bool wants = target ? engine_.wants_target_read(conn) : engine_.wants_local_read(conn);
    if (!wants) {
      return;  // the stream window is closed: leave the bytes in TCP
    }
    const int n = ::recv(sock, reinterpret_cast<char*>(buf), static_cast<int>(sizeof(buf)), 0);
    if (n > 0) {
      if (target) {
        engine_.on_target_bytes(conn, buf, static_cast<size_t>(n), now_ms);
      } else {
        engine_.on_local_bytes(conn, buf, static_cast<size_t>(n), now_ms);
      }
      continue;
    }
    if (n == 0) {
      // 对端的 FIN；对端半关闭后仍可能收我们的字节，socket 保留在表里。
      if (target) {
        engine_.on_target_closed(conn, now_ms);
      } else {
        engine_.on_local_closed(conn, now_ms);
      }
      return;
    }
    // 真错误（对端 RST、句柄失效……）：这一刻起 recv 永远命中同一个错误。
    // socket 留在表里的话，select 每一轮都会因为持久错误把它报为可读，
    // 于是 on_*_closed 以一次读一轮的频率反复进入引擎 —— 一个被 RST 的
    // 客户端能把整个 tick 预算烧成千次同步回调（defeating flush grace）。
    // 因此先摘句柄再通知引擎；反向 flush 路径会查不到 socket 而自然跳过
    // （engine 的 teardown 心跳与计时照常），与“句柄已死”之情一致。
    const int err = SockErr();
    // EINTR is not an error: a signal (SIGINT/SIGTERM are handled by this
    // reactor) interrupted the syscall before it moved any byte. Treating it as
    // a persistent error used to close a healthy connection and report a
    // spurious EOF to the engine. The socket is still readable, so retry.
    if (Interrupted(err)) {
      continue;
    }
    if (!WouldBlock(err)) {
      if (target) {
        const auto it = targets_.find(conn);
        if (it != targets_.end()) {
          CloseSock(it->second);
          targets_.erase(it);
        }
        engine_.on_target_reset(conn, now_ms);
      } else {
        const auto it = locals_.find(conn);
        if (it != locals_.end()) {
          CloseSock(it->second);
          locals_.erase(it);
        }
        engine_.on_local_reset(conn, now_ms);
      }
    }
    return;
  }
}

void Reactor::flush_conn(uint64_t conn, int64_t now_ms) {
  engine_.on_app_writable(conn, now_ms);
}

Reactor::ConnectAttempt Reactor::connect_once(uint64_t conn, const sockaddr* addr,
                                              socklen_t len, int64_t now_ms, int* err) {
  if (!engine_.has_connection(conn)) {
    return ConnectAttempt::kGone;  // torn down while the name was being looked up
  }
  const Sock s = ::socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (s == kBadSock) {
    *err = SockErr();
    return ConnectAttempt::kFailed;
  }
  if (!SetNonBlocking(s)) {
    *err = SockErr();
    CloseSock(s);
    return ConnectAttempt::kFailed;
  }
  if (::connect(s, addr, len) == 0) {
    // emplace can fail when the id already has a target (a retry racing an
    // earlier attempt); the fresh socket must not leak in that case, and the
    // engine must not be told a target exists for a socket nobody owns.
    if (!targets_.emplace(conn, s).second) {
      CloseSock(s);
      return ConnectAttempt::kFailed;
    }
    engine_.on_dial_result(conn, true, OpenError::kRefused, now_ms);
    return ConnectAttempt::kConnected;
  }
  const int connect_err = SockErr();
  if (!Connecting(connect_err) && !WouldBlock(connect_err)) {
    CloseSock(s);
    *err = connect_err;
    return ConnectAttempt::kFailed;
  }
  Pending p;
  p.sock = s;
  p.deadline_ms = now_ms + opt_.connect_timeout_ms;
  // Same contract as targets_ above: if an earlier attempt for this id is
  // still pending, keep it and close the socket this attempt just opened --
  // overwriting the entry would leave the old descriptor with no owner.
  if (!pending_.emplace(conn, p).second) {
    CloseSock(s);
    return ConnectAttempt::kFailed;
  }
  return ConnectAttempt::kPending;
}

bool Reactor::connect_addresses(uint64_t conn, int64_t now_ms, int* last_err) {
  // The queue is detached before connect_once() runs. A connect that succeeds
  // immediately (loopback, LAN, a host already listening) calls
  // engine_.on_dial_result() synchronously, and that can finish the connection
  // and reap it -- which calls back into app_close() and erases this very entry.
  // Holding a deque reference or a dial_addrs_ iterator across the call was a
  // use-after-free; only an id may cross a host callback.
  std::deque<ResolvedAddr> queue;
  {
    const auto it = dial_addrs_.find(conn);
    if (it == dial_addrs_.end()) {
      return false;
    }
    queue.swap(it->second);
    dial_addrs_.erase(it);
  }
  while (!queue.empty()) {
    const ResolvedAddr a = queue.front();
    queue.pop_front();
    const ConnectAttempt r =
        connect_once(conn, reinterpret_cast<const sockaddr*>(&a.addr), a.len, now_ms, last_err);
    if (r == ConnectAttempt::kFailed) {
      continue;
    }
    if (r == ConnectAttempt::kGone) {
      return true;
    }
    if (!queue.empty()) {
      // Another address is still to be tried if this one fails; put the rest
      // back (the connection may have disappeared in the callback, in which
      // case the records are simply dropped with this scope).
      dial_addrs_[conn].swap(queue);
    }
    // The attempt in flight is the last record: a later connect failure has
    // nothing left to try.
    return true;
  }
  return false;
}

void Reactor::connect_event(Sock sock, uint64_t conn, int64_t now_ms) {
  const auto it = pending_.find(conn);
  if (it == pending_.end() || it->second.sock != sock) {
    return;  // already handled, or the socket was closed under the event
  }
  int err = 0;
  socklen_t len = sizeof(err);
  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) {
    err = SockErr();
  }
  pending_.erase(it);
  if (err == 0) {
    targets_.emplace(conn, sock);
    dial_addrs_.erase(conn);
    engine_.on_dial_result(conn, true, OpenError::kRefused, now_ms);
    return;
  }
  CloseSock(sock);
  if (connect_addresses(conn, now_ms, &err)) {
    return;  // another record is in flight, or the tunnel is already gone
  }
  engine_.on_dial_result(conn, false, open_error_for(err), now_ms);
}

void Reactor::except_event(Sock sock, uint64_t conn, int64_t now_ms) {
  const auto pending = pending_.find(conn);
  if (pending != pending_.end() && pending->second.sock == sock) {
    // Windows puts a connect that *failed* in the exception set, not the write
    // set: without this branch a refused target would sit until the dial timeout
    // and be reported as a timeout instead of a refusal.
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) {
      err = SockErr();
    }
    if (err == 0) {
      err = kErrRefused;
    }
    CloseSock(sock);
    pending_.erase(pending);
    if (connect_addresses(conn, now_ms, &err)) {
      return;
    }
    engine_.on_dial_result(conn, false, open_error_for(err), now_ms);
    return;
  }
  // On a live socket an exception means a broken connection or urgent data this
  // proxy does not carry, so either way the tunnel is over. The descriptor in
  // the set is a snapshot: an earlier branch in this same iteration may have
  // closed it and a new connection may already own that number, so only act
  // when the table still maps this conn to the very same socket (A-11).
  const auto target = targets_.find(conn);
  if (target != targets_.end() && target->second == sock) {
    targets_.erase(target);
    CloseSock(sock);
    engine_.on_target_reset(conn, now_ms);
    return;
  }
  const auto local = locals_.find(conn);
  if (local != locals_.end() && local->second == sock) {
    locals_.erase(local);
    CloseSock(sock);
    // The local half is gone, so the engine only needs to be told the app stopped
    // reading; app_close on an already-erased socket is a no-op.
    engine_.on_local_reset(conn, now_ms);
  }
}

void Reactor::expire_connects(int64_t now_ms) {
  scratch_due_.clear();
  for (const auto& e : pending_) {
    if (e.second.deadline_ms <= now_ms) {
      scratch_due_.push_back(e.first);
    }
  }
  for (uint64_t conn : scratch_due_) {
    const auto it = pending_.find(conn);
    if (it == pending_.end()) {
      continue;
    }
    CloseSock(it->second.sock);
    pending_.erase(it);
    // The budget belongs to one address attempt. Spend the remaining records
    // before giving up with the timeout the application is owed.
    int last_err = kErrTimeout;
    if (connect_addresses(conn, now_ms, &last_err)) {
      continue;
    }
    engine_.on_dial_result(conn, false, OpenError::kTargetTimeout, now_ms);
  }
}

void Reactor::dial(uint64_t conn, const ProxyTarget& target) {
  std::string host;
  uint16_t port = 0;
  target_text(target, &host, &port);
  if (host.empty() || port == 0) {
    engine_.on_dial_result(conn, false, OpenError::kDns, NowMs());
    return;
  }
  sockaddr_in direct{};
  if (inet_pton(AF_INET, host.c_str(), &direct.sin_addr) == 1) {
    direct.sin_family = AF_INET;
    direct.sin_port = htons(port);
    int err = 0;
    if (connect_once(conn, reinterpret_cast<sockaddr*>(&direct), sizeof(direct), NowMs(),
                     &err) == ConnectAttempt::kFailed) {
      engine_.on_dial_result(conn, false, open_error_for(err), NowMs());
    }
    return;
  }
  in6_addr v6{};
  if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    sockaddr_in6 a6{};
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons(port);
    std::memcpy(&a6.sin6_addr, &v6, sizeof(v6));
    int err = 0;
    if (connect_once(conn, reinterpret_cast<sockaddr*>(&a6), sizeof(a6), NowMs(), &err) ==
        ConnectAttempt::kFailed) {
      engine_.on_dial_result(conn, false, open_error_for(err), NowMs());
    }
    return;
  }
  // A name: hand it to the resolver pool, then connect on this thread when the
  // answer lands in drain_resolves(). The workers never touch a descriptor, so
  // the reactor stays the only socket owner.
  ResolveJob job;
  job.conn = conn;
  job.host = host;
  job.port = port;
  bool queued = false;
  {
    const std::lock_guard<std::mutex> lock(resolve_->mutex);
    if (!resolve_->stopping && resolve_->jobs.size() < kResolverMaxQueued) {
      resolve_->jobs.push_back(std::move(job));
      queued = true;
    }
  }
  if (!queued) {
    // Saturated or shutting down: answer now rather than leave the connection
    // hanging until its dial deadline.
    engine_.on_dial_result(conn, false, OpenError::kDns, NowMs());
    return;
  }
  resolve_->wake.notify_one();
}

void Reactor::resolve_worker(std::shared_ptr<ResolveQueue> queue) {
  for (;;) {
    ResolveJob job;
    {
      std::unique_lock<std::mutex> lock(queue->mutex);
      queue->wake.wait(lock, [&queue] { return queue->stopping || !queue->jobs.empty(); });
      if (queue->stopping) {
        return;
      }
      job = std::move(queue->jobs.front());
      queue->jobs.pop_front();
    }
    ResolveResult r;
    r.conn = job.conn;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char service[8];
    std::snprintf(service, sizeof(service), "%u", static_cast<unsigned>(job.port));
    addrinfo* res = nullptr;
    if (getaddrinfo(job.host.c_str(), service, &hints, &res) == 0) {
      // Keep every usable answer, not just the first: "localhost" is usually
      // ::1 even when the service listens on IPv4 only, and a multi-homed
      // name has to fail over between its records.
      for (const addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_addr == nullptr || ai->ai_addrlen > sizeof(sockaddr_storage)) {
          continue;
        }
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
          continue;
        }
        if (r.addrs.size() >= kResolverMaxAddrs) {
          break;
        }
        ResolvedAddr a;
        std::memcpy(&a.addr, ai->ai_addr, static_cast<size_t>(ai->ai_addrlen));
        a.len = static_cast<socklen_t>(ai->ai_addrlen);
        r.addrs.push_back(a);
      }
      r.ok = !r.addrs.empty();
    }
    if (res != nullptr) {
      freeaddrinfo(res);
    }
    {
      const std::lock_guard<std::mutex> lock(queue->mutex);
      if (queue->stopping) {
        return;
      }
      queue->done.push_back(r);
    }
  }
}

void Reactor::drain_resolves(int64_t now_ms) {
  std::vector<ResolveResult> done;
  {
    const std::lock_guard<std::mutex> lock(resolve_->mutex);
    if (resolve_->done.empty()) {
      return;
    }
    done.swap(resolve_->done);
  }
  for (const ResolveResult& r : done) {
    if (!r.ok) {
      engine_.on_dial_result(r.conn, false, OpenError::kDns, now_ms);
      continue;
    }
    std::deque<ResolvedAddr>& queue = dial_addrs_[r.conn];
    queue.assign(r.addrs.begin(), r.addrs.end());
    int last_err = 0;
    if (connect_addresses(r.conn, now_ms, &last_err)) {
      continue;
    }
    // Every record failed locally (socket()/connect() error, no pending
    // attempt): the last error is the one the application is owed.
    engine_.on_dial_result(r.conn, false, open_error_for(last_err), now_ms);
  }
}

size_t Reactor::app_send(uint64_t conn, const uint8_t* data, size_t len) {
  Sock s = first_sock_of(locals_, conn);
  if (s == kBadSock) {
    s = first_sock_of(targets_, conn);
  }
  if (s == kBadSock || len == 0) {
    return 0;
  }
  const int n = ::send(s, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
  if (n > 0) {
    return static_cast<size_t>(n);
  }
  if (n < 0) {
    const int err = SockErr();
    if (!WouldBlock(err) && !Interrupted(err)) {
      // EPIPE/ECONNRESET/EBADF will never become writable. Treated as "would
      // block" the engine retried until the flush grace expired and the
      // application saw a tunnel that never drained (A-05/B-10). Drop the
      // socket now and tell the engine once this callback has returned.
      bool target = false;
      const auto local = locals_.find(conn);
      if (local != locals_.end()) {
        CloseSock(local->second);
        locals_.erase(local);
      } else {
        const auto t = targets_.find(conn);
        if (t != targets_.end()) {
          CloseSock(t->second);
          targets_.erase(t);
          target = true;
        }
      }
      dead_apps_.emplace_back(conn, target);
    }
  }
  return 0;
}

void Reactor::flush_dead_apps(int64_t now_ms) {
  if (dead_apps_.empty()) {
    return;
  }
  const std::vector<std::pair<uint64_t, bool>> dead = std::move(dead_apps_);
  dead_apps_.clear();
  for (const auto& e : dead) {
    if (!engine_.has_connection(e.first)) {
      continue;
    }
    if (e.second) {
      engine_.on_target_reset(e.first, now_ms);
    } else {
      engine_.on_local_reset(e.first, now_ms);
    }
  }
}

Sock Reactor::first_sock_of(const std::unordered_map<uint64_t, Sock>& m, uint64_t conn) {
  const auto it = m.find(conn);
  return it == m.end() ? kBadSock : it->second;
}

void Reactor::app_shutdown(uint64_t conn) {
  // The tunnel's peer finished sending, so the local socket must see EOF. Only
  // the write half goes: the local application may still be producing bytes
  // (the request body after a half-close, a target's response) and those keep
  // flowing through the same conn's read direction.
  const auto local = locals_.find(conn);
  if (local != locals_.end()) {
#ifdef _WIN32
    ::shutdown(local->second, SD_SEND);
#else
    ::shutdown(local->second, SHUT_WR);
#endif
    return;
  }
  const auto target = targets_.find(conn);
  if (target != targets_.end()) {
#ifdef _WIN32
    ::shutdown(target->second, SD_SEND);
#else
    ::shutdown(target->second, SHUT_WR);
#endif
  }
}

void Reactor::app_close(uint64_t conn) {
  const auto local = locals_.find(conn);
  if (local != locals_.end()) {
    CloseSock(local->second);
    locals_.erase(local);
  }
  const auto target = targets_.find(conn);
  if (target != targets_.end()) {
    CloseSock(target->second);
    targets_.erase(target);
  }
  const auto pending = pending_.find(conn);
  if (pending != pending_.end()) {
    CloseSock(pending->second.sock);
    pending_.erase(pending);
  }
  // A resolver result may still be in flight; drain_resolves() finds that the
  // engine no longer knows the conn and stops there.
  dial_addrs_.erase(conn);
}

void Reactor::app_abort(uint64_t conn) {
  Sock s = kBadSock;
  const auto local = locals_.find(conn);
  if (local != locals_.end()) {
    s = local->second;
    locals_.erase(local);
  } else {
    const auto target = targets_.find(conn);
    if (target != targets_.end()) {
      s = target->second;
      targets_.erase(target);
    } else {
      const auto pending = pending_.find(conn);
      if (pending != pending_.end()) {
        s = pending->second.sock;
        pending_.erase(pending);
      }
    }
  }
  if (s != kBadSock) {
    // A zero linger makes close() emit RST instead of FIN, on POSIX and
    // Winsock alike, so the application does not mistake a reset tunnel for a
    // clean end of stream.
    struct linger lg{};
    lg.l_onoff = 1;
    lg.l_linger = 0;
#ifdef _WIN32
    ::setsockopt(s, SOL_SOCKET, SO_LINGER,
                 reinterpret_cast<const char*>(&lg), sizeof(lg));
#else
    ::setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
#endif
    CloseSock(s);
  }
  // A resolver result may still be in flight; drain_resolves() finds that the
  // engine no longer knows the conn and stops there.
  dial_addrs_.erase(conn);
}

// A UDP send that fails permanently used to be indistinguishable from a full
// socket: wire_send returned 0 and the tunnel stalled with no diagnostic. The
// one that matters is EMSGSIZE -- the kernel's own ICMP-learned path-MTU cache
// can sit BELOW the configured --mtu (an intermediate tunnel or firewall sent
// "fragmentation needed", the kernel cached it, and every datagram of that
// size now dies inside send() without reaching the wire). That is immediate,
// authoritative path evidence: feed it straight into the engine's sessions
// (on_wire_send_too_big, not rate-limited -- each refusal is one bounded
// descent step) so the send bound moves the moment the kernel says so, then
// still count the failure and say the first one per second on stderr.
void Reactor::note_udp_send_error(int err, size_t len, uint64_t peer) {
  if (WouldBlock(err) || Interrupted(err)) {
    return;  // transient: the engine retries on the next tick
  }
  ++udp_send_errors_;
#ifdef _WIN32
  const bool too_big = err == WSAEMSGSIZE;
#else
  const bool too_big = err == EMSGSIZE;
#endif
  if (too_big) {
    engine_.on_wire_send_too_big(peer, len, NowMs());
    const int64_t now = NowMs();
    if (last_udp_send_error_ms_ != 0 && now - last_udp_send_error_ms_ < 1000) {
      return;
    }
    last_udp_send_error_ms_ = now;
    char msg[512];
    std::snprintf(msg, sizeof(msg),
                  "UDP send rejected a %zu-byte datagram (EMSGSIZE) at --mtu=%u: "
                  "the kernel's path MTU cache is below it; sessions lowered "
                  "their send bound",
                  len, static_cast<unsigned>(base_config_.mtu));
    note(msg, Severity(LogLevel::kError));
  } else {
    const int64_t now = NowMs();
    if (last_udp_send_error_ms_ != 0 && now - last_udp_send_error_ms_ < 1000) {
      return;
    }
    last_udp_send_error_ms_ = now;
    note(std::string("UDP send failed: ") + ErrText(err),
         Severity(LogLevel::kError));
  }
}

size_t Reactor::wire_send(uint64_t peer, const uint8_t* wire, size_t len) {
  if (udp_ == kBadSock || len == 0) {
    return 0;
  }
  const sockaddr_in* to = nullptr;
  if (opt_.role == EngineRole::kServer) {
    if (peer >= peers_.size() || !peers_[peer].used) {
      return 0;
    }
    to = &peers_[peer].addr;
  }
  const uint64_t budget = shaper_bytes_per_sec();
  if (budget == 0) {
    return emit_wire(peer, wire, len, to);
  }
  // A datagram bigger than the whole second's budget can never be admitted;
  // the CLI forbids such a --rate-limit, so this is a defensive passthrough
  // only (better one unshaped datagram than a permanent hold). While any
  // datagram is held, this one queues behind it: the hold queue is strictly
  // in order, and letting a newcomer pass through would hand the FEC layer
  // out-of-order symbols the shaping was not asked for.
  const int64_t now = NowMs();
  wire_charge(now, 0);  // expire the trailing window's aged entries first
  if (!wire_deferred_.empty()) {
    if (wire_deferred_bytes_ + len <= budget) {
      DeferredWire held;
      held.peer = peer;
      if (to != nullptr) {
        held.to = *to;
        held.has_addr = true;
      }
      held.bytes.assign(wire, wire + len);
      wire_deferred_bytes_ += len;
      wire_deferred_.push_back(std::move(held));
      return len;
    }
    ++wire_over_budget_;
    return len;
  }
  if (len > budget) {
    // An impossible-to-shape datagram goes through rather than stuck forever,
    // but must not be charged: one oversized report would otherwise lock the
    // whole next second's budget and black-hole every normal datagram behind
    // it. The CLI rejects such a --rate-limit; this is a defensive passthrough.
    return emit_wire(peer, wire, len, to);
  }
  if (wire_admit(len)) {
    wire_charge(now, len);
    return emit_wire(peer, wire, len, to);
  }
  // Over budget: hold at the tail of the queue (in order) while the queue is
  // within one second of budget, else drop as a shaped link would. Either way
  // the engine sees an accept -- a shaped drop is link loss, not a wire error,
  // and re-enqueueing the symbol is the FEC/ARQ layer's own business.
  if (wire_deferred_bytes_ + len <= budget) {
    DeferredWire held;
    held.peer = peer;
    if (to != nullptr) {
      held.to = *to;
      held.has_addr = true;
    }
    held.bytes.assign(wire, wire + len);
    wire_deferred_bytes_ += len;
    wire_deferred_.push_back(std::move(held));
    return len;
  }
  ++wire_over_budget_;
  return len;
}

size_t Reactor::emit_wire(uint64_t peer, const uint8_t* wire, size_t len,
                          const sockaddr_in* to) {
#ifndef __linux__
  (void)peer;  // only the Linux GSO batch keys by peer id
#endif
#ifdef __linux__
  // P1-4: coalesce equal-size datagrams into one GSO sendmsg (one syscall for
  // a whole pacer burst). Failures surface at flush_udp_batch(), which degrades
  // the socket to plain sends; the engine's flow-control read of the return
  // value relied on the old byte-for-byte contract, which the buffering keeps
  // (the batch is "accepted" on the spot, kernel loss is UDP loss either way).
  if (gso_reprieve_ > 0) {
    // Count down the pause an EINVAL asked for and re-arm once when it lapses.
    if (--gso_reprieve_ == 0) {
      gso_ok_ = true;
    }
  }
  if (gso_ok_) {
    gso_append(peer, wire, len, to);
    return len;
  }
#endif
  if (opt_.role == EngineRole::kClient) {
    const int n =
        ::send(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0);
    if (n < 0) {
      note_udp_send_error(SockErr(), len, peer);
      return 0;
    }
    return n > 0 ? static_cast<size_t>(n) : 0;
  }
  const int n = ::sendto(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0,
                         reinterpret_cast<const sockaddr*>(to), sizeof(*to));
  if (n < 0) {
    note_udp_send_error(SockErr(), len, peer);
    return 0;
  }
  return n > 0 ? static_cast<size_t>(n) : 0;
}

uint64_t Reactor::shaper_bytes_per_sec() const {
  return opt_.role == EngineRole::kClient ? opt_.rate_up_bytes : opt_.rate_down_bytes;
}

bool Reactor::wire_admit(size_t len) {
  return wire_window_bytes_ + len <= shaper_bytes_per_sec();
}

void Reactor::wire_charge(int64_t now_ms, size_t len) {
  if (len != 0) {
    wire_window_.emplace_back(now_ms, len);
    wire_window_bytes_ += len;
  }
  // Retire what aged out of the trailing second (len == 0 is the pure-expire
  // entry point wire_send uses before testing admission).
  const int64_t floor = now_ms - 1000;
  while (!wire_window_.empty() && wire_window_.front().first <= floor) {
    wire_window_bytes_ -= wire_window_.front().second;
    wire_window_.pop_front();
  }
}

void Reactor::flush_wire_deferred(int64_t now_ms, bool force) {
  if (wire_deferred_.empty()) {
    return;
  }
  const uint64_t budget = shaper_bytes_per_sec();
  if (budget == 0 || force) {
    // `force` is the shutdown path: engine counters already claim these bytes,
    // so hold state must not strand them past budget either.
    while (!wire_deferred_.empty()) {
      DeferredWire& held = wire_deferred_.front();
      wire_deferred_bytes_ -= held.bytes.size();
      emit_wire(held.peer, held.bytes.data(), held.bytes.size(),
                held.has_addr ? &held.to : nullptr);
      wire_deferred_.pop_front();
    }
    wire_window_.clear();
    wire_window_bytes_ = 0;
    return;
  }
  wire_charge(now_ms, 0);
  while (!wire_deferred_.empty() && wire_admit(wire_deferred_.front().bytes.size())) {
    DeferredWire& held = wire_deferred_.front();
    const std::vector<uint8_t> bytes = std::move(held.bytes);
    const uint64_t peer = held.peer;
    const sockaddr_in to = held.to;
    const bool has_addr = held.has_addr;
    wire_deferred_bytes_ -= bytes.size();
    wire_deferred_.pop_front();
    wire_charge(now_ms, bytes.size());
    emit_wire(peer, bytes.data(), bytes.size(), has_addr ? &to : nullptr);
  }
}

void Reactor::check_stall(int64_t now_ms) {
  if (opt_.role != EngineRole::kClient || opt_.stall_ms <= 0) {
    return;
  }
  const ProxyEngine::Counters& c = engine_.counters();
  if (c.live == 0 && stall_since_ms_ == 0) {
    // 空闲隧道两个方向都冻结，这不是死路径。把基线刷到当下：否则空闲几分钟
    // 后第一条新连接发出的 OPEN 会让 TX 看起来"还在动"，而 last_rx 还停在
    // 上一段活跃期，看门狗就把整段空窗报成 half-open（0.0.6 实测：16:32 起
    // 空闲 6 分钟，16:38 新连接一到就误报 371.8s，1.3s 后"恢复"）。
    stall_last_rx_ms_ = now_ms;
    stall_last_tx_ms_ = now_ms;
    return;
  }
  const bool rx_moved = c.bytes_rx != stall_seen_rx_bytes_;
  const bool tx_moved = c.bytes_tx != stall_seen_tx_bytes_;
  if (rx_moved) {
    stall_seen_rx_bytes_ = c.bytes_rx;
    stall_last_rx_ms_ = now_ms;
  }
  if (tx_moved) {
    stall_seen_tx_bytes_ = c.bytes_tx;
    stall_last_tx_ms_ = now_ms;
  }
  if (stall_since_ms_ != 0) {
    // Recovery needs inbound on two consecutive ticks: `bytes_rx` grows on
    // anything that reaches the socket (the engine drops forcible junk on a
    // later validation step), so one forged datagram must not print
    // "recovered" and silence the watchdog. Real traffic recovers within 50ms.
    if (rx_moved && stall_rx_pending_) {
      const double lasted = (now_ms - stall_since_ms_) / 1000.0;
      stall_since_ms_ = 0;
      stall_rx_pending_ = false;
      note("tunnel stall recovered after " + Secs(lasted) + "s (inbound resumed)",
           Severity(LogLevel::kWarn));
      return;
    }
    stall_rx_pending_ = rx_moved;
    if (c.live == 0) {
      const double lasted = (now_ms - stall_since_ms_) / 1000.0;
      stall_since_ms_ = 0;
      note("tunnel closed after " + Secs(lasted) + "s of stall",
           Severity(LogLevel::kWarn));
    } else if (now_ms >= stall_next_log_ms_) {
      // Still dark: re-state the stall every kStallLogMs so a long outage
      // does not look like a single forgotten line in a long log.
      stall_next_log_ms_ = now_ms + kStallLogMs;
      note("tunnel stall: no inbound for " + Secs((now_ms - stall_since_ms_) / 1000.0) +
               "s (still dark)",
           Severity(LogLevel::kWarn));
    }
    return;
  }
  // A tunnel nobody is using freezes both directions; that is an idle tunnel,
  // not a dead path. The stall claim needs traffic still being pushed out
  // (retransmissions count) and a live session behind it. `live` is the
  // current session count (it decrements on teardown); `tunnels` is a
  // monotonic lifetime total and must never gate a "still alive" check.
  const bool looking = c.live != 0 && now_ms - stall_last_rx_ms_ >= opt_.stall_ms;
  const bool pushing = stall_last_tx_ms_ + kStallTxWindowMs > now_ms;
  if (looking && pushing) {
    stall_since_ms_ = stall_last_rx_ms_;
    stall_next_log_ms_ = now_ms + kStallLogMs;
    stall_rx_pending_ = false;
    note("tunnel stall: no inbound for " + Secs((now_ms - stall_since_ms_) / 1000.0) +
             "s while TX is still moving (half-open path?); watching for recovery",
         Severity(LogLevel::kWarn));
  }
  // Dark path with a retransmission engine that has also gone quiet: keep
  // watching without re-declaring (the idle timeout is the backstop that
  // closes the session, which routes through the closed branch above).
}

void Reactor::check_high_loss(int64_t now_ms) {
  if (opt_.role != EngineRole::kClient) {
    return;  // the server aggregates many sessions; the client owns this readout
  }
  if (loss_check_ms_ != 0 && now_ms - loss_check_ms_ < kHighLossSampleMs) {
    return;
  }
  loss_check_ms_ = now_ms;
  if (engine_.counters().live == 0) {
    if (loss_warned_) {
      loss_warned_ = false;
      note("tunnel loss warning cleared (tunnel closed)", Severity(LogLevel::kWarn));
    }
    return;
  }
  const ProxyEngine::LossSample loss = engine_.loss_sample();
  const uint64_t in_ppm = loss.in_expected >= kHighLossMinExpected
                              ? loss.in_lost * 1000000ull / loss.in_expected
                              : 0;
  const uint64_t out_ppm = loss.out_expected >= kHighLossMinExpected
                               ? loss.out_lost * 1000000ull / loss.out_expected
                               : 0;
  const uint64_t ppm = in_ppm > out_ppm ? in_ppm : out_ppm;
  if (ppm < kHighLossWarnPpm) {
    if (loss_warned_) {
      loss_warned_ = false;
      char msg[160];
      std::snprintf(msg, sizeof(msg), "tunnel loss recovered (in=%u ppm, out=%u ppm)",
                    static_cast<unsigned>(in_ppm), static_cast<unsigned>(out_ppm));
      note(msg, Severity(LogLevel::kWarn));
    }
    return;
  }
  // The sample describes the traffic that was flowing when the report was made.
  // A quiet tunnel keeps its last numbers; warning about stale loss would be
  // noise, and the stall watchdog covers the "nothing moves" case.
  if (stall_last_tx_ms_ + kStallTxWindowMs <= now_ms) {
    return;
  }
  if (loss_warned_ && now_ms < loss_warn_next_ms_) {
    return;
  }
  loss_warned_ = true;
  loss_warn_next_ms_ = now_ms + kStallLogMs;
  // Only point at --no-pmtud when it is actually on; with it already off the
  // advice would send the operator in a circle.
  const char* hint = base_config_.pmtud ? " (try --no-pmtud)" : "";
  char msg[224];
  std::snprintf(msg, sizeof(msg),
                "high tunnel loss: in=%u ppm of %llu, out=%u ppm of %llu; full-size "
                "datagrams may be dropped by the path%s",
                static_cast<unsigned>(in_ppm),
                static_cast<unsigned long long>(loss.in_expected),
                static_cast<unsigned>(out_ppm),
                static_cast<unsigned long long>(loss.out_expected), hint);
  note(msg, Severity(LogLevel::kWarn));
}

#ifdef __linux__
void Reactor::gso_append(uint64_t peer, const uint8_t* wire, size_t len,
                         const sockaddr_in* to) {
  // A batch is one (peer, size, address) triple: a changed key flushes
  // whatever packed up before it. Segment size changes (control frames, the
  // tail of a chunk) do the same, so windows between GSO shipments cost at
  // most one sendmsg. The address matters as well as the id: a retired peer's
  // id is reused for a different source address, and two clients may share a
  // segment size -- the batch must never mix their destinations.
  const bool has_to = to != nullptr;
  if (gso_seg_len_ != 0 &&
      (len != gso_seg_len_ || peer != gso_peer_ ||
       (has_to != gso_has_to_ || (has_to && 0 != std::memcmp(to, &gso_to_, sizeof(*to)))) ||
       gso_segs_ >= kGsoMaxSegs)) {
    flush_udp_batch();
  }
  if (gso_buf_.size() < (gso_segs_ + 1) * len) {
    gso_buf_.resize(kGsoMaxSegs * len);
  }
  if (gso_segs_ == 0) {
    gso_has_to_ = has_to;
    if (has_to) {
      gso_to_ = *to;
    }
  }
  std::memcpy(gso_buf_.data() + gso_segs_ * len, wire, len);
  gso_seg_len_ = len;
  gso_peer_ = peer;
  ++gso_segs_;
}

void Reactor::flush_udp_batch() {
  if (gso_seg_len_ == 0) {
    return;
  }
  const size_t seg_len = gso_seg_len_;
  const size_t segs = gso_segs_;
  bool addressed = false;
  sockaddr_in to{};
  // Address what was batched, not what the peer slot may hold by flush time.
  if (gso_has_to_) {
    to = gso_to_;
    addressed = true;
  }
  gso_seg_len_ = 0;
  gso_segs_ = 0;
  gso_has_to_ = false;

  iovec iov{gso_buf_.data(), seg_len * segs};
  msghdr mh{};
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  if (addressed) {
    mh.msg_name = &to;
    mh.msg_namelen = sizeof(to);
  }
  if (gso_ok_ && segs >= 2) {
    alignas(cmsghdr) char cbuf[CMSG_SPACE(sizeof(uint16_t))];
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof(cbuf);
    cmsghdr* cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = IPPROTO_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    const uint16_t gso_size = static_cast<uint16_t>(seg_len);
    std::memcpy(CMSG_DATA(cm), &gso_size, sizeof(gso_size));
    const int n = ::sendmsg(udp_, &mh, 0);
    if (n >= 0) {
      return;
    }
    const int err = SockErr();
    if (err == EIO || err == EOPNOTSUPP) {
      // The kernel or the path below it refuses to segment: this socket never
      // tries GSO again, and what was already batched goes out per datagram.
      // quic-go treats the same pair as a permanent local degradation.
      gso_ok_ = false;
    } else if (err == EINVAL) {
      // Ambiguous: a PMTUD probe above the path MTU produces this (its GSO
      // size exceeds the interface MTU) without GSO being broken at all, and
      // deactivating segmentation for good over one probe is exactly the
      // quiet throughput loss this batch path exists to avoid. Pause instead
      // of retire: wire_send re-arms after the pause lapses, so a PMTUD
      // stream pays at most one failed cmsg per pause, and a kernel without
      // UDP_SEGMENT degrades for real on the first re-arm attempt.
      gso_ok_ = false;
      gso_reprieve_ = 16;
    } else if (err != EINTR) {
      note_udp_send_error(err, seg_len, gso_peer_);
      return;
    }
  }
  // Per-datagram fallback: the normal path for single-segment batches, and
  // the recovery path after the failure above.
  const uint8_t* p = reinterpret_cast<const uint8_t*>(gso_buf_.data());
  for (size_t i = 0; i < segs; ++i, p += seg_len) {
    const int n = addressed ? ::sendto(udp_, reinterpret_cast<const char*>(p),
                                       static_cast<int>(seg_len), 0,
                                       reinterpret_cast<const sockaddr*>(&to), sizeof(to))
                            : ::send(udp_, reinterpret_cast<const char*>(p),
                                     static_cast<int>(seg_len), 0);
    if (n < 0) {
      note_udp_send_error(SockErr(), seg_len, gso_peer_);
      return;
    }
  }
}
#endif

std::string Reactor::peer_key(uint64_t peer) {
  if (peer >= peers_.size() || !peers_[peer].used) {
    return std::string();
  }
  const sockaddr_in& a = peers_[peer].addr;
  return host_port(ip_text(a), ntohs(a.sin_port));
}

bool Reactor::add_peer(const sockaddr_in& from, uint64_t* peer) {
  uint64_t id = 0;
  if (!free_peers_.empty()) {
    id = free_peers_.back();
    free_peers_.pop_back();
  } else if (peers_.size() < kReactorMaxPeers) {
    id = peers_.size();
    peers_.emplace_back();
  } else {
    // At the ceiling. A source without a session -- junk, a refused handshake,
    // a client that has already gone -- must not pin the table and lock every
    // new client out, which is what an append-only table did. Recycle one such
    // slot; the scan is bounded and rotating, and if every slot still has a
    // live session the datagram is dropped as before.
    bool recycled = false;
    for (size_t i = 0; i < kPeerReclaimScan && !recycled; ++i) {
      const size_t at = peer_cursor_;
      peer_cursor_ = (peer_cursor_ + 1) % peers_.size();
      if (peers_[at].used && peers_[at].refs == 0) {
        id = at;
        recycled = true;
      }
    }
    if (!recycled) {
      return false;
    }
    forget_peer(id);  // reused below, so it is not returned to free_peers_
  }
  PeerSlot& slot = peers_[id];
  slot.addr = from;
  slot.refs = 0;
  slot.used = true;
  peer_ids_[addr_key(reinterpret_cast<const sockaddr*>(&from))] = id;
  *peer = id;
  return true;
}

void Reactor::forget_peer(uint64_t peer) {
  if (peer >= peers_.size() || !peers_[peer].used) {
    return;
  }
  const std::string key = addr_key(reinterpret_cast<const sockaddr*>(&peers_[peer].addr));
  const auto it = peer_ids_.find(key);
  if (it != peer_ids_.end() && it->second == peer) {
    peer_ids_.erase(it);
  }
  peers_[peer].used = false;
  peers_[peer].refs = 0;
}

void Reactor::free_peer(uint64_t peer) {
  if (peer >= peers_.size() || !peers_[peer].used) {
    return;
  }
  forget_peer(peer);
  free_peers_.push_back(peer);
}

void Reactor::peer_bound(uint64_t peer) {
  if (peer < peers_.size() && peers_[peer].used) {
    ++peers_[peer].refs;
  }
}

void Reactor::peer_retired(uint64_t peer) {
  if (peer >= peers_.size() || !peers_[peer].used) {
    return;
  }
  if (peers_[peer].refs > 0) {
    --peers_[peer].refs;
  }
  // Eager release: the table then tracks live sessions instead of every source
  // address the process has ever seen. A late datagram from the old address
  // simply allocates a fresh slot (and the engine's salt tombstone deals with
  // the tail).
  if (peers_[peer].refs == 0) {
    free_peer(peer);
  }
}

std::string Reactor::addr_key(const sockaddr* sa) {
  if (sa->sa_family == AF_INET) {
    const sockaddr_in* a = reinterpret_cast<const sockaddr_in*>(sa);
    return host_port(ip_text(*a), ntohs(a->sin_port));
  }
  return std::string(reinterpret_cast<const char*>(sa->sa_data), sizeof(sa->sa_data));
}

void Reactor::target_text(const ProxyTarget& target, std::string* host, uint16_t* port) {
  *port = target.port;
  host->clear();
  if (target.atyp == kAtypDomain) {
    *host = target.addr;
    return;
  }
  char buf[INET6_ADDRSTRLEN] = {0};
  const int family = target.atyp == kAtypIpv4 ? AF_INET : AF_INET6;
  if (target.addr.size() == (family == AF_INET ? 4u : 16u) &&
      inet_ntop(family, target.addr.data(), buf, sizeof(buf)) != nullptr) {
    *host = buf;
  }
}

void Reactor::print_stats(int64_t now_ms) {
  const ProxyEngine::Counters& c = engine_.counters();
  const ProxyEngine::LossSample loss = engine_.loss_sample();
  const auto ppm = [](uint64_t lost, uint64_t expected) {
    return expected == 0
               ? 0u
               : static_cast<unsigned>((lost * 1000000ull + expected / 2) / expected);
  };
  char row[512];
  std::snprintf(
      row, sizeof(row),
      "stats %6.1fs live=%zu up=%zu tunnels=%zu tx=%" PRIu64 "B rx=%" PRIu64
      "B bad_entry=%u refused=%u hs_failed=%u reset=%u idle=%u clash=%u over=%u"
      " bad_cfg=%u no_entropy=%u budget=%u unknown=%u tomb=%u duprec=%u wrerr=%llu"
      " loss_in_ppm=%u loss_in_n=%llu loss_out_ppm=%u loss_out_n=%llu"
      " stall=%d held=%zu shaped=%llu",
      (now_ms - started_ms_) / 1000.0, c.live, c.established, c.tunnels, c.bytes_tx, c.bytes_rx,
      c.bad_entry, c.open_failed, c.handshake_failed, c.reset, c.idle_closed, c.salt_clash,
      c.over_limit, c.bad_config, c.no_entropy, c.over_budget, c.unknown_salt,
      c.salt_tombstone, engine_.dup_after_recovered(),
      static_cast<unsigned long long>(c.wire_errors),
      ppm(loss.in_lost, loss.in_expected),
      static_cast<unsigned long long>(loss.in_expected),
      ppm(loss.out_lost, loss.out_expected),
      static_cast<unsigned long long>(loss.out_expected),
      stall_since_ms_ != 0 ? static_cast<int>((now_ms - stall_since_ms_) / 1000) : 0,
      wire_deferred_bytes_,
      static_cast<unsigned long long>(wire_over_budget_));
  // stdout 是给 GUI/脚本的机器通道：sidecar 逐行解析这一行算出采样图与
  // 连接时长，因此与 --log 等级无关、永远输出（--log=off 时也不静默，
  // 那是"人读通道"的开关）。
  std::printf("%s\n", row);
  std::fflush(stdout);
  // 文件里按 info 级落一份带时间戳的存档（与其它引擎行同一把阈值尺）；
  // 不写 stderr：GUI 的日志窗显示 stderr，0.5s 一行会把逐请求行冲掉。
  if (Severity(opt_.log_level) <= Severity(LogLevel::kInfo)) {
    write_log(std::string("[INFO] ") + row);
  }
}

void Reactor::open_log_file() {
  if (opt_.log_file.empty()) {
    return;
  }
  std::filesystem::path path = opt_.log_file;
  std::error_code ec;
  // 目录形式（结尾是分隔符，或路径本身就是存在的目录）：文件名放进程内造好。
  if (path.filename().empty() || std::filesystem::is_directory(path, ec)) {
    path /= "fcp-" +
            std::string(opt_.role == EngineRole::kClient ? "client" : "server") +
            "-" + std::to_string(ThisPid()) + ".log";
  }
  // 父目录不存在就现造（GUI 的 AppLogLocation / deb 的 /var/log/fcp 都是
  // systemd 或 GUI 预先建好的；手工路径也能直接用）。
  std::filesystem::create_directories(path.parent_path(), ec);
  ec.clear();

  log_stream_.open(path, std::ios::app | std::ios::binary);
  if (!log_stream_) {
    // 保持语义：起不来 ≠ 拒绝启动，stderr 提示即可（响应"响亮失败"的同时
    // 不让排障工具把隧道拖死）。
    note("--log-file " + opt_.log_file + " 写入失败，日志只到 stderr",
         Severity(LogLevel::kWarn));
    return;
  }
  log_path_ = path.string();
  log_bytes_ = static_cast<size_t>(std::filesystem::exists(path, ec)
                                       ? std::filesystem::file_size(path, ec)
                                       : 0);
  write_log("[INFO] == start pid=" + std::to_string(ThisPid()) + " log=" + log_path_);
}

void Reactor::note(const std::string& line, int severity) {
  // 启动/配置/stall 这类内部行没有标签，级别由调用点给（默认 info）。
  // 与 log_line 同一把阈值尺：--log=off / --log=error 时低级别行不出场，
  // stderr 与文件都不写（否则 --log=off 下启动横幅还会漏出来）。
  if (!Wanted(severity, Severity(opt_.log_level))) {
    return;
  }
  // 时间戳 + 级别与 log_line 同一种渲染，GUI 才能统一解析/上色。
  const std::string rendered = LogLine(severity, line);
  std::fprintf(stderr, "%s\n", rendered.c_str());
  write_log_stamped(rendered);
}

// 唯一的分级汇集点：标签分级 → 阈值过滤（stderr 与文件同一把尺）→ 渲染。
// 无法分级（无标签）按 info。行文本统一是
// `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] 正文`；GUI 的日志窗按 [LEVEL] 上色，
// CLI 本身不吐 ANSI（服务端 journal 保持纯文本）。
void Reactor::log_line(const std::string& line) {
  int severity = 0;
  TaggedLine(line, &severity);
  if (!Wanted(severity, Severity(opt_.log_level))) {
    return;
  }
  const std::string body = LineBody(line);
  const std::string rendered = LogLine(severity, body);
  std::fprintf(stderr, "%s\n", rendered.c_str());
  write_log_stamped(rendered);
}

// 契约：持有 log_mutex_ 时调用。
void Reactor::rotate_log_file() {
  if (!log_stream_.is_open()) {
    return;
  }
  log_stream_.flush();
  log_stream_.close();
  std::error_code ec;
  const std::filesystem::path rotated = log_path_ + ".1";
  std::filesystem::remove(rotated, ec);
  std::filesystem::rename(log_path_, rotated, ec);
  // 无论成败都必须重新打开并清账：close() 之后留着无流，write_log_stamped
  // 的 is_open() 会直接 return，此后整个进程的日志全丢（stderr 还在，不显眼）。
  // 计数不按新文件大小重算——正是那个等于旧文件大小的值让下一行立刻再次
  // 轮转，于是每次轮转都把一个空文件 .1、上一个文件被删掉。
  log_stream_.open(log_path_, std::ios::app | std::ios::binary);
  log_bytes_ = 0;
  if (ec) {
    // Windows 先 fclose 再 rename 是铁律；被占用（编辑器开着）也只降级
    // 继续追加，再写满 32 MiB 后重试——与 trace 轮转同一容错策略。降级后
    // 计数归零，这条 warn 也就不会每行打一次。
    if (!log_rotate_warned_) {
      log_rotate_warned_ = true;
      std::fprintf(stderr, "%s\n",
                   LogLine(Severity(LogLevel::kWarn),
                           "--log-file 轮转失败，继续追加写")
                       .c_str());
    }
  } else {
    log_rotate_warned_ = false;
  }
}

void Reactor::write_log(const std::string& line) {
  // 每行一个时间戳 + 每行 flush：排障时崩溃前的最后一行必须已经在盘上。
  write_log_stamped(LogStamp() + " " + line);
}

void Reactor::write_log_stamped(const std::string& line) {
  if (!log_stream_.is_open()) {
    return;
  }
  const std::string stamped = line + "\n";
  const std::lock_guard<std::mutex> lock(log_mutex_);
  log_stream_ << stamped;
  log_stream_.flush();
  log_bytes_ += stamped.size();
  if (log_bytes_ >= kLogFileRotateBytes) {
    rotate_log_file();
  }
}

}  // namespace fcp
