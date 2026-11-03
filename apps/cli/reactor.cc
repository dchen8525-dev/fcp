#include "reactor.h"

#include <algorithm>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <thread>
#include <utility>

#include "fcp/session.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
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
#else
using SOCKET = int;
int SockErr() { return errno; }
bool WouldBlock(int err) { return err == EAGAIN || err == EWOULDBLOCK; }
bool Interrupted(int err) { return err == EINTR; }
bool Connecting(int err) { return err == EINPROGRESS || err == EALREADY; }
void CloseSock(SOCKET s) { ::close(s); }
std::string ErrText(int err) { return std::strerror(err); }
#endif

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

void TuneUdp(SOCKET s) {
  const int size = 2 * 1024 * 1024;
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&size), sizeof(size));
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&size), sizeof(size));
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
    if (self->opt_.verbose) {
      std::fprintf(stderr, "%s\n", line.c_str());
    }
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
  if (udp_ != kBadSock) {
    CloseSock(udp_);
  }
  if (listener_ != kBadSock) {
    CloseSock(listener_);
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
  if (!open_udp(error)) {
    return false;
  }
  if (opt_.role == EngineRole::kClient && !open_listener(error)) {
    if (udp_ != kBadSock) {
      CloseSock(udp_);
      udp_ = kBadSock;
    }
    return false;
  }
  workers_.reserve(kResolverWorkers);
  for (size_t i = 0; i < kResolverWorkers; ++i) {
    workers_.emplace_back([queue = resolve_]() { resolve_worker(queue); });
  }
  if (opt_.role == EngineRole::kClient) {
    std::printf("client: socks5/http on %s -> fcp %s\n",
                host_port(opt_.listen_addr, opt_.listen_port).c_str(),
                host_port(opt_.remote_host, opt_.remote_port).c_str());
  } else {
    std::printf("server: fcp on %s\n", host_port(opt_.bind_addr, opt_.bind_port).c_str());
  }
  std::fflush(stdout);
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
  return true;
}

void Reactor::run() {
  // The flag is process-wide (the signal handler cannot capture `this`); a
  // Reactor that was stopped and started again must not exit on the first
  // loop iteration because of the previous run's signal (A-13).
  g_signalled.store(false);
  while (!g_signalled.load()) {
    int64_t now = NowMs();

    flush_dead_apps(now);
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
    const int64_t wait = wait_ms(now);
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(wait / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((wait % 1000) * 1000);
    const int ready = ::select(nfds, &read_set, &write_set, &except_set, &tv);
    if (ready < 0) {
      const int err = SockErr();
#ifndef _WIN32
      if (err != EINTR) {
        std::fprintf(stderr, "select: %s\n", ErrText(err).c_str());
        break;
      }
#else
      std::fprintf(stderr, "select: %s\n", ErrText(err).c_str());
      break;
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
        std::fprintf(stderr,
                     "reactor: %zu socket(s) could not be watched by select "
                     "(total %llu); lower --max-sessions\n",
                     skipped_this_pass_,
                     static_cast<unsigned long long>(skipped_total_));
        std::fflush(stderr);
      }
    }

    if (now >= next_tick_ms_) {
      next_tick_ms_ = now + kReactorTickMs;
      engine_.on_tick(now);
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
  print_stats(NowMs());
}

int64_t Reactor::wait_ms(int64_t now_ms) const {
  int64_t wait = next_tick_ms_ > now_ms ? next_tick_ms_ - now_ms : 1;
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
  for (int i = 0; i < 128; ++i) {  // bounded: a flood must not starve the tick
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const int n = ::recvfrom(udp_, reinterpret_cast<char*>(udp_buf_.data()),
                             static_cast<int>(udp_buf_.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) {
      return;
    }
    uint64_t peer = 0;
    if (opt_.role == EngineRole::kServer) {
      const auto it = peer_ids_.find(addr_key(reinterpret_cast<sockaddr*>(&from)));
      if (it != peer_ids_.end()) {
        peer = it->second;
      } else if (!add_peer(from, &peer)) {
        continue;  // every slot is bound to a live session: drop, do not track
      }
    }
    engine_.on_wire(peer, udp_buf_.data(), static_cast<size_t>(n), now_ms);
  }
}

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
    if (!WouldBlock(SockErr())) {
      if (target) {
        const auto it = targets_.find(conn);
        if (it != targets_.end()) {
          CloseSock(it->second);
          targets_.erase(it);
        }
        engine_.on_target_closed(conn, now_ms);
      } else {
        const auto it = locals_.find(conn);
        if (it != locals_.end()) {
          CloseSock(it->second);
          locals_.erase(it);
        }
        engine_.on_local_closed(conn, now_ms);
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
    targets_.emplace(conn, s);
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
  pending_.emplace(conn, p);
  return ConnectAttempt::kPending;
}

bool Reactor::connect_addresses(uint64_t conn, int64_t now_ms, int* last_err) {
  const auto it = dial_addrs_.find(conn);
  if (it == dial_addrs_.end()) {
    return false;
  }
  std::deque<ResolvedAddr>& queue = it->second;
  while (!queue.empty()) {
    const ResolvedAddr a = queue.front();
    queue.pop_front();
    const ConnectAttempt r =
        connect_once(conn, reinterpret_cast<const sockaddr*>(&a.addr), a.len, now_ms, last_err);
    if (r == ConnectAttempt::kFailed) {
      continue;
    }
    if (r == ConnectAttempt::kGone) {
      dial_addrs_.erase(it);
      return true;
    }
    if (queue.empty()) {
      // The attempt in flight is the last record: a later connect failure has
      // nothing left to try.
      dial_addrs_.erase(it);
    }
    return true;
  }
  dial_addrs_.erase(it);
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
    engine_.on_target_closed(conn, now_ms);
    return;
  }
  const auto local = locals_.find(conn);
  if (local != locals_.end() && local->second == sock) {
    locals_.erase(local);
    CloseSock(sock);
    // The local half is gone, so the engine only needs to be told the app stopped
    // reading; app_close on an already-erased socket is a no-op.
    engine_.on_local_closed(conn, now_ms);
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
      engine_.on_target_closed(e.first, now_ms);
    } else {
      engine_.on_local_closed(e.first, now_ms);
    }
  }
}

Sock Reactor::first_sock_of(const std::unordered_map<uint64_t, Sock>& m, uint64_t conn) {
  const auto it = m.find(conn);
  return it == m.end() ? kBadSock : it->second;
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

size_t Reactor::wire_send(uint64_t peer, const uint8_t* wire, size_t len) {
  if (udp_ == kBadSock) {
    return 0;
  }
  if (opt_.role == EngineRole::kClient) {
    const int n =
        ::send(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0);
    return n > 0 ? static_cast<size_t>(n) : 0;
  }
  if (peer >= peers_.size() || !peers_[peer].used) {
    return 0;
  }
  const sockaddr_in& to = peers_[peer].addr;
  const int n = ::sendto(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0,
                         reinterpret_cast<const sockaddr*>(&to), sizeof(to));
  return n > 0 ? static_cast<size_t>(n) : 0;
}

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
  std::printf(
      "stats %6.1fs live=%zu up=%zu tunnels=%zu tx=%" PRIu64 "B rx=%" PRIu64
      "B bad_entry=%u refused=%u hs_failed=%u reset=%u idle=%u clash=%u over=%u"
      " bad_cfg=%u no_entropy=%u budget=%u unknown=%u tomb=%u duprec=%u wrerr=%llu\n",
      (now_ms - started_ms_) / 1000.0, c.live, c.established, c.tunnels, c.bytes_tx, c.bytes_rx,
      c.bad_entry, c.open_failed, c.handshake_failed, c.reset, c.idle_closed, c.salt_clash,
      c.over_limit, c.bad_config, c.no_entropy, c.over_budget, c.unknown_salt,
      c.salt_tombstone, engine_.dup_after_recovered(),
      static_cast<unsigned long long>(c.wire_errors));
  std::fflush(stdout);
}

}  // namespace fcp
