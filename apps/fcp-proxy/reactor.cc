#include "reactor.h"

#include <algorithm>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <thread>

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
    : opt_(options), engine_(engine_config, make_host(this)) {}

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
    self->wire_send(peer, wire, len);
  };
  host.dial = [self](uint64_t conn, const ProxyTarget& target) {
    self->dial(conn, target);
  };
  host.peer_key = [self](uint64_t peer) { return self->peer_key(peer); };
  host.log = [self](const std::string& line) {
    if (self->opt_.verbose) {
      std::fprintf(stderr, "%s\n", line.c_str());
    }
  };
  return host;
}

Reactor::~Reactor() {
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
  if (opt_.role == EngineRole::kClient) {
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(static_cast<uint16_t>(opt_.remote_port));
    if (inet_pton(AF_INET, opt_.remote_host.c_str(), &remote.sin_addr) != 1) {
      *error = "--remote must be an IPv4 address, got '" + opt_.remote_host + "'";
      return false;
    }
    if (::connect(udp_, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
      *error = "udp connect: " + ErrText(SockErr());
      return false;
    }
    peer_addrs_.push_back(remote);  // peer id 0, the only one a client has
  } else {
    EnableReuse(udp_);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(static_cast<uint16_t>(opt_.bind_port));
    if (opt_.bind_addr.empty() || opt_.bind_addr == "0.0.0.0") {
      local.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, opt_.bind_addr.c_str(), &local.sin_addr) != 1) {
      *error = "--bind must be an IPv4 address, got '" + opt_.bind_addr + "'";
      return false;
    }
    if (::bind(udp_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
      *error = "udp bind " + host_port(opt_.bind_addr, opt_.bind_port) + ": " + ErrText(SockErr());
      return false;
    }
  }
  return SetNonBlocking(udp_);
}

bool Reactor::open_listener(std::string* error) {
  listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener_ == kBadSock) {
    *error = "listener: " + ErrText(SockErr());
    return false;
  }
  EnableReuse(listener_);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(opt_.listen_port));
  if (inet_pton(AF_INET, opt_.listen_addr.c_str(), &addr.sin_addr) != 1) {
    *error = "--listen must be an IPv4 address, got '" + opt_.listen_addr + "'";
    return false;
  }
  if (::bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    *error = "listener bind " + host_port(opt_.listen_addr, opt_.listen_port) + ": " +
             ErrText(SockErr());
    return false;
  }
  if (::listen(listener_, 64) != 0) {
    *error = "listen: " + ErrText(SockErr());
    return false;
  }
  return SetNonBlocking(listener_);
}

bool Reactor::start(std::string* error) {
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
    return false;
  }
  if (opt_.role == EngineRole::kClient) {
    std::printf("client: socks5/http on %s -> fcp %s\n",
                host_port(opt_.listen_addr, opt_.listen_port).c_str(),
                host_port(opt_.remote_host, opt_.remote_port).c_str());
  } else {
    std::printf("server: fcp on %s\n", host_port(opt_.bind_addr, opt_.bind_port).c_str());
  }
  std::fflush(stdout);
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);
  started_ms_ = NowMs();
  next_tick_ms_ = started_ms_;
  next_stats_ms_ = opt_.stats_ms != 0 ? started_ms_ + opt_.stats_ms : 0;
  return true;
}

void Reactor::run() {
  while (!g_signalled.load()) {
    int64_t now = NowMs();

    drain_resolves(now);
    drain_udp(now);
    expire_connects(now);

    fd_set read_set;
    fd_set write_set;
    fd_set except_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);
    std::unordered_map<Sock, uint64_t> read_conn;
    std::unordered_map<Sock, uint64_t> connect_conn;
    std::unordered_map<Sock, uint64_t> write_conn;
    std::unordered_map<Sock, uint64_t> except_conn;
    const int nfds =
        build_sets(&read_set, &write_set, &except_set, &read_conn, &connect_conn, &write_conn,
                   &except_conn);

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
      for (const auto& e : connect_conn) {
        if (FD_ISSET(e.first, &write_set)) {
          connect_event(e.first, e.second, now);
        }
      }
      for (const auto& e : read_conn) {
        if (FD_ISSET(e.first, &read_set)) {
          read_socket(e.first, e.second, targets_.count(e.second) != 0, now);
        }
      }
      for (const auto& e : write_conn) {
        if (FD_ISSET(e.first, &write_set)) {
          flush_conn(e.second, now);
        }
      }
      for (const auto& e : except_conn) {
        if (FD_ISSET(e.first, &except_set)) {
          except_event(e.first, e.second, now);
        }
      }
    }

    if (now >= next_tick_ms_) {
      next_tick_ms_ = now + kReactorTickMs;
      engine_.on_tick(now);
      // Anything the engine still owes an application socket gets another try
      // here, whether or not select reported it: the pending byte count is the
      // engine's, so this is the only place a stalled write can be retried.
      for (const auto& e : locals_) {
        if (engine_.pending_app_bytes(e.first) != 0) {
          flush_conn(e.first, now);
        }
      }
      for (const auto& e : targets_) {
        if (engine_.pending_app_bytes(e.first) != 0) {
          flush_conn(e.first, now);
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
  // FD_SET past FD_SETSIZE is not an error on Windows (the entry is silently
  // dropped) and is a buffer overrun on Linux, so both are refused here instead:
  // a socket that does not fit stays unmonitored for this iteration and the tick
  // retries it. The count is per set, hence three counters.
  size_t nread = 0;
  size_t nwrite = 0;
  size_t nexcept = 0;
  auto bump = [&nfds](Sock s) {
    if (static_cast<int>(s) + 1 > nfds) {
      nfds = static_cast<int>(s) + 1;
    }
  };
  auto add_read = [&](Sock s, uint64_t conn) {
    if (nread >= FD_SETSIZE) {
      return;
    }
    ++nread;
    FD_SET(s, read_set);
    read_conn->emplace(s, conn);
    bump(s);
  };
  auto add_write = [&](Sock s, uint64_t conn, std::unordered_map<Sock, uint64_t>* into) {
    if (nwrite >= FD_SETSIZE) {
      return;
    }
    ++nwrite;
    FD_SET(s, write_set);
    into->emplace(s, conn);
    bump(s);
  };
  auto add_except = [&](Sock s, uint64_t conn) {
    if (nexcept >= FD_SETSIZE) {
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
    if (nread < FD_SETSIZE) {
      ++nread;
      FD_SET(udp_, read_set);
      bump(udp_);
    }
  }
  if (listener_ != kBadSock) {
    if (nread < FD_SETSIZE) {
      ++nread;
      FD_SET(listener_, read_set);
      bump(listener_);
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
  uint8_t buf[2048];
  for (int i = 0; i < 128; ++i) {  // bounded: a flood must not starve the tick
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const int n = ::recvfrom(udp_, reinterpret_cast<char*>(buf), static_cast<int>(sizeof(buf)),
                             0, reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) {
      return;
    }
    uint64_t peer = 0;
    if (opt_.role == EngineRole::kServer) {
      const std::string key = addr_key(reinterpret_cast<sockaddr*>(&from));
      const auto it = peer_ids_.find(key);
      if (it != peer_ids_.end()) {
        peer = it->second;
      } else {
        if (peer_ids_.size() >= kReactorMaxPeers) {
          continue;  // over the peer budget: drop rather than track
        }
        peer = peer_addrs_.size();
        peer_addrs_.push_back(from);
        peer_ids_.emplace(key, peer);
      }
    }
    engine_.on_wire(peer, buf, static_cast<size_t>(n), now_ms);
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
    SetNonBlocking(s);
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
      if (target) {
        engine_.on_target_closed(conn, now_ms);
      } else {
        engine_.on_local_closed(conn, now_ms);
      }
      return;
    }
    if (!WouldBlock(SockErr())) {
      if (target) {
        engine_.on_target_closed(conn, now_ms);
      } else {
        engine_.on_local_closed(conn, now_ms);
      }
    }
    return;
  }
}

void Reactor::flush_conn(uint64_t conn, int64_t now_ms) {
  engine_.on_app_writable(conn, now_ms);
}

void Reactor::connect_now(uint64_t conn, const sockaddr* addr, socklen_t len,
                          int64_t now_ms) {
  if (!engine_.has_connection(conn)) {
    return;  // the tunnel was torn down while the name was being looked up
  }
  const Sock s = ::socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (s == kBadSock) {
    engine_.on_dial_result(conn, false, OpenError::kRefused, now_ms);
    return;
  }
  SetNonBlocking(s);
  if (::connect(s, addr, len) == 0) {
    targets_.emplace(conn, s);
    engine_.on_dial_result(conn, true, OpenError::kRefused, now_ms);
    return;
  }
  const int connect_err = SockErr();
  if (!Connecting(connect_err) && !WouldBlock(connect_err)) {
    CloseSock(s);
    engine_.on_dial_result(conn, false, OpenError::kRefused, now_ms);
    return;
  }
  Pending p;
  p.sock = s;
  p.deadline_ms = now_ms + opt_.connect_timeout_ms;
  pending_.emplace(conn, p);
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
    engine_.on_dial_result(conn, true, OpenError::kRefused, now_ms);
    return;
  }
  CloseSock(sock);
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
    engine_.on_dial_result(conn, false, open_error_for(err), now_ms);
    return;
  }
  // On a live socket an exception means a broken connection or urgent data this
  // proxy does not carry, so either way the tunnel is over.
  if (targets_.erase(conn) != 0) {
    CloseSock(sock);
    engine_.on_target_closed(conn, now_ms);
    return;
  }
  if (locals_.erase(conn) != 0) {
    CloseSock(sock);
    // The local half is gone, so the engine only needs to be told the app stopped
    // reading; app_close on an already-erased socket is a no-op.
    engine_.on_local_closed(conn, now_ms);
  }
}

void Reactor::expire_connects(int64_t now_ms) {
  std::vector<uint64_t> due;
  for (const auto& e : pending_) {
    if (e.second.deadline_ms <= now_ms) {
      due.push_back(e.first);
    }
  }
  for (uint64_t conn : due) {
    const auto it = pending_.find(conn);
    if (it == pending_.end()) {
      continue;
    }
    CloseSock(it->second.sock);
    pending_.erase(it);
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
    connect_now(conn, reinterpret_cast<sockaddr*>(&direct), sizeof(direct), NowMs());
    return;
  }
  in6_addr v6{};
  if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    sockaddr_in6 a6{};
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons(port);
    std::memcpy(&a6.sin6_addr, &v6, sizeof(v6));
    connect_now(conn, reinterpret_cast<sockaddr*>(&a6), sizeof(a6), NowMs());
    return;
  }
  // A name: resolve off the loop thread, then connect here. The worker never
  // touches a descriptor, so the reactor stays their only owner.
  const int service_port = static_cast<int>(port);
  std::thread([this, conn, host, service_port]() {
    ResolveResult r;
    r.conn = conn;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char service[8];
    std::snprintf(service, sizeof(service), "%d", service_port);
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), service, &hints, &res) == 0 && res != nullptr) {
      r.ok = true;
      std::memcpy(&r.addr, res->ai_addr, static_cast<size_t>(res->ai_addrlen));
      r.addr_len = static_cast<socklen_t>(res->ai_addrlen);
    }
    if (res != nullptr) {
      freeaddrinfo(res);
    }
    const std::lock_guard<std::mutex> lock(results_mutex_);
    results_.push_back(r);
  }).detach();
}

void Reactor::drain_resolves(int64_t now_ms) {
  std::vector<ResolveResult> done;
  {
    const std::lock_guard<std::mutex> lock(results_mutex_);
    if (results_.empty()) {
      return;
    }
    done.swap(results_);
  }
  for (const ResolveResult& r : done) {
    if (!r.ok) {
      engine_.on_dial_result(r.conn, false, OpenError::kDns, now_ms);
      continue;
    }
    connect_now(r.conn, reinterpret_cast<const sockaddr*>(&r.addr), r.addr_len, now_ms);
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
  return n > 0 ? static_cast<size_t>(n) : 0;
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
}

void Reactor::wire_send(uint64_t peer, const uint8_t* wire, size_t len) {
  if (udp_ == kBadSock) {
    return;
  }
  if (opt_.role == EngineRole::kClient) {
    ::send(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0);
    return;
  }
  if (peer >= peer_addrs_.size()) {
    return;
  }
  const sockaddr_in& to = peer_addrs_[static_cast<size_t>(peer)];
  ::sendto(udp_, reinterpret_cast<const char*>(wire), static_cast<int>(len), 0,
           reinterpret_cast<const sockaddr*>(&to), sizeof(to));
}

std::string Reactor::peer_key(uint64_t peer) {
  if (peer >= peer_addrs_.size()) {
    return std::string();
  }
  const sockaddr_in& a = peer_addrs_[static_cast<size_t>(peer)];
  return host_port(ip_text(a), ntohs(a.sin_port));
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
      "B bad_entry=%u refused=%u hs_failed=%u reset=%u idle=%u clash=%u over=%u unknown=%u tomb=%u duprec=%u\n",
      (now_ms - started_ms_) / 1000.0, c.live, c.established, c.tunnels, c.bytes_tx, c.bytes_rx,
      c.bad_entry, c.open_failed, c.handshake_failed, c.reset, c.idle_closed, c.salt_clash,
      c.over_limit, c.unknown_salt, c.salt_tombstone, engine_.dup_after_recovered());
  std::fflush(stdout);
}

}  // namespace fcp
