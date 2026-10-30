// Cross-platform select reactor for the FCP proxy CLI (docs/FCP_M2_PROXY.md §6).
//
// The socket half of the picture: ProxyEngine owns every byte of the protocol
// and none of the descriptors, and this file is the mirror image -- it owns the
// descriptors and decides nothing about FCP. One thread runs one select() loop
// over
//
//   * the UDP socket (connected to the server on the client, bound and
//     multi-peer on the server),
//   * the local TCP listener (client only: the SOCKS5/HTTP port),
//   * one descriptor per proxied connection (the local socket on the client,
//     the dialed target on the server),
//   * non-blocking connects, preceded by a getaddrinfo() on a worker thread
//     when the target is a domain name,
//
// and forwards the bytes to the engine. Two rules keep the buffering honest:
// the reactor only touches a socket when `wants_local_read()` /
// `wants_target_read()` allows it, and `app_send` returns what the socket
// actually accepted, so the engine holds the only byte buffer in the process --
// the reactor never queues application payload itself.
//
// The Qt adapter (#23) drives the same engine from QTcpSocket/QHostInfo signals
// instead of select(), which is why none of this file is reusable outside the
// CLI -- and why the engine must not be able to tell which host it is in.
//
// Address families: the UDP socket and the local listener are IPv4 (a proxy
// entry on 127.0.0.1 and a VPS with an IPv4 address cover the deployment),
// while targets are dialed through getaddrinfo and therefore reach IPv6 sites.

#ifndef FCP_PROXY_REACTOR_H_
#define FCP_PROXY_REACTOR_H_

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// The default of 64 is smaller than one process's worth of proxied connections,
// and Windows FD_SET past it is dropped without an error. Has to be defined
// before winsock2.h reads it.
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "engine.h"
#include "fcp/proxy_proto.h"

namespace fcp {

// select() wakes at least this often, so the engine's tick and the DNS results
// land on a predictable cadence.
constexpr int kReactorTickMs = 25;  // matches kSessionTickMs
constexpr size_t kReactorMaxReadBytes = 16 * 1024;
// Ceiling on distinct UDP peers (server side). The source address of every
// datagram is whatever the other end sends from, so the count needs a bound;
// past it a new peer's traffic is dropped instead of being tracked.
constexpr size_t kReactorMaxPeers = 8192;

struct ReactorOptions {
  EngineRole role = EngineRole::kClient;
  // Client: the FCP server to reach over UDP, plus the local proxy port.
  std::string remote_host;
  int remote_port = 4460;
  std::string listen_addr = "127.0.0.1";
  int listen_port = 1080;
  // Server: the UDP port to bind.
  std::string bind_addr = "0.0.0.0";
  int bind_port = 4460;
  // TCP connect budget for a target. The engine's own dial_timeout_ms covers
  // resolution plus connect, so this is the smaller inner clock.
  int64_t connect_timeout_ms = 5000;
  int64_t stats_ms = 0;  // 0 = no periodic stats line
  bool verbose = false;
};

class Reactor {
 public:
  Reactor(const EngineConfig& engine_config, const ReactorOptions& options);
  ~Reactor();

  Reactor(const Reactor&) = delete;
  Reactor& operator=(const Reactor&) = delete;

  bool start(std::string* error);
  // Runs until stop() or SIGINT/SIGTERM.
  void run();

 private:
#ifdef _WIN32
  using Sock = SOCKET;
  static constexpr Sock kBadSock = INVALID_SOCKET;
#else
  using Sock = int;
  static constexpr Sock kBadSock = -1;
#endif

  // A connect that has been started but has not resolved yet.
  struct Pending {
    Sock sock = kBadSock;
    int64_t deadline_ms = 0;
  };
  // What a getaddrinfo() worker hands back. The vector is append-only from the
  // workers and swapped out by the loop thread, so no index is ever shared
  // across the two sides.
  struct ResolveResult {
    uint64_t conn = 0;
    bool ok = false;
    sockaddr_storage addr{};
    socklen_t addr_len = 0;
  };

  static EngineHost make_host(Reactor* self);

  bool open_udp(std::string* error);
  bool open_listener(std::string* error);

  // Engine host callbacks.
  size_t app_send(uint64_t conn, const uint8_t* data, size_t len);
  void app_close(uint64_t conn);
  void wire_send(uint64_t peer, const uint8_t* wire, size_t len);
  void dial(uint64_t conn, const ProxyTarget& target);
  std::string peer_key(uint64_t peer);

  // Loop steps.
  void drain_udp(int64_t now_ms);
  void accept_local(int64_t now_ms);
  void read_socket(Sock sock, uint64_t conn, bool target, int64_t now_ms);
  void flush_conn(uint64_t conn, int64_t now_ms);
  void connect_now(uint64_t conn, const sockaddr* addr, socklen_t len, int64_t now_ms);
  void connect_event(Sock sock, uint64_t conn, int64_t now_ms);
  void except_event(Sock sock, uint64_t conn, int64_t now_ms);
  void expire_connects(int64_t now_ms);
  void drain_resolves(int64_t now_ms);
  int build_sets(fd_set* read_set, fd_set* write_set, fd_set* except_set,
                 std::unordered_map<Sock, uint64_t>* read_conn,
                 std::unordered_map<Sock, uint64_t>* connect_conn,
                 std::unordered_map<Sock, uint64_t>* write_conn,
                 std::unordered_map<Sock, uint64_t>* except_conn);
  int64_t wait_ms(int64_t now_ms) const;
  void print_stats(int64_t now_ms);

  static std::string addr_key(const sockaddr* sa);
  static void target_text(const ProxyTarget& target, std::string* host, uint16_t* port);
  static Sock first_sock_of(const std::unordered_map<uint64_t, Sock>& m, uint64_t conn);

  ReactorOptions opt_;
  ProxyEngine engine_;
  Sock udp_ = kBadSock;
  Sock listener_ = kBadSock;
  // The client has exactly one peer (id 0); the server assigns an id per
  // distinct source address and keeps the addresses indexed by that id.
  std::vector<sockaddr_in> peer_addrs_;
  std::unordered_map<std::string, uint64_t> peer_ids_;
  std::unordered_map<uint64_t, Sock> locals_;   // client: accepted sockets
  std::unordered_map<uint64_t, Sock> targets_;  // server: connected targets
  std::unordered_map<uint64_t, Pending> pending_;
  std::vector<ResolveResult> results_;
  std::mutex results_mutex_;
  uint64_t next_local_conn_ = 1;
  int64_t next_tick_ms_ = 0;
  int64_t next_stats_ms_ = 0;
  int64_t started_ms_ = 0;
  bool wsa_owner_ = false;
};

}  // namespace fcp

#endif  // FCP_PROXY_REACTOR_H_
