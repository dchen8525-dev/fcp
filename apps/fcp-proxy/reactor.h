// Cross-platform select reactor for the FCP proxy CLI (M2代理设计.md §6).
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
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
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

#include "proxy/proxy_engine.h"
#include "proxy/proxy_proto.h"

namespace fcp {

// select() wakes at least this often, so the engine's tick and the DNS results
// land on a predictable cadence.
constexpr int kReactorTickMs = 25;  // matches kSessionTickMs
constexpr size_t kReactorMaxReadBytes = 16 * 1024;
// Ceiling on distinct UDP peers (server side). The source address of every
// datagram is whatever the other end sends from, so the count needs a bound;
// past it a new peer's traffic is dropped instead of being tracked.
constexpr size_t kReactorMaxPeers = 8192;
// At the ceiling only this many slots are examined per new source before the
// datagram is dropped; the cursor rotates so every slot is reachable.
constexpr size_t kPeerReclaimScan = 64;
// Off-loop name resolution. getaddrinfo() can block for many seconds, so it
// never runs on the select thread, and a fixed pool keeps a burst of dials from
// spawning one thread each. Past the queue ceiling a dial fails immediately
// instead of waiting for a resolver that may never answer.
constexpr size_t kResolverWorkers = 4;
constexpr size_t kResolverMaxQueued = 256;
// A name with hundreds of records must not turn one dial into hundreds of
// connect attempts; the resolver keeps the first this many answers.
constexpr size_t kResolverMaxAddrs = 16;
// One maximum-size IPv4 UDP datagram. The old 2 KiB stack buffer silently
// truncated every symbol once --mtu exceeded ~2 KiB, which the session then
// dropped as an authentication failure with no diagnostic.
constexpr size_t kUdpRecvBytes = 64 * 1024;

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
  // TCP connect budget for one resolved address. A name with several records
  // may spend this per record; the engine's own dial_timeout_ms still bounds
  // resolution plus all attempts from above.
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
  struct ResolvedAddr {
    sockaddr_storage addr{};
    socklen_t len = 0;
  };
  // What a getaddrinfo() worker hands back. The vector is append-only from the
  // workers and swapped out by the loop thread, so no index is ever shared
  // across the two sides.
  struct ResolveResult {
    uint64_t conn = 0;
    bool ok = false;
    // Every usable answer, in resolver order. A name is not one address:
    // "localhost" is usually ::1 first even when the service listens on IPv4
    // only, and a multi-homed name fails over between records.
    std::vector<ResolvedAddr> addrs;
  };
  enum class ConnectAttempt : uint8_t {
    kPending,    // non-blocking connect started
    kConnected,  // connected on the first call
    kFailed,     // this address failed synchronously
    kGone,       // the engine already tore the connection down
  };
  struct ResolveJob {
    uint64_t conn = 0;
    std::string host;
    uint16_t port = 0;
  };
  // Shared with the resolver threads: getaddrinfo() may outlive this Reactor,
  // so the queue cannot be a member the workers reach through `this`.
  struct ResolveQueue {
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<ResolveJob> jobs;
    std::vector<ResolveResult> done;
    bool stopping = false;
  };
  // Server-side source-address slot. `refs` counts sessions the engine says are
  // routed through this id; a slot with no sessions may be recycled.
  struct PeerSlot {
    sockaddr_in addr{};
    uint32_t refs = 0;
    bool used = false;
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

  bool add_peer(const sockaddr_in& from, uint64_t* peer);
  // Erase the slot's address key and mark it free; the caller either returns
  // the id to free_peers_ or reuses it immediately.
  void forget_peer(uint64_t peer);
  void free_peer(uint64_t peer);
  void peer_bound(uint64_t peer);
  void peer_retired(uint64_t peer);
  static void resolve_worker(std::shared_ptr<ResolveQueue> queue);

  // Loop steps.
  void drain_udp(int64_t now_ms);
  void accept_local(int64_t now_ms);
  void read_socket(Sock sock, uint64_t conn, bool target, int64_t now_ms);
  void flush_conn(uint64_t conn, int64_t now_ms);
  ConnectAttempt connect_once(uint64_t conn, const sockaddr* addr, socklen_t len,
                              int64_t now_ms, int* err);
  // Starts the next resolved address. True means an attempt is in flight or the
  // answer was consumed (connected/gone); false means every address failed
  // synchronously and `last_err` holds the final error.
  bool connect_addresses(uint64_t conn, int64_t now_ms, int* last_err);
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
  std::vector<PeerSlot> peers_;
  std::vector<uint64_t> free_peers_;
  size_t peer_cursor_ = 0;
  std::unordered_map<std::string, uint64_t> peer_ids_;
  std::unordered_map<uint64_t, Sock> locals_;   // client: accepted sockets
  std::unordered_map<uint64_t, Sock> targets_;  // server: connected targets
  std::unordered_map<uint64_t, Pending> pending_;
  // Addresses still to try for a connection whose name resolved to several.
  // Dropped on success, on the final failure and when the conn goes away.
  std::unordered_map<uint64_t, std::deque<ResolvedAddr>> dial_addrs_;
  std::vector<uint8_t> udp_buf_ = std::vector<uint8_t>(kUdpRecvBytes);
  // Per-iteration scratch, reused across passes instead of reallocated: run()
  // is the proxy's hot loop and these are cleared (capacity kept) every time.
  // build_sets() fills the four maps; the three id vectors carry the walks that
  // must survive a callback erasing a connection mid-pass.
  std::unordered_map<Sock, uint64_t> sel_read_;
  std::unordered_map<Sock, uint64_t> sel_connect_;
  std::unordered_map<Sock, uint64_t> sel_write_;
  std::unordered_map<Sock, uint64_t> sel_except_;
  std::vector<uint64_t> scratch_local_ids_;
  std::vector<uint64_t> scratch_target_ids_;
  std::vector<uint64_t> scratch_due_;
  std::shared_ptr<ResolveQueue> resolve_ = std::make_shared<ResolveQueue>();
  uint64_t next_local_conn_ = 1;
  int64_t next_tick_ms_ = 0;
  int64_t next_stats_ms_ = 0;
  int64_t started_ms_ = 0;
  bool wsa_owner_ = false;
};

}  // namespace fcp

#endif  // FCP_PROXY_REACTOR_H_
