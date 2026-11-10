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
#include <csignal>
#include <cstdint>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "fcp/log_level.h"

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

class BenchServer;

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
// Linux recvmmsg datagrams per syscall (P1-4, mirroring quic-go's 8-message
// read loop). The receive arena is this × the per-slot byte bound; a read
// shorter than a full batch means the socket emptied for now.
constexpr int kRecvBatchMsgs = 8;
// Linux UDP_SEGMENT GSO batch (P1-4): segments coalesced per sendmsg. The
// kernel's own ceiling for a UDP GSO send is 64 segments.
constexpr size_t kGsoMaxSegs = 64;
// Dead-path watchdog cadence: while a stall is declared the reminder repeats
// this often until recovery, and TX counts as "still moving" when it advanced
// within this window (the stream retransmission timer backs off, so the window
// must cover its gaps; truly idle tunnels freeze both directions and stay
// silent on purpose).
constexpr int64_t kStallLogMs = 30000;
// High-loss warning. Separate from the stall watchdog: a tunnel can keep
// moving small packets while every full-size datagram is dropped, which shows
// up only as loss in the FECSTAT numbers (see session.cc pmtu_note_loss for
// the same evidence acting on the MTU). Sampling is once a second, the
// reminder repeats at the stall cadence, and the sample floor keeps a couple
// of badly-timed reports from tripping it.
constexpr uint32_t kHighLossWarnPpm = 200000;  // 20%
constexpr uint64_t kHighLossMinExpected = 64;
constexpr int64_t kHighLossSampleMs = 1000;
// --log-file 的单文件上限：写满即轮转到 <名字>.1（保留上一份）。
constexpr size_t kLogFileRotateBytes = 32u * 1024u * 1024u;
constexpr int64_t kStallTxWindowMs = 10000;

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
  // Server: answer the desktop speed test's frame-layer bench on the FCP UDP
  // port (bench.h). Off by default: the responder creates an authenticated
  // session from an unauthenticated rendezvous, so exposing it is opt-in.
  bool speedtest = false;
  // Linux UDP GRO receive aggregation (P1-4). On by default; --no-udp-gro
  // retires it for hosts where the benchmark says the deep copies cost more
  // than the interrupts they save. A kernel without the option (or a sandbox
  // refusing the setsockopt) degrades to the plain loop regardless.
  bool udp_gro = true;
  // TCP connect budget for one resolved address. A name with several records
  // may spend this per record; the engine's own dial_timeout_ms still bounds
  // resolution plus all attempts from above.
  int64_t connect_timeout_ms = 5000;
  int64_t stats_ms = 0;  // 0 = no periodic stats line
  // 显示级别的下限：Debug 打开全部（默认），Off 全关。stderr 与 --log-file
  // 用同一个阈值（排障问题的答案两处一致——fcp.env 里怎么调，两边就一样）。
  LogLevel log_level = LogLevel::kDebug;
  // Client only: dead-path watchdog (半开/断流). A tunnel that keeps ACKs and
  // retransmitted segments going out while nothing at all comes back for this
  // long is logged as a stall (and again every kStallLogMs until it recovers);
  // recovery is logged with its duration. 0 = off. Data traffic untouched --
  // the idle timeout is still the thing that closes genuinely dead sessions;
  // this exists so an operator (and the GUI log page) can see the wall-clock
  // window the path was dark.
  int64_t stall_ms = 60000;
  // Persistent file log (排障用)：`--log-file=<路径>`。路径落在目录形式
  // （以 / 或 \\ 结尾，或本身就是目录）时写 `<目录>/fcp-<角色>-<pid>.log`；
  // 否则按给定文件名追加写。写满 kLogFileRotateBytes（32 MiB）轮转到
  // `<名字>.1`。文件与 stderr 共用 log_level 阈值（日志等级是全局裁决
  // 者）：默认 debug 下逐请求行都在，--log=off 时文件也安静。
  std::string log_file;
  // No --key* argument was given and the key came from the FCP_PSK variable
  // (the packaged /etc/fcp/fcp.env shape: one line, unit injects it). Only
  // marks the config echo; the key value itself is never printed anywhere.
  bool psk_from_default_env = false;
  // Send shaping budget, bytes/s (0 = off; the CLI converts --rate-limit's
  // Mbps). The tunnel has one upload end and one download end, so the halves
  // never apply to the same host: the client shapes what it sends with UP, the
  // server shapes what it sends down with DOWN. Applied at the socket send
  // path: datagrams over the allowance are held in order for at most one
  // second's worth of budget, then dropped as a shaped link would drop them --
  // the FEC/ARQ layer is built to absorb exactly that loss.
  uint64_t rate_up_bytes = 0;
  uint64_t rate_down_bytes = 0;
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
  void app_shutdown(uint64_t conn);
  void app_close(uint64_t conn);
  // Close with an RST (SO_LINGER 0) so a tunnel reset reaches the application
  // as a reset rather than a clean EOF.
  void app_abort(uint64_t conn);
  size_t wire_send(uint64_t peer, const uint8_t* wire, size_t len);
  // wire_send's send path under no shaping: the GSO batch on Linux, else the
  // plain ::send/::sendto. `to` is the destination captured at wire_send time
  // (nullptr on the connected client socket), so a datagram held by the shaper
  // can never be re-routed to a peer id that was freed and reused meanwhile.
  size_t emit_wire(uint64_t peer, const uint8_t* wire, size_t len,
                   const sockaddr_in* to);
  // Send-shaping budget this host enforces (rate_up_bytes on the client that
  // uploads, rate_down_bytes on the server that serves the download).
  uint64_t shaper_bytes_per_sec() const;
  // Sliding one-second admission window: true when `len` fits the budget that
  // is still charged for datagrams sent over the trailing second.
  bool wire_admit(size_t len);
  void wire_charge(int64_t now_ms, size_t len);
  // Releases the head of the hold queue while budget lasts (or everything, in
  // force mode: the shutdown path must drain the shaper even past budget).
  // Called once per loop pass, never re-entrant.
  void flush_wire_deferred(int64_t now_ms, bool force = false);
  // Count a permanent UDP send error and explain the first one per second on
  // stderr (EMSGSIZE is the "MTU larger than the path" case and names --mtu).
  void note_udp_send_error(int err, size_t len, uint64_t peer);
  // #90: recover a Windows client UDP socket that Winsock put into an unusable
  // state. note_udp_send_error() only sets a flag; the descriptor swap runs at
  // the top of run(), never inside a host callback (flush_wire_deferred()
  // calls emit_wire() in a loop, so changing udp_ mid-callback would leave the
  // fd_set snapshot and the deferred queue pointing at different sockets).
  void maybe_rebuild_udp(int64_t now_ms);
#ifdef _WIN32
  // Rebuild udp_ while keeping the original local port: the server keys peers
  // by IP:port (addr_key), so a fresh ephemeral port would look like a new
  // peer and lose every in-flight session. Returns false without touching the
  // live descriptor, so the next attempt can retry.
  bool rebuild_udp_socket(std::string* error);
#endif
  // Last resort when the descriptor cannot be rebuilt at all: reset every
  // local connection so the browser retries immediately instead of waiting out
  // the server's 135 s liveness window.
  void fail_fast_locals(int64_t now_ms);
  // Dead-path watchdog (opt_.stall_ms): one counters snapshot per tick. Nothing
  // functional hangs on it -- the log line is its output.
  void check_stall(int64_t now_ms);
  // High-loss warning (client): reads the FECSTAT loss sample once a second and
  // warns when a direction is losing >= kHighLossWarnPpm of a credible sample.
  // This is the only signal for the "small packets flow, full-size ones do not"
  // failure -- the stall watchdog sees no stall there.
  void check_high_loss(int64_t now_ms);
  // Connections whose application socket hit a fatal send error. The engine
  // must not be re-entered from a host callback, so they are queued and the
  // loop tells it once the call stack has unwound (M-05).
  void flush_dead_apps(int64_t now_ms);
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
  // One received UDP datagram, shared by the recvfrom path and the recvmmsg
  // batch: bench dispatch, peer-id books on the server, engine delivery.
  void drain_datagram(const sockaddr_in& from, const uint8_t* data, size_t len,
                      int64_t now_ms);
#ifdef __linux__
  void drain_udp_mmsg(int64_t now_ms);
  // Hand GRO cmsg results to the engine: an aggregated read (kernel-verified
  // same-size run) splits into exact-size pieces; anything else goes whole.
  void drain_gro(const sockaddr_in& from, const uint8_t* data, size_t len,
                 int gro_seg, int64_t now_ms);
  // Coalesce one datagram into the pending GSO batch (flushing a mismatched
  // batch first); `to` is the destination captured at send time (nullptr on
  // the connected client socket), so a batch is never re-addressed via a peer
  // id that may have been freed and reused by flush time.
  void gso_append(uint64_t peer, const uint8_t* wire, size_t len,
                  const sockaddr_in* to);
  // One sendmsg per batch with UDP_SEGMENT; falls back to per-datagram sends
  // when the kernel does not segment (or the batch already had to be flushed
  // by a mismatch). Called before every select() wait: a pump burst goes out
  // within the iteration that produced it.
  void flush_udp_batch();
#endif
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
  // select() timeout: the next engine tick, the earliest stream wake
  // (ProxyEngine::next_wake_ms) and any pending connect deadline, whichever
  // comes first, clamped to one reactor tick.
  int64_t wait_ms(int64_t now_ms, int64_t wake_ms) const;
  void print_stats(int64_t now_ms);

  static std::string addr_key(const sockaddr* sa);
  static void target_text(const ProxyTarget& target, std::string* host, uint16_t* port);
  static Sock first_sock_of(const std::unordered_map<uint64_t, Sock>& m, uint64_t conn);

  ReactorOptions opt_;
  // Snapshot of the engine config for the bench responder (key and FEC
  // geometry); the engine owns its own copy.
  EngineConfig base_config_;
  ProxyEngine engine_;
  // Created in start() when opt_.speedtest is set (server role only).
  std::unique_ptr<BenchServer> bench_;
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
#ifdef __linux__
  // P1-4 Linux fast paths. UDP_SEGMENT is retired on EIO/EOPNOTSUPP (with an
  // EINVAL pause+rearm for the PMTU-probe case); recvmmsg + UDP_GRO degrade by
  // their own option failures, not by per-read fallbacks. The batch buffers
  // are allocated in open_udp and never change after that.
  std::vector<uint8_t> udp_batch_;
  // Per-slot byte bound: a GRO bundle is at most 64 segments, each within the
  // largest datagram this socket can carry (PMTUD ceiling when probing is on,
  // else --mtu). A smaller slot would make the kernel truncate the bundle
  // silently — the rest is dropped, not re-read later.
  size_t udp_slot_bytes_ = 0;
  // Coalesced equal-size equal-peer datagrams waiting for one GSO sendmsg.
  std::vector<uint8_t> gso_buf_;
  size_t gso_seg_len_ = 0;  // datagram size of the pending batch; 0 = empty
  size_t gso_segs_ = 0;
  uint64_t gso_peer_ = 0;   // batching key only; the address below is the truth
  // Destination captured when the first segment entered the batch. flush time
  // is arbitrary relative to peer retirement, and a server peer id can be
  // freed and reused for a different source address inside the same loop
  // iteration -- the batch must address what was batched, not what the slot
  // holds later.
  sockaddr_in gso_to_{};
  bool gso_has_to_ = false;
  bool gso_ok_ = true;
  // P1-4 receive counterpart: UDP_GRO coalesces same-size same-flow datagrams
  // in the kernel and the read that returns them carries a SOL_UDP/UDP_GRO
  // cmsg with the segment size, so the reactor never has to guess the symbol
  // wire length. A kernel without the option (or a sandbox that says no)
  // keeps the plain per-datagram reads.
  bool gro_ok_ = true;
  // After an EINVAL (which a PMTUD probe above the path MTU legitimately
  // produces) GSO pauses for this many sends and is re-armed once, instead of
  // dying to one probe forever. Fully unsupported kernels fail teardown
  // every re-arm attempt, so their steady-state cost is one rejected cmsg
  // per ~16 datagrams; the fast-path sockets never see an EINVAL at all.
  int gso_reprieve_ = 0;
#endif
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
  // Resolver workers are joined in ~Reactor before WSACleanup(); a detached
  // thread still inside getaddrinfo() makes shutdown undefined behaviour (A-01).
  std::vector<std::thread> workers_;
  std::vector<std::pair<uint64_t, bool>> dead_apps_;  // {conn, is_target}
  // Sockets build_sets() could not place in this iteration's fd_set. They are
  // retried from the tick, and counted so the silent drop becomes visible (M-01).
  std::vector<uint64_t> unmonitored_;
  size_t skipped_this_pass_ = 0;
  uint64_t skipped_total_ = 0;
  uint64_t udp_send_errors_ = 0;          // permanent send failures (stats/debug)
  int64_t last_udp_send_error_ms_ = 0;    // rate limit for the log line above
  // #90 UDP socket recovery. A connected UDP socket on Windows can enter a
  // state where every send() fails; counting and dropping (the old behaviour)
  // also kills the keepalives, so the server's 135 s liveness window closes
  // the whole session set. Three consecutive "socket dead" verdicts arm a
  // rebuild; a successful send clears the streak. FCP_UDP_REBUILD=0 disables
  // the whole mechanism at runtime (no CLI/GUI change, no stats row change).
  uint32_t socket_dead_streak_ = 0;
  uint32_t rebuild_failures_ = 0;
  uint32_t udp_rebuilds_ = 0;
  int64_t last_rebuild_ms_ = 0;
  int64_t next_rebuild_allowed_ms_ = 0;
  bool rebuild_pending_ = false;
  bool udp_rebuild_enabled_ = true;
  int64_t next_skip_log_ms_ = 0;
  // Send shaper: the sliding window holds {ms, bytes} of what this host has
  // passed through in the trailing second; wire_deferred_ is the ordered hold
  // queue for datagrams that arrived over budget (capped at one second's worth,
  // so a sustained overload turns into shaped-link loss instead of memory).
  // The destination address, not the peer id, is captured: on the server a
  // peer slot can be retired and its id reused for a different source address
  // between enqueue and the next flush.
  struct DeferredWire {
    uint64_t peer = 0;  // GSO batching key (same iteration only)
    sockaddr_in to{};    // server: destination; unused on the client
    bool has_addr = false;
    std::vector<uint8_t> bytes;
  };
  std::deque<DeferredWire> wire_deferred_;
  size_t wire_deferred_bytes_ = 0;
  uint64_t wire_over_budget_ = 0;  // datagrams past the cap: shaped-link drops
  std::deque<std::pair<int64_t, size_t>> wire_window_;
  size_t wire_window_bytes_ = 0;
  // Stall watchdog state, seeded from the counters at start().
  uint64_t stall_seen_rx_bytes_ = 0;
  uint64_t stall_seen_tx_bytes_ = 0;
  int64_t stall_last_rx_ms_ = 0;
  int64_t stall_last_tx_ms_ = 0;
  int64_t stall_since_ms_ = 0;  // 0 = not stalled
  int64_t stall_next_log_ms_ = 0;
  // Recovery confirmation: `bytes_rx` also counts datagrams the engine then
  // drops (unknown salt, tombstone, garbage), so one spoofed packet must not
  // print "recovered". A stall clears only after inbound moved on two
  // consecutive watchdog ticks.
  bool stall_rx_pending_ = false;
  // High-loss warning state. `loss_warned_` latches so recovery is logged once,
  // and the next-log deadline rate-limits the reminder while it persists.
  int64_t loss_check_ms_ = 0;
  int64_t loss_warn_next_ms_ = 0;
  bool loss_warned_ = false;
  // --log-file 的落盘端：追加写 + 32 MiB 轮转（.1），改名失败降级继续
  // 追加（与 trace 的容错策略一致）。引擎 log 回调与关键内部行都经
  // emit()/写走文件；stderr 行为照旧。
  std::ofstream log_stream_;
  std::string log_path_;
  size_t log_bytes_ = 0;
  bool log_rotate_warned_ = false;
  std::mutex log_mutex_;
  void open_log_file();
  void rotate_log_file();
  // 给行补时间戳后落文件（stats/启动横幅用；注意正文要自带 [LEVEL]）。
  void write_log(const std::string& line);
  // 已经渲染好（时间戳 + 级别）的行直接落文件（log_line()/note() 用）。
  void write_log_stamped(const std::string& line);
  // 分级汇集点：标签分级 → 过滤 → 渲染（时间戳 + [LEVEL]）→ 双落
  // （stderr + 文件同一行文本；颜色由读日志的 GUI 按级别加，CLI 不吐 ANSI）。
  void log_line(const std::string& line);
  // 不走标签的内部行（启动/配置/stall）：同样渲染时间戳 + 级别，双落。
  void note(const std::string& line, int severity = Severity(LogLevel::kInfo));
  size_t max_sessions_ = 0;
  using SignalHandler = void (*)(int);
  SignalHandler prev_int_ = nullptr;
  SignalHandler prev_term_ = nullptr;
#ifndef _WIN32
  SignalHandler prev_pipe_ = nullptr;
#endif
  uint64_t next_local_conn_ = 1;
  int64_t next_tick_ms_ = 0;
  int64_t next_stats_ms_ = 0;
  int64_t started_ms_ = 0;
  bool wsa_owner_ = false;
};

}  // namespace fcp

#endif  // FCP_PROXY_REACTOR_H_
