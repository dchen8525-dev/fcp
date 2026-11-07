// ProxyEngine: the socket-free heart of the FCP proxy (M2代理设计.md §6).
//
// One engine holds every proxied connection. It owns the FCP sessions (one per
// connection, §3), the FCP-STREAM attached to each, the proxy entry codec
// (§4) and the prewarm cache (§5) -- and nothing else. Sockets, threads, DNS
// and clocks all belong to the host: the CLI select reactor and the Qt adapter
// drive the same engine through the callbacks below, which is what lets the
// GUI embed a proxy instead of spawning a process.
//
// Connection ids are the host's. On the client a connection is a local
// application socket, so the reactor allocates the id at accept(); on the
// server there is no local socket, so the engine allocates the id when it
// creates a session and the host keys its target socket by that same id. Every
// host callback therefore receives an id the host already knows.
//
// Data flow of one tunneled byte, client side:
//   local socket -> on_local_bytes -> Stream::write -> Session -> wire_send
//   wire -> on_wire -> Session -> Stream::on_segment -> app_in -> local_send
// and the server mirrors it through the target socket. Both directions are
// gated: reads are only requested while the stream has send space (§wants_*),
// and a host that will not take bytes back grows app_in, which the stream
// advertises as a shrinking window until the sender stops.

#ifndef FCP_PROXY_ENGINE_H_
#define FCP_PROXY_ENGINE_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "fcp/envelope.h"
#include "fcp/prewarm.h"
#include "fcp/session.h"
#include "fcp/stream.h"
#include "proxy/proxy_proto.h"

namespace fcp {

// #29a/#35: one JSONL controller-trace sink per session, written to
// `<prefix>.<cid>.jsonl`; the parent directory chain is created on demand and
// an unopenable path disables recording. Shared by the CLI (--trace) and the
// Qt client (settings proxy/trace_prefix). `log` routes the diagnostic to the
// host too: a GUI has no stderr, so a trace that silently records nothing used
// to be invisible (C-16).
//
// Rotation: the live file is capped at kTraceRotateBytes -- on crossing, it
// becomes ".1" and recording continues into a fresh file. `rotate_bytes` is a
// hook for tests: 64 MiB is the shipping default, not reachable in a unit
// test, so a test shrinks it; the constant carries that default in one place.
constexpr size_t kTraceRotateBytes = 64u * 1024u * 1024u;
SessionConfig::TraceFn make_trace_sink(const std::string& prefix, uint64_t cid,
                                       std::function<void(const std::string&)> log = {},
                                       size_t rotate_bytes = kTraceRotateBytes);

enum class EngineRole : uint8_t {
  kClient = 0,  // local SOCKS5/HTTP listener, one session per connection
  kServer = 1,  // remote end: session table, resolves and dials the targets
};

struct EngineConfig {
  EngineRole role = EngineRole::kClient;
  // Pre-shared key: both ends must be configured with the same one.
  uint8_t key[16] = {};
  uint8_t d = kDefaultD;
  uint8_t p = kDefaultP;
  uint8_t p_max = kDefaultPmax;
  uint16_t mtu = kDefaultMtu;
  size_t ip_hdr_len = kDefaultIpHeaderLen;
  // PMTUD (pmtu.h): probe upward from `mtu` to at most pmtu_max_mtu once the
  // peer advertises the capability. Product default on; the session-level
  // default stays off so library tests see exactly the wire they configure.
  // The reactor clears this if the socket could not be put in DF mode.
  bool pmtud = true;
  uint16_t pmtu_max_mtu = kDefaultPmtuMaxMtu;
  int pinned_k = -1;  // >= 0 bypasses the adaptive strategy (measurements)
  // M3 byte budget (M3控制设计.md §2), passed to SessionConfig verbatim.
  double fec_budget = kDefaultFecBudget;
  // #29a controller trace: when non-empty, every session writes a JSONL
  // controller trace (SessionConfig::trace) to `<prefix>.<cid>.jsonl` —
  // the calibration input for tools/fcp-replay.
  std::string trace_prefix;
  // Cap for that trace file (passed to make_trace_sink's rotate_bytes). The
  // default is the shipping value; only tests shrink it (64 MiB cannot be
  // crossed in a unit test).
  size_t trace_rotate_bytes = kTraceRotateBytes;
  size_t send_window_bytes = kDefaultSendWindowBytes;
  // True when the start was set explicitly (CLI --window / GUI spinbox), which
  // keeps the prewarm cache from replacing it with the peer's converged value.
  bool window_explicit = false;
  size_t rcv_buf_bytes = kDefaultRcvBufBytes;
  // Window autotune (StreamConfig::auto_window): the stream's send window
  // starts at send_window_bytes, grows while the stream is its own bottleneck
  // between window_min_bytes and window_max_bytes, and holds or shrinks when
  // its own queue shows up in the RTT. Not a BDP tracker: the measured BDP is
  // only the recovery reference after a loss.
  bool auto_window = true;
  // Congestion controller for the adaptive window: BBR (delivery-rate model +
  // pacing) is the default; false selects the epoch controller
  // (StreamConfig::bbr).
  bool bbr = true;
  // 1 = BBRv1, 2 = BBRv2 (default).
  int bbr_version = 2;
  // Loss-epoch rate probe: grow instead of cutting when a lossy epoch still
  // delivered data and shows no standing queue (epoch controller only).
  bool window_probe = true;
  size_t window_min_bytes = kDefaultWindowMinBytes;
  size_t window_max_bytes = kDefaultWindowMaxBytes;
  // Auto window + BBR: the send ceiling may follow the measured BDP up to this
  // many bytes, with window_max_bytes as its floor. 0 keeps the ceiling fixed
  // (the CLI raises it; a Stream configured directly keeps the old behaviour).
  size_t window_ceiling_bytes = 0;
  // One ACK per this many in-order data segments (StreamConfig::ack_every).
  // 1 = per segment, which is what the unit tests want; the CLI and the desktop
  // turn coalescing on for the wire.
  uint8_t ack_every = 1;
  // Teardown of a tunnel that stopped speaking (§7: dead peer detection).
  int64_t idle_timeout_ms = kDefaultIdleTimeoutMs;
  // Remote resolution plus dial (§4.3).
  int64_t dial_timeout_ms = 5000;
  // How long a finished tunnel may still take to flush its own bytes: the fin
  // and the last OPEN_ERR have to reach the peer before the session dies.
  int64_t flush_grace_ms = 2000;
  // Server only: ceiling on concurrent sessions, and on the pre-negotiation
  // cache a not-yet-established session may hold (§3 --max-sessions).
  size_t max_sessions = 256;
  bool prewarm = true;
  int64_t prewarm_ttl_ms = kPrewarmTtlMs;
};

// The host's side of the contract. Every function may be called many times per
// tick and must not call back into the engine.
struct EngineHost {
  // Write bytes to the application socket on the other end of this
  // connection -- the local one on the client, the dialed target on the
  // server. Returns how many the socket accepted; the engine keeps the rest
  // and lets the advertised window close. 0 with a non-empty buffer means
  // "would block".
  std::function<size_t(uint64_t conn, const uint8_t* data, size_t len)> app_send;
  // Done with this connection's application socket: close it and forget it.
  std::function<void(uint64_t conn)> app_close;
  // The other end of the tunnel will send nothing more: half-close this
  // connection's application socket (shutdown write, keep reading). The local
  // side then finishes in its own time and its close drives the teardown, so a
  // target that answers after the request is complete is still relayed.
  // Optional: a host without half-close support leaves it unset and the engine
  // falls back to closing the tunnel here.
  std::function<void(uint64_t conn)> app_shutdown;
  // One sealed datagram for `peer`. On the client there is a single peer (the
  // server); on the server `peer` is the client address the reactor saw first.
  // Returns the bytes the transport accepted (0 = dropped/would-block). The
  // engine counts only what actually left, so a dead UDP path cannot inflate
  // `bytes_tx` while the tunnel silently loses every datagram (M-05).
  std::function<size_t(uint64_t peer, const uint8_t* wire, size_t len)> wire_send;
  // Resolve and connect the target. The answer comes back through
  // on_dial_result(); the engine only enforces the deadline.
  std::function<void(uint64_t conn, const ProxyTarget& target)> dial;
  // Cache key for a wire peer (§5): the client returns its server address, the
  // server the client's. Empty string means "do not prewarm this peer".
  std::function<std::string(uint64_t peer)> peer_key;
  // Server only: a session routed through `peer` has been created / destroyed.
  // The host keys its source-address table by peer id; the reactor recycles a
  // slot only once its last session retires, so the two calls are balanced by
  // create_server_conn() and reap(). Optional: a host without an address table
  // (the Qt adapter) can leave them unset.
  std::function<void(uint64_t peer)> peer_bound;
  std::function<void(uint64_t peer)> peer_retired;
  std::function<void(uint8_t salt[Envelope::kSaltLen])> new_salt;
  std::function<void(const std::string& line)> log;
};

class ProxyEngine {
 public:
  ProxyEngine(const EngineConfig& config, EngineHost host);
  ProxyEngine(const ProxyEngine&) = delete;
  ProxyEngine& operator=(const ProxyEngine&) = delete;

  // ---- host -> engine ----

  // Client: a new local application connection. The session and its handshake
  // start here, so the (57-156ms) negotiation overlaps the greeting exchange.
  // Server: not used -- its connections are born from an inbound HELLO.
  void on_local_open(uint64_t conn, uint64_t peer, int64_t now_ms);
  void on_local_bytes(uint64_t conn, const uint8_t* data, size_t len, int64_t now_ms);
  // The local socket reached EOF or was reset. Nothing further arrives for it.
  void on_local_closed(uint64_t conn, int64_t now_ms);

  // Server: the dialed socket. `conn` is the id the engine passed to dial().
  void on_target_bytes(uint64_t conn, const uint8_t* data, size_t len, int64_t now_ms);
  void on_target_closed(uint64_t conn, int64_t now_ms);
  void on_dial_result(uint64_t conn, bool ok, OpenError err, int64_t now_ms);

  // Both: one inbound datagram from `peer`. Routes by the plaintext salt.
  void on_wire(uint64_t peer, const uint8_t* data, size_t len, int64_t now_ms);

  // The kernel refused an outbound datagram of wire_len bytes to `peer` with
  // EMSGSIZE: its own ICMP-learned path-MTU cache is below the refused IP
  // size, and datagrams that size die inside send() without reaching the
  // wire. Authoritative, immediate evidence -- the host's sessions sharing
  // that peer lower their send bound at once (session.cc
  // on_kernel_send_too_big) instead of waiting out the reachability
  // watchdog. Client role has a single remote, so the peer id is matched
  // loosely there; the server routes by peer exactly.
  void on_wire_send_too_big(uint64_t peer, size_t wire_len, int64_t now_ms);

  // Timer pump: handshake retries, stream retransmission, dial and flush
  // deadlines, idle reaping. 25ms (kSessionTickMs) is the intended period.
  void on_tick(int64_t now_ms);
  // PMTUD is only sound with DF set on the UDP socket (reactor.cc): without
  // it a router fragments an oversized probe instead of dropping it, and the
  // session would raise its MTU to a size the path cannot carry whole. The
  // host calls this when the setsockopt failed; sessions created afterwards
  // stop advertising the capability.
  void set_pmtud(bool enabled) { cfg_.pmtud = enabled; }

  // Earliest time any stream wants the host to tick again before the regular
  // 25 ms cadence: a coalesced ACK's deadline, or the pacer releasing the next
  // segment. 0 = nothing is waiting on a sub-tick wake. The reactor folds this
  // into its select() timeout, which is what gives the pacer a granularity
  // finer than the tick (and keeps ACK coalescing from adding a tick of
  // latency to short exchanges).
  int64_t next_wake_ms(int64_t now_ms) const;

  // The application socket took more bytes: retry the flush. Called when select
  // reports the socket writable, and again on every tick, because a window that
  // reopened between events still has to make progress.
  void on_app_writable(uint64_t conn, int64_t now_ms);

  // Does the engine still hold this connection? A DNS answer that arrives for a
  // connection that was already torn down must not open a socket for it.
  bool has_connection(uint64_t conn) const { return find(conn) != nullptr; }

  // ---- engine -> host (polled once per tick, before the fd_set is built) ----

  // Read more from the local socket / the target? False while the stream's send
  // window is full, which is what turns a slow peer into TCP backpressure
  // instead of an unbounded buffer.
  bool wants_local_read(uint64_t conn) const;
  bool wants_target_read(uint64_t conn) const;

  // ---- diagnostics ----

  struct Counters {
    size_t live = 0;         // connections held, established or not
    size_t established = 0;  // sessions that finished negotiation
    size_t tunnels = 0;      // OPEN_OK exchanged, both directions usable
    uint32_t salt_clash = 0;
    uint32_t unknown_salt = 0;
    uint32_t salt_tombstone = 0;  // #29a: dropped as a dead session's tail
    uint32_t over_limit = 0;  // refused: max_sessions reached
    // Refused before any traffic: the configured D/P'/MTU cannot carry a data
    // symbol (Session::config_valid()). Every connection is refused, so a
    // non-zero value here means the engine was misconfigured, not a peer.
    uint32_t bad_config = 0;
    // Refused because the OS CSPRNG could not draw the session salt. Never
    // blame the config for this one: the fix is in the entropy environment,
    // not in --mtu.
    uint32_t no_entropy = 0;
    // 拒在预认证构筑预算门外的新会话（见 create_server_conn）。正常运行
    // 应恒为 0；非 0 说明对端以新盐洪泛，或者该预算被顶满要求调参。
    uint32_t over_budget = 0;
    uint32_t bad_entry = 0;   // malformed local request
    uint32_t open_failed = 0;  // OPEN_ERR sent or received
    uint32_t handshake_failed = 0;
    uint32_t reset = 0;        // stream RST either way
    uint32_t idle_closed = 0;
    uint64_t bytes_tx = 0;  // accepted by the transport, not merely attempted
    uint64_t bytes_rx = 0;
    // Sealed datagrams the host could not send (`send`/`sendto`/writeDatagram
    // returned an error). Non-zero means the wire path is failing even though
    // the session layer looks healthy (M-05).
    uint64_t wire_errors = 0;
  };

  const Counters& counters() const { return counters_; }
  // #31 (M4 trigger metric): live sum of every session's FEC/ARQ waste
  // counter — retransmissions that lost the race to parity.
  uint32_t dup_after_recovered() const;
  // Raw loss of the most recent FECSTAT interval, summed over live sessions.
  // `in_*` is this end's inbound direction (what we failed to receive, from
  // FcpReporter); `out_*` is the peer's view of our outbound direction (from
  // the last report the peer sent us). Counts are data symbols, pre-FEC.
  // A zero `expected` means no report has arrived for that direction yet.
  struct LossSample {
    uint64_t in_expected = 0;
    uint64_t in_lost = 0;
    uint64_t out_expected = 0;
    uint64_t out_lost = 0;
  };
  LossSample loss_sample() const;
  const PrewarmCache& prewarm_cache() const { return prewarm_; }
  // Bytes the engine is holding for `conn`'s application socket.
  size_t pending_app_bytes(uint64_t conn) const;
  // The stream's send window in force for `conn` right now (0 before it has one).
  // With autotune on this moves every RTT, so the host can show what the path
  // was measured to carry instead of what it was configured with.
  size_t send_window(uint64_t conn) const;
  // The receive room the peer last advertised to `conn`'s stream (0 before it
  // has an ACK). Together with send_window() this says which of the two
  // windows is holding the tunnel back.
  size_t peer_window(uint64_t conn) const;

 private:
  enum class Phase : uint8_t {
    // Client: still reading the local request. Covers the protocol sniff (from
    // byte 0), the HTTP head, and the SOCKS5 greeting.
    kEntry,
    // Client: the SOCKS5 greeting was answered, the CONNECT request is not in
    // yet. A request may be corked behind the greeting, so parse_entry() falls
    // straight through from kEntry into this phase.
    kSocks5Request,
    kAwaitReply,  // client: OPEN written, OPEN_OK/ERR not yet in
    kNegotiating,  // server: session created by an inbound HELLO, not yet up
    kAwaitOpen,   // server: stream up, OPEN message not yet complete
    kDialing,     // server: dial requested, deadline running
    kTunnel,      // both directions usable
    kDone,        // marked for reap
  };

  // Is the client still exchanging its entry request? Asked instead of comparing
  // against kEntry, so adding an entry phase cannot silently reclassify a
  // connection as "past the entry exchange" at a call site that forgot it.
  static bool in_entry_phase(Phase phase) {
    return phase == Phase::kEntry || phase == Phase::kSocks5Request;
  }

  struct Conn {
    uint64_t id = 0;
    uint64_t peer = 0;
    Phase phase = Phase::kEntry;
    std::unique_ptr<Session> session;
    std::unique_ptr<Stream> stream;
    StreamConfig stream_cfg;
    std::string salt_key;  // the 8-byte wire salt, as a map key

    bool socks5 = true;     // client: entry protocol, sniffed from byte 0
    bool sniffed = false;   // socks5 was decided from the first byte
    bool local_eof = false;  // the application socket gave up
    // Two independent teardown paths, and the difference is load-bearing:
    //   closing  -- we refused the tunnel (OPEN_ERR). Inbound stream bytes are
    //               dropped by on_stream_bytes(); nothing may be forwarded.
    //   want_fin -- we are done sending (local EOF, peer close, or the flush
    //               after an OPEN_ERR) but the peer's bytes are still taken
    //               until the fin lands.
    // send_open_error() sets both; on_local_closed()/on_target_closed() set only
    // want_fin; the stream's own close callback sets only want_fin.
    bool closing = false;
    bool want_fin = false;
    bool established_seen = false;
    // A1 follow-up: only a session that once presented a valid GCM tag may
    // leave a salt tombstone. Untagged traffic must not grow that table.
    bool authenticated_once = false;
    // flush_app re-entrancy: app_send may emit bytesWritten synchronously,
    // which re-enters on_app_writable -> flush_app while the outer loop is
    // still holding the accepted/taken bookkeeping.
    bool in_flush_app = false;

    std::vector<uint8_t> entry;      // local request bytes, still being parsed
    std::vector<uint8_t> to_stream;  // queued for Stream::write, window-bound
    std::vector<uint8_t> stream_in;  // tunnel bytes not yet consumed by a parser
    std::vector<uint8_t> app_in;     // bytes waiting for the app socket

    ProxyTarget target;
    int64_t dial_deadline_ms = 0;
    // Deadline for kAwaitReply / kAwaitOpen: without it a peer that completes
    // the handshake but never sends OPEN/OPEN_OK keeps the session (and its
    // max_sessions slot) alive forever, because plain ACKs refresh the stream's
    // idle clock (B-06).
    int64_t phase_deadline_ms = 0;
    int64_t flush_deadline_ms = 0;
    // Bytes the application socket has taken, counted with the stream's own
    // progress to decide whether the grace clock should keep running.
    uint64_t app_accepted = 0;
    uint64_t grace_progress = 0;
  };

  Conn* find_by_salt(const uint8_t* salt, size_t len);
  Conn* find(uint64_t conn);
  const Conn* find(uint64_t conn) const;

  // Client: the greeting/request exchange on a local connection.
  bool parse_entry(Conn& conn, int64_t now_ms);
  void start_tunnel_client(Conn& conn, int64_t now_ms);
  // Server: the OPEN exchange on a stream.
  void send_open_error(Conn& conn, OpenError err);

  // The fields both ends share. A new SessionConfig field belongs here, never
  // in a create_*_conn(); fill_stream_config() in attach_stream() is the same
  // rule for StreamConfig. (History: A15/B11.)
  void fill_session_config(SessionConfig* sc, uint64_t conn_id) const;
  void fill_stream_config(StreamConfig* sc) const;
  std::unique_ptr<Session> make_session(uint64_t conn_id, const SessionConfig& sc);

  // 会话建立退出码。熵源失败与配置失败是两类故障，stats 行分开计数
  // （bad_config 会归因到 --mtu/--fec；no_entropy 指向 OS 熵源）。
  enum class CreateStatus : uint8_t {
    kOk = 0,
    kNoEntropy,
    kBadConfig,
  };
  CreateStatus create_client_conn(uint64_t conn, uint64_t peer, int64_t now_ms);
  Conn* create_server_conn(uint64_t peer, const uint8_t* salt, int64_t now_ms);
  void attach_stream(Conn& conn);
  // Handshake completion and failure, watched after every inbound pump.
  void session_events(Conn& conn, int64_t now_ms);

  void queue_stream(Conn& conn, const uint8_t* data, size_t len);
  void drain_stream(Conn& conn);
  void flush_app(Conn& conn);
  // Runs the dial requests the parsers queued. Deferred because host_.dial()
  // can call back into on_dial_result() -- and therefore erase the Conn -- while
  // the caller is still holding a reference to it.
  void flush_dials();
  // Stream delivery sink.
  void on_stream_bytes(Conn& conn, const uint8_t* data, size_t len);
  void run_pre_tunnel_parser(Conn& conn, int64_t now_ms);
  void parse_open_reply(Conn& conn);
  void parse_open_request(Conn& conn, int64_t now_ms);
  // The answer this proxy gives its application socket when the tunnel did not
  // come up: the SOCKS5 reply or the HTTP status, whichever the client speaks.
  void queue_local_reply(Conn& conn, Socks5Rep rep, HttpReply http);
  // queue_local_reply + the graceful close choreography (want_fin/fin/grace
  // clock), so the reply actually reaches the application instead of dying
  // with the socket when the flush cannot complete on the spot.
  void refuse_local(Conn& conn, const char* why, Socks5Rep rep, HttpReply http);

  // Close the application socket, drop the session and its table entries, and
  // write the peer profile back into the prewarm cache.
  void finish_conn(Conn& conn, int64_t now_ms, const char* why);
  void reap(int64_t now_ms);
  void maybe_fin(Conn& conn);
  // Bytes moved so far, from whichever clocks are running: what the peer
  // acknowledged, what it delivered, and what the application socket accepted.
  uint64_t progress_of(const Conn& conn) const;
  // Arms (or re-arms) the grace clock and takes the progress sample it is judged
  // against. Only a conn with the clock armed can be cut off, so every arm site
  // has to sample here or the first tick would read "no progress".
  void arm_grace(Conn& conn, bool only_if_idle);
  void save_profile(Conn& conn, int64_t now_ms);
  PeerProfile profile_for(uint64_t peer, int64_t now_ms) const;
  std::string label(const Conn& conn) const;
  std::string label(uint64_t conn) const;
  char diag_[512] = {};  // #33③: teardown forensics scratch
  void log(const std::string& line) const;

  EngineConfig cfg_;
  EngineHost host_;
  PrewarmCache prewarm_;
  std::unordered_map<uint64_t, std::unique_ptr<Conn>> by_conn_;
  std::unordered_map<std::string, uint64_t> by_salt_;
  // #29a: salts of recently reaped sessions, expiry stamped. Their tail
  // retransmissions are dropped as `salt_tombstone` instead of counting as
  // unknown_salt (client) or rebirthing a phantom session (server).
  std::unordered_map<std::string, int64_t> salt_tombstones_;
  uint64_t next_server_conn_ = 1;
  int64_t now_ms_ = 0;
  int64_t next_prune_ms_ = 0;
  // Rate limit for the "datagram from another address" line. The salt travels
  // in the clear, so anyone who has seen the session can reach this drop path;
  // it must not turn into a log flood.
  int64_t last_rebind_drop_log_ms_ = 0;
  bool rebind_drop_logged_ = false;
  std::vector<uint64_t> reap_ids_;
  std::vector<uint64_t> dial_queue_;
  bool in_flush_dials_ = false;
  // A dial runs the host's connect, which can call back into on_dial_result() and
  // therefore into reap(); the flag makes the nested call a no-op so only the
  // owner walks the id list.
  bool in_reap_ = false;
  // 预认证会话构筑预算（对抗分析第七轮 P2，见 create_server_conn）。
  int64_t create_window_ = -1;
  int32_t create_budget_ = 0;
  Counters counters_;
};

}  // namespace fcp

#endif  // FCP_PROXY_ENGINE_H_
