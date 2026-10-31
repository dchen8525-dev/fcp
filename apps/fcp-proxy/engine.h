// ProxyEngine: the socket-free heart of the FCP proxy (docs/FCP_M2_PROXY.md §6).
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
#include "fcp/proxy_proto.h"
#include "fcp/session.h"
#include "fcp/stream.h"

namespace fcp {

// #29a/#35: one JSONL controller-trace sink per session, written to
// `<prefix>.<cid>.jsonl`; the parent directory chain is created on demand and
// an unopenable path disables recording with a stderr note. Shared by the CLI
// (--trace) and the Qt client (settings proxy/trace_prefix).
SessionConfig::TraceFn make_trace_sink(const std::string& prefix, uint64_t cid);

enum class EngineRole : uint8_t {
  kClient = 0,  // local SOCKS5/HTTP listener, one session per connection
  kServer = 1,  // remote end: session table, resolves and dials the targets
};

struct EngineConfig {
  EngineRole role = EngineRole::kClient;
  // Pre-shared key: both ends must be configured with the same one.
  uint8_t key[16] = {};
  uint8_t d = 10;
  uint8_t p = 3;
  uint8_t p_max = kDefaultPmax;
  uint16_t mtu = 1400;
  size_t ip_hdr_len = 20;
  int pinned_k = -1;  // >= 0 bypasses the adaptive strategy (measurements)
  // M3 byte budget (FCP_M3_CONTROL.md §2), passed to SessionConfig verbatim.
  double fec_budget = 0.50;
  // #29a controller trace: when non-empty, every session writes a JSONL
  // controller trace (SessionConfig::trace) to `<prefix>.<cid>.jsonl` —
  // the calibration input for tools/fcp_replay.
  std::string trace_prefix;
  size_t send_window_bytes = 256 * 1024;
  size_t rcv_buf_bytes = 256 * 1024;
  // Teardown of a tunnel that stopped speaking (§7: dead peer detection).
  int64_t idle_timeout_ms = 300000;
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
  // One sealed datagram for `peer`. On the client there is a single peer (the
  // server); on the server `peer` is the client address the reactor saw first.
  std::function<void(uint64_t peer, const uint8_t* wire, size_t len)> wire_send;
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

  // Timer pump: handshake retries, stream retransmission, dial and flush
  // deadlines, idle reaping. 25ms (kSessionTickMs) is the intended period.
  void on_tick(int64_t now_ms);

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
    uint32_t bad_entry = 0;   // malformed local request
    uint32_t open_failed = 0;  // OPEN_ERR sent or received
    uint32_t dup_rec = 0;      // #31: FEC recovered a slot the ARQ rtx also hit
    uint32_t handshake_failed = 0;
    uint32_t reset = 0;        // stream RST either way
    uint32_t idle_closed = 0;
    uint64_t bytes_tx = 0;
    uint64_t bytes_rx = 0;
  };

  const Counters& counters() const { return counters_; }
  // #31 (M4 trigger metric): live sum of every session's FEC/ARQ waste
  // counter — retransmissions that lost the race to parity.
  uint32_t dup_after_recovered() const;
  const PrewarmCache& prewarm_cache() const { return prewarm_; }
  // Bytes the engine is holding for `conn`'s application socket.
  size_t pending_app_bytes(uint64_t conn) const;

 private:
  enum class Phase : uint8_t {
    kEntry,       // client: local request not yet complete
    kAwaitReply,  // client: OPEN written, OPEN_OK/ERR not yet in
    kNegotiating,  // server: session created by an inbound HELLO, not yet up
    kAwaitOpen,   // server: stream up, OPEN message not yet complete
    kDialing,     // server: dial requested, deadline running
    kTunnel,      // both directions usable
    kDone,        // marked for reap
  };

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
    bool greeting_done = false;  // client: SOCKS5 method negotiation is over
    bool local_eof = false;  // the application socket gave up
    bool closing = false;  // OPEN_ERR went out: flush, then tear down
    bool want_fin = false;   // close the stream once both buffers are empty
    bool established_seen = false;

    std::vector<uint8_t> entry;      // local request bytes, still being parsed
    std::vector<uint8_t> to_stream;  // queued for Stream::write, window-bound
    std::vector<uint8_t> stream_in;  // tunnel bytes not yet consumed by a parser
    std::vector<uint8_t> app_in;     // bytes waiting for the app socket

    ProxyTarget target;
    int64_t dial_deadline_ms = 0;
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

  bool create_client_conn(uint64_t conn, uint64_t peer, int64_t now_ms);
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
  char diag_[256] = {};  // #33③: teardown forensics scratch
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
  std::vector<uint64_t> reap_ids_;
  std::vector<uint64_t> dial_queue_;
  bool in_flush_dials_ = false;
  // A dial runs the host's connect, which can call back into on_dial_result() and
  // therefore into reap(); the flag makes the nested call a no-op so only the
  // owner walks the id list.
  bool in_reap_ = false;
  Counters counters_;
};

}  // namespace fcp

#endif  // FCP_PROXY_ENGINE_H_
