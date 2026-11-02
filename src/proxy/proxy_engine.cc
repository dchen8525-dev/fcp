#include "proxy/proxy_engine.h"

#include <cstdio>
#include <cstring>
#include <random>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

namespace fcp {
namespace {

void append_bytes(std::vector<uint8_t>* dst, const uint8_t* src, size_t len) {
  if (len != 0) {
    dst->insert(dst->end(), src, src + len);
  }
}

void drop_front(std::vector<uint8_t>* v, size_t n) {
  if (n >= v->size()) {
    v->clear();
    return;
  }
  v->erase(v->begin(), v->begin() + static_cast<std::ptrdiff_t>(n));
}

// #29a: how long a reaped session's salt keeps absorbing the peer's tail
// retransmissions before the routing entry is truly forgotten.
// A1 follow-up: a reclaimed salt must stay forgotten long enough that a
// recorded HELLO cannot resurrect the session. Five seconds only covered the
// peer's RTO tail; a replayed handshake a moment later rebuilt the session
// with the same (key, IV) space. Five minutes with a bounded table keeps the
// memory cost fixed (only authenticated sessions may enter) while making the
// replay window operationally useless. The residual (a recording older than
// the TTL) needs a handshake challenge and is tracked as a protocol item.
constexpr int64_t kSaltTombstoneMs = 5 * 60 * 1000;
// Only authenticated sessions insert here, so this bound is a flood ceiling
// for PSK holders, not for arbitrary UDP senders.
constexpr size_t kSaltTombstoneMax = 8192;

std::string salt_key_of(const uint8_t* salt) {
  return std::string(reinterpret_cast<const char*>(salt), Envelope::kSaltLen);
}

// #29a: one JSONL controller-trace sink per session, closed with the session
// (the shared_ptr dies with the captured lambda). Empty prefix = disabled.
// #33: the prefix may name a directory that does not exist yet (--trace=/run/
// fcp/cli before anyone created /run/fcp) — create the parent chain instead of
// silently recording nothing, which is how the first WAN run lost every
// client-side trace.
void make_directories_for(const std::string& path) {
  for (size_t i = 1; i < path.size(); ++i) {
    if (path[i] != '/' && path[i] != '\\') {
      continue;
    }
    const std::string dir = path.substr(0, i);
#ifdef _WIN32
    _mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), 0755);
#endif
  }
}

void random_salt(uint8_t out[Envelope::kSaltLen]) {
  static std::random_device rd;
  for (size_t i = 0; i < Envelope::kSaltLen; ++i) {
    out[i] = static_cast<uint8_t>(rd() & 0xFFu);
  }
}

const char* stream_reason_text(CloseReason reason) {
  switch (reason) {
    case CloseReason::kNone:
      return "open";
    case CloseReason::kLocalEof:
      return "flushed and closed";
    case CloseReason::kPeerClose:
      return "peer closed";
    case CloseReason::kReset:
      return "reset";
    case CloseReason::kIdle:
      return "idle timeout";
  }
  return "closed";
}

}  // namespace

// Declared in proxy_engine.h; the Qt client builds its own sinks from settings.
// The sink opens lazily on the first trace entry: a server creates the Conn
// before the first datagram authenticates, so opening eagerly meant one empty
// file per forged 8-byte salt (a trivially amplified inode DoS). Only
// authenticated sessions emit a controller report, so the file appears only
// for those.
SessionConfig::TraceFn make_trace_sink(const std::string& prefix, uint64_t cid) {
  if (prefix.empty()) {
    return nullptr;
  }
  struct Lazy {
    std::string path;
    std::shared_ptr<std::FILE> file;
    bool attempted = false;
  };
  auto state = std::make_shared<Lazy>();
  state->path = prefix + "." + std::to_string(cid) + ".jsonl";
  return [state](const TraceEntry& e) {
    if (!state->attempted) {
      state->attempted = true;
      make_directories_for(state->path);
      state->file = std::shared_ptr<std::FILE>(
          std::fopen(state->path.c_str(), "wb"),
          [](std::FILE* f) {
            if (f != nullptr) {
              std::fclose(f);
            }
          });
      if (!state->file || state->file.get() == nullptr) {
        // #33: never silent again — stderr is the only surface here.
        std::fprintf(stderr, "fcp: trace path %s unopenable; recording disabled\n",
                     state->path.c_str());
      }
    }
    if (!state->file || state->file.get() == nullptr) {
      return;
    }
    std::string line;
    encode_trace_line(e, &line);
    line.push_back('\n');
    std::fwrite(line.data(), 1, line.size(), state->file.get());
  };
}

ProxyEngine::ProxyEngine(const EngineConfig& config, EngineHost host)
    : cfg_(config),
      host_(std::move(host)),
      prewarm_(config.prewarm_ttl_ms, kPrewarmMaxEntries) {}

// ---- host -> engine ----

void ProxyEngine::on_local_open(uint64_t conn, uint64_t peer, int64_t now_ms) {
  now_ms_ = now_ms;
  if (cfg_.role != EngineRole::kClient || by_conn_.count(conn) != 0) {
    return;
  }
  if (by_conn_.size() >= cfg_.max_sessions) {
    ++counters_.over_limit;
    log(label(conn) + " refused: session limit");
    if (host_.app_close) {
      host_.app_close(conn);
    }
    return;
  }
  // A refusal here (the configured MTU leaves no room for a data symbol) has to
  // look like every other refusal: the engine holds no Conn for this socket, so
  // unless the host is told to close it the local socket is never freed and the
  // application waits on a tunnel that will never exist.
  if (!create_client_conn(conn, peer, now_ms)) {
    ++counters_.bad_config;
    log(label(conn) + " refused: MTU leaves no room for a data symbol");
    if (host_.app_close) {
      host_.app_close(conn);
    }
  }
  reap(now_ms);
}

void ProxyEngine::on_local_bytes(uint64_t conn, const uint8_t* data, size_t len,
                                 int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->phase == Phase::kDone || len == 0) {
    return;
  }
  if (in_entry_phase(c->phase)) {
    append_bytes(&c->entry, data, len);
    parse_entry(*c, now_ms);
  } else {
    queue_stream(*c, data, len);
    drain_stream(*c);
  }
  reap(now_ms);
}

void ProxyEngine::on_local_closed(uint64_t conn, int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->phase == Phase::kDone) {
    return;
  }
  c->local_eof = true;
  if (in_entry_phase(c->phase)) {
    // The application hung up before finishing its request: nothing to tunnel,
    // and no reply is owed to a client that never asked for one.
    finish_conn(*c, now_ms, "local closed before the request");
  } else {
    c->want_fin = true;
    maybe_fin(*c);
  }
  reap(now_ms);
}

void ProxyEngine::on_target_bytes(uint64_t conn, const uint8_t* data, size_t len,
                                  int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->phase != Phase::kTunnel || len == 0) {
    return;
  }
  queue_stream(*c, data, len);
  drain_stream(*c);
  reap(now_ms);
}

void ProxyEngine::on_target_closed(uint64_t conn, int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->phase == Phase::kDone) {
    return;
  }
  c->local_eof = true;
  c->want_fin = true;
  maybe_fin(*c);
  reap(now_ms);
}

void ProxyEngine::on_dial_result(uint64_t conn, bool ok, OpenError err, int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->closing || c->phase != Phase::kDialing) {
    return;
  }
  if (!ok) {
    send_open_error(*c, err);
    reap(now_ms);
    return;
  }
  uint8_t buf[kOpenOkLen];
  const size_t n = open_write_ok(buf, sizeof(buf));
  c->phase = Phase::kTunnel;
  ++counters_.tunnels;
  queue_stream(*c, buf, n);
  drain_stream(*c);
  // Bytes the client pipelined behind its OPEN now have somewhere to go.
  append_bytes(&c->app_in, c->stream_in.data(), c->stream_in.size());
  c->stream_in.clear();
  flush_app(*c);
  log(label(*c) + " tunnel open");
  reap(now_ms);
}

void ProxyEngine::on_wire(uint64_t peer, const uint8_t* data, size_t len, int64_t now_ms) {
  now_ms_ = now_ms;
  counters_.bytes_rx += len;
  if (data == nullptr || len < Envelope::kSaltLen) {
    ++counters_.unknown_salt;
    return;
  }
  // #29a: a tombstoned salt is a dead session's tail — drop quietly. On the
  // server this also stops a late retransmission from being mistaken for the
  // first HELLO of a phantom session. A live session's salt never gets here:
  // the lookup below finds it first, and reap() only tombstones salts it just
  // removed from by_salt_.
  const auto tomb_it = salt_tombstones_.find(salt_key_of(data));
  if (tomb_it != salt_tombstones_.end()) {
    if (now_ms < tomb_it->second) {
      ++counters_.salt_tombstone;
      return;
    }
    salt_tombstones_.erase(tomb_it);  // grace over: forget it for real
  }
  Conn* c = find_by_salt(data, len);
  bool born = false;
  if (c == nullptr) {
    // Client: a salt we did not mint is not ours. Server: this may be the first
    // HELLO of a new connection, which is the only way a session is born here.
    if (cfg_.role != EngineRole::kServer) {
      ++counters_.unknown_salt;
      return;
    }
    c = create_server_conn(peer, data, now_ms);
    if (c == nullptr) {
      return;
    }
    born = true;
  }
  // A1: the salt rides in the clear, so the lookup above proves nothing. The
  // envelope must authenticate before the datagram gets any authority over the
  // session -- in particular before a mismatched source address may tear it
  // down. Otherwise one 8-byte prefix from any spoofed address kills a live
  // tunnel without the PSK.
  const bool authenticated = c->session->on_wire(data, len, now_ms);
  if (authenticated) {
    // A1 follow-up: remember that this Conn earned the right to a tombstone.
    c->authenticated_once = true;
  }
  if (born) {
    // A salt is minted by a peer that holds the PSK, so the datagram that
    // creates a server session must authenticate. Otherwise anyone with a UDP
    // socket could insert a Conn per random salt and pin max_sessions; the
    // session would sit in kNegotiating forever because there is no peer to
    // negotiate with. (The start() in create_server_conn bounds the same table
    // for an authenticated peer that never completes a handshake.)
    if (!authenticated) {
      finish_conn(*c, now_ms, "unauthenticated first datagram");
      reap(now_ms);
      return;
    }
  } else if (c->peer != peer) {
    if (!authenticated) {
      // Replayed or forged prefix from another address: it never reached the
      // session (no tag, no nonce accepted), so dropping it is enough.
      return;
    }
    // Same salt, different source address, and a fresh nonce that only the
    // session key could have sealed: a fourth-party replay (or the peer after
    // a NAT rebind). No envelope can attribute the source address, so this is
    // the only place the binding is enforceable.
    ++counters_.salt_clash;
    log(label(*c) + " salt replay from another address");
    finish_conn(*c, now_ms, "salt re-bound to a new address");
    reap(now_ms);
    return;
  }
  session_events(*c, now_ms);
  if (c->phase != Phase::kDone) {
    drain_stream(*c);
    flush_app(*c);
    run_pre_tunnel_parser(*c, now_ms);
  }
  reap(now_ms);
}

void ProxyEngine::on_app_writable(uint64_t conn, int64_t now_ms) {
  now_ms_ = now_ms;
  Conn* c = find(conn);
  if (c == nullptr || c->phase == Phase::kDone) {
    return;
  }
  flush_app(*c);
  reap(now_ms);
}

void ProxyEngine::on_tick(int64_t now_ms) {
  now_ms_ = now_ms;
  // #29a: expired tombstones whose salts never see another datagram would
  // otherwise live forever; the lookup path only prunes the one it touches.
  for (auto it = salt_tombstones_.begin(); it != salt_tombstones_.end();) {
    if (now_ms >= it->second) {
      it = salt_tombstones_.erase(it);
    } else {
      ++it;
    }
  }
  std::vector<uint64_t> ids;
  ids.reserve(by_conn_.size());
  for (const auto& entry : by_conn_) {
    ids.push_back(entry.first);
  }
  for (uint64_t id : ids) {
    Conn* c = find(id);
    if (c == nullptr || c->phase == Phase::kDone) {
      continue;
    }
    if (c->stream) {
      c->stream->on_tick(now_ms);
    }
    if (c->phase == Phase::kDone) {
      continue;  // the stream reset or idled inside its own tick
    }
    if (c->session) {
      c->session->on_tick(now_ms);
    }
    session_events(*c, now_ms);
    if (c->phase == Phase::kDone) {
      continue;
    }
    drain_stream(*c);
    flush_app(*c);
    run_pre_tunnel_parser(*c, now_ms);
    if (c->flush_deadline_ms != 0) {
      // A grace clock is only ever armed for a tunnel that is closing or has
      // been refused. Slide it while bytes keep moving in either direction, so
      // that firing means "nothing moved for the whole window" rather than
      // "this tunnel happened to be long".
      const uint64_t progress = progress_of(*c);
      if (progress != c->grace_progress) {
        c->grace_progress = progress;
        c->flush_deadline_ms = now_ms + cfg_.flush_grace_ms;
      }
    }
    // `!closing` is what makes the second branch reachable at all: a tunnel the
    // dial deadline already refused stays in kDialing, and the first branch would
    // keep winning the else-if on every tick, so the grace clock would never be
    // read and the session would live until the idle timeout.
    if (c->phase == Phase::kDialing && !c->closing && now_ms >= c->dial_deadline_ms) {
      send_open_error(*c, OpenError::kTargetTimeout);
    } else if (c->flush_deadline_ms != 0 && now_ms >= c->flush_deadline_ms) {
      const bool wedged = !c->app_in.empty() || !c->to_stream.empty();
      finish_conn(*c, now_ms, wedged ? "the application socket stopped taking bytes"
                                     : "the peer stopped acknowledging");
    }
  }
  if (cfg_.prewarm && now_ms >= next_prune_ms_) {
    next_prune_ms_ = now_ms + kPrewarmTtlMs;
    prewarm_.prune(now_ms);
  }
  reap(now_ms);
}

// ---- engine -> host ----

bool ProxyEngine::wants_local_read(uint64_t conn) const {
  const Conn* c = find(conn);
  if (c == nullptr || cfg_.role != EngineRole::kClient || c->phase == Phase::kDone ||
      c->local_eof) {
    return false;
  }
  if (in_entry_phase(c->phase)) {
    // One head is all the parsers look at, so a client that never completes one
    // cannot make this buffer grow past the budget it is judged against.
    return c->entry.size() <= kHttpHeadMaxBytes;
  }
  return c->to_stream.empty() && c->stream && c->stream->can_write();
}

bool ProxyEngine::wants_target_read(uint64_t conn) const {
  const Conn* c = find(conn);
  if (c == nullptr || cfg_.role != EngineRole::kServer || c->local_eof ||
      c->phase != Phase::kTunnel) {
    return false;
  }
  return c->to_stream.empty() && c->stream && c->stream->can_write();
}

uint32_t ProxyEngine::dup_after_recovered() const {
  uint32_t total = 0;
  for (const auto& entry : by_conn_) {
    const Conn& c = *entry.second;
    if (c.session) {
      total += c.session->dup_after_recovered();
    }
  }
  return total;
}

size_t ProxyEngine::pending_app_bytes(uint64_t conn) const {
  const Conn* c = find(conn);
  return c == nullptr ? 0 : c->app_in.size();
}

size_t ProxyEngine::send_window(uint64_t conn) const {
  const Conn* c = find(conn);
  return c == nullptr || c->stream == nullptr ? 0 : c->stream->send_window();
}

size_t ProxyEngine::peer_window(uint64_t conn) const {
  const Conn* c = find(conn);
  return c == nullptr || c->stream == nullptr ? 0 : c->stream->peer_window();
}

// ---- connection setup ----

// Every field whose value does not depend on which end we are. The caller fills
// only what genuinely differs between the ends -- salt and the two directions
// -- so a new SessionConfig field lands for both directions by construction.
void ProxyEngine::fill_session_config(SessionConfig* sc, uint64_t conn_id) const {
  std::memcpy(sc->key, cfg_.key, sizeof(sc->key));
  sc->d = cfg_.d;
  sc->p = cfg_.p;
  sc->p_max = cfg_.p_max;
  sc->mtu = cfg_.mtu;
  sc->ip_hdr_len = cfg_.ip_hdr_len;
  sc->pinned_k = cfg_.pinned_k;
  sc->fec_budget = cfg_.fec_budget;
  sc->trace = make_trace_sink(cfg_.trace_prefix, conn_id);
  // A stream numbers bytes, so a retransmission deliberately repeats an id the
  // peer has to see again; the frame-layer dedup keyed on the KCP sn would eat
  // it and stall the send window (session.h, SessionConfig::sn_of).
  sc->sn_of = nullptr;
}

// Same contract as fill_session_config, for the stream half: every
// StreamConfig field the engine owns a copy of in EngineConfig. The caller
// keeps what is per-connection (the prewarm profile, which apply_prewarm
// writes into Conn::stream_cfg at creation) and fills max_segment afterwards,
// since it needs the negotiated MTU.
void ProxyEngine::fill_stream_config(StreamConfig* sc) const {
  sc->send_window_bytes = cfg_.send_window_bytes;
  // The loss floor is the configured start, captured before apply_prewarm()
  // may replace send_window_bytes with a prior (decision #33: only the
  // delay evidence may take the window below the operator's --window).
  sc->loss_floor_bytes = cfg_.send_window_bytes;
  sc->send_window_explicit = cfg_.window_explicit;
  sc->rcv_buf_bytes = cfg_.rcv_buf_bytes;
  sc->auto_window = cfg_.auto_window;
  sc->window_min_bytes = cfg_.window_min_bytes;
  sc->window_max_bytes = cfg_.window_max_bytes;
  sc->idle_timeout_ms = cfg_.idle_timeout_ms;
}

// The Session's three host hooks: every one of them re-resolves the Conn by id
// instead of capturing it, because a callback can fire while the table entry is
// being replaced (find() returns nullptr, and the hook is a no-op). Both ends
// wire themselves this way; only the engine knows which end it is, the Session
// never does.
std::unique_ptr<Session> ProxyEngine::make_session(uint64_t cid, const SessionConfig& sc) {
  return std::make_unique<Session>(
      sc,
      [this, cid](const uint8_t* wire, size_t len, SymbolType) {
        Conn* p = find(cid);
        if (p == nullptr || p->phase == Phase::kDone || !host_.wire_send) {
          return;
        }
        counters_.bytes_tx += len;
        host_.wire_send(p->peer, wire, len);
      },
      [this, cid](const uint8_t* payload, size_t len) {
        Conn* p = find(cid);
        if (p == nullptr || p->stream == nullptr) {
          return;
        }
        p->stream->on_segment(payload, len, now_ms_);
      },
      [this](const std::string& line) { log(line); });
}

bool ProxyEngine::create_client_conn(uint64_t id, uint64_t peer, int64_t now_ms) {
  auto conn = std::make_unique<Conn>();
  Conn* raw = conn.get();
  raw->id = id;
  raw->peer = peer;
  raw->phase = Phase::kEntry;

  SessionConfig sc;
  // One call is enough: fill_session_config() writes key/D/P'/MTU/budget/trace
  // but never sc.salt, so it composes with host_.new_salt() in either order.
  // (This used to be called on both sides of the salt draw, which built and
  // discarded a trace sink per connection.)
  fill_session_config(&sc, id);
  if (host_.new_salt) {
    host_.new_salt(sc.salt);
  } else {
    random_salt(sc.salt);
  }
  sc.send_direction = Direction::kC2S;
  sc.recv_direction = Direction::kS2C;
  // Fill the engine-owned half first: apply_prewarm() decides whether the
  // window prior may replace the start from StreamConfig::auto_window and
  // StreamConfig::send_window_explicit, so those flags have to be real values,
  // not the default-constructed false/false.
  fill_stream_config(&raw->stream_cfg);
  apply_prewarm(profile_for(peer, now_ms), &sc, &raw->stream_cfg);

  raw->session = make_session(id, sc);
  if (!raw->session->config_valid()) {
    log(label(id) + " bad MTU configuration");
    return false;
  }
  raw->salt_key = salt_key_of(sc.salt);
  attach_stream(*raw);
  by_conn_[id] = std::move(conn);
  by_salt_.emplace(raw->salt_key, id);
  ++counters_.live;
  raw->session->start(now_ms);
  return true;
}

ProxyEngine::Conn* ProxyEngine::create_server_conn(uint64_t peer, const uint8_t* salt,
                                                   int64_t now_ms) {
  if (by_conn_.size() >= cfg_.max_sessions) {
    ++counters_.over_limit;
    return nullptr;
  }
  const std::string key = salt_key_of(salt);
  if (by_salt_.count(key) != 0) {
    ++counters_.salt_clash;
    return nullptr;
  }
  const uint64_t id = next_server_conn_++;

  auto conn = std::make_unique<Conn>();
  Conn* raw = conn.get();
  raw->id = id;
  raw->peer = peer;
  raw->phase = Phase::kNegotiating;
  raw->socks5 = false;  // the server never answers a local request

  SessionConfig sc;
  fill_session_config(&sc, id);
  std::memcpy(sc.salt, salt, Envelope::kSaltLen);
  sc.send_direction = Direction::kS2C;
  sc.recv_direction = Direction::kC2S;
  // Same order as the client path: the flags apply_prewarm() reads must be the
  // configured ones. The stream is attached later, when the handshake
  // completes, so this is also the only point where conn.stream_cfg is filled.
  fill_stream_config(&raw->stream_cfg);
  apply_prewarm(profile_for(peer, now_ms), &sc, &raw->stream_cfg);

  raw->session = make_session(id, sc);
  if (!raw->session->config_valid()) {
    return nullptr;
  }
  raw->salt_key = key;
  by_conn_[id] = std::move(conn);
  by_salt_.emplace(key, id);
  ++counters_.live;
  if (host_.peer_bound) {
    host_.peer_bound(peer);
  }
  // The server side of the handshake has to run its own retry clock too: an
  // authenticated first datagram that is not a HELLO leaves the peer silent,
  // and without start() the session would stay in kNegotiating (and in this
  // table) forever. "Both sides may send HELLO simultaneously" (§6), so this
  // costs nothing when the creating datagram was a HELLO -- it negotiates
  // before the next tick and the scheduled HELLO never goes out.
  raw->session->start(now_ms);
  return raw;
}

void ProxyEngine::attach_stream(Conn& conn) {
  // conn.stream_cfg already holds the engine-owned fields plus whatever
  // apply_prewarm() seeded (both creation paths fill it before seeding). Do not
  // call fill_stream_config() here: it would overwrite the seeded
  // send_window_bytes with the configured default and silently disable the
  // window prior.
  StreamConfig sc = conn.stream_cfg;
  sc.max_segment = conn.session->mtu_limits().payload_max;
  conn.stream_cfg = sc;

  const uint64_t id = conn.id;
  conn.stream = std::make_unique<Stream>(
      sc,
      [this, id](const uint8_t* seg, size_t len) {
        Conn* p = find(id);
        if (p == nullptr || !p->session) {
          return;
        }
        p->session->on_kcp_output(seg, len, now_ms_);
      },
      [this, id](const uint8_t* bytes, size_t len) {
        Conn* p = find(id);
        if (p != nullptr && p->phase != Phase::kDone) {
          on_stream_bytes(*p, bytes, len);
        }
      },
      [this, id](CloseReason reason) {
        Conn* p = find(id);
        if (p == nullptr || p->phase == Phase::kDone) {
          return;
        }
        if (reason == CloseReason::kReset) {
          ++counters_.reset;
        } else if (reason == CloseReason::kIdle) {
          ++counters_.idle_closed;
        }
        finish_conn(*p, now_ms_, stream_reason_text(reason));
      },
      [this, id]() {
        Conn* p = find(id);
        if (p == nullptr || p->phase == Phase::kDone) {
          return;
        }
        // The far side is done sending. In a proxy that ends the exchange: hand
        // over what is left, then send our own fin (§2.3 has no shutdown()).
        p->want_fin = true;
        maybe_fin(*p);
      },
      [this, id](int64_t srtt_ms) {
        Conn* p = find(id);
        if (p != nullptr && p->session) {
          p->session->on_rtt_sample(srtt_ms);
        }
      },
      [this](const std::string& line) { log(line); });
}

void ProxyEngine::session_events(Conn& conn, int64_t now_ms) {
  if (conn.session == nullptr || conn.phase == Phase::kDone) {
    return;
  }
  if (!conn.established_seen && conn.session->established()) {
    conn.established_seen = true;
    ++counters_.established;
    if (cfg_.role == EngineRole::kServer) {
      attach_stream(conn);
      conn.phase = Phase::kAwaitOpen;
    }
  }
  if (conn.session->state() == HandshakeState::kFailed) {
    ++counters_.handshake_failed;
    if (cfg_.role == EngineRole::kClient && !in_entry_phase(conn.phase)) {
      queue_local_reply(conn, Socks5Rep::kGeneralFailure, HttpReply::kBadGateway);
    }
    finish_conn(conn, now_ms, "handshake failed");
    return;
  }
  // #26①: past 2^32 packets the GCM block budget is spent and Session stops
  // sealing (spec §4.1: the sender must disconnect, not go silent). Without
  // this the tunnel would keep reading the application while every datagram
  // was dropped, and only the peer's idle timer would end it.
  if (conn.session->nonce_exhausted()) {
    // No reply can be sent -- the budget that would carry it is exactly what
    // ran out -- so the application socket is simply closed.
    finish_conn(conn, now_ms, "send nonce space exhausted");
  }
}

// ---- entry protocol (client) ----

bool ProxyEngine::parse_entry(Conn& conn, int64_t now_ms) {
  while (in_entry_phase(conn.phase) && !conn.entry.empty()) {
    if (!conn.sniffed) {
      conn.sniffed = true;
      conn.socks5 = conn.entry[0] == kSocks5Version;
    }

    if (!conn.socks5) {
      size_t consumed = 0;
      ProxyTarget target;
      const HttpParse r =
          http_parse_connect(conn.entry.data(), conn.entry.size(), &consumed, &target);
      if (r == HttpParse::kOk) {
        conn.target = target;
        drop_front(&conn.entry, consumed);
        start_tunnel_client(conn, now_ms);
        return !in_entry_phase(conn.phase);
      }
      if (r == HttpParse::kNeedMore) {
        if (conn.entry.size() > kHttpHeadMaxBytes) {
          counters_.bad_entry++;
          finish_conn(conn, now_ms, "HTTP head never terminated");
        }
        return false;
      }
      counters_.bad_entry++;
      // The SOCKS5 rep is irrelevant on the HTTP path: queue_local_reply picks
      // the body by conn.socks5, which is false here.
      queue_local_reply(conn, Socks5Rep::kGeneralFailure,
                        r == HttpParse::kMethodNotAllowed
                            ? HttpReply::kMethodNotAllowed
                            : (r == HttpParse::kHeadTooLarge
                                   ? HttpReply::kRequestHeaderTooLarge
                                   : HttpReply::kBadRequest));
      finish_conn(conn, now_ms, "rejected HTTP CONNECT");
      return false;
    }

    if (conn.phase == Phase::kEntry) {
      size_t consumed = 0;
      Socks5Greeting greeting;
      const Socks5Parse r =
          socks5_parse_greeting(conn.entry.data(), conn.entry.size(), &consumed, &greeting);
      if (r == Socks5Parse::kNeedMore) {
        if (conn.entry.size() > kSocks5MaxGreetingBytes) {
          counters_.bad_entry++;
          finish_conn(conn, now_ms, "SOCKS5 greeting too large");
        }
        return false;
      }
      if (r != Socks5Parse::kOk) {
        counters_.bad_entry++;
        finish_conn(conn, now_ms, "malformed SOCKS5 greeting");
        return false;
      }
      drop_front(&conn.entry, consumed);
      uint8_t rep[kSocks5GreetingReplyLen] = {0};
      const size_t n = socks5_write_greeting_reply(rep, sizeof(rep), greeting.no_auth);
      append_bytes(&conn.app_in, rep, n);
      flush_app(conn);
      if (!greeting.no_auth) {
        counters_.bad_entry++;
        finish_conn(conn, now_ms, "no acceptable SOCKS5 method");
        return false;
      }
      conn.phase = Phase::kSocks5Request;
      continue;  // the request may already be corked behind the greeting
    }

    size_t consumed = 0;
    ProxyTarget target;
    const Socks5Parse r =
        socks5_parse_request(conn.entry.data(), conn.entry.size(), &consumed, &target);
    if (r == Socks5Parse::kOk) {
      conn.target = target;
      drop_front(&conn.entry, consumed);
      start_tunnel_client(conn, now_ms);
      return !in_entry_phase(conn.phase);
    }
    if (r == Socks5Parse::kNeedMore) {
      if (conn.entry.size() > kSocks5MaxRequestBytes) {
        counters_.bad_entry++;
        finish_conn(conn, now_ms, "SOCKS5 request too large");
      }
      return false;
    }
    counters_.bad_entry++;
    if (r == Socks5Parse::kCommandNotSupported) {
      queue_local_reply(conn, Socks5Rep::kCommandNotSupported, HttpReply::kMethodNotAllowed);
    } else if (r == Socks5Parse::kAtypNotSupported) {
      queue_local_reply(conn, Socks5Rep::kAtypNotSupported, HttpReply::kBadRequest);
    }
    finish_conn(conn, now_ms, "rejected SOCKS5 request");
    return false;
  }
  return !in_entry_phase(conn.phase);
}

void ProxyEngine::start_tunnel_client(Conn& conn, int64_t now_ms) {
  uint8_t buf[kOpenMaxBytes];
  const size_t n = open_write_request(buf, sizeof(buf), conn.target);
  if (n == 0) {
    counters_.bad_entry++;
    finish_conn(conn, now_ms, "target not encodable");
    return;
  }
  queue_stream(conn, buf, n);
  // Everything the client wrote behind its request is tunnel payload.
  append_bytes(&conn.to_stream, conn.entry.data(), conn.entry.size());
  conn.entry.clear();
  conn.phase = Phase::kAwaitReply;
  drain_stream(conn);
  log(label(conn) + " OPEN sent");
}

void ProxyEngine::queue_local_reply(Conn& conn, Socks5Rep rep, HttpReply http) {
  if (conn.socks5) {
    uint8_t buf[kSocks5ReplyLen] = {0};
    const size_t n = socks5_write_reply(buf, sizeof(buf), rep);
    append_bytes(&conn.app_in, buf, n);
  } else {
    uint8_t buf[128] = {0};
    const size_t n = http_write_response(buf, sizeof(buf), http);
    append_bytes(&conn.app_in, buf, n);
  }
  flush_app(conn);
}

// ---- tunnel OPEN (both sides) ----

void ProxyEngine::run_pre_tunnel_parser(Conn& conn, int64_t now_ms) {
  if (conn.stream_in.empty() || conn.phase == Phase::kDone || conn.closing) {
    return;
  }
  if (conn.phase == Phase::kAwaitReply) {
    parse_open_reply(conn);
  } else if (conn.phase == Phase::kAwaitOpen) {
    parse_open_request(conn, now_ms);
  }
}

void ProxyEngine::parse_open_reply(Conn& conn) {
  size_t consumed = 0;
  bool ok = false;
  OpenError err = OpenError::kRefused;
  const OpenParse r =
      open_parse_reply(conn.stream_in.data(), conn.stream_in.size(), &consumed, &ok, &err);
  if (r == OpenParse::kNeedMore) {
    if (conn.stream_in.size() > kOpenMaxBytes) {
      counters_.open_failed++;
      finish_conn(conn, now_ms_, "no complete OPEN reply");
    }
    return;
  }
  if (r != OpenParse::kOk) {
    counters_.open_failed++;
    queue_local_reply(conn, Socks5Rep::kGeneralFailure, HttpReply::kBadGateway);
    finish_conn(conn, now_ms_, "malformed OPEN reply");
    return;
  }
  drop_front(&conn.stream_in, consumed);
  if (!ok) {
    counters_.open_failed++;
    queue_local_reply(conn, socks5_rep_for_open_error(err), HttpReply::kBadGateway);
    finish_conn(conn, now_ms_, "server refused the tunnel");
    return;
  }
  conn.phase = Phase::kTunnel;
  ++counters_.tunnels;
  queue_local_reply(conn, Socks5Rep::kSucceeded, HttpReply::kEstablished);
  // queue_local_reply appends the handshake answer first, so the payload that
  // came behind OPEN_OK is already in stream_in and goes after it.
  append_bytes(&conn.app_in, conn.stream_in.data(), conn.stream_in.size());
  conn.stream_in.clear();
  flush_app(conn);
  log(label(conn) + " tunnel established");
}

void ProxyEngine::parse_open_request(Conn& conn, int64_t now_ms) {
  size_t consumed = 0;
  ProxyTarget target;
  const OpenParse r =
      open_parse_request(conn.stream_in.data(), conn.stream_in.size(), &consumed, &target);
  if (r == OpenParse::kNeedMore) {
    if (conn.stream_in.size() > kOpenMaxBytes) {
      send_open_error(conn, OpenError::kRefused);
    }
    return;
  }
  if (r == OpenParse::kBadAtyp) {
    send_open_error(conn, OpenError::kNotSupported);
    return;
  }
  if (r != OpenParse::kOk) {
    send_open_error(conn, OpenError::kRefused);
    return;
  }
  drop_front(&conn.stream_in, consumed);
  conn.target = target;
  conn.phase = Phase::kDialing;
  conn.dial_deadline_ms = now_ms + cfg_.dial_timeout_ms;
  log(label(conn) + " dial");
  if (host_.dial) {
    // Deferred, not called here: a literal target connects synchronously, and the
    // resulting on_dial_result() can tear this Conn down while the caller above
    // still holds it. reap() runs the queue once the stack has unwound.
    dial_queue_.push_back(conn.id);
  } else {
    send_open_error(conn, OpenError::kRefused);
  }
}

void ProxyEngine::flush_dials() {
  if (in_flush_dials_ || !host_.dial) {
    return;
  }
  in_flush_dials_ = true;
  while (!dial_queue_.empty()) {
    const uint64_t id = dial_queue_.back();
    dial_queue_.pop_back();
    Conn* c = find(id);
    // Looked up again rather than carried: the queue holds ids precisely because
    // a Conn may not survive the walk down here.
    if (c == nullptr || c->closing || c->phase != Phase::kDialing) {
      continue;
    }
    host_.dial(id, c->target);
  }
  in_flush_dials_ = false;
}

void ProxyEngine::send_open_error(Conn& conn, OpenError err) {
  if (conn.closing || conn.phase == Phase::kDone) {
    return;  // one refusal per tunnel, whatever else times out afterwards
  }
  conn.closing = true;
  ++counters_.open_failed;
  uint8_t buf[kOpenErrLen] = {0};
  const size_t n = open_write_err(buf, sizeof(buf), err);
  queue_stream(conn, buf, n);
  drain_stream(conn);
  conn.want_fin = true;
  arm_grace(conn, /*only_if_idle=*/true);
  maybe_fin(conn);
  log(label(conn) + " OPEN_ERR " + std::to_string(static_cast<unsigned>(err)));
}

// ---- buffers ----

void ProxyEngine::queue_stream(Conn& conn, const uint8_t* data, size_t len) {
  append_bytes(&conn.to_stream, data, len);
}

void ProxyEngine::drain_stream(Conn& conn) {
  while (!conn.to_stream.empty() && conn.stream && conn.stream->can_write()) {
    const size_t n = conn.stream->write(conn.to_stream.data(), conn.to_stream.size());
    if (n == 0) {
      break;
    }
    drop_front(&conn.to_stream, n);
  }
  maybe_fin(conn);
}

void ProxyEngine::flush_app(Conn& conn) {
  // Qt emits bytesWritten synchronously from inside write(), so app_send can
  // re-enter this function while the outer loop still holds `n`/`taken`.
  // Without the guard the inner pass drains app_in and the outer one then
  // drops bytes it never sent (or sends the same bytes twice).
  if (conn.in_flush_app) {
    return;
  }
  conn.in_flush_app = true;
  while (!conn.app_in.empty()) {
    if (!host_.app_send) {
      break;
    }
    const size_t n = host_.app_send(conn.id, conn.app_in.data(), conn.app_in.size());
    if (n == 0) {
      break;
    }
    const size_t taken = n > conn.app_in.size() ? conn.app_in.size() : n;
    conn.app_accepted += taken;
    drop_front(&conn.app_in, taken);
  }
  conn.in_flush_app = false;
  if (conn.stream) {
    // What the socket would not take, plus what a parser has not consumed yet,
    // is still this stream's receive buffer. The pre-tunnel phases matter as
    // much as kTunnel: a client may pipeline payload behind its OPEN, and the
    // server can spend up to dial_timeout_ms in kDialing. Counting only app_in
    // there would keep the window open and let the peer grow stream_in without
    // bound -- the exact bypass the rwnd exists to prevent.
    conn.stream->set_delivery_pending(conn.app_in.size() + conn.stream_in.size());
  }
  maybe_fin(conn);
}

void ProxyEngine::on_stream_bytes(Conn& conn, const uint8_t* data, size_t len) {
  if (conn.closing) {
    return;  // the tunnel was already refused; nothing more is wanted
  }
  if (conn.phase == Phase::kTunnel) {
    append_bytes(&conn.app_in, data, len);
    flush_app(conn);
    return;
  }
  append_bytes(&conn.stream_in, data, len);
  run_pre_tunnel_parser(conn, now_ms_);
}

void ProxyEngine::maybe_fin(Conn& conn) {
  if (!conn.want_fin || conn.stream == nullptr || conn.phase == Phase::kDone) {
    return;
  }
  if (!conn.app_in.empty() || !conn.to_stream.empty()) {
    // A wedged application socket must not pin the session: the grace clock is
    // already running for whoever asked for the fin.
    arm_grace(conn, /*only_if_idle=*/true);
    return;
  }
  if (conn.stream->state() == StreamState::kOpen ||
      conn.stream->state() == StreamState::kPeerClosed) {
    conn.stream->close(now_ms_);
  }
  // The fin still has to reach the peer. Keeping the clock armed here rather
  // than clearing it bounds the case where the peer has vanished: without it the
  // session retransmits a fin nobody will ever acknowledge, until the idle
  // timeout. on_tick() is what slides the clock, and only on real progress, so
  // arming must stay idle-only: re-arming here every tick would never expire.
  arm_grace(conn, /*only_if_idle=*/true);
}

uint64_t ProxyEngine::progress_of(const Conn& conn) const {
  const uint64_t streamed =
      conn.stream ? conn.stream->bytes_acked() + conn.stream->bytes_delivered() : 0;
  return streamed + conn.app_accepted;
}

void ProxyEngine::arm_grace(Conn& conn, bool only_if_idle) {
  if (only_if_idle && conn.flush_deadline_ms != 0) {
    return;
  }
  conn.flush_deadline_ms = now_ms_ + cfg_.flush_grace_ms;
  conn.grace_progress = progress_of(conn);
}

// ---- teardown ----

void ProxyEngine::finish_conn(Conn& conn, int64_t now_ms, const char* why) {
  if (conn.phase == Phase::kDone) {
    return;
  }
  conn.phase = Phase::kDone;
  reap_ids_.push_back(conn.id);
  // #33③ forensics: on a teardown, the stream's own counters say which side
  // stopped moving — a sender stuck mid-window (acked < queued) vs a receiver
  // that stopped delivering turns "upload froze" into a localizable defect.
  // The same line is the only place the autotune's verdict survives the run, so
  // it also prints on a clean finish whenever the window actually moved.
  const bool stuck = conn.stream != nullptr &&
                     (conn.stream->bytes_acked() != conn.stream->bytes_queued() ||
                      conn.stream->bytes_delivered() != conn.stream->bytes_acked());
  // Compare against the start this stream actually used, not the configured
  // default: apply_prewarm() may have seeded a prior, and a connection that
  // ended exactly at its prior has not "moved" relative to it.
  const bool tuned = conn.stream != nullptr && cfg_.auto_window &&
                     conn.stream->send_window() != conn.stream_cfg.send_window_bytes;
  if (stuck || tuned) {
    std::snprintf(diag_, sizeof(diag_),
                  "stream queued=%llu acked=%llu delivered=%llu unacked=%zu in_flight=%zu "
                  "rwnd=%zu cwnd=%zu rto=%lld loss_rto=%llu loss_dup=%llu probes=%llu",
                  static_cast<unsigned long long>(conn.stream->bytes_queued()),
                  static_cast<unsigned long long>(conn.stream->bytes_acked()),
                  static_cast<unsigned long long>(conn.stream->bytes_delivered()),
                  conn.stream->unacked_segs(), conn.stream->in_flight(),
                  conn.stream->peer_window(), conn.stream->send_window(),
                  static_cast<long long>(conn.stream->rto_ms()),
                  static_cast<unsigned long long>(conn.stream->rto_loss_events()),
                  static_cast<unsigned long long>(conn.stream->dup_loss_events()),
                  static_cast<unsigned long long>(conn.stream->probes_sent()));
    log(label(conn) + " closed: " + why + " [" + diag_ + "]");
  } else {
    log(label(conn) + " closed: " + why);
  }
  (void)now_ms;
}

void ProxyEngine::reap(int64_t now_ms) {
  if (in_reap_) {
    return;  // the walk below drains what this pass queues
  }
  in_reap_ = true;
  // Every public entry point ends here, so this is the one place that is always
  // outside a parser's frame: the safe point to hand the host a dial request.
  while (!reap_ids_.empty() || !dial_queue_.empty()) {
    flush_dials();
    std::vector<uint64_t> ids;
    ids.swap(reap_ids_);
    for (uint64_t id : ids) {
      const auto it = by_conn_.find(id);
      if (it == by_conn_.end()) {
        continue;
      }
      Conn& conn = *it->second;
      save_profile(conn, now_ms);
      // §14.6 (#30): the last report interval rides out before the session
      // dies; the peer's tombstone window keeps the datagram routable even
      // if its own session is already gone.
      if (conn.session) {
        conn.session->flush_report(now_ms);
      }
      if (!conn.salt_key.empty() && conn.authenticated_once) {
        const auto salt_it = by_salt_.find(conn.salt_key);
        if (salt_it != by_salt_.end() && salt_it->second == id) {
          by_salt_.erase(salt_it);
          // #29a (M2 §8.1 tail race): the peer's retransmit tail keeps
          // arriving after our side is gone. Keep the salt known-but-dead so
          // those datagrams drop as tombstones instead of counting as
          // unknown_salt (client) or — worse on the server — being mistaken
          // for a fresh HELLO and rebirthing a phantom session. Only an
          // authenticated session may insert (A1 follow-up): otherwise every
          // 8-byte forgery would buy a five-minute table entry.
          if (salt_tombstones_.size() >= kSaltTombstoneMax) {
            salt_tombstones_.erase(salt_tombstones_.begin());
          }
          salt_tombstones_[conn.salt_key] = now_ms + kSaltTombstoneMs;
        }
      }
      // save_profile / flush_report above still needed the peer's address, so
      // the release has to wait until the connection is really gone -- and the
      // id is copied out first, because erase() destroys the Conn.
      const uint64_t conn_peer = conn.peer;
      by_conn_.erase(it);
      --counters_.live;
      if (cfg_.role == EngineRole::kServer && host_.peer_retired) {
        host_.peer_retired(conn_peer);
      }
      if (host_.app_close) {
        host_.app_close(id);
      }
    }
  }
  in_reap_ = false;
}

void ProxyEngine::save_profile(Conn& conn, int64_t now_ms) {
  if (!cfg_.prewarm || !conn.established_seen || !conn.stream) {
    return;
  }
  const std::string key = host_.peer_key ? host_.peer_key(conn.peer) : std::string();
  if (key.empty()) {
    return;
  }
  PeerProfile profile;
  profile.srtt_ms = conn.stream->srtt_ms();
  // k == 0 means the link stayed clean, which is what a cold start assumes
  // anyway, so it is stored as "unknown" rather than as a third state.
  const uint8_t k = conn.session ? conn.session->k() : 0;
  profile.initial_k = k > 0 ? static_cast<int>(k) : -1;
  // Only the autotuner's result describes the link; a fixed window describes
  // the operator's configuration and must not become a prior for a later
  // adaptive session.
  if (conn.stream_cfg.auto_window) {
    profile.window_bytes = conn.stream->send_window();
  }
  prewarm_.put(key, profile, now_ms);
}

PeerProfile ProxyEngine::profile_for(uint64_t peer, int64_t now_ms) const {
  PeerProfile profile;
  if (!cfg_.prewarm || !host_.peer_key) {
    return profile;
  }
  const std::string key = host_.peer_key(peer);
  if (key.empty()) {
    return profile;
  }
  prewarm_.get(key, now_ms, &profile);
  return profile;
}

// ---- lookups ----

ProxyEngine::Conn* ProxyEngine::find(uint64_t conn) {
  const auto it = by_conn_.find(conn);
  return it == by_conn_.end() ? nullptr : it->second.get();
}

const ProxyEngine::Conn* ProxyEngine::find(uint64_t conn) const {
  const auto it = by_conn_.find(conn);
  return it == by_conn_.end() ? nullptr : it->second.get();
}

ProxyEngine::Conn* ProxyEngine::find_by_salt(const uint8_t* salt, size_t len) {
  if (len < Envelope::kSaltLen) {
    return nullptr;
  }
  const auto it = by_salt_.find(salt_key_of(salt));
  if (it == by_salt_.end()) {
    return nullptr;
  }
  return find(it->second);
}

std::string ProxyEngine::label(const Conn& conn) const {
  std::string out = "conn " + std::to_string(conn.id);
  if (!conn.target.addr.empty()) {
    out += " ";
    out += target_text(conn.target);
  }
  return out;
}

std::string ProxyEngine::label(uint64_t conn) const {
  const Conn* c = find(conn);
  return c == nullptr ? "conn " + std::to_string(conn) : label(*c);
}

void ProxyEngine::log(const std::string& line) const {
  if (host_.log) {
    host_.log(line);
  }
}

}  // namespace fcp
