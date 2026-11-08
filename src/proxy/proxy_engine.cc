#include "proxy/proxy_engine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "fcp/log_level.h"
#include "fcp/random.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <direct.h>
#include <windows.h>
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

// The CLI passes argv bytes (the ANSI code page on Windows) while the Qt host
// passes QString::toUtf8(); try UTF-8 first and fall back to the ANSI code page
// so both spellings reach the wide-char API instead of being mangled by
// toLocal8Bit/_mkdir/fopen (C-11).
#ifdef _WIN32
std::wstring path_to_wide(const std::string& path) {
  if (path.empty()) {
    return std::wstring();
  }
  auto convert = [&path](UINT cp, DWORD flags) {
    const int n = MultiByteToWideChar(cp, flags, path.data(),
                                      static_cast<int>(path.size()), nullptr, 0);
    if (n <= 0) {
      return std::wstring();
    }
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(cp, flags, path.data(), static_cast<int>(path.size()),
                        w.data(), n);
    return w;
  };
  std::wstring w = convert(CP_UTF8, MB_ERR_INVALID_CHARS);
  if (w.empty()) {
    w = convert(CP_ACP, 0);
  }
  return w;
}

std::FILE* open_trace_file(const std::string& path, bool append) {
  const std::wstring w = path_to_wide(path);
  if (w.empty()) {
    return nullptr;
  }
  std::FILE* f = nullptr;
  return _wfopen_s(&f, w.c_str(), append ? L"ab" : L"wb") == 0 ? f : nullptr;
}
#else
std::FILE* open_trace_file(const std::string& path, bool append) {
  return std::fopen(path.c_str(), append ? "ab" : "wb");
}
#endif

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
// 预认证会话构筑预算（见 create_server_conn）：收费窗口宽度与窗口内配额。
constexpr int64_t kNewConnWindowMs = 250;
constexpr int32_t kMaxNewServerConnsPerWindow = 256;

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
    const std::wstring wide = path_to_wide(dir);
    if (!wide.empty()) {
      _wmkdir(wide.c_str());  // a failed mkdir surfaces at fopen below
    }
#else
    mkdir(dir.c_str(), 0755);
#endif
  }
}

// 唯一的熵源是核心库的 random_bytes（BCryptGenRandom // /dev/urandom）。
// std::random_device 在 MinGW 一类工具链下是固定种子 PRNG，用它画盐会让
// #28① 的逐会话密钥派生拿到同一个盐值（跨会话 key, IV 重用），所以这里
// 沿用库的约定：失败即失败，caller 负责拒绝建会话。
bool random_salt(uint8_t out[Envelope::kSaltLen]) {
  return random_bytes(out, Envelope::kSaltLen);
}

// B-03: before negotiation the session buffers KCP output. The stream can hand
// it at most one send window of segments, so the cache has to cover that window
// -- the fixed 512 segments / 512 KiB default silently failed the handshake for
// any --window above 512 KiB (and for a small --mtu, where 512 segments is only
// ~96 KiB). Size from the window this connection will actually use, after
// apply_prewarm() has had its say, and keep the documented floor.
void size_handshake_cache(const StreamConfig& stream_cfg, size_t mtu,
                          size_t ip_hdr_len, SessionConfig* sc) {
  const MtuLimits limits = compute_mtu_limits(mtu, ip_hdr_len);
  const size_t seg = limits.payload_max != 0 ? limits.payload_max : 1;
  const size_t window = stream_cfg.send_window_bytes;
  sc->handshake_cache_bytes =
      std::max(kHandshakeMaxCachedBytes, window + seg);
  sc->handshake_cache_segments =
      std::max(kHandshakeMaxCachedSegments, window / seg + 2);
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
//
// Rotation: a calibrated trace runs unattended for as long as the session
// lives, so the file is capped at kTraceRotateBytes -- on crossing, the
// current file becomes ".1" (the previous ".1" is dropped) and recording
// continues into a fresh file. One generation is deliberately all the trace
// keeps: it is a debugging aid, not an audit archive.
SessionConfig::TraceFn make_trace_sink(const std::string& prefix, uint64_t cid,
                                       std::function<void(const std::string&)> log,
                                       size_t rotate_bytes) {
  if (prefix.empty()) {
    return nullptr;
  }
  struct Lazy {
    std::string path;
    std::shared_ptr<std::FILE> file;
    bool attempted = false;
    bool disabled = false;
    bool warned_rotate = false;
    size_t written = 0;
  };
  auto state = std::make_shared<Lazy>();
  state->path = prefix + "." + std::to_string(cid) + ".jsonl";
  auto report = [state, log](const std::string& why) {
    state->disabled = true;
    const std::string line = "trace path " + state->path + " " + why +
                             "; recording disabled";
    // 有汇集点就只走汇集点（CLI 的 stderr 与 GUI 的日志窗都由它渲染），
    // 否则才是无宿主的 stderr 兜底——避免同一行出现两次。
    if (log) {
      log(std::string(kTagWarn) + line);
    } else {
      std::fprintf(stderr, "fcp: %s\n", line.c_str());
    }
  };
  return [state, report, log, rotate_bytes](const TraceEntry& e) {
    if (state->disabled) {
      return;
    }
    if (!state->attempted) {
      state->attempted = true;
      make_directories_for(state->path);
    }
    if (!state->file || state->written > rotate_bytes) {
      state->file.reset();  // Windows rename() needs the file closed first
      bool rotated = true;
      if (state->written != 0) {
        const std::string backup = state->path + ".1";
        std::remove(backup.c_str());
        rotated = std::rename(state->path.c_str(), backup.c_str()) == 0;
      }
      // A failed rename is a transient filesystem/permission hiccup, not a
      // reason to lose the session's whole remaining trace: reopen the existing
      // file in append mode, keep `written`, and try the rotation again on the
      // next entry. A busy file then costs one line of delay, not the trace.
      state->file = std::shared_ptr<std::FILE>(
          open_trace_file(state->path, !rotated), [](std::FILE* f) {
            if (f != nullptr) {
              std::fclose(f);
            }
          });
      if (rotated) {
        state->written = 0;
        state->warned_rotate = false;
      }
      if (!state->file) {
        report("unopenable");
        return;
      }
      if (!rotated && !state->warned_rotate) {
        state->warned_rotate = true;
        const std::string line = "trace path " + state->path +
                                 " rotate failed; retrying on next entry";
        if (log) {
          log(std::string(kTagWarn) + line);
        } else {
          std::fprintf(stderr, "fcp: %s\n", line.c_str());
        }
      }
    }
    std::string line;
    encode_trace_line(e, &line);
    line.push_back('\n');
    // A short write means the audit record is incomplete: say so once and stop
    // pretending the file is a full trace (disk full / read-only media).
    if (std::fwrite(line.data(), 1, line.size(), state->file.get()) != line.size()) {
      report("write failed (disk full or read-only)");
      return;
    }
    state->written += line.size();
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
    log(std::string(kTagWarn) + label(conn) + " refused: session limit");
    if (host_.app_close) {
      host_.app_close(conn);
    }
    return;
  }
  // A refusal here has to look like every other refusal: the engine holds no
  // Conn for this socket, so unless the host is told to close it the local
  // socket is never freed and the application waits on a tunnel that will
  // never exist. The *reason* lines and counters must not merge: an entropy
  // failure is "fix the OS entropy story", a bad config is "fix --mtu".
  switch (create_client_conn(conn, peer, now_ms)) {
    case CreateStatus::kNoEntropy:
      ++counters_.no_entropy;
      if (host_.app_close) {
        host_.app_close(conn);
      }
      return;
    case CreateStatus::kBadConfig:
      ++counters_.bad_config;
      log(std::string(kTagWarn) + label(conn) + " refused: MTU leaves no room for a data symbol");
      if (host_.app_close) {
        host_.app_close(conn);
      }
      return;
    case CreateStatus::kOk:
      break;
  };
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
    if (c->closing) {
      return;  // refused: the reply is out and the grace clock decides the rest
    }
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
  // Only a dialed socket that is actually carrying the tunnel may close it.
  // During kDialing the connect result is still on its way; a stray
  // disconnected() (a failed connect can emit it before errorOccurred) used to
  // arm the fin, so the tunnel was closed before OPEN_OK was ever written
  // (B-07).
  if (c->phase != Phase::kTunnel) {
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
  log(std::string(kTagInfo) + label(*c) + " tunnel open");
  reap(now_ms);
}

// See the declaration. The kernel's EMSGSIZE is authoritative path evidence:
// the refused datagram never reached the wire. Every live session sharing the
// refused peer lowers its send bound at once -- on the client that is every
// tunnel's session (one remote), on the server exactly the refused peer's.
void ProxyEngine::on_wire_send_too_big(uint64_t peer, size_t wire_len,
                                       int64_t now_ms) {
  const bool client = cfg_.role == EngineRole::kClient;
  for (auto& kv : by_conn_) {
    Conn& c = *kv.second;
    if (c.phase == Phase::kDone || c.session == nullptr) {
      continue;
    }
    if (!client && c.peer != peer) {
      continue;
    }
    c.session->on_kernel_send_too_big(wire_len, now_ms);
  }
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
  // Same salt, a different source address. The check has to run before
  // Session::on_wire(), not after it: on_wire decrypts, feeds FrameRx and
  // delivers payload straight to host_.app_send, so an "address mismatch" that
  // was only noticed afterwards had already processed the datagram -- stored
  // its symbols, consumed its nonce and poisoned the cross-set dedup -- while
  // the log said it was dropped.
  //
  // The binding must not move either way. A genuine NAT rebind is
  // indistinguishable from a recorded datagram the original address never
  // delivered, and adopting the new address would hand that replayer a full
  // redirect of the downstream. So a mismatched datagram gets no authority at
  // all; it does not even buy an AEAD attempt.
  //
  // A1 still holds where it matters: after this branch, nothing is done with
  // the datagram before the envelope authenticates it (the born path below
  // destroys the session when the first datagram fails the tag).
  if (!born && c->peer != peer) {
    // salt_clash now counts unauthenticated mismatches too. The salt travels in
    // the clear, so a spoofed prefix could always have been aimed at this
    // table; the counter is a warning signal ("someone else is racing this
    // session"), not an accounting identity, and the log is rate-limited.
    ++counters_.salt_clash;
    if (!rebind_drop_logged_ || now_ms - last_rebind_drop_log_ms_ >= 5000) {
      rebind_drop_logged_ = true;
      last_rebind_drop_log_ms_ = now_ms;
      log(std::string(kTagWarn) + label(*c) + " datagram from another address dropped");
    }
    return;
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

int64_t ProxyEngine::next_wake_ms(int64_t now_ms) const {
  int64_t next = 0;
  for (const auto& entry : by_conn_) {
    const Conn* c = entry.second.get();
    if (c == nullptr || !c->stream || c->phase == Phase::kDone) {
      continue;
    }
    const int64_t due = c->stream->next_wake_ms(now_ms);
    if (due > 0 && (next == 0 || due < next)) {
      next = due;
    }
  }
  return next;
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
      // PMTUD may have moved the proven payload size during that tick -- up on
      // a successful climb, down on a black-hole fallback. The stream must
      // adopt it either way before its next pump(): a raise would otherwise
      // only benefit the next connection, and a fallback would keep re-sending
      // segments carved at the size the path just dropped.
      if (c->stream) {
        c->stream->set_max_segment(c->session->payload_max());
      }
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
    if (!c->closing && c->phase_deadline_ms != 0 &&
        (c->phase == Phase::kAwaitReply || c->phase == Phase::kAwaitOpen) &&
        now_ms >= c->phase_deadline_ms) {
      // The handshake completed but the OPEN exchange never did. Without this
      // deadline every ACK refreshed the stream's idle clock, so an
      // authenticated peer could hold a max_sessions slot forever (B-06).
      if (cfg_.role == EngineRole::kServer) {
        finish_conn(*c, now_ms, "no OPEN after the handshake");
      } else {
        refuse_local(*c, "server never answered OPEN", Socks5Rep::kGeneralFailure,
                     HttpReply::kBadGateway);
      }
    } else if (c->phase == Phase::kDialing && !c->closing && now_ms >= c->dial_deadline_ms) {
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

ProxyEngine::LossSample ProxyEngine::loss_sample() const {
  LossSample total;
  for (const auto& entry : by_conn_) {
    const Conn& c = *entry.second;
    if (!c.session) {
      continue;
    }
    if (const FcpReporter* reporter = c.session->reporter()) {
      total.in_expected += reporter->last_expected();
      total.in_lost += reporter->last_lost();
    }
    total.out_expected += c.session->last_peer_expected();
    total.out_lost += c.session->last_peer_lost();
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
  sc->pmtud = cfg_.pmtud;
  sc->pmtu_max_mtu = cfg_.pmtu_max_mtu;
  sc->pinned_k = cfg_.pinned_k;
  sc->fec_budget = cfg_.fec_budget;
  sc->trace = make_trace_sink(cfg_.trace_prefix, conn_id,
                              [this](const std::string& line) {
                                log(std::string(kTagWarn) + line);
                              },
                              cfg_.trace_rotate_bytes);
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
  sc->bbr = cfg_.bbr;
  sc->bbr_version = cfg_.bbr_version;
  sc->window_probe = cfg_.window_probe;
  sc->window_min_bytes = cfg_.window_min_bytes;
  sc->window_max_bytes = cfg_.window_max_bytes;
  sc->window_ceiling_bytes = cfg_.window_ceiling_bytes;
  sc->ack_every = cfg_.ack_every;
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
        // §14.6 (#30)：reap 里的最后一份 FECSTAT（flush_report）必须能出门。
        // teardown 先标 kDone、后 flush，若对 kDone 一刀切，"the last report
        // interval rides out before the session dies" 就成了死代码——对端的
        // 控制器永远丢最后一个区段的账。in_reap_ 正是本轮的独占标记，且
        // reap 期间该 session 是唯一在发送的，放开这一扇不会放进别的包。
        if (p == nullptr || (p->phase == Phase::kDone && !in_reap_) ||
            !host_.wire_send) {
          return;
        }
        // Count only what the transport actually took: a failing UDP path used
        // to show a rising tx counter while every datagram was dropped.
        const size_t sent = host_.wire_send(p->peer, wire, len);
        if (sent != 0) {
          counters_.bytes_tx += sent;
        } else {
          ++counters_.wire_errors;
        }
      },
      [this, cid](const uint8_t* payload, size_t len) {
        Conn* p = find(cid);
        if (p == nullptr || p->stream == nullptr) {
          return;
        }
        p->stream->on_segment(payload, len, now_ms_);
      },
      // session.cc / session_log.cc 的每条日志都自带 [d]/[i]/[w]/[e] 标签，
      // 汇集点（Reactor::log_line）只剥一层。这里再套一层 kTagInfo 会把所有
      // 会话行都判成 info（--log=info 也压不住 [d] 行，--log=error 反而吞掉
      // 会话错误），渲染时还会残留内层标签。原样透传。
      [this](const std::string& line) { log(line); });
}

// 会话建立失败的两种本质上不同的原因。混淆它们会让运维把一条熵源故障
// （CSPRNG 不可用）当成 MTU 配置错误去排查——stats 行的 bad_config 会一路
// 增长，而配置明明是对的。
ProxyEngine::CreateStatus ProxyEngine::create_client_conn(uint64_t id, uint64_t peer,
                                                          int64_t now_ms) {
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
  } else if (!random_salt(sc.salt)) {
    // 熵源不可用时不建会话：固定盐会把 #28① 的跨会话密钥隔离整个打掉。
    log(std::string(kTagError) + label(id) + " no CSPRNG entropy for session salt");
    return ProxyEngine::CreateStatus::kNoEntropy;
  }
  sc.send_direction = Direction::kC2S;
  sc.recv_direction = Direction::kS2C;
  // Fill the engine-owned half first: apply_prewarm() decides whether the
  // window prior may replace the start from StreamConfig::auto_window and
  // StreamConfig::send_window_explicit, so those flags have to be real values,
  // not the default-constructed false/false.
  fill_stream_config(&raw->stream_cfg);
  apply_prewarm(profile_for(peer, now_ms), &sc, &raw->stream_cfg);

  size_handshake_cache(raw->stream_cfg, cfg_.mtu, cfg_.ip_hdr_len, &sc);
  raw->session = make_session(id, sc);
  // 握手并发限流（EngineConfig::hs_concurrency，仅 client）：槽位满时本会话
  // 不 start——HELLO 不出网，本地 stream 段进握手缓存（有界），槽位释放后
  // 由 pump_handshake_queue 按序补位。未 start 的会话不注册 by_salt_
  // （B-04：入站 HELLO 不得建立它）；本地 socket 照常活着，浏览器的
  // SOCKS CONNECT 只是变慢（这正是排队想要的形状）。
  if (cfg_.hs_concurrency != 0 && hs_in_flight_ >= cfg_.hs_concurrency) {
    raw->hs_queued = true;
    hs_queue_.push_back(id);
    raw->salt_key = salt_key_of(sc.salt);
    attach_stream(*raw);
    by_conn_[id] = std::move(conn);
    ++counters_.live;
    return ProxyEngine::CreateStatus::kOk;
  }
  // The refusal has to reach the caller: this used to log and return kOk, so
  // an unstarted session still sat in the tables and an inbound HELLO could
  // establish it (B-04).
  switch (raw->session->start(now_ms)) {
    case Session::StartStatus::kOk:
      break;
    case Session::StartStatus::kNoEntropy:
      return ProxyEngine::CreateStatus::kNoEntropy;
    case Session::StartStatus::kBadConfig:
      return ProxyEngine::CreateStatus::kBadConfig;
  }
  raw->salt_key = salt_key_of(sc.salt);
  attach_stream(*raw);
  by_conn_[id] = std::move(conn);
  by_salt_.emplace(raw->salt_key, id);
  ++counters_.live;
  ++hs_in_flight_;
  raw->hs_slot_held = true;
  return ProxyEngine::CreateStatus::kOk;
}

ProxyEngine::Conn* ProxyEngine::create_server_conn(uint64_t peer, const uint8_t* salt,
                                                   int64_t now_ms) {
  // 预认证防.cpu 放大（对抗分析第七轮 P2）：每一个未认证的 8 字节伪造包都能
  // 买一次完整的 Session 构造（两次 CSPRNG 抽取 + 四套 AES 轮密钥扩展 + KDF
  // 链 + 一次分配回收），毫秒内即被丢弃。这扇门不是认证（那要协议级
  // cookie），而是收费窗口：每 250ms 至多 kMaxNewServerConnsPerWindow 次
  // 构造，超出即丢。合法流首包即认证（HELLO 在 on_wire 的同一调用里通过
  // 验证），256/250ms = 1024 新建/秒，远超正常流量的到达率；只要 budget
  // 放得足够宽，它只对"恶意洪泛"形状收敛。
  const int64_t window = now_ms / kNewConnWindowMs;
  if (window != create_window_) {
    create_window_ = window;
    create_budget_ = kMaxNewServerConnsPerWindow;
  }
  if (create_budget_ == 0) {
    ++counters_.over_budget;
    return nullptr;
  }

  if (by_conn_.size() >= cfg_.max_sessions) {
    ++counters_.over_limit;
    return nullptr;
  }
  const std::string key = salt_key_of(salt);
  if (by_salt_.count(key) != 0) {
    // A replayed salt must not consume the construction budget: charging it
    // here let an 8-byte flood starve a legitimate first HELLO that arrived in
    // the same 250ms window (B-05).
    ++counters_.salt_clash;
    return nullptr;
  }
  // Only a datagram that will actually build a session is charged, and the
  // charge happens before the (expensive) construction below.
  --create_budget_;
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

  size_handshake_cache(raw->stream_cfg, cfg_.mtu, cfg_.ip_hdr_len, &sc);
  raw->session = make_session(id, sc);
  // B-09: a config refusal used to return nullptr with no log and no counter,
  // so the server looked like it ignored every HELLO while bad_config stayed 0.
  switch (raw->session->start(now_ms)) {
    case Session::StartStatus::kOk:
      break;
    case Session::StartStatus::kNoEntropy:
      ++counters_.no_entropy;
      return nullptr;
    case Session::StartStatus::kBadConfig:
      ++counters_.bad_config;
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
  // #78: ACK v2 rides the handshake TLV negotiation, which resolves at
  // establishment -- later than the pre-filled snapshot above.
  sc.ack_v2 = conn.session->stream_ack_v2();
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
        // The far side is done sending. That is a half-close, not the end of the
        // exchange: shutdown the local socket's write half (the app/target sees
        // EOF) and keep the tunnel's send side open for whatever the local side
        // still produces -- a response the target has not written yet, request
        // bytes queued after the app's shutdown. Sending our own fin here, as
        // the symmetric counterpart of on_local_closed(), used to end the
        // tunnel the moment the peer stopped talking and drop that traffic.
        if (host_.app_shutdown) {
          host_.app_shutdown(id);
        } else {
          p->want_fin = true;
          maybe_fin(*p);
        }
      },
      [this, id](int64_t srtt_ms) {
        Conn* p = find(id);
        if (p != nullptr && p->session) {
          p->session->on_rtt_sample(srtt_ms, now_ms_);
        }
      },
      [this](const std::string& line) {
        log(std::string(kTagInfo) + line);
      });
}

void ProxyEngine::session_events(Conn& conn, int64_t now_ms) {
  if (conn.session == nullptr || conn.phase == Phase::kDone) {
    return;
  }
  if (!conn.established_seen && conn.session->established()) {
    conn.established_seen = true;
    ++counters_.established;
    // 槽位随建立释放，队头补位（EngineConfig::hs_concurrency，仅 client）。
    release_handshake_slot(conn);
    pump_handshake_queue(now_ms);
    if (cfg_.role == EngineRole::kServer) {
      attach_stream(conn);
      conn.phase = Phase::kAwaitOpen;
      conn.phase_deadline_ms = now_ms + cfg_.dial_timeout_ms;
    }
  }
  if (conn.session->state() == HandshakeState::kFailed) {
    // 握手失败的连接同样释放槽位（队头立即补位），否则一次失败会把
    // 并发上限永久占掉一格。
    release_handshake_slot(conn);
    pump_handshake_queue(now_ms);
    ++counters_.handshake_failed;
    if (cfg_.role == EngineRole::kClient) {
      if (in_entry_phase(conn.phase)) {
        // 应用还没发出请求，谈不上下一步的协议回复：立即关。
        finish_conn(conn, now_ms, "handshake failed");
      } else {
        // kAwaitReply：应用收到的是 SOCKS5/HTTP 失败码，而不是被 RST。
        refuse_local(conn, "handshake failed", Socks5Rep::kGeneralFailure,
                     HttpReply::kBadGateway);
      }
    } else {
      finish_conn(conn, now_ms, "handshake failed");
    }
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
  // A refused connection keeps its phase inside the entry family, so the phase
  // alone does not say "stop": on_local_bytes() drops what arrives after the
  // refusal, and this guard keeps a parse already in flight from acting on it.
  while (in_entry_phase(conn.phase) && !conn.closing && !conn.entry.empty()) {
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
      // The SOCKS5 rep is irrelevant on the HTTP path: refuse_local picks
      // the body by conn.socks5, which is false here.
      refuse_local(conn, "rejected HTTP CONNECT", Socks5Rep::kGeneralFailure,
                   r == HttpParse::kMethodNotAllowed
                       ? HttpReply::kMethodNotAllowed
                       : (r == HttpParse::kHeadTooLarge
                              ? HttpReply::kRequestHeaderTooLarge
                              : HttpReply::kBadRequest));
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
        // Same choreography as refuse_local: let the 0xFF method-selection
        // reply (already queued above) leave before the socket dies. Calling
        // finish_conn here reaped the conn on the spot and turned a protocol
        // reply into a RST whenever the write had not completed (B-12).
        conn.closing = true;
        conn.want_fin = true;
        arm_grace(conn, /*only_if_idle=*/true);
        maybe_fin(conn);
        log(std::string(kTagWarn) + label(conn) + " no acceptable SOCKS5 method");
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
      refuse_local(conn, "rejected SOCKS5 request", Socks5Rep::kCommandNotSupported,
                   HttpReply::kMethodNotAllowed);
    } else if (r == Socks5Parse::kAtypNotSupported) {
      refuse_local(conn, "rejected SOCKS5 request", Socks5Rep::kAtypNotSupported,
                   HttpReply::kBadRequest);
    } else {
      finish_conn(conn, now_ms, "rejected SOCKS5 request");
    }
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
  // Strictly longer than the server's dial budget: the server's OPEN_ERR is
  // the answer this deadline must not race. Equal budgets made the client give
  // up locally in the same tick the server refused, losing the real reason.
  conn.phase_deadline_ms = now_ms + cfg_.dial_timeout_ms + cfg_.flush_grace_ms;
  drain_stream(conn);
  log(std::string(kTagDebug) + label(conn) + " OPEN sent");
}

// 一个带回复的本地拒绝：把回复排队后走 grace 关机而不是立即 finish_conn。
// 与 send_open_error() 同一模型：回复先于 socket 消失，应用（比如按
// RFC 1928 处理失败码的 curl）能读到置位的原因，而不是收到连接重置。
// 立即 finish 的话，应用写缓冲已满时回复根本没机会出门（flush_app 的
// sendto 返回 0 不再给第二次机会），只能凭空送一个 RST。
void ProxyEngine::refuse_local(Conn& conn, const char* why, Socks5Rep rep,
                               HttpReply http) {
  if (conn.closing || conn.phase == Phase::kDone) {
    return;
  }
  conn.closing = true;
  queue_local_reply(conn, rep, http);
  conn.want_fin = true;
  arm_grace(conn, /*only_if_idle=*/true);
  maybe_fin(conn);
  log(std::string(kTagWarn) + label(conn) + " " + why);
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
    refuse_local(conn, "malformed OPEN reply", Socks5Rep::kGeneralFailure,
                 HttpReply::kBadGateway);
    return;
  }
  drop_front(&conn.stream_in, consumed);
  if (!ok) {
    counters_.open_failed++;
    refuse_local(conn, "server refused the tunnel", socks5_rep_for_open_error(err),
                 HttpReply::kBadGateway);
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
  log(std::string(kTagInfo) + label(conn) + " tunnel established");
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
  log(std::string(kTagInfo) + label(conn) + " dial");
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
  log(std::string(kTagError) + label(conn) + " OPEN_ERR " + std::to_string(static_cast<unsigned>(err)));
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
  // The grace clock belongs to the refusal path (refuse_local/send_open_error:
  // the reply is out, the socket only has to live long enough for the app to
  // read it). A plain half-close is not that: the app said "done sending" and
  // is waiting for a response that may legitimately take far longer than
  // flush_grace_ms. Arming here used to kill the tunnel -- and the app socket --
  // 2 s after shutdown(SHUT_WR), so a slow target's answer never arrived.
  // A vanished peer is still bounded: the stream retransmits the fin under its
  // own RTO rules and its idle timeout ends the connection.
  if (!conn.app_in.empty() || !conn.to_stream.empty()) {
    if (conn.closing) {
      arm_grace(conn, /*only_if_idle=*/true);
    }
    return;
  }
  if (conn.stream->state() == StreamState::kOpen ||
      conn.stream->state() == StreamState::kPeerClosed) {
    conn.stream->close(now_ms_);
  }
  if (conn.closing) {
    // Slide on real progress only; re-arming every tick would never expire.
    arm_grace(conn, /*only_if_idle=*/true);
  }
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
  // Only the send direction can be judged from these two: acked < queued means
  // this side still had bytes on the wire. bytes_delivered() is the *receive*
  // side's delivery count, so comparing it with acked (the send side) made
  // almost every clean close look stuck and drowned the real cases (B-11).
  const bool stuck = conn.stream != nullptr &&
                     conn.stream->bytes_acked() != conn.stream->bytes_queued();
  // Compare against the start this stream actually used, not the configured
  // default: apply_prewarm() may have seeded a prior, and a connection that
  // ended exactly at its prior has not "moved" relative to it.
  const bool tuned = conn.stream != nullptr && cfg_.auto_window &&
                     conn.stream->send_window() != conn.stream_cfg.send_window_bytes;
  // A stall verdict is reported from whichever side stopped moving. The receive
  // side has no "stuck" send counter, so its oob/pending numbers only exist in
  // this line — print them for a stall even when this side's send is clean.
  const bool stalled = std::strcmp(why, "the peer stopped acknowledging") == 0;
  if (stuck || tuned || stalled) {
    char bbr[160] = "";
    if (conn.stream->using_bbr()) {
      std::snprintf(bbr, sizeof(bbr),
                    " bbr=%s bw=%llu gain=%.2f eff=%.2f hi=%zu lo=%zu",
                    Bbr::mode_name(conn.stream->bbr_mode()),
                    static_cast<unsigned long long>(conn.stream->bbr_bandwidth_bps()),
                    conn.stream->bbr_pacing_gain(), conn.stream->bbr_efficiency(),
                    conn.stream->bbr_inflight_hi(), conn.stream->bbr_inflight_lo());
    } else {
      std::snprintf(bbr, sizeof(bbr), " bbr=off");
    }
    std::snprintf(diag_, sizeof(diag_),
                  "stream queued=%llu acked=%llu delivered=%llu unacked=%zu in_flight=%zu "
                  "rwnd=%zu cwnd=%zu rto=%lld loss_rto=%llu loss_dup=%llu probes=%llu "
                  "retx=%llu (fast=%llu fill=%llu rto=%llu passes=%llu) "
                  "oob=%zu pending=%zu%s",
                  static_cast<unsigned long long>(conn.stream->bytes_queued()),
                  static_cast<unsigned long long>(conn.stream->bytes_acked()),
                  static_cast<unsigned long long>(conn.stream->bytes_delivered()),
                  conn.stream->unacked_segs(), conn.stream->in_flight(),
                  conn.stream->peer_window(), conn.stream->send_window(),
                  static_cast<long long>(conn.stream->rto_ms()),
                  static_cast<unsigned long long>(conn.stream->rto_loss_events()),
                  static_cast<unsigned long long>(conn.stream->dup_loss_events()),
                  static_cast<unsigned long long>(conn.stream->probes_sent()),
                  static_cast<unsigned long long>(conn.stream->retransmits()),
                  static_cast<unsigned long long>(conn.stream->retx_fast()),
                  static_cast<unsigned long long>(conn.stream->retx_fill()),
                  static_cast<unsigned long long>(conn.stream->retx_rto()),
                  static_cast<unsigned long long>(conn.stream->fill_passes()),
                  conn.stream->oob_bytes(), conn.stream->delivery_pending(), bbr);
    log(std::string(kTagInfo) + label(conn) + " closed: " + why + " [" + diag_ + "]");
  } else {
    log(std::string(kTagInfo) + label(conn) + " closed: " + why);
  }
  (void)now_ms;
}

// 握手并发限流（EngineConfig::hs_concurrency，仅 client）：释放连接持有的
// 槽位；未持有者（server 角色连接、已建立的、排队中未 start 的）是 no-op。
void ProxyEngine::release_handshake_slot(Conn& conn) {
  if (!conn.hs_slot_held) {
    return;
  }
  conn.hs_slot_held = false;
  if (hs_in_flight_ > 0) {
    --hs_in_flight_;
  }
}

// 槽位空出后按 FIFO 补位：出队的会话此刻才真正 start（HELLO 出网），并
// 补注册 by_salt_（排队期间不注册，B-04：入站 HELLO 不得建立它）。start
// 失败的拒绝形状与 on_local_open 的拒绝路径一致：计数 + 关闭本地 socket。
void ProxyEngine::pump_handshake_queue(int64_t now_ms) {
  if (cfg_.role != EngineRole::kClient || cfg_.hs_concurrency == 0) {
    return;
  }
  while (!hs_queue_.empty() && hs_in_flight_ < cfg_.hs_concurrency) {
    const uint64_t id = hs_queue_.front();
    hs_queue_.pop_front();
    Conn* c = find(id);
    if (c == nullptr || c->phase == Phase::kDone || c->session == nullptr ||
        !c->hs_queued) {
      continue;  // 排队期间本地已关闭：它没持有槽位，直接跳过
    }
    c->hs_queued = false;
    switch (c->session->start(now_ms)) {
      case Session::StartStatus::kOk:
        break;
      case Session::StartStatus::kNoEntropy:
        ++counters_.no_entropy;
        if (host_.app_close) {
          host_.app_close(id);
        }
        continue;
      case Session::StartStatus::kBadConfig:
        ++counters_.bad_config;
        log(std::string(kTagWarn) + label(*c) +
            " refused: MTU leaves no room for a data symbol");
        if (host_.app_close) {
          host_.app_close(id);
        }
        continue;
    }
    by_salt_.emplace(c->salt_key, id);
    ++hs_in_flight_;
    c->hs_slot_held = true;
  }
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
      if (!conn.salt_key.empty()) {
        // by_salt_ 的条目无条件摘除：只有认证过的会话才配留下面的死盐墓碑。
        // 未认证的会话（每个首包伪造盐买到的）本来就不该留下半点路由痕迹，
        // 否则 ~8 字节垃圾包 × 不同随机盐 = 无上限的表生长（每条目数十节
        // 点，永不被 reap 触及，因为墓碑分支只在 authenticated_once 下执行）。
        const auto salt_it = by_salt_.find(conn.salt_key);
        if (salt_it != by_salt_.end() && salt_it->second == id) {
          by_salt_.erase(salt_it);
        }
        if (conn.authenticated_once) {
          // #29a (M2 §8.1 tail race): the peer's retransmit tail keeps
          // arriving after our side is gone. Keep the salt known-but-dead so
          // those datagrams drop as tombstones instead of counting as
          // unknown_salt (client) or — worse on the server — being mistaken
          // for a fresh HELLO and rebirthing a phantom session. Only an
          // authenticated session may insert (A1 follow-up): otherwise every
          // 8-byte forgery would buy a five-minute table entry. 伪造盐不同：
          // 它不进墓碑——否则攻击者可用猜测的盐把墓碑表顶满。
          if (salt_tombstones_.size() >= kSaltTombstoneMax) {
            // Evict the entry closest to its deadline rather than whatever the
            // hash bucket order puts first: every eviction re-opens that salt
            // to a phantom session, so the entry that was about to expire
            // anyway is the cheapest one to lose.
            auto soonest = salt_tombstones_.begin();
            for (auto it = salt_tombstones_.begin(); it != salt_tombstones_.end(); ++it) {
              if (it->second < soonest->second) {
                soonest = it;
              }
            }
            salt_tombstones_.erase(soonest);
          }
          salt_tombstones_[conn.salt_key] = now_ms + kSaltTombstoneMs;
        }
      }
      // save_profile / flush_report above still needed the peer's address, so
      // the release has to wait until the connection is really gone -- and the
      // id is copied out first, because erase() destroys the Conn.
      const uint64_t conn_peer = conn.peer;
      // `it` was taken before the host callbacks above. A host that re-enters
      // through wire_send (in-process loopback, test hosts) can create a
      // connection, insert into by_conn_ and rehash it -- after which `it` is
      // dangling and erase(it) frees the wrong node. Resolve again; the extra
      // lookup is O(1) on a table we are deleting from anyway.
      const auto again = by_conn_.find(id);
      if (again == by_conn_.end()) {
        continue;  // a re-entrant path already released it; nothing left to do
      }
      // 连接此刻真正消失：若还占着握手槽位（已 start 未建立），先释放并
      // 补位，再从表里摘除。
      release_handshake_slot(conn);
      pump_handshake_queue(now_ms);
      by_conn_.erase(again);
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
  // BBR's model as a prior for the next connection to this peer. Both are kept
  // apart from the epoch controller's window above: the bandwidth is what
  // STARTUP would have spent a page of connections re-learning.
  if (conn.stream->using_bbr()) {
    profile.bw_bps = conn.stream->bbr_bandwidth_bps();
    profile.min_rtt_ms = conn.stream->min_rtt_ms();
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
