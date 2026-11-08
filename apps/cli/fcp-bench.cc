// Real-network FCP benchmark: one session per process, no KCP underneath.
//
// Usage: <role> is the first positional argument; --key=HEX32 is mandatory
// (there is no test PSK), and every other option defaults as shown.
//   fcp-bench server --port=5555 --key=HEX32 [--mbps=30] [--seg=1200] [--k=-1]
//   fcp-bench client --host=1.2.3.4 --port=5555 --key=HEX32 [...same...]
// Run the server first: both ends rendezvous on a 15s FCPBENCH magic exchange.
//
// The server receives for 7s (upload phase), then sends for 7s (download
// phase); the client mirrors it. Phases are aligned by data flow, not by wall
// clocks: the client sends for 7s starting 1s after its handshake completes,
// the server detects the end of that stream (500ms silence), waits 1s, then
// sends for 7s. A handshake that needed HELLO retries therefore shifts only
// the client's send start, never its receive window. With k=-1 the strategy
// runs (and stays k=0 on a clean path); --k=N pins N parity symbols per set to
// measure FEC overhead on the same path.

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "cli_parse.h"
#include "fcp/fecstat.h"
#include "fcp/frame_tx.h"
#include "fcp/handshake.h"
#include "fcp/random.h"
#include "fcp/session.h"

namespace {

// Range-checked numbers live in cli_parse.h: one copy of the
// diagnostics the proxy CLI and both tools use.
using fcp::tools::ParseDouble;
using fcp::tools::ParseLong;

#ifdef _WIN32
using Sock = SOCKET;
constexpr Sock kBadSock = INVALID_SOCKET;
#else
using Sock = int;
constexpr Sock kBadSock = -1;
#endif

// Upload phase, relative to the client's handshake completing: send from
// kUpStartMs to kUpEndMs, so kPhaseSeconds is the window both sides divide by.
constexpr int64_t kUpStartMs = 1000;
constexpr int64_t kUpEndMs = 8000;
constexpr double kPhaseSeconds = (kUpEndMs - kUpStartMs) / 1000.0;
// #36 WAN smoke: under a sustained flood the kernel buffer never empties, so an
// unbounded drain loop never returns to the outer loop -- `now`, on_tick() and
// the phase clock freeze for the whole upload. The proxy reactor and the Qt
// host already bound their drain for the same reason (128 datagrams).
constexpr int kMaxRecvPerIteration = 256;

// The benchmark's fixed FEC geometry. It is a compile-time constant, so --k can
// be validated against it *before* the rendezvous loop: otherwise a bad --k
// waits out the full rendezvous timeout (or a whole run) before failing.
constexpr unsigned kBenchD = 10;
constexpr unsigned kBenchP = 3;

struct Options {
  std::string role;
  std::string host;
  int port = 5555;
  double mbps = 30.0;
  size_t seg = 1200;
  int k = -1;
  // A3 follow-up (P2' N7): there is no default PSK. The FIPS-197 vector this
  // used to ship is a public test key, and a benchmark that silently encrypts
  // with it is worse than one that refuses to start. --key is mandatory.
  std::string key_hex;
  bool progress = false;
};

// Everything the run tallies: the tx_* fields are written from the session's
// send callback, rx_data_bytes/rx_data_segs/rx_corrupt from its delivery
// callback, and the rest from the receive loop in main(). They are read once at
// the end, which is why they live in one struct instead of a dozen loose locals
// threaded through the loop.
struct Stats {
  uint64_t tx_data_bytes = 0;
  uint64_t tx_data_segs = 0;
  uint64_t tx_wire_bytes = 0;
  uint64_t tx_parity_segs = 0;
  uint64_t tx_oob = 0;
  uint64_t tx_fail = 0;
  uint64_t rx_datagrams = 0;
  uint64_t rx_data_bytes = 0;
  uint64_t rx_data_segs = 0;
  // Data symbols as they arrive on the wire (fixed kDataWireOverhead + seg
  // size), before the
  // session decodes, dedups or drops them. Phase timing uses this clock: the
  // delivery callbacks lag behind arrival when the receiver falls behind.
  // A datagram's type is inside the envelope, so this is classified by exact
  // length; ParseOptions rejects --seg values whose data length collides with
  // a control frame, otherwise HELLO/HELLO_ACK/FECSTAT would be counted here.
  uint64_t rx_data_wire = 0;
  uint64_t rx_corrupt = 0;
  size_t rx_min_len = static_cast<size_t>(-1);
  size_t rx_max_len = 0;
};

int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void SleepMs(int64_t ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

bool ParseKey(const char* text, uint8_t out[16]) {
  if (text == nullptr || std::strlen(text) != 32) {
    return false;
  }
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < 16; ++i) {
    const int hi = hex(text[2 * i]);
    const int lo = hex(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool SetNonBlocking(Sock s) {
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  const int flags = fcntl(s, F_GETFL, 0);
  return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) >= 0;
#endif
}

void SetBuffers(Sock s) {
  const int size = 4 * 1024 * 1024;
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&size), sizeof(size));
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&size), sizeof(size));
}

struct Endpoint {
  Sock sock = kBadSock;
  sockaddr_in peer{};
  bool server = false;

  ~Endpoint() {
    if (sock == kBadSock) {
      return;
    }
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
  }

  bool OpenServer(int port) {
    server = true;
    sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kBadSock) {
      return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      return false;
    }
    SetBuffers(sock);
    return SetNonBlocking(sock);
  }

  bool OpenClient(const char* host, int port) {
    server = false;
    sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kBadSock) {
      return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
      return false;
    }
    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      return false;
    }
    SetBuffers(sock);
    return SetNonBlocking(sock);
  }

  bool Recv(uint8_t* buf, size_t cap, size_t* len) {
    if (server) {
      sockaddr_in from{};
      socklen_t from_len = sizeof(from);
      const int n = static_cast<int>(
          ::recvfrom(sock, reinterpret_cast<char*>(buf), static_cast<int>(cap), 0,
                     reinterpret_cast<sockaddr*>(&from), &from_len));
      if (n <= 0) {
        return false;
      }
      peer = from;
      *len = static_cast<size_t>(n);
      return true;
    }
    const int n = ::recv(sock, reinterpret_cast<char*>(buf), static_cast<int>(cap), 0);
    if (n <= 0) {
      return false;
    }
    *len = static_cast<size_t>(n);
    return true;
  }

  bool Send(const uint8_t* data, size_t len) {
    if (server) {
      return ::sendto(sock, reinterpret_cast<const char*>(data), static_cast<int>(len), 0,
                      reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) >= 0;
    }
    return ::send(sock, reinterpret_cast<const char*>(data), static_cast<int>(len), 0) >= 0;
  }
};

void MakeSegment(uint32_t sn, size_t len, std::vector<uint8_t>* out) {
  out->assign(len < 16 ? 16 : len, 0);
  (*out)[12] = static_cast<uint8_t>(sn);
  (*out)[13] = static_cast<uint8_t>(sn >> 8);
  (*out)[14] = static_cast<uint8_t>(sn >> 16);
  (*out)[15] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 0; i < out->size(); ++i) {
    if (i >= 12 && i < 16) {
      continue;
    }
    (*out)[i] = static_cast<uint8_t>(sn * 31 + i * 7);
  }
}

bool PayloadOk(const uint8_t* p, size_t len, size_t expect_len) {
  if (len != expect_len || len < 16) {
    return false;
  }
  const uint32_t sn = static_cast<uint32_t>(p[12]) |
                      (static_cast<uint32_t>(p[13]) << 8) |
                      (static_cast<uint32_t>(p[14]) << 16) |
                      (static_cast<uint32_t>(p[15]) << 24);
  for (size_t i = 0; i < len; ++i) {
    if (i >= 12 && i < 16) {
      continue;
    }
    if (p[i] != static_cast<uint8_t>(sn * 31 + i * 7)) {
      return false;
    }
  }
  return true;
}

bool ParseOptions(int argc, char** argv, Options* opt) {
  if (argc < 2) {
    return false;
  }
  opt->role = argv[1];
  std::vector<std::string> seen;
  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    auto value = [&](const char* prefix) -> const char* {
      const size_t n = std::strlen(prefix);
      return arg.compare(0, n, prefix) == 0 ? arg.c_str() + n : nullptr;
    };
    const char* v_host = value("--host=");
    const char* v_port = value("--port=");
    const char* v_mbps = value("--mbps=");
    const char* v_seg = value("--seg=");
    const char* v_k = value("--k=");
    const char* v_key = value("--key=");
    const bool v_progress = arg == "--progress";
    // One spelling per setting, and repeating it is a script bug rather than
    // "the last one wins" (same rule as the proxy CLI's MarkSeen).
    const char* name = v_host    ? "host"
                       : v_port  ? "port"
                       : v_mbps  ? "mbps"
                       : v_seg   ? "seg"
                       : v_k     ? "k"
                       : v_key   ? "key"
                       : v_progress ? "progress"
                                    : nullptr;
    if (name == nullptr) {
      std::fprintf(stderr, "unknown option: %s\n", arg.c_str());
      return false;
    }
    std::string dup_error;
    if (!fcp::tools::MarkSeen(&seen, name, &dup_error)) {
      std::fprintf(stderr, "%s\n", dup_error.c_str());
      return false;
    }
    if (opt->role == "server" && v_host != nullptr) {
      std::fprintf(stderr, "--host is a client option\n");
      return false;
    }
    long n = 0;
    if (v_host != nullptr) {
      opt->host = v_host;
    } else if (v_port != nullptr) {
      if (!ParseLong("--port", v_port, 1, 65535, &n)) {
        return false;
      }
      opt->port = static_cast<int>(n);
    } else if (v_mbps != nullptr) {
      if (!ParseDouble("--mbps", v_mbps, 0.1, 10000.0, &opt->mbps)) {
        return false;
      }
    } else if (v_seg != nullptr) {
      if (!ParseLong("--seg", v_seg, 16, 1200, &n)) {
        return false;
      }
      opt->seg = static_cast<size_t>(n);
    } else if (v_k != nullptr) {
      if (!ParseLong("--k", v_k, -1, 7, &n)) {
        return false;
      }
      opt->k = static_cast<int>(n);
    } else if (v_key != nullptr) {
      opt->key_hex = v_key;
    } else {
      opt->progress = true;
    }
  }
  if (opt->role != "server" && (opt->role != "client" || opt->host.empty())) {
    return false;
  }
  // The receiver here only gets bytes, not the decoded frame type, so data
  // symbols are recognised by their fixed wire length (kDataWireOverhead +
  // --seg). That is only sound while no control frame has the same length:
  // --seg=34 makes a data symbol 70 bytes, exactly HELLO; 50 -> HELLO_ACK (86),
  // 126 -> FECSTAT (162). The server's phase clock arms on the first "data"
  // datagram, so at --seg=34 the handshake itself would end the upload phase
  // before it starts, and the reported wire counters would include control
  // frames. Reject those three instead of publishing polluted numbers.
  const struct {
    const char* name;
    size_t plain_len;
  } kControls[] = {
      {"HELLO", fcp::kHelloLen},
      {"HELLO_ACK", fcp::kHelloAckLen},
      {"FECSTAT", fcp::kFecstatLen},
  };
  const size_t data_wire = fcp::kDataWireOverhead + opt->seg;
  for (const auto& c : kControls) {
    if (data_wire == fcp::kFrameEnvelopeOverhead + fcp::kFecHdrLen + c.plain_len) {
      std::fprintf(stderr,
                   "--seg=%zu makes every data symbol %zu wire bytes, the same as a "
                   "%s control frame; the bench separates data from control by length, "
                   "so pick another --seg\n",
                   opt->seg, data_wire, c.name);
      return false;
    }
  }
  return true;
}

constexpr size_t kSaltLen = 8;
constexpr size_t kMeetLen = 8;
constexpr int64_t kRendezvousTimeoutMs = 15000;

// The FCP handshake retries for ~39.7s before it fails (#76; the old budget
// was three HELLOs / ~2.1s), so two processes started a few seconds apart can
// still establish. Rendezvous outside the protocol is kept anyway: both sides
// send a magic datagram every 50ms until each has seen the peer's, then
// start their sessions together.
//
// The client's datagram also carries the run's session salt (A2: a fresh salt
// per run from the OS CSPRNG, with no constant fallback -- P2' N7, a fixed salt
// is exactly the cross-session (key, IV) reuse A2 removed). The server adopts
// the first salt it is offered; `salt` is in/out: filled by the client, filled
// in by the server.
//
// Stray magics still in flight authenticate as nothing and count as
// auth_fail, which the RESULT line reports.
bool Rendezvous(Endpoint* ep, bool server, uint8_t salt[kSaltLen]) {
  if (!server) {
    // 与 random_salt 同一约定：盐只走核心库 CSPRNG（std::random_device 在
    // MinGW 下可为固定种子 PRNG，固定盐 = 跨 run (key, IV) 重用，P2' N7）。
    if (!fcp::random_bytes(salt, kSaltLen)) {
      std::fprintf(stderr, "no CSPRNG entropy for session salt\n");
      return false;
    }
  }
  static const uint8_t kMeet[kMeetLen] = {'F', 'C', 'P', 'B', 'E', 'N', 'C', 'H'};
  static_assert(sizeof(kMeet) == kMeetLen,
                "the server only adopts a salt from a datagram of exactly kMeetLen + kSaltLen");
  uint8_t client_meet[sizeof(kMeet) + kSaltLen];
  std::memcpy(client_meet, kMeet, sizeof(kMeet));
  std::memcpy(client_meet + sizeof(kMeet), salt, kSaltLen);

  bool met = false;
  bool salt_adopted = false;
  uint64_t meet_rx = 0;
  int meet_sent = 0;
  const int64_t meet_t0 = NowMs();
  while (NowMs() - meet_t0 < kRendezvousTimeoutMs) {
    uint8_t mbuf[64];
    size_t mlen = 0;
    // Bounded like the main loop: a sustained flood must not pin this thread
    // inside the drain and turn the 15s timeout into an unbounded wait.
    for (int drained = 0; drained < kMaxRecvPerIteration; ++drained) {
      if (!ep->Recv(mbuf, sizeof(mbuf), &mlen)) {
        break;
      }
      ++meet_rx;
      if (mlen < sizeof(kMeet) || std::memcmp(mbuf, kMeet, sizeof(kMeet)) != 0) {
        continue;
      }
      if (!server) {
        met = true;
        continue;
      }
      // P2' N7: adopt the FIRST client salt exactly once. A later datagram can
      // no longer rewrite it, and an 8-byte legacy magic is only a liveness
      // hint -- it carries no salt, so it cannot start a run.
      if (mlen == sizeof(kMeet) + kSaltLen && !salt_adopted) {
        std::memcpy(salt, mbuf + sizeof(kMeet), kSaltLen);
        salt_adopted = true;
        met = true;
      }
    }
    // Seeing the peer's magic is not enough: it is still waiting for ours, so
    // send a few of our own first (the server cannot send until its peer
    // address is known, hence the port check).
    if (met && meet_sent >= 3) {
      break;
    }
    if (!ep->server || ep->peer.sin_port != 0) {
      if (server) {
        ep->Send(kMeet, sizeof(kMeet));
      } else {
        ep->Send(client_meet, sizeof(client_meet));
      }
      ++meet_sent;
    }
    SleepMs(50);
  }
  if (!met) {
    std::fprintf(stderr, "rendezvous timeout (datagrams=%llu peer_port=%u)\n",
                 static_cast<unsigned long long>(meet_rx),
                 static_cast<unsigned>(ntohs(ep->peer.sin_port)));
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  if (!ParseOptions(argc, argv, &opt)) {
    std::fprintf(stderr,
                 "usage: %s server --port=P --key=HEX32 [--mbps=M] [--seg=N] [--k=K]\n"
                 "       %s client --host=IP --port=P --key=HEX32 [--mbps=M] [--seg=N] [--k=K]\n"
                 "       [--progress]\n",
                 argv[0], argv[0]);
    return 1;
  }
  uint8_t key[16];
  if (opt.key_hex.empty()) {
    std::fprintf(stderr, "--key=HEX32 is required (the PSK shared by both ends)\n");
    return 1;
  }
  if (!ParseKey(opt.key_hex.c_str(), key)) {
    std::fprintf(stderr, "--key must be 32 hex digits (16 bytes)\n");
    return 1;
  }
  // P8' N12: --k above the negotiated P' is silently clamped by the session and
  // the benchmark would report a k it never ran. Validate before doing any I/O.
  if (opt.k > static_cast<int>(kBenchP)) {
    std::fprintf(stderr, "--k=%d exceeds --p=%u\n", opt.k, kBenchP);
    return 1;
  }
#ifdef _WIN32
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    std::fprintf(stderr, "WSAStartup failed\n");
    return 1;
  }
#endif

  const bool server = opt.role == "server";
  Endpoint ep;
  const bool opened = server ? ep.OpenServer(opt.port) : ep.OpenClient(opt.host.c_str(), opt.port);
  if (!opened) {
    std::fprintf(stderr, "socket setup failed (port %d)\n", opt.port);
    return 1;
  }

  Stats stats;

  uint8_t salt[kSaltLen] = {};
  if (!Rendezvous(&ep, server, salt)) {
    return 4;
  }

  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, key, sizeof(cfg.key));
  std::memcpy(cfg.salt, salt, sizeof(cfg.salt));
  cfg.send_direction = server ? fcp::Direction::kS2C : fcp::Direction::kC2S;
  cfg.recv_direction = server ? fcp::Direction::kC2S : fcp::Direction::kS2C;
  cfg.d = kBenchD;
  cfg.p = kBenchP;
  cfg.mtu = 1400;
  // (--k > p is rejected in main, before the rendezvous.)
  cfg.pinned_k = opt.k;

  fcp::Session session(
      cfg,
      [&](const uint8_t* wire, size_t len, fcp::SymbolType type) {
        if (ep.server && ep.peer.sin_port == 0) {
          return;  // no peer address yet (cannot happen before the first HELLO)
        }
        if (!ep.Send(wire, len)) {
          ++stats.tx_fail;
          return;
        }
        // A20: only datagrams the kernel accepted count toward throughput; the
        // old code booked them before ::send, so a full send buffer inflated
        // exactly the runs that were under pressure.
        if (type == fcp::SymbolType::kData) {
          stats.tx_wire_bytes += len;
          ++stats.tx_data_segs;
          // 与 kDataWireOverhead 同源（对抗分析第九轮：36 的裸常数会在
          // 信封/头预算变化时静默偏离）。
          if (len > fcp::kDataWireOverhead) {
            stats.tx_data_bytes += len - fcp::kDataWireOverhead;
          }
        } else if (type == fcp::SymbolType::kParity) {
          ++stats.tx_parity_segs;
        } else {
          ++stats.tx_oob;
        }
      },
      [&](const uint8_t* payload, size_t len) {
        stats.rx_data_bytes += len;
        ++stats.rx_data_segs;
        if (!PayloadOk(payload, len, opt.seg)) {
          ++stats.rx_corrupt;
        }
      },
      [](const std::string& line) { std::printf("LOG %s\n", line.c_str()); });

  const int64_t t0 = NowMs();
  int64_t now = 0;
  session.start(0);
  session.on_tick(0);
  const double rate_bytes_per_s = opt.mbps * 1000000.0 / 8.0;
  const double wire_per_seg =
      static_cast<double>(fcp::kDataWireOverhead) + static_cast<double>(opt.seg);
  const size_t data_wire_len = static_cast<size_t>(wire_per_seg);
  constexpr int64_t kSendWindowMs = static_cast<int64_t>(kPhaseSeconds * 1000);
  double tokens = 0.0;
  int64_t token_ms = 0;
  int64_t next_tick = 25;
  int64_t est = -1;
  uint32_t sn = 1;
  std::vector<uint8_t> segment;

  // Event-driven phase state. The server never trusts its own handshake clock
  // against the peer's: it watches the upload stream itself. The clock is wire
  // arrival, not delivery: under load the decode/deliver path lags arrival.
  bool up_sending = false;
  bool down_sending = false;
  bool down_done = false;
  int64_t first_rx_wire_ms = -1;
  int64_t last_rx_wire_ms = -1;
  int64_t down_start_ms = -1;
  uint64_t up_wire_segs = 0;
  uint64_t seen_rx_wire = 0;

  bool done = false;
  int64_t next_progress = 1000;
  while (!done) {
    now = NowMs() - t0;

    uint8_t buf[2048];
    size_t len = 0;
    for (int drained = 0; drained < kMaxRecvPerIteration; ++drained) {
      if (!ep.Recv(buf, sizeof(buf), &len)) {
        break;
      }
      ++stats.rx_datagrams;
      if (len == data_wire_len) {
        ++stats.rx_data_wire;
      }
      stats.rx_min_len = std::min(stats.rx_min_len, len);
      stats.rx_max_len = std::max(stats.rx_max_len, len);
      now = NowMs() - t0;
      session.on_wire(buf, len, now);
    }

    if (opt.progress && now >= next_progress) {
      next_progress = now + 1000;
      std::printf("PROGRESS role=%s t=%lld dgrams=%llu data_wire=%llu delivered=%llu "
                  "tx_segs=%llu active=%u\n",
                  opt.role.c_str(), static_cast<long long>(now),
                  static_cast<unsigned long long>(stats.rx_datagrams),
                  static_cast<unsigned long long>(stats.rx_data_wire),
                  static_cast<unsigned long long>(stats.rx_data_segs),
                  static_cast<unsigned long long>(stats.tx_data_segs),
                  session.rx() ? static_cast<unsigned>(session.rx()->active_sets()) : 0u);
      std::fflush(stdout);
    }

    if (est < 0 && session.established()) {
      est = now;
      std::printf("ESTABLISHED role=%s handshake_ms=%lld\n", opt.role.c_str(),
                  static_cast<long long>(est));
      std::fflush(stdout);
    }
    if (est < 0 && now > 6000) {
      std::fprintf(stderr, "handshake timeout (state=%d error=%d)\n",
                   static_cast<int>(session.state()), static_cast<int>(session.error()));
      return 2;
    }

    if (now >= next_tick) {
      session.on_tick(now);
      next_tick = now + fcp::kSessionTickMs;
    }

    if (!server) {
      const int64_t rel = now - est;
      const bool in_up = est >= 0 && rel >= kUpStartMs && rel < kUpEndMs;
      if (in_up) {
        if (!up_sending) {
          up_sending = true;
          tokens = 0.0;
          token_ms = now;
        }
      } else if (up_sending) {
        up_sending = false;
        std::printf("PHASE_END role=client rel_ms=%lld tx_data_bytes=%llu tx_data_segs=%llu\n",
                    static_cast<long long>(rel),
                    static_cast<unsigned long long>(stats.tx_data_bytes),
                    static_cast<unsigned long long>(stats.tx_data_segs));
        std::fflush(stdout);
      }
      if (est >= 0 && rel >= 18000) {
        done = true;
      }
    } else {
      if (stats.rx_data_wire != seen_rx_wire) {
        seen_rx_wire = stats.rx_data_wire;
        if (first_rx_wire_ms < 0) {
          first_rx_wire_ms = now;
        }
        last_rx_wire_ms = now;
      }
      if (!down_done && !down_sending && down_start_ms < 0 && first_rx_wire_ms >= 0 &&
          now - last_rx_wire_ms > 500) {
        // The upload stream has stopped (500ms of silence on the wire, before
        // the decode backlog): snapshot it and schedule the download phase one
        // second after its last datagram.
        up_wire_segs = stats.rx_data_wire;
        down_start_ms = last_rx_wire_ms + 1000;
      }
      if (!down_done && !down_sending && down_start_ms >= 0 && now >= down_start_ms) {
        down_sending = true;
        tokens = 0.0;
        token_ms = now;
        std::printf("PHASE_START role=server rel_ms=%lld up_wire_segs=%llu up_delivered=%llu\n",
                    static_cast<long long>(now),
                    static_cast<unsigned long long>(up_wire_segs),
                    static_cast<unsigned long long>(stats.rx_data_segs));
        std::fflush(stdout);
      }
      if (down_sending && now >= down_start_ms + kSendWindowMs) {
        down_sending = false;
        down_done = true;
        std::printf("PHASE_END role=server rel_ms=%lld tx_data_bytes=%llu tx_data_segs=%llu\n",
                    static_cast<long long>(now),
                    static_cast<unsigned long long>(stats.tx_data_bytes),
                    static_cast<unsigned long long>(stats.tx_data_segs));
        std::fflush(stdout);
      }
      if (down_done && now >= down_start_ms + kSendWindowMs + 1500) {
        done = true;
      }
      if (est >= 0 && down_start_ms < 0 && now - est > 25000) {
        std::fprintf(stderr, "no upload stream within 25s\n");
        return 3;
      }
    }

    if (up_sending || down_sending) {
      tokens = std::min(tokens + rate_bytes_per_s * static_cast<double>(now - token_ms) / 1000.0,
                        std::max(rate_bytes_per_s * 0.05, wire_per_seg));
      token_ms = now;
      int burst = 0;
      while (tokens >= wire_per_seg && burst < 4000) {
        MakeSegment(sn, opt.seg, &segment);
        session.on_kcp_output(segment.data(), segment.size(), now);
        ++sn;
        tokens -= wire_per_seg;
        ++burst;
      }
    }

    SleepMs(1);
  }

  // Upload bytes: client transmitter, server data-symbol payload (P9' N1: the
  // server used to classify by datagram length, but data and parity are both
  // 36+seg bytes, so every --k>0 run was inflated by 1+k/D). Download bytes:
  // server transmitter, client delivered payload. Each side divides by the
  // fixed 7s send window. A role's own transmit counters are zeroed in the
  // field it does not own so the two RESULT lines stay directly comparable.
  const Stats& s = stats;
  const double up_bytes = server ? static_cast<double>(session.data_payload_rx())
                                 : static_cast<double>(s.tx_data_bytes);
  const double down_bytes = server ? static_cast<double>(s.tx_data_bytes)
                                   : static_cast<double>(s.rx_data_bytes);
  const unsigned long long up_tx_segs = server ? 0 : s.tx_data_segs;
  const unsigned long long down_tx_segs = server ? s.tx_data_segs : 0;
  const unsigned long long up_wire = server ? up_wire_segs : 0;
  const unsigned long long down_rx_segs = server ? 0 : s.rx_data_segs;
  const unsigned long long down_rx_wire = server ? 0 : s.rx_data_wire;
  const auto counters = session.rx();
  const auto settle = session.settle();

  std::printf(
      "RESULT role=%s handshake_ms=%lld up_mbps=%.3f down_mbps=%.3f "
      "up_bytes=%llu down_bytes=%llu up_tx_segs=%llu up_wire_segs=%llu "
      "down_tx_segs=%llu down_rx_segs=%llu down_rx_wire=%llu rx_datagrams=%llu "
      "rx_corrupt=%llu rx_stale=%u rx_retired=%u rx_dup=%u rx_tail=%u "
      "active_sets=%u rx_len_min=%llu rx_len_max=%llu "
      "tx_wire_data=%llu tx_parity=%llu tx_oob=%llu tx_fail=%llu "
      "auth_fail=%u struct_fail=%u fecstat_rx=%u k=%u "
      "settle_expected=%u delivered=%u identity_ok=%d delivered_le_sum=%d\n",
      opt.role.c_str(), static_cast<long long>(est),
      up_bytes * 8.0 / kPhaseSeconds / 1e6, down_bytes * 8.0 / kPhaseSeconds / 1e6,
      static_cast<unsigned long long>(up_bytes),
      static_cast<unsigned long long>(down_bytes), up_tx_segs, up_wire, down_tx_segs,
      down_rx_segs, down_rx_wire,
      static_cast<unsigned long long>(s.rx_datagrams),
      static_cast<unsigned long long>(s.rx_corrupt),
      counters ? counters->stale() : 0u, counters ? counters->retired_dropped() : 0u,
      counters ? counters->late_dup() : 0u, counters ? counters->tail_dropped() : 0u,
      counters ? static_cast<unsigned>(counters->active_sets()) : 0u,
      static_cast<unsigned long long>(s.rx_max_len == 0 ? 0 : s.rx_min_len),
      static_cast<unsigned long long>(s.rx_max_len),
      static_cast<unsigned long long>(s.tx_wire_bytes),
      static_cast<unsigned long long>(s.tx_parity_segs),
      static_cast<unsigned long long>(s.tx_oob),
      static_cast<unsigned long long>(s.tx_fail), session.auth_fail(),
      session.struct_fail(), session.fecstat_rx(), session.k(),
      settle ? settle->counters().data_expected : 0,
      settle ? settle->counters().data_delivered : 0,
      settle ? static_cast<int>(settle->identity_ok()) : 0,
      settle ? static_cast<int>(settle->delivered_le_sum()) : 0);
#ifdef _WIN32
  WSACleanup();
#endif
  // P5' N6: a run where most sends failed is not a measurement. Exit non-zero
  // so automation does not ingest a zero-throughput sample as success.
  if (stats.tx_data_segs > 0 && stats.tx_fail * 2 > stats.tx_data_segs) {
    std::fprintf(stderr, "benchmark invalid: %llu of %llu datagrams failed to send\n",
                 static_cast<unsigned long long>(stats.tx_fail),
                 static_cast<unsigned long long>(stats.tx_data_segs + stats.tx_fail));
    return 5;
  }
  return 0;
}
