// Shared UDP-loopback harness for the end-to-end (C2) and soak (C3) tests.
//
// Two sessions talk through a pair of connected 127.0.0.1 UDP sockets. Loss
// injection happens at the application layer, before sendto, so every dropped
// datagram is known; KCP retransmission is emulated explicitly by the caller.

#ifndef FCP_TESTS_E2E_LINK_H_
#define FCP_TESTS_E2E_LINK_H_

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
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

#include "fcp/fecstat.h"
#include "fcp/session.h"

namespace fcp_e2e {

using Bytes = std::vector<uint8_t>;

inline const uint8_t* Key() {
  static const uint8_t kKey[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
  return kKey;
}

inline const uint8_t* Salt() {
  static const uint8_t kSalt[8] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
  return kSalt;
}

// KCP-like segment: 16 bytes with the sn at offset 12 (dedup key).
inline Bytes Segment(uint32_t sn) {
  Bytes out(16, 0);
  out[12] = static_cast<uint8_t>(sn);
  out[13] = static_cast<uint8_t>(sn >> 8);
  out[14] = static_cast<uint8_t>(sn >> 16);
  out[15] = static_cast<uint8_t>(sn >> 24);
  for (size_t i = 0; i < 12; ++i) {
    out[i] = static_cast<uint8_t>(sn * 31 + i * 7);
  }
  return out;
}

// Delegates to the library so a wire-layout change cannot leave the test
// reading a different offset than the code under test.
inline uint32_t SnOf(const uint8_t* payload, size_t len) {
  uint32_t sn = 0;
  return fcp::kcp_sn_of(payload, len, &sn) ? sn : 0;
}

inline uint32_t SnOf(const Bytes& payload) { return SnOf(payload.data(), payload.size()); }

inline bool PayloadOk(const uint8_t* payload, size_t len) {
  if (len != 16) {
    return false;
  }
  const uint32_t sn = SnOf(payload, len);
  for (size_t i = 0; i < 12; ++i) {
    if (payload[i] != static_cast<uint8_t>(sn * 31 + i * 7)) {
      return false;
    }
  }
  return true;
}

inline fcp::SessionConfig MakeConfig(fcp::Direction send, fcp::Direction recv, uint8_t p,
                                     int pinned_k = -1) {
  fcp::SessionConfig cfg;
  std::memcpy(cfg.key, Key(), 16);
  std::memcpy(cfg.salt, Salt(), sizeof(cfg.salt));
  cfg.send_direction = send;
  cfg.recv_direction = recv;
  cfg.d = 10;
  cfg.p = p;
  cfg.p_max = fcp::kDefaultPmax;
  cfg.pinned_k = pinned_k;
  return cfg;
}

struct FecstatLogFields {
  uint32_t sets = 0;
  uint32_t expect = 0;
  uint32_t rx = 0;
  uint32_t rec = 0;
  uint32_t late = 0;
  uint32_t lost = 0;
  uint32_t pre = 0;
  uint32_t usable = 0;
  unsigned k = 0;
  std::string state;
};

inline bool ParseFecstatLog(const std::vector<std::string>& logs, FecstatLogFields* out) {
  for (const std::string& line : logs) {
    if (line.rfind("FECSTAT sets=", 0) != 0) {
      continue;
    }
    char state[8] = {};
    const int n = std::sscanf(
        line.c_str(),
        "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u pre=%uppm "
        "usable=%uppm -> k=%u state=%7s",
        &out->sets, &out->expect, &out->rx, &out->rec, &out->late, &out->lost,
        &out->pre, &out->usable, &out->k, state);
    if (n == 10) {
      out->state = state;
      return true;
    }
  }
  return false;
}

inline bool SameCounters(const fcp::SettleCounters& x, const fcp::SettleCounters& y) {
  return x.sets_expected == y.sets_expected && x.data_expected == y.data_expected &&
         x.data_rx_orig == y.data_rx_orig &&
         x.data_recovered_dl == y.data_recovered_dl &&
         x.data_recovered_late == y.data_recovered_late &&
         x.data_late_rx == y.data_late_rx && x.data_delivered == y.data_delivered &&
         x.parity_rx == y.parity_rx && x.parity_expected == y.parity_expected &&
         x.sets_k_unknown == y.sets_k_unknown && x.sets_full == y.sets_full &&
         x.sets_partial == y.sets_partial &&
         x.sets_tail_dropped == y.sets_tail_dropped && x.late_dup == y.late_dup;
}

#ifdef _WIN32
using SocketHandle = SOCKET;
using SockLen = int;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;

class WinsockGuard {
 public:
  WinsockGuard() {
    WSADATA data{};
    started_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  ~WinsockGuard() {
    if (started_) {
      WSACleanup();
    }
  }
  WinsockGuard(const WinsockGuard&) = delete;
  WinsockGuard& operator=(const WinsockGuard&) = delete;
  bool ok() const { return started_; }

 private:
  bool started_ = false;
};
#else
using SocketHandle = int;
using SockLen = socklen_t;
constexpr SocketHandle kInvalidSocket = -1;

class WinsockGuard {
 public:
  bool ok() const { return true; }
};
#endif

class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket() { Close(); }
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  bool Open() {
    handle_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (handle_ == kInvalidSocket) {
      return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(handle_, reinterpret_cast<sockaddr*>(&addr),
               static_cast<SockLen>(sizeof(addr))) != 0) {
      Close();
      return false;
    }
    SockLen len = static_cast<SockLen>(sizeof(addr));
    if (::getsockname(handle_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
      Close();
      return false;
    }
    port_ = ntohs(addr.sin_port);
    // The default loopback buffer (~8KiB) overflows as soon as a test pushes a
    // window of full-MTU segments, and the datagrams it drops are invisible to
    // the loss injector. Size it past the largest window these tests use.
    const int rcv_buf = 1 << 20;
    ::setsockopt(handle_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcv_buf),
                 static_cast<SockLen>(sizeof(rcv_buf)));
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(handle_, FIONBIO, &mode) != 0) {
      Close();
      return false;
    }
#else
    const int flags = fcntl(handle_, F_GETFL, 0);
    if (flags < 0 || fcntl(handle_, F_SETFL, flags | O_NONBLOCK) < 0) {
      Close();
      return false;
    }
#endif
    return true;
  }

  bool Connect(uint16_t peer_port) {
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port = htons(peer_port);
    return ::connect(handle_, reinterpret_cast<sockaddr*>(&peer),
                     static_cast<SockLen>(sizeof(peer))) == 0;
  }

  bool Send(const uint8_t* data, size_t len) {
#ifdef _WIN32
    const int n = ::send(handle_, reinterpret_cast<const char*>(data),
                         static_cast<int>(len), 0);
#else
    const ssize_t n = ::send(handle_, data, len, 0);
#endif
    return n >= 0 && static_cast<size_t>(n) == len;
  }

  bool Recv(uint8_t* buf, size_t cap, size_t* len) {
#ifdef _WIN32
    const int n = ::recv(handle_, reinterpret_cast<char*>(buf),
                         static_cast<int>(cap), 0);
#else
    const ssize_t n = ::recv(handle_, buf, cap, 0);
#endif
    if (n <= 0) {
      return false;
    }
    *len = static_cast<size_t>(n);
    return true;
  }

  void Close() {
    if (handle_ == kInvalidSocket) {
      return;
    }
#ifdef _WIN32
    ::closesocket(handle_);
#else
    ::close(handle_);
#endif
    handle_ = kInvalidSocket;
  }

  uint16_t port() const { return port_; }

 private:
  SocketHandle handle_ = kInvalidSocket;
  uint16_t port_ = 0;
};

// Loopback pair plus an application-layer loss injector. Control and OOB
// datagrams are never dropped so the handshake and FECSTAT cadence stay
// deterministic; data/parity loss drives recovery and the strategy.
struct Harness {
  WinsockGuard winsock;
  UdpSocket sock_a;
  UdpSocket sock_b;

  std::unique_ptr<fcp::Session> a_holder;
  std::unique_ptr<fcp::Session> b_holder;
  fcp::Session* a = nullptr;
  fcp::Session* b = nullptr;

  std::vector<std::string> log_a;
  std::vector<std::string> log_b;
  std::vector<Bytes> delivered_a;
  std::vector<Bytes> delivered_b;
  std::vector<uint32_t> hits_a;  // deliveries per sn, A <- B
  std::vector<uint32_t> hits_b;  // deliveries per sn, B <- A
  uint32_t corrupt_a = 0;
  uint32_t corrupt_b = 0;

  int64_t now = 0;

  bool loss_enabled = false;
  uint32_t loss_percent = 20;
  uint32_t rng = 0x9E3779B9u;
  bool drop_next_data_a = false;

  // Deterministic burst injection (task E2, spec #27②): every `burst_period`
  // outgoing data symbols from A, the first `burst_len` are dropped — e.g.
  // period=25/len=5 is a 20% average loss made of 5-in-a-row bursts. Only data
  // symbols are affected; parity, oob and control always pass. The counter
  // covers every A→data datagram, so it must only be enabled while the caller
  // drives a known 1:1 sn→datagram stream (e.g. Harness::Inject).
  bool burst_enabled = false;
  uint32_t burst_period = 25;
  uint32_t burst_len = 5;
  uint32_t burst_data_seen = 0;

  uint32_t a_data = 0;
  uint32_t a_parity = 0;
  uint32_t a_oob = 0;
  uint32_t a_control = 0;
  uint32_t b_data = 0;
  uint32_t b_parity = 0;
  uint32_t b_oob = 0;
  uint32_t b_control = 0;

  Bytes last_a_wire;
  fcp::SymbolType last_a_type = fcp::SymbolType::kData;

  bool Init(const fcp::SessionConfig& cfg_a, const fcp::SessionConfig& cfg_b) {
    if (!winsock.ok() || !sock_a.Open() || !sock_b.Open()) {
      return false;
    }
    if (!sock_a.Connect(sock_b.port()) || !sock_b.Connect(sock_a.port())) {
      return false;
    }
    a_holder = std::make_unique<fcp::Session>(
        cfg_a, [this](const uint8_t* w, size_t n, fcp::SymbolType t) { from_a(w, n, t); },
        [this](const uint8_t* p, size_t n) { note_delivery_a(p, n); },
        [this](const std::string& s) { log_a.push_back(s); });
    b_holder = std::make_unique<fcp::Session>(
        cfg_b, [this](const uint8_t* w, size_t n, fcp::SymbolType t) { from_b(w, n, t); },
        [this](const uint8_t* p, size_t n) { note_delivery_b(p, n); },
        [this](const std::string& s) { log_b.push_back(s); });
    a = a_holder.get();
    b = b_holder.get();
    return true;
  }

  bool drop(fcp::SymbolType type) {
    if (burst_enabled && type == fcp::SymbolType::kData) {
      const uint32_t idx = burst_data_seen++;
      return (idx % burst_period) < burst_len;
    }
    if (!loss_enabled) {
      return false;
    }
    if (type != fcp::SymbolType::kData && type != fcp::SymbolType::kParity) {
      return false;
    }
    rng = rng * 1103515245u + 12345u;
    return ((rng >> 16) % 100) < loss_percent;
  }

  void from_a(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++a_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++a_parity;
    } else if (type == fcp::SymbolType::kOob) {
      ++a_oob;
    } else {
      ++a_control;
    }
    last_a_wire.assign(wire, wire + len);
    last_a_type = type;
    if (drop_next_data_a && type == fcp::SymbolType::kData) {
      drop_next_data_a = false;
      return;
    }
    if (drop(type)) {
      return;
    }
    sock_a.Send(wire, len);
  }

  void from_b(const uint8_t* wire, size_t len, fcp::SymbolType type) {
    if (type == fcp::SymbolType::kData) {
      ++b_data;
    } else if (type == fcp::SymbolType::kParity) {
      ++b_parity;
    } else if (type == fcp::SymbolType::kOob) {
      ++b_oob;
    } else {
      ++b_control;
    }
    if (drop(type)) {
      return;
    }
    sock_b.Send(wire, len);
  }

  void note_delivery_a(const uint8_t* payload, size_t len) {
    if (!PayloadOk(payload, len)) {
      ++corrupt_a;
    }
    delivered_a.emplace_back(payload, payload + len);
    if (len < 16) {
      return;
    }
    const uint32_t sn = SnOf(payload, len);
    if (sn >= (1u << 24)) {
      return;
    }
    if (hits_a.size() <= sn) {
      hits_a.resize(sn + 1, 0);
    }
    ++hits_a[sn];
  }

  void note_delivery_b(const uint8_t* payload, size_t len) {
    if (!PayloadOk(payload, len)) {
      ++corrupt_b;
    }
    delivered_b.emplace_back(payload, payload + len);
    if (len < 16) {
      return;
    }
    const uint32_t sn = SnOf(payload, len);
    if (sn >= (1u << 24)) {
      return;
    }
    if (hits_b.size() <= sn) {
      hits_b.resize(sn + 1, 0);
    }
    ++hits_b[sn];
  }

  bool pump_once() {
    bool moved = false;
    uint8_t buf[2048];
    size_t len = 0;
    while (sock_b.Recv(buf, sizeof(buf), &len)) {
      b->on_wire(buf, len, now);
      moved = true;
    }
    while (sock_a.Recv(buf, sizeof(buf), &len)) {
      a->on_wire(buf, len, now);
      moved = true;
    }
    return moved;
  }

  void pump() {
    for (int guard = 0; guard < 1024; ++guard) {
      if (!pump_once()) {
        return;
      }
    }
  }

  bool Handshake() {
    now = 0;
    a->start(0);
    b->start(0);
    a->on_tick(0);
    b->on_tick(0);
    pump();
    return a->established() && b->established();
  }

  void TickAt(int64_t t) {
    now = t;
    a->on_tick(t);
    pump();
    b->on_tick(t);
    pump();
  }

  void TickTo(int64_t first, int64_t last) {
    for (int64_t t = first; t <= last; t += fcp::kSessionTickMs) {
      TickAt(t);
    }
  }

  void Inject(uint32_t first, uint32_t last, int64_t t) {
    now = t;
    for (uint32_t sn = first; sn < last; ++sn) {
      const Bytes seg = Segment(sn);
      a->on_kcp_output(seg.data(), seg.size(), t);
      pump();
    }
  }

  // Single-segment helpers without a pump; the caller batches and pumps.
  void SendA(uint32_t sn, int64_t t) {
    now = t;
    const Bytes seg = Segment(sn);
    a->on_kcp_output(seg.data(), seg.size(), t);
  }

  void SendB(uint32_t sn, int64_t t) {
    now = t;
    const Bytes seg = Segment(sn);
    b->on_kcp_output(seg.data(), seg.size(), t);
  }
};

}  // namespace fcp_e2e

#endif  // FCP_TESTS_E2E_LINK_H_
