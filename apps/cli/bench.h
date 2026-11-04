// FCP link speed test: raw frame-layer throughput, not a TCP stream.
//
// The proxy's speed test used to run an HTTP request through the tunnel. That
// measures the FCP *stream* layer (window, BBR, local TCP legs) on top of the
// link, so the number is really "how fast a TCP connection goes through FCP".
// This unit measures the thing underneath: both ends push synthetic FCP data
// symbols straight into the frame/FEC layer, with no stream window and no
// target socket in the path. The result is the tunnel's own goodput.
//
// Roles (the server's UDP port is reused, so there is no second port to open):
//   * server: `fcp-server --speedtest` makes the reactor answer a 20-byte
//     rendezvous magic (unencrypted) by creating an FCP session bound to that
//     source address. Every later datagram from that address is fed to the
//     session instead of the proxy engine. The session is PSK-authenticated,
//     exactly like a tunnel.
//   * client: `fcp-client --speedtest` runs one test and exits. It never opens
//     the SOCKS listener; the desktop spawns it as a second sidecar process.
//
// Each direction runs for `seconds` and both senders use the same open-loop
// token bucket: the offered rate starts at kStartBps and is multiplied every
// kRampMs until kMaxBps. The receiver keeps a one-second sliding window of
// delivered payload bytes (post-FEC) and reports the best window it saw; that
// is the link's achievable goodput. A ramp is used instead of a fixed rate
// because this path has no congestion controller of its own -- the operator
// would otherwise have to guess the offered rate and re-run the test.
//
// The protocol payload is deliberately tiny. Every payload starts with a
// 16-byte header whose sn sits at offset 12 (the frame layer's cross-set dedup
// reads the KCP sn there), so a data payload doubles as a KCP-like segment:
//
//   magic[8] | version u16 | type u8 | reserved u8 | sn u32 | body...
//
// type=kData body is filler. type=kReport carries the receiver's cumulative
// delivered bytes and best one-second rate; only the server sends reports (the
// client is the receiver of the upload phase), and they ride the same session
// in the opposite direction.

#ifndef FCP_BENCH_H_
#define FCP_BENCH_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>

#include "fcp/defaults.h"
#include "fcp/session.h"

namespace fcp {

namespace bench {

// Rendezvous datagram (client -> server, unencrypted): magic, version, phase
// length, session salt. The salt is what binds the server's session to the
// client's key derivation; the magic alone authorizes nothing.
constexpr size_t kMagicLen = 8;
constexpr size_t kSaltLen = 8;
constexpr uint16_t kVersion = 1;
constexpr size_t kRendezvousLen = kMagicLen + 2 + 2 + kSaltLen;  // 20

constexpr size_t kHeaderLen = 16;
constexpr size_t kDataPayloadLen = 1200;  // <= payload_max at the default MTU
// magic[8] + version[2] + type[1] + reserved[1] + sn[4] + delivered[8] +
// best_bps[8]
constexpr size_t kReportPayloadLen = kHeaderLen + 16;

constexpr int kMinSeconds = 3;
constexpr int kMaxSeconds = 30;
constexpr int kDefaultSeconds = 8;

// Offered-rate ramp. 20 Mbps -> 1 Gbps takes about eight seconds, which fits
// the shortest phase; above 1 Gbps the probe stops growing and the reported
// number becomes the link's ceiling under this test.
constexpr double kStartBps = 20e6;
constexpr double kMaxBps = 1000e6;
constexpr int64_t kRampMs = 500;

// Receiver bookkeeping.
constexpr int64_t kWindowMs = 1000;
constexpr int64_t kSilenceMs = 700;   // no data for this long = direction done
constexpr int64_t kReportMs = 250;    // server -> client upload progress
constexpr int64_t kDrainMs = 1500;    // client waits this long for reports
constexpr int64_t kSetupTimeoutMs = 6000;
constexpr int64_t kSettleBeforePhaseMs = 300;

enum class PayloadType : uint8_t { kData = 0, kReport = 1 };

extern const uint8_t kMagic[kMagicLen];

// All four return false only for malformed input (wrong magic, short buffer,
// unknown version/type). `out` is filled only on success.
bool EncodeRendezvous(const uint8_t salt[kSaltLen], uint16_t seconds,
                      uint8_t out[kRendezvousLen]);
bool DecodeRendezvous(const uint8_t* data, size_t len, uint8_t salt[kSaltLen],
                      uint16_t* seconds);
bool IsMagic(const uint8_t* data, size_t len);

// Fills exactly `len` bytes (len >= kHeaderLen) with a data payload; the body
// is zero. A unique `sn` per payload keeps the frame layer's dedup honest.
void EncodeData(uint32_t sn, uint8_t* out, size_t len);
void EncodeReport(uint32_t sn, uint64_t delivered, uint64_t best_bps, uint8_t* out,
                  size_t len);

struct DecodedPayload {
  PayloadType type = PayloadType::kData;
  uint32_t sn = 0;
  uint64_t delivered = 0;  // kReport only: receiver's cumulative user bytes
  uint64_t best_bps = 0;   // kReport only: receiver's best one-second goodput
};
bool DecodePayload(const uint8_t* payload, size_t len, DecodedPayload* out);

// Payload bytes that count as application throughput (the header is framing).
inline uint64_t UserBytes(size_t payload_len) {
  return payload_len > kHeaderLen ? payload_len - kHeaderLen : 0;
}

// Exponential offered-rate schedule. Pure so the ramp is testable without a
// socket.
class Ramp {
 public:
  explicit Ramp(double bps = kStartBps) : bps_(bps) {}
  void Reset(double bps = kStartBps) { bps_ = bps; }
  // One probe interval elapsed: multiply by 1.5, saturating at kMaxBps.
  void Advance();
  double bps() const { return bps_; }

 private:
  double bps_;
};

// Best one-second delivered-rate window seen so far. Buckets are 100ms of
// accumulated user bytes; gaps (lost intervals) simply contribute nothing.
class RateWindow {
 public:
  void Add(int64_t now_ms, uint64_t bytes);
  void Reset();
  uint64_t total_bytes() const { return total_; }
  uint64_t best_bps() const { return best_bps_; }

 private:
  struct Slot {
    int64_t index = 0;  // now_ms / 100
    uint64_t bytes = 0;
  };
  static constexpr int64_t kSlotMs = 100;
  static constexpr size_t kSlotsPerWindow = kWindowMs / kSlotMs;
  static constexpr size_t kMaxSlots = 32;

  std::deque<Slot> slots_;
  uint64_t total_ = 0;
  uint64_t best_bps_ = 0;
};

struct Options {
  uint8_t key[16] = {};
  uint8_t d = kDefaultD;
  uint8_t p = kDefaultP;
  uint8_t p_max = kDefaultPmax;
  uint16_t mtu = kDefaultMtu;
  size_t ip_hdr_len = kDefaultIpHeaderLen;
  double fec_budget = kDefaultFecBudget;
};

struct ClientOptions {
  std::string host;
  uint16_t port = 4460;
  uint8_t key[16] = {};
  uint16_t seconds = kDefaultSeconds;
  uint16_t mtu = kDefaultMtu;
  size_t ip_hdr_len = kDefaultIpHeaderLen;
};

struct Sample {
  double mbps = 0.0;
  uint64_t bytes = 0;
  double seconds = 0.0;
  bool acked = false;
  // Pre-FEC raw loss of this direction's receive side, as last reported.
  uint32_t loss_ppm = 0;
  uint32_t loss_n = 0;
};

struct Result {
  Sample download;
  Sample upload;
  bool have_download = false;
  bool have_upload = false;
  std::string error;
};

// direction is "down" or "up"; bytes are delivered (down) or sent (up).
using ProgressFn = std::function<void(const char* direction, uint64_t bytes,
                                      int64_t elapsed_ms)>;

// Blocking; returns false only when no measurement could be made at all
// (socket, rendezvous, handshake). A run whose upload report never arrived
// still returns true with have_upload == false and an explanatory error.
bool RunClient(const ClientOptions& options, const ProgressFn& progress, Result* out);

}  // namespace bench

// Server side of the speed test, owned by the reactor when `--speedtest` is
// given. The peer key is the raw sockaddr_in bytes (16 on every platform),
// so this header does not need any socket headers and the same code runs on
// Windows and POSIX.
class BenchServer {
 public:
  struct Peer {
    uint8_t bytes[16] = {};
  };
  using SendFn = std::function<size_t(const Peer& peer, const uint8_t* data, size_t len)>;
  using LogFn = std::function<void(const std::string& line)>;

  BenchServer(const bench::Options& options, SendFn send, LogFn log = {});
  ~BenchServer();

  BenchServer(const BenchServer&) = delete;
  BenchServer& operator=(const BenchServer&) = delete;

  // True when the datagram belonged to the responder (a rendezvous magic or a
  // datagram from the active bench peer) and must not reach the proxy engine.
  bool OnDatagram(const Peer& from, const uint8_t* data, size_t len, int64_t now_ms);
  void OnTick(int64_t now_ms);

  bool active() const { return session_ != nullptr; }

 private:
  void Reset();
  void StartSession(const Peer& from, const uint8_t salt[bench::kSaltLen],
                    uint16_t seconds, int64_t now_ms);
  void SendRendezvousEcho(int64_t now_ms);
  void SendReport(int64_t now_ms, bool final);
  void OnDelivered(const uint8_t* payload, size_t len, int64_t now_ms);
  void ApplyTokens(int64_t now_ms);

  bench::Options opt_;
  SendFn send_;
  LogFn log_;

  std::unique_ptr<Session> session_;
  Peer peer_;
  bool have_peer_ = false;
  uint8_t salt_[bench::kSaltLen] = {};

  enum class Phase : uint8_t {
    kWaitEstablished,
    kDownload,
    kAwaitUpload,
    kUpload,
    kDraining,
  };
  Phase phase_ = Phase::kWaitEstablished;
  int64_t created_ms_ = 0;
  int64_t phase_start_ms_ = 0;
  int64_t download_end_ms_ = 0;
  int64_t last_upload_data_ms_ = 0;
  int64_t last_report_ms_ = 0;
  int64_t drain_end_ms_ = 0;
  int64_t last_echo_ms_ = -1000000;
  uint16_t seconds_ = bench::kDefaultSeconds;

  uint32_t sn_ = 1;
  double tokens_ = 0.0;
  int64_t token_ms_ = 0;
  int64_t last_ramp_ms_ = 0;
  bench::Ramp ramp_;

  uint64_t upload_bytes_ = 0;
  bench::RateWindow upload_window_;
  uint8_t payload_[bench::kDataPayloadLen] = {};
};

}  // namespace fcp

#endif  // FCP_BENCH_H_
