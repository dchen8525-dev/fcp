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
// delivered bytes and best one-second rate, plus the sender's best one-second
// offered (framer) rate for the download direction; only the server sends reports (the
// client is the receiver of the upload phase), and they ride the same session
// in the opposite direction. type=kPing (client -> server, ts in the body) and
// type=kPingEcho (the server's answer, ts echoed untouched) add a lightweight
// RTT sampler that shares the data session; the server answers pings whenever
// the session is established, in every phase.

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
constexpr uint16_t kVersion = 2;
constexpr size_t kRendezvousLen = kMagicLen + 2 + 2 + kSaltLen;  // 20

constexpr size_t kHeaderLen = 16;
constexpr size_t kDataPayloadLen = 1200;  // <= payload_max at the default MTU
// magic[8] + version[2] + type[1] + reserved[1] + sn[4] | body:
//   delivered[8] | best_bps[8] | down_wire_bps[8] | down_sent[8] |
//   capped_ratio_ppm[4] | capped[1] | reserved[3]
// delivered/best_bps describe the server's *upload* accounting (it is the
// receiver there); down_wire_bps is the server's best one-second offered
// (framer) rate for the download direction; down_sent is the server's
// cumulative offered download user bytes, against which the client computes
// download.loss_bytes; capped/capped_ratio_ppm describe the server's rate
// controller for the download direction (0/never-capped when the climb never
// hit a ceiling). Reports are fixed length; no version tolerance.
constexpr size_t kReportPayloadLen = kHeaderLen + 40;
// magic[8] .. sn[4] | delivered[8] | best_bps[8]. The client's download-side
// delivery report (client -> server), feeding the server's rate controller the
// same way the server's kReport feeds the client's.
constexpr size_t kDownReportPayloadLen = kHeaderLen + 16;
// magic[8] .. sn[4] + ts[8]. The ts is the sender's NowMs; the echo carries it
// back untouched, and whoever sent the ping turns the difference into an RTT
// sample.
constexpr size_t kPingPayloadLen = kHeaderLen + 8;
constexpr int64_t kPingEveryMs = 500;

constexpr int kMinSeconds = 3;
constexpr int kMaxSeconds = 30;
constexpr int kDefaultSeconds = 8;

// Offered-rate bounds shared by the rate controller. The climb starts at
// kStartBps and stops growing at kMaxBps; a path that carries kMaxBps reports
// no ceiling under this test.
constexpr double kStartBps = 20e6;
constexpr double kMaxBps = 1000e6;
// Floor for a converged rate: below this the test would measure nothing worth
// reporting, and pathological feedback (a report racing a phase change) must
// not collapse the offered rate to zero.
constexpr double kMinBps = 4e6;

// Receiver bookkeeping.
constexpr int64_t kWindowMs = 1000;
constexpr int64_t kSilenceMs = 700;   // no data for this long = direction done
constexpr int64_t kReportMs = 250;    // delivery-report cadence, both directions
// The server goes silent once the upload stops, so the client has to outlast
// the server's own silence detector (kSilenceMs) before it can judge the
// result, on top of the last report still being in flight.
constexpr int64_t kDrainMs = kSilenceMs + 1500;
constexpr int64_t kSetupTimeoutMs = 6000;
constexpr int64_t kSettleBeforePhaseMs = 300;
// The server flushes every set within flush_ms_ (25..200ms), but a control
// report goes out on its own when the set queue is idle, and both run on the
// reactor's 25ms tick. Two seconds is far beyond any of those.
constexpr int64_t kFinalReportsMs = 2000;

enum class PayloadType : uint8_t {
  kData = 0,
  kReport = 1,      // server -> client: upload delivery + download wire/loss info
  kPing = 2,
  kPingEcho = 3,
  kDownReport = 4,  // client -> server: download delivery, feeds the server's
                    // rate controller the same way kReport feeds the client's
};

extern const uint8_t kMagic[kMagicLen];

// All four return false only for malformed input (wrong magic, short buffer,
// unknown version/type). `out` is filled only on success.
bool EncodeRendezvous(const uint8_t salt[kSaltLen], uint16_t seconds,
                      uint8_t out[kRendezvousLen]);
bool DecodeRendezvous(const uint8_t* data, size_t len, uint8_t salt[kSaltLen],
                      uint16_t* seconds);
// IsMagic is the exact 8-byte echo. IsMagicPrefix only asks whether the
// datagram starts with the magic, which the server uses to classify stray
// datagrams without trusting them as bench traffic.
bool IsMagic(const uint8_t* data, size_t len);
bool IsMagicPrefix(const uint8_t* data, size_t len);

// Fills exactly `len` bytes (len >= kHeaderLen) with a data payload; the body
// is zero. A unique `sn` per payload keeps the frame layer's dedup honest.
void EncodeData(uint32_t sn, uint8_t* out, size_t len);
void EncodeReport(uint32_t sn, uint64_t delivered, uint64_t best_bps,
                  uint64_t down_wire_bps, uint64_t down_sent,
                  uint32_t capped_ratio_ppm, bool capped, uint8_t* out,
                  size_t len);
void EncodeDownReport(uint32_t sn, uint64_t delivered, uint64_t best_bps,
                      uint8_t* out, size_t len);
// Ping bodies carry the sender's NowMs; the echo reverses only the type byte
// and keeps the sn (already unique at the sender).
void EncodePing(uint32_t sn, uint64_t timestamp, uint8_t* out, size_t len);
void EncodePingEcho(uint32_t sn, uint64_t timestamp, uint8_t* out, size_t len);

struct DecodedPayload {
  PayloadType type = PayloadType::kData;
  uint32_t sn = 0;
  uint64_t delivered = 0;      // kReport/kDownReport: receiver's cumulative user bytes
  uint64_t best_bps = 0;       // kReport/kDownReport: receiver's best one-second goodput
  uint64_t down_wire_bps = 0;  // kReport only: sender's download wire rate
  uint64_t down_sent = 0;      // kReport only: sender's cumulative offered download bytes
  uint32_t capped_ratio_ppm = 0;  // kReport only: download controller steady ratio
  bool capped = false;            // kReport only: download controller hit a ceiling
  uint64_t timestamp = 0;  // kPing / kPingEcho only
};
bool DecodePayload(const uint8_t* payload, size_t len, DecodedPayload* out);

// Payload bytes that count as application throughput (the header is framing).
inline uint64_t UserBytes(size_t payload_len) {
  return payload_len > kHeaderLen ? payload_len - kHeaderLen : 0;
}

// Delivery-feedback rate controller for the bench. Neither direction has a
// congestion controller of its own (see the header comment), so the offered
// rate is steered by the receiver's periodic delivery reports instead of the
// old open-loop ramp: climb while what is sent is what arrives, converge to
// the measured delivery rate when arrivals fall well behind, hold for a
// steady window, then probe gently above the ceiling again -- the controller
// hugs the path's real cap instead of trusting one report.
//
// The delivery ratio is lag-tolerant by construction: bytes answering an
// epoch's offer arrive about one RTT later, i.e. in the NEXT report on a
// path whose RTT is at least one report period. So the ratio compares this
// report's arrivals against the PREVIOUS report's offered size, not the
// current one -- comparing against the current offer reads the normal climb
// as loss and converges on the first ramp step (measured on a 273ms-RTT
// path: the naive ratio converges at 1/1.5 of the ramp step).
//
// Feeding is once per delivery report; deltas are cumulative-counter
// differences, both sides counted in user bytes, so they are
// apples-to-apples. One ambiguous report (ratio between the thresholds)
// decides nothing.
class RateController {
 public:
  enum class State : uint8_t { kProbing, kCapped, kMaxed };

  void Reset(int64_t now_ms) {
    state_ = State::kProbing;
    rate_ = kStartBps;
    now_ = now_ms;
    prev_sent_ = 0;
    prev_got_ = 0;
    prev_sent_delta_ = 0;
    have_prev_ = false;
    converged_ = false;
    capped_at_ms_ = 0;
    cap_base_sent_ = 0;
    cap_base_got_ = 0;
    capped_ratio_ppm_ = 0;
  }

  // Returns the offered rate to use until the next feed. The first feed only
  // sets the baseline (no delta yet, and no lag reference to compare against).
  double Feed(int64_t now_ms, uint64_t sent_total, uint64_t got_total) {
    if (!have_prev_) {
      have_prev_ = true;
      prev_sent_ = sent_total;
      prev_got_ = got_total;
      now_ = now_ms;
      return rate_;
    }
    const uint64_t sent_delta = sent_total >= prev_sent_ ? sent_total - prev_sent_ : 0;
    const uint64_t got_delta = got_total >= prev_got_ ? got_total - prev_got_ : 0;
    const uint64_t ref_sent = prev_sent_delta_;  // last epoch's offer size
    prev_sent_ = sent_total;
    prev_got_ = got_total;
    prev_sent_delta_ = sent_delta;
    const int64_t dt = now_ms - now_;
    now_ = now_ms;
    if (sent_delta == 0 && got_delta == 0) {
      return rate_;  // nothing moved since the last report: nothing to learn
    }
    const double ratio =
        ref_sent > 0 ? static_cast<double>(got_delta) / static_cast<double>(ref_sent)
                     : 1.0;  // first delta: no lag reference, assume healthy
    // A converged rate re-opens for probing after the hold: one report epoch
    // above the ceiling is the price of checking whether the cap moved.
    if (converged_ && now_ms - capped_at_ms_ >= kCapHoldMs) {
      converged_ = false;
      rate_ = std::min(kMaxBps, rate_ * kResumeClimb);
      prev_sent_delta_ = 0;  // the probe's size is new; skip one lag reference
    }
    if (!converged_) {
      if (ratio < kProbeLossRatio && got_delta > 0 && sent_delta > 0) {
        // The path has a ceiling below what we are offering. Converge to the
        // delivered rate with a small margin.
        Converge(now_ms, sent_total, got_total, GotBps(got_delta, dt));
      } else if (ratio >= kProbeOkRatio) {
        if (rate_ >= kMaxBps) {
          state_ = State::kMaxed;
        } else {
          rate_ = std::min(kMaxBps, rate_ * kProbeClimb);
        }
      }
      // Between the thresholds: hold -- the offer is in transition (in-flight
      // backlog catching up), so one report must not conclude.
    } else if (ratio < kProbeLossRatio && got_delta > 0 && ref_sent > 0) {
      // The converged margin is still too generous: re-converge lower and
      // restart the hold.
      Converge(now_ms, sent_total, got_total, GotBps(got_delta, dt));
    }
    if (converged_ && sent_total >= cap_base_sent_) {
      const uint64_t window_sent = sent_total - cap_base_sent_;
      const uint64_t window_got = got_total >= cap_base_got_ ? got_total - cap_base_got_ : 0;
      capped_ratio_ppm_ =
          window_sent > 0
              ? static_cast<uint32_t>((window_got * 1000000ull + window_sent / 2) /
                                      window_sent)
              : 0;
    }
    return rate_;
  }

  double rate() const { return rate_; }
  State state() const { return state_; }
  // Delivery ratio since the last convergence point, in ppm. Zero while
  // never capped. Drives the result's acked/error semantics: the climb's
  // overshoot is the probe's own cost, loss at the converged rate is the
  // path's.
  uint32_t capped_ratio_ppm() const { return capped_ratio_ppm_; }

 private:
  static double GotBps(uint64_t got_delta, int64_t dt_ms) {
    return static_cast<double>(got_delta) * 8.0 * 1000.0 / static_cast<double>(dt_ms);
  }
  void Converge(int64_t now_ms, uint64_t sent_total, uint64_t got_total,
                double got_bps) {
    rate_ = std::min(kMaxBps, std::max(kMinBps, got_bps * kCapMargin));
    state_ = State::kCapped;
    converged_ = true;
    capped_at_ms_ = now_ms;
    cap_base_sent_ = sent_total;
    cap_base_got_ = got_total;
    capped_ratio_ppm_ = 0;
  }
  // Climb while healthy; converge on sustained loss. The middle band is the
  // in-flight transition, held for one more report before concluding. After a
  // convergence the controller pauses (kCapHoldMs) and then re-probes gently
  // (kResumeClimb), so a premature or stale ceiling gets re-checked within
  // the same run.
  static constexpr double kProbeClimb = 1.5;
  static constexpr double kResumeClimb = 1.3;
  static constexpr double kProbeOkRatio = 0.95;
  static constexpr double kProbeLossRatio = 0.80;
  static constexpr double kCapMargin = 1.05;
  static constexpr int64_t kCapHoldMs = 1500;
  // Floor for a converged rate: below this the test would measure nothing
  // worth reporting, and pathological feedback must not collapse the offered
  // rate to zero.
  static constexpr double kMinBps = 4e6;

  State state_ = State::kProbing;
  double rate_ = kStartBps;
  int64_t now_ = 0;
  uint64_t prev_sent_ = 0;
  uint64_t prev_got_ = 0;
  uint64_t prev_sent_delta_ = 0;
  bool have_prev_ = false;
  bool converged_ = false;
  int64_t capped_at_ms_ = 0;
  uint64_t cap_base_sent_ = 0;
  uint64_t cap_base_got_ = 0;
  uint32_t capped_ratio_ppm_ = 0;
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
  // Upload only: bytes the framer accepted that the server never counted
  // (upload.loss_n is the server's symbol-level loss; this one only moves
  // when something was actually lost). acked is false whenever it is > 0.
  uint64_t lost_bytes = 0;
  // The sender's best one-second offered (framer) rate for this direction, on
  // the same scale as `mbps` (receiver's best one-second delivered rate). The
  // gap between the two is FEC redundancy plus whatever the direction lost.
  // Download receives it via the kReport down_wire_bps field; upload keeps the
  // client's own RateWindow over the payloads it poured.
  uint64_t wire_bps = 0;
  // Pre-FEC raw loss of this direction's receive side, as last reported.
  uint32_t loss_ppm = 0;
  uint32_t loss_n = 0;
  // The rate controller converged to a delivery ceiling (steady-state
  // measurement). With it, wireMbps sits just above mbps and the residual
  // "lostBytes" is the climb's own overshoot, not a path problem.
  bool adaptive = false;
};

// RTT samples from the ping/echo exchange across the whole run.
struct RttStats {
  uint32_t n = 0;
  uint32_t min_ms = 0;
  uint32_t avg_ms = 0;
  uint32_t max_ms = 0;
};

struct Result {
  Sample download;
  Sample upload;
  bool have_download = false;
  bool have_upload = false;
  // Rendezvous start -> session established.
  int64_t setup_ms = 0;
  RttStats rtt;
  std::string error;
};

// direction is "down" or "up"; bytes are delivered (down) or sent (up).
using ProgressFn = std::function<void(const char* direction, uint64_t bytes,
                                      int64_t elapsed_ms)>;

// Process-wide single-bench gate. RunClient takes it and releases it on every
// exit path; the server's BenchServer takes it per session. A second bench in
// the same process is refused instead of interleaving on the shared socket.
bool BenchGate(std::string* error);
void BenchRelease();

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
  bench::RateController down_ctrl_;  // download offered-rate controller

  uint64_t upload_bytes_ = 0;
  bench::RateWindow upload_window_;
  // One-second offered-rate window for the download phase (the server is the
  // sender there); its best value rides every report.
  bench::RateWindow download_window_;
  bool outcome_logged_ = false;
  uint8_t payload_[bench::kDataPayloadLen] = {};
};

}  // namespace fcp

#endif  // FCP_BENCH_H_
