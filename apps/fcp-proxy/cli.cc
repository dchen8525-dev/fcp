#include "cli.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "fcp/session.h"
#include "fcp/version.h"
#include "reactor.h"

namespace fcp {
namespace {

bool HexNibble(char c, uint8_t* out) {
  if (c >= '0' && c <= '9') {
    *out = static_cast<uint8_t>(c - '0');
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    *out = static_cast<uint8_t>(c - 'a' + 10);
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    *out = static_cast<uint8_t>(c - 'A' + 10);
    return true;
  }
  return false;
}

bool ParseKey(const std::string& text, uint8_t out[16]) {
  if (text.size() != 32) {
    return false;
  }
  for (size_t i = 0; i < 16; ++i) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!HexNibble(text[i * 2], &hi) || !HexNibble(text[i * 2 + 1], &lo)) {
      return false;
    }
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

void Usage(EngineRole role, const char* argv0) {
  const bool client = role == EngineRole::kClient;
  std::printf(
      "usage: %s %s\n"
      "  --key=HEX32          16-byte pre-shared key (required, both ends equal)\n",
      argv0, client ? "[--host=IP --port=P] [--listen=IP --local-port=P] [options]"
                    : "[--bind=IP --port=P] [options]");
  if (client) {
    std::printf("  --host=IP            FCP server address (required)\n"
                "  --port=N             FCP server UDP port (default 4460)\n"
                "  --listen=IP          local proxy bind (default 127.0.0.1)\n"
                "  --local-port=N       local proxy port (default 1080)\n");
  } else {
    std::printf("  --bind=IP            UDP bind address (default 0.0.0.0)\n"
                "  --port=N             UDP listen port (default 4460)\n");
  }
  std::printf(
      "  --mtu=N              IP packet budget incl. IP+UDP headers (default 1400)\n"
      "  --d=N --p=N          frame geometry (default 10/3)\n"
      "  --k=N                pinned parity per set, -1 = adaptive (default -1)\n"
      "  --fec-budget=R       redundancy ceiling parity/data per report, 0 = off (default 0.5)\n"
      "  --trace=PREFIX       per-session controller trace JSONL (calibration)\n"
      "  --window=KiB         stream send window; autotune start when adaptive (default 256)\n"
      "  --rcv-buf=KiB        stream receive buffer; a floor when adaptive (default 256)\n"
      "  --auto-window        grow the send window while it is the bottleneck (default on)\n"
      "  --no-auto-window     keep the fixed --window (disables --window-cap)\n"
      "  --window-cap=KiB     autotune ceiling 64..4096 (default 1024)\n"
      "  --idle=ms            tunnel idle teardown (default 300000)\n"
      "  --dial-timeout=ms    remote resolve + connect budget (default 5000)\n"
      "  --connect-timeout=ms per-address TCP connect budget (default 5000)\n"
      "  --max-sessions=N     concurrent sessions (default 256)\n"
      "  --no-prewarm         start every session cold (default: reuse link priors)\n"
      "  --stats=ms           print a stats line this often (default: only on exit)\n"
      "  -v                   per-connection protocol log\n"
      "  --version            print the release version and exit\n");
}

bool CollectArgs(int argc, char** argv, std::map<std::string, std::string>* opts,
                 bool* help, std::string* error) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-v" || arg == "--verbose") {
      (*opts)["verbose"] = "1";
      continue;
    }
    if (arg == "-h" || arg == "--help") {
      *help = true;
      continue;
    }
    if (arg == "--version" || arg == "-V") {
      (*opts)["version"] = "1";
      continue;
    }
    const size_t eq = arg.find('=');
    if (arg.rfind("--", 0) != 0) {
      *error = "unknown argument: " + arg;
      return false;
    }
    if (eq == std::string::npos) {
      // Bare boolean flag (e.g. --no-prewarm): presence is the value.
      (*opts)[arg.substr(2)] = "";
    } else {
      (*opts)[arg.substr(2, eq - 2)] = arg.substr(eq + 1);
    }
  }
  return true;
}

const std::string* Find(const std::map<std::string, std::string>& opts, const char* name) {
  const auto it = opts.find(name);
  return it == opts.end() ? nullptr : &it->second;
}

// Full-string integer parse with a range check. Plain atoi() silently wrapped
// values into the narrow wire fields (--mtu=70000 became 4464, --d=266 became
// 10) and turned typos into zero, so every numeric option whose range is known
// comes through here.
bool ParseInt(const std::string& text, long lo, long hi, long* out) {
  if (text.empty()) {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const long value = std::strtol(text.c_str(), &end, 10);
  if (errno != 0 || end == text.c_str() || *end != '\0' || value < lo || value > hi) {
    return false;
  }
  *out = value;
  return true;
}

bool ParseDouble(const std::string& text, double* out) {
  if (text.empty()) {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const double value = std::strtod(text.c_str(), &end);
  if (errno != 0 || end == text.c_str() || *end != '\0' || !std::isfinite(value)) {
    return false;
  }
  *out = value;
  return true;
}

}  // namespace

bool parse_proxy_args(EngineRole role, int argc, char** argv, ProxyArgs* out,
                      std::string* error) {
  out->ec = EngineConfig{};
  out->ro = ReactorOptions{};
  out->help = false;
  out->version = false;
  out->notes.clear();

  std::map<std::string, std::string> opts;
  if (!CollectArgs(argc, argv, &opts, &out->help, error)) {
    return false;
  }
  // --version 先于 --key 校验：装完包自检 `fcp-proxy-server --version` 不该要求 PSK。
  out->version = Find(opts, "version") != nullptr;
  if (out->help || out->version) {
    return true;
  }
  const bool client = role == EngineRole::kClient;
  out->ro.role = role;

  const std::string* key = Find(opts, "key");
  if (key == nullptr || !ParseKey(*key, out->ec.key)) {
    *error = "--key=HEX32 (16 bytes as 32 hex digits) is required";
    return false;
  }
  if (const std::string* v = Find(opts, "mtu")) {
    // 256..65535: below that the codec has no room for even one symbol, above
    // it the value no longer fits the uint16 wire/field and would wrap.
    long n = 0;
    if (!ParseInt(*v, 256, 65535, &n)) {
      *error = "--mtu must be an integer in 256..65535 (IP packet bytes)";
      return false;
    }
    out->ec.mtu = static_cast<uint16_t>(n);
  }
  if (const std::string* v = Find(opts, "d")) {
    long n = 0;
    if (!ParseInt(*v, 1, 255, &n)) {
      *error = "--d must be an integer in 1..255";
      return false;
    }
    out->ec.d = static_cast<uint8_t>(n);
  }
  if (const std::string* v = Find(opts, "p")) {
    long n = 0;
    if (!ParseInt(*v, 0, 7, &n)) {
      *error = "--p must be an integer in 0..7";
      return false;
    }
    out->ec.p = static_cast<uint8_t>(n);
  }
  // P8-4: D + P <= 256 is a protocol hard limit (the symbol table index is
  // u8); each flag is in range above, but the pair can still be illegal. Fail
  // at startup instead of on every tunnel's first handshake.
  if (static_cast<uint16_t>(out->ec.d) + out->ec.p > 256) {
    *error = "--d + --p must not exceed 256 (got " +
             std::to_string(static_cast<unsigned>(out->ec.d)) + " + " +
             std::to_string(static_cast<unsigned>(out->ec.p)) + ")";
    return false;
  }
  if (const std::string* v = Find(opts, "p-max")) {
    long n = 0;
    if (!ParseInt(*v, 0, 7, &n)) {
      *error = "--p-max must be an integer in 0..7";
      return false;
    }
    out->ec.p_max = static_cast<uint8_t>(n);
  }
  if (const std::string* v = Find(opts, "k")) {
    long n = 0;
    if (!ParseInt(*v, -1, 7, &n)) {
      *error = "--k must be -1 (adaptive) or 0..7";
      return false;
    }
    out->ec.pinned_k = static_cast<int>(n);
  }
  if (const std::string* v = Find(opts, "fec-budget")) {
    double r = 0.0;
    // P6' N12: the controller's domain is R in [0,1] (0 = off). A value above
    // 1 used to pass and silently disable the cap (ratio can never exceed it).
    if (!ParseDouble(*v, &r) || r < 0.0 || r > 1.0) {
      *error = "--fec-budget must be a number in 0..1 (0 = off)";
      return false;
    }
    out->ec.fec_budget = r;
  }
  if (const std::string* v = Find(opts, "trace")) {
    out->ec.trace_prefix = *v;
  }
  if (const std::string* v = Find(opts, "window")) {
    long n = 0;
    if (!ParseInt(*v, 1, 1048576, &n)) {
      *error = "--window must be an integer in 1..1048576 KiB";
      return false;
    }
    out->ec.send_window_bytes = static_cast<size_t>(n) * 1024;
  }
  if (const std::string* v = Find(opts, "rcv-buf")) {
    long n = 0;
    if (!ParseInt(*v, 1, 1048576, &n)) {
      *error = "--rcv-buf must be an integer in 1..1048576 KiB";
      return false;
    }
    out->ec.rcv_buf_bytes = static_cast<size_t>(n) * 1024;
  }
  const bool auto_flag = Find(opts, "auto-window") != nullptr;
  if (const std::string* v = Find(opts, "auto-window"); v != nullptr && !v->empty()) {
    *error = "--auto-window takes no value; use --no-auto-window to disable";
    return false;
  }
  if (auto_flag && Find(opts, "no-auto-window") != nullptr) {
    *error = "--auto-window and --no-auto-window are mutually exclusive";
    return false;
  }
  if (auto_flag) {
    out->ec.auto_window = true;  // already the default; the flag is for explicit scripts
  }
  if (Find(opts, "no-auto-window") != nullptr) {
    out->ec.auto_window = false;
  }
  const bool cap_given = Find(opts, "window-cap") != nullptr;
  if (const std::string* v = Find(opts, "window-cap")) {
    long n = 0;
    // The engine's window floor is 64 KiB; a cap below it would be silently
    // raised, so reject it here instead. The ceiling is 4 MiB: the advertised
    // receive capacity is raised to the same value, so a 1 GiB cap would let
    // one connection promise 2 GiB of buffering (--max-sessions multiplies it).
    if (!ParseInt(*v, 64, 4096, &n)) {
      *error = "--window-cap must be an integer in 64..4096 KiB";
      return false;
    }
    out->ec.window_max_bytes = static_cast<size_t>(n) * 1024;
  }
  if (cap_given && !out->ec.auto_window) {
    *error = "--window-cap only applies to the adaptive window; "
             "drop --no-auto-window or remove it";
    return false;
  }
  if (out->ec.auto_window) {
    // Say out loud what the autotune overrides: these two flags look effective
    // in a command line but are clamped or raised by the window controller.
    if (out->ec.rcv_buf_bytes < out->ec.window_max_bytes) {
      out->notes.push_back(
          "[fcp] note: adaptive window raises the advertised receive capacity "
          "from --rcv-buf=" + std::to_string(out->ec.rcv_buf_bytes / 1024) +
          " KiB to --window-cap=" + std::to_string(out->ec.window_max_bytes / 1024) +
          " KiB per connection");
    }
    if (out->ec.send_window_bytes < out->ec.window_min_bytes) {
      out->notes.push_back(
          "[fcp] note: --window=" + std::to_string(out->ec.send_window_bytes / 1024) +
          " KiB is below the autotune floor, starting at " +
          std::to_string(out->ec.window_min_bytes / 1024) + " KiB");
    } else if (out->ec.send_window_bytes > out->ec.window_max_bytes) {
      out->notes.push_back(
          "[fcp] note: --window=" + std::to_string(out->ec.send_window_bytes / 1024) +
          " KiB is above the autotune ceiling, starting at " +
          std::to_string(out->ec.window_max_bytes / 1024) + " KiB");
    }
  }
  if (const std::string* v = Find(opts, "idle")) {
    long n = 0;
    if (!ParseInt(*v, 1, 86400000, &n)) {
      *error = "--idle must be an integer in 1..86400000 ms";
      return false;
    }
    out->ec.idle_timeout_ms = static_cast<int64_t>(n);
  }
  if (const std::string* v = Find(opts, "dial-timeout")) {
    long n = 0;
    if (!ParseInt(*v, 1, 600000, &n)) {
      *error = "--dial-timeout must be an integer in 1..600000 ms";
      return false;
    }
    out->ec.dial_timeout_ms = static_cast<int64_t>(n);
  }
  if (const std::string* v = Find(opts, "max-sessions")) {
    long n = 0;
    if (!ParseInt(*v, 1, 65536, &n)) {
      *error = "--max-sessions must be an integer in 1..65536";
      return false;
    }
    out->ec.max_sessions = static_cast<size_t>(n);
  }
  if (Find(opts, "no-prewarm") != nullptr) {
    out->ec.prewarm = false;
  }

  if (client) {
    const std::string* host = Find(opts, "host");
    if (host == nullptr || host->empty()) {
      *error = "--host=IP is required on the client";
      return false;
    }
    out->ro.remote_host = *host;
    if (const std::string* v = Find(opts, "port")) {
      long n = 0;
      if (!ParseInt(*v, 1, 65535, &n)) {
        *error = "--port must be an integer in 1..65535";
        return false;
      }
      out->ro.remote_port = static_cast<int>(n);
    }
    if (const std::string* v = Find(opts, "listen")) {
      out->ro.listen_addr = *v;
    }
    if (const std::string* v = Find(opts, "local-port")) {
      long n = 0;
      if (!ParseInt(*v, 1, 65535, &n)) {
        *error = "--local-port must be an integer in 1..65535";
        return false;
      }
      out->ro.listen_port = static_cast<int>(n);
    }
  } else {
    if (const std::string* v = Find(opts, "bind")) {
      out->ro.bind_addr = *v;
    }
    if (const std::string* v = Find(opts, "port")) {
      long n = 0;
      if (!ParseInt(*v, 1, 65535, &n)) {
        *error = "--port must be an integer in 1..65535";
        return false;
      }
      out->ro.bind_port = static_cast<int>(n);
    }
  }
  if (const std::string* v = Find(opts, "stats")) {
    long n = 0;
    if (!ParseInt(*v, 0, 86400000, &n)) {
      *error = "--stats must be an integer in 0..86400000 ms";
      return false;
    }
    out->ro.stats_ms = static_cast<int64_t>(n);
  }
  if (const std::string* v = Find(opts, "connect-timeout")) {
    long n = 0;
    if (!ParseInt(*v, 1, 600000, &n)) {
      *error = "--connect-timeout must be an integer in 1..600000 ms";
      return false;
    }
    out->ro.connect_timeout_ms = static_cast<int64_t>(n);
  }
  out->ro.verbose = Find(opts, "verbose") != nullptr;
  return true;
}

int run_proxy(EngineRole role, int argc, char** argv) {
  ProxyArgs args;
  std::string error;
  if (!parse_proxy_args(role, argc, argv, &args, &error)) {
    std::fprintf(stderr, "%s\n", error.c_str());
    Usage(role, argv[0]);
    return 1;
  }
  if (args.version) {
    std::printf("%s %s\n", role == EngineRole::kClient ? "fcp-proxy-client" : "fcp-proxy-server",
                kProductVersion);
    return 0;
  }
  if (args.help) {
    Usage(role, argv[0]);
    return 0;
  }
  for (const std::string& note : args.notes) {
    std::fprintf(stderr, "%s\n", note.c_str());
  }

  Reactor reactor(args.ec, args.ro);
  std::string startup_error;
  if (!reactor.start(&startup_error)) {
    std::fprintf(stderr, "startup failed: %s\n", startup_error.c_str());
    return 1;
  }
  reactor.run();
  return 0;
}

}  // namespace fcp
