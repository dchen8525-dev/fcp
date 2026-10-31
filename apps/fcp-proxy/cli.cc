#include "cli.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "fcp/session.h"
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

int64_t KiB(const std::string& v) { return static_cast<int64_t>(std::atoll(v.c_str())) * 1024; }

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
      "  --mtu=N              UDP payload budget (default 1400)\n"
      "  --d=N --p=N          frame geometry (default 10/3)\n"
      "  --k=N                pinned parity per set, -1 = adaptive (default -1)\n"
      "  --fec-budget=R       redundancy ceiling parity/data per report, 0 = off (default 0.5)\n"
      "  --trace=PREFIX       per-session controller trace JSONL (calibration)\n"
      "  --window=KiB         stream send window (default 256)\n"
      "  --rcv-buf=KiB        stream receive buffer (default 256)\n"
      "  --idle=ms            tunnel idle teardown (default 300000)\n"
      "  --dial-timeout=ms    remote resolve + connect budget (default 5000)\n"
      "  --max-sessions=N     concurrent sessions (default 256)\n"
      "  --no-prewarm         start every session cold (default: reuse link priors)\n"
      "  --stats=ms           print a stats line this often (default: only on exit)\n"
      "  -v                   per-connection protocol log\n");
}

bool CollectArgs(int argc, char** argv, std::map<std::string, std::string>* opts,
                 bool* help) {
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
    const size_t eq = arg.find('=');
    if (arg.rfind("--", 0) != 0) {
      std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
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

}  // namespace

int run_proxy(EngineRole role, int argc, char** argv) {
  std::map<std::string, std::string> opts;
  bool help = false;
  if (!CollectArgs(argc, argv, &opts, &help)) {
    Usage(role, argv[0]);
    return 1;
  }
  if (help) {
    Usage(role, argv[0]);
    return 0;
  }
  const bool client = role == EngineRole::kClient;

  EngineConfig ec;
  ec.role = role;
  const std::string* key = Find(opts, "key");
  if (key == nullptr || !ParseKey(*key, ec.key)) {
    std::fprintf(stderr, "--key=HEX32 (16 bytes as 32 hex digits) is required\n");
    return 1;
  }
  if (const std::string* v = Find(opts, "mtu")) {
    ec.mtu = static_cast<uint16_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "d")) {
    ec.d = static_cast<uint8_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "p")) {
    ec.p = static_cast<uint8_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "p-max")) {
    ec.p_max = static_cast<uint8_t>(std::atoi(v->c_str()));
  }
  if (const std::string* v = Find(opts, "k")) {
    ec.pinned_k = std::atoi(v->c_str());
  }
  if (const std::string* v = Find(opts, "fec-budget")) {
    ec.fec_budget = std::strtod(v->c_str(), nullptr);
  }
  if (const std::string* v = Find(opts, "trace")) {
    ec.trace_prefix = *v;
  }
  if (const std::string* v = Find(opts, "window")) {
    ec.send_window_bytes = static_cast<size_t>(KiB(*v));
  }
  if (const std::string* v = Find(opts, "rcv-buf")) {
    ec.rcv_buf_bytes = static_cast<size_t>(KiB(*v));
  }
  if (const std::string* v = Find(opts, "idle")) {
    ec.idle_timeout_ms = std::atoll(v->c_str());
  }
  if (const std::string* v = Find(opts, "dial-timeout")) {
    ec.dial_timeout_ms = std::atoll(v->c_str());
  }
  if (const std::string* v = Find(opts, "max-sessions")) {
    ec.max_sessions = static_cast<size_t>(std::atoll(v->c_str()));
  }
  if (Find(opts, "no-prewarm") != nullptr) {
    ec.prewarm = false;
  }

  ReactorOptions ro;
  ro.role = role;
  if (client) {
    const std::string* host = Find(opts, "host");
    if (host == nullptr || host->empty()) {
      std::fprintf(stderr, "--host=IP is required on the client\n");
      return 1;
    }
    ro.remote_host = *host;
    if (const std::string* v = Find(opts, "port")) {
      ro.remote_port = std::atoi(v->c_str());
    }
    if (const std::string* v = Find(opts, "listen")) {
      ro.listen_addr = *v;
    }
    if (const std::string* v = Find(opts, "local-port")) {
      ro.listen_port = std::atoi(v->c_str());
    }
  } else {
    if (const std::string* v = Find(opts, "bind")) {
      ro.bind_addr = *v;
    }
    if (const std::string* v = Find(opts, "port")) {
      ro.bind_port = std::atoi(v->c_str());
    }
  }
  if (const std::string* v = Find(opts, "stats")) {
    ro.stats_ms = std::atoll(v->c_str());
  }
  if (const std::string* v = Find(opts, "connect-timeout")) {
    ro.connect_timeout_ms = std::atoll(v->c_str());
  }
  ro.verbose = Find(opts, "verbose") != nullptr;

  Reactor reactor(ec, ro);
  std::string error;
  if (!reactor.start(&error)) {
    std::fprintf(stderr, "startup failed: %s\n", error.c_str());
    return 1;
  }
  reactor.run();
  return 0;
}

}  // namespace fcp
