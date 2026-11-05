#include "cli.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <netioapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "bench.h"
#include "cli_parse.h"
#include "fcp/frame_rx.h"
#include "fcp/frame_tx.h"
#include "fcp/session.h"
#include "fcp/version.h"
#include "reactor.h"

namespace fcp {
namespace {

// Period of `--log=stats` when no milliseconds are given.
constexpr int64_t kDefaultStatsMs = 10000;

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

// Reads a 32-hex-digit key from a file (the recommended spelling: an argument
// is visible in `ps`). Surrounding whitespace is dropped, so `openssl rand -hex
// 16 > psk` produces a usable file. The whole file is read: accepting a prefix
// of a longer file would silently ignore the rest (which, in a file that holds
// several keys, is the wrong key being used).
bool ParseKeyFile(const std::string& path, uint8_t out[16], std::string* error) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    *error = "--key-file: cannot open " + path + ": " + std::strerror(errno);
    return false;
  }
  // One key plus whitespace is nowhere near this; anything bigger is a sign
  // the wrong file was pointed at.
  char buf[4097] = {};
  const size_t got = std::fread(buf, 1, sizeof(buf) - 1, f);
  const bool read_ok = std::ferror(f) == 0;
  std::fclose(f);
  if (!read_ok) {
    *error = "--key-file: cannot read " + path;
    return false;
  }
  if (got == sizeof(buf) - 1) {
    *error = "--key-file: " + path + " is larger than " + std::to_string(sizeof(buf) - 1) +
             " bytes; it must hold exactly 32 hex digits (16 bytes)";
    return false;
  }
  std::string text(buf, got);
  const size_t first = text.find_first_not_of(" \t\r\n");
  const size_t last = text.find_last_not_of(" \t\r\n");
  text = first == std::string::npos ? std::string() : text.substr(first, last - first + 1);
  if (!ParseKey(text, out)) {
    *error = "--key-file: " + path + " must hold 32 hex digits (16 bytes) and nothing else";
    return false;
  }
  return true;
}

// Short spellings. Every one is rewritten to its long form before matching, so
// there is still exactly one code path per option. The list is deliberately
// small: the flags a startup command cannot avoid (key, address, port, MTU),
// not a second alphabet to learn. -h/-V/-v predate it and keep their meaning.
struct ShortOption {
  char flag;
  const char* long_name;
  bool takes_value;
};

constexpr ShortOption kShortOptions[] = {
    {'h', "--help", false},     {'V', "--version", false}, {'v', "--log=verbose", false},
    {'k', "--key-file", true},  {'H', "--host", true},     {'p', "--port", true},
    {'b', "--bind", true},      {'l', "--listen", true},    {'m', "--mtu", true},
};

const ShortOption* FindShortOption(char flag) {
  for (const ShortOption& option : kShortOptions) {
    if (option.flag == flag) {
      return &option;
    }
  }
  return nullptr;
}

// The accepted spellings of every option, in the order --help lists them.
// Compound forms (--window=START[:MAX], --fec=D:P) land in the EngineConfig
// fields their halves name. Matching is longest-prefix, so --key-env never
// collapses into --key, and --speedtest-seconds never into --speedtest.
const std::vector<tools::Alias>& OptionAliases() {
  static const std::vector<tools::Alias> kAliases = {
      {"--key", true},
      {"--key-file", true},
      {"--key-env", true},
      {"--host", true},
      {"--bind", true},
      {"--port", true},
      {"--listen", true},
      {"--local-port", true},
      {"--mtu", true},
      {"--pmtu-max", true},
      {"--fec", true},
      {"--p-max", true},
      {"--k", true},
      {"--fec-budget", true},
      {"--trace", true},
      {"--window", true},
      {"--rcv-buf", true},
      {"--no-auto-window", false},
      {"--no-pmtud", false},
      {"--no-window-probe", false},
      {"--no-bbr", false},
      {"--no-udp-gro", false},
      {"--bbr-version", true},
      {"--idle", true},
      {"--dial-timeout", true},
      {"--connect-timeout", true},
      {"--max-sessions", true},
      {"--speedtest", false},
      {"--speedtest-seconds", true},
      {"--stall-ms", true},
      {"--rate-limit", true},
      {"--no-prewarm", false},
      {"--log", true},
      {"--help", false},
      {"--version", false},
  };
  return kAliases;
}

void Usage(EngineRole role, const char* argv0) {
  const bool client = role == EngineRole::kClient;
  std::printf(
      "usage: %s %s\n"
      "  -k, --key-file=FILE  PSK file (recommended: keeps the key out of `ps`)\n"
      "  --key=HEX32          16-byte pre-shared key (one of --key/--key-file/\n"
      "                       --key-env; both ends equal)\n"
      "  --key-env=VAR        read the key from environment variable VAR (for the\n"
      "                       packaged unit: a DynamicUser cannot read a 0600\n"
      "                       file, but systemd hands the service its env)\n"
      "  Addresses also take ADDR:PORT, so one argument replaces the pair:\n"
      "  -H 203.0.113.7:40000 is --host=203.0.113.7 --port=40000.\n",
      argv0, client ? "[-H IP[:P]] [-l IP[:P]] [options]"
                    : "[-b IP[:P]] [options]");
  if (client) {
    std::printf("  -H, --host=IP[:P]    FCP server address (required); :P sets --port\n"
                "  -p, --port=N         FCP server UDP port (default 4460)\n"
                "  -l, --listen=IP[:P]  local proxy bind (default 127.0.0.1:1080);\n"
                "                       :P sets --local-port\n"
                "  --local-port=N       local proxy port (default 1080)\n"
                "  --speedtest          run one raw FCP link speed test against\n"
                "                       --host/--port and exit (no local proxy)\n"
                "  --speedtest-seconds=N  seconds per direction, 3..30 (default 8)\n");
  } else {
    std::printf("  -b, --bind=IP[:P]    UDP bind address (default 0.0.0.0):P sets\n"
                "                       --port; -b :40000 keeps 0.0.0.0:40000\n"
                "  -p, --port=N         UDP listen port (default 4460)\n"
                "  --speedtest          answer the desktop link speed test on the\n"
                "                       same UDP port (off by default; the test is\n"
                "                       PSK-authenticated like a tunnel)\n");
  }
  std::printf(
      "  -m, --mtu=N          IP packet budget incl. IP+UDP headers (default 1400;\n"
      "                       lowered to fit the largest local interface MTU)\n"
      "  --no-pmtud           do not probe upward past --mtu (PMTUD is on by\n"
      "                       default; both ends must support it)\n"
      "  --pmtu-max=N         largest IP packet PMTUD may prove, 1280..9000\n"
      "                       (default 1500; jumbo is a LAN property, ask for it)\n"
      "  --no-udp-gro         disable kernel UDP GRO receive aggregation (Linux\n"
      "                       only; on by default, dropped quietly if the kernel\n"
      "                       cannot)\n"
      "  --fec=D:P            frame geometry (default 10:3)\n"
      "  --p-max=N            controller parity ceiling 0..7 (default 4; the\n"
      "                       documented 5..7 range needs this raised)\n"
      "  --k=N                pinned parity per set, -1 = adaptive (default -1;\n"
      "                       must not exceed min(--fec P, --p-max))\n"
      "  --fec-budget=R       redundancy ceiling parity/data per report, 0 = off (default 0.5)\n"
      "  --trace=PREFIX       per-session controller trace JSONL (calibration)\n"
      "  --window=START[:MAX] send window KiB; autotune start + ceiling\n"
      "                       (default 256:1024; START 64..4096 in autotune --\n"
      "                       the floor rises with --mtu above ~2 KiB, and the\n"
      "                       error names the value -- 1..1048576 fixed, but\n"
      "                       not below two segments at this --mtu). An empty\n"
      "                       START keeps the default start and the prewarm\n"
      "                       prior: --window=:4096 pins only the ceiling\n"
      "                       (default: the adaptive ceiling follows the\n"
      "                       measured BDP up to 4096 KiB -- a 1 MiB cap holds\n"
      "                       a 200 ms path to ~40 Mbps)\n"
      "  --no-auto-window     fixed --window instead of autotune (autotune is\n"
      "                       the default)\n"
      "  --no-bbr             use the epoch controller (slow start/AIMD) instead\n"
      "                       of BBR; BBR is the default\n"
      "  --bbr-version=N      1 = BBRv1 (loss is not congestion evidence),\n"
      "                       2 = BBRv2 (default: learns inflight_hi/lo from\n"
      "                       stream loss on top of v1; see #51)\n"
      "  --no-window-probe    disable the loss-epoch growth probe (epoch\n"
      "                       controller only; the probe is on by default)\n"
      "  --rcv-buf=KiB        fixed-mode receive buffer (default: the fixed\n"
      "                       --window, at least 256; --no-auto-window only)\n"
      "  --idle=ms            tunnel idle teardown (default 300000)\n"
      "  --dial-timeout=ms    whole-dial budget: resolve + every connect\n"
      "                       attempt (default 5000)\n"
      "  --connect-timeout=ms per-address TCP connect budget (default 5000)\n"
      "  --max-sessions=N     concurrent sessions (default 256; warns when the fd\n"
      "                       or address-space limit cannot cover the worst case)\n"
      "  --rate-limit=UP[:DOWN]  Mbps send shaping (0 = off); the client enforces\n"
      "                       UP, the server enforces DOWN -- each end shapes the\n"
      "                       direction it sends, inapplicable half is a setting\n"
      "                       for the other end\n"
      "  --stall-ms=N         client dead-path watchdog: log a stall when TX\n"
      "                       keeps moving but nothing comes back for N ms\n"
      "                       (0 = off, default 60000)\n"
      "  --no-prewarm         start every session cold (default: reuse RTT/k/window priors)\n"
      "  --log=LEVEL          off (default; exit summary only) |\n"
      "                       stats[:ms] (periodic line) | verbose\n"
      "  -v                   shorthand for --log=verbose\n"
      "  -h, --help           this text; -V, --version prints the build and exits\n");
}

// --window=START[:MAX]. 0 in either field means "not given" (the parsers never
// accept a 0), which is also how an empty START is expressed: ":4096" pins the
// ceiling and leaves the start to the default/prewarm prior.
struct ParsedWindows {
  size_t start = 0;
  size_t ceiling = 0;
};

// START and MAX have different domains: MAX is autotune-only and bounded to
// 64..4096 KiB (below that the engine would silently raise it; above it one
// connection could promise 4+ GiB, times --max-sessions). START is also a
// fixed-mode window, which has always accepted up to 1 GiB, so its narrow
// 64..4096 autotune range is enforced later, once --no-auto-window is known.
bool ParseWindowValue(const std::string& flag, const std::string& value, ParsedWindows* w,
                      std::string* error) {
  const std::string what = "--" + flag + " must be START, START:MAX or :MAX; START 1..1048576 "
                                        "KiB and MAX 64..4096 KiB (got '" + value + "')";
  const std::vector<std::string> parts = tools::SplitFields(value);
  if (parts.size() > 2 || (parts.size() == 2 && parts[1].empty())) {
    *error = what;
    return false;
  }
  if (!parts[0].empty()) {
    long start = 0;
    const std::string flag_start = "--" + flag;
    if (!tools::ParseLong(flag_start.c_str(), parts[0].c_str(), 1, 1048576, &start, error)) {
      return false;
    }
    w->start = static_cast<size_t>(start);
  }
  if (parts.size() == 2) {
    long ceiling = 0;
    const std::string flag_max = "--" + flag + " (MAX)";
    if (!tools::ParseLong(flag_max.c_str(), parts[1].c_str(), 64, 4096, &ceiling, error)) {
      return false;
    }
    w->ceiling = static_cast<size_t>(ceiling);
  }
  if (w->start == 0 && w->ceiling == 0) {
    *error = what;  // "--window=" or "--window=:"
    return false;
  }
  return true;
}

// One option that takes a value: whether it was given, and the text. The text
// is copied rather than pointed at: the caller must not depend on the lifetime
// of the vector the matches live in.
struct SeenValue {
  bool given = false;
  std::string value;
};

// Which option groups the command line set.
struct ProxyFlags {
  SeenValue key;
  SeenValue key_file;
  SeenValue key_env;
  SeenValue host;
  SeenValue bind;
  SeenValue port;
  SeenValue listen;
  SeenValue local_port;
  SeenValue trace;
  SeenValue idle;
  SeenValue dial_timeout;
  SeenValue connect_timeout;
  SeenValue max_sessions;
  bool speedtest = false;
  SeenValue speedtest_seconds;
  SeenValue stall_ms;
  SeenValue rate_limit;
  SeenValue log;
  SeenValue rcv_buf;
  SeenValue fec_budget;
  SeenValue p_max;
  SeenValue k;
  SeenValue mtu;
  SeenValue pmtu_max;
  bool pmtud_off = false;
  bool prewarm_off = false;
  bool no_auto_window = false;
  bool no_window_probe = false;
  bool no_bbr = false;
  bool no_udp_gro = false;
  SeenValue bbr_version;
};

// Applies one matched argument's value. Numbers whose range is a property of
// the field are parsed here (so the diagnostic names the flag the user typed);
// everything that needs more than one option to decide is left to
// parse_proxy_args, which runs once every group is known.
bool ApplyValue(const tools::Match& m, ProxyFlags* f, ParsedWindows* windows, ProxyArgs* out,
                std::string* error) {
  const std::string& name = m.name;
  const std::string& v = m.value;
  long n = 0;
  if (name == "--key") {
    f->key = {true, v};
  } else if (name == "--key-file") {
    f->key_file = {true, v};
  } else if (name == "--key-env") {
    f->key_env = {true, v};
  } else if (name == "--host") {
    f->host = {true, v};
  } else if (name == "--bind") {
    f->bind = {true, v};
  } else if (name == "--port") {
    f->port = {true, v};
  } else if (name == "--listen") {
    f->listen = {true, v};
  } else if (name == "--local-port") {
    f->local_port = {true, v};
  } else if (name == "--trace") {
    f->trace = {true, v};
  } else if (name == "--idle") {
    f->idle = {true, v};
  } else if (name == "--dial-timeout") {
    f->dial_timeout = {true, v};
  } else if (name == "--connect-timeout") {
    f->connect_timeout = {true, v};
  } else if (name == "--max-sessions") {
    f->max_sessions = {true, v};
  } else if (name == "--speedtest") {
    f->speedtest = true;
  } else if (name == "--speedtest-seconds") {
    f->speedtest_seconds = {true, v};
  } else if (name == "--stall-ms") {
    f->stall_ms = {true, v};
  } else if (name == "--rate-limit") {
    f->rate_limit = {true, v};
  } else if (name == "--log") {
    f->log = {true, v};
  } else if (name == "--rcv-buf") {
    f->rcv_buf = {true, v};
  } else if (name == "--fec-budget") {
    f->fec_budget = {true, v};
  } else if (name == "--p-max") {
    f->p_max = {true, v};
  } else if (name == "--k") {
    f->k = {true, v};
  } else if (name == "--mtu") {
    f->mtu = {true, v};
  } else if (name == "--pmtu-max") {
    f->pmtu_max = {true, v};
  } else if (name == "--no-pmtud") {
    f->pmtud_off = true;
  } else if (name == "--no-prewarm") {
    f->prewarm_off = true;
  } else if (name == "--no-auto-window") {
    f->no_auto_window = true;
  } else if (name == "--no-window-probe") {
    f->no_window_probe = true;
  } else if (name == "--no-bbr") {
    f->no_bbr = true;
  } else if (name == "--no-udp-gro") {
    f->no_udp_gro = true;
  } else if (name == "--bbr-version") {
    f->bbr_version = {true, v};
  } else if (name == "--fec") {
    const std::vector<std::string> parts = tools::SplitFields(v);
    if (parts.size() > 2) {
      *error = "--fec takes D or D:P (got '" + v + "')";
      return false;
    }
    if (!tools::ParseLong("--fec D", parts[0].c_str(), 1, 255, &n, error)) {
      return false;
    }
    out->ec.d = static_cast<uint8_t>(n);
    if (parts.size() == 2) {
      if (parts[1].empty()) {
        *error = "--fec takes D or D:P (got '" + v + "')";
        return false;
      }
      if (!tools::ParseLong("--fec P", parts[1].c_str(), 0, 7, &n, error)) {
        return false;
      }
      out->ec.p = static_cast<uint8_t>(n);
    }
  } else if (name == "--window") {
    if (!ParseWindowValue(name.substr(2), v, windows, error)) {
      return false;
    }
  } else {
    *error = "internal: unhandled option " + name;
    return false;
  }
  return true;
}

// "ADDR:PORT" -> address + port, so one argument replaces the pair. The tunnel
// socket is AF_INET, so an address with several colons is an IPv6 literal (or a
// typo) and is left as the whole address; a non-numeric tail is equally not a
// port. An empty address ("--bind=:40000") means "keep the default address".
bool SplitAddressPort(const std::string& text, std::string* address, std::string* port) {
  // Exactly one colon: an IPv6 literal ("::1", "[::1]:4000") has more than one
  // and must stay a single address, or it would be split into a nonsense host
  // plus a bogus port and reported as "port given twice".
  const size_t colon = text.find(':');
  if (colon == std::string::npos || colon != text.rfind(':') || colon + 1 == text.size()) {
    return false;
  }
  const std::string tail = text.substr(colon + 1);
  for (const char c : tail) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  *address = text.substr(0, colon);
  *port = tail;
  return true;
}

bool ApplyHostPort(EngineRole role, const ProxyFlags& f, ProxyArgs* out, std::string* error) {
  const bool client = role == EngineRole::kClient;
  long n = 0;
  // The address options carry an optional :PORT. Resolving it here (rather
  // than each option on its own) keeps one rule: a port may come from --port
  // or from an address, and two sources are an ambiguity, not an override.
  std::string host = f.host.given ? f.host.value : std::string();
  std::string host_port;
  const bool host_has_port = f.host.given && SplitAddressPort(f.host.value, &host, &host_port);
  std::string bind = f.bind.given ? f.bind.value : std::string();
  std::string bind_port;
  const bool bind_has_port = f.bind.given && SplitAddressPort(f.bind.value, &bind, &bind_port);
  const std::string* compound_port = host_has_port ? &host_port : (bind_has_port ? &bind_port : nullptr);
  if (f.port.given) {
    if (compound_port != nullptr) {
      *error = "the port is given twice: --port and the address suffix; drop one";
      return false;
    }
    if (!tools::ParseLong("--port", f.port.value.c_str(), 1, 65535, &n, error)) {
      return false;
    }
    if (client) {
      out->ro.remote_port = static_cast<int>(n);
    } else {
      out->ro.bind_port = static_cast<int>(n);
    }
  } else if (compound_port != nullptr) {
    // Name the option the operator typed, not the port half of it.
    const char* flag = host_has_port ? "--host" : "--bind";
    if (!tools::ParseLong(flag, compound_port->c_str(), 1, 65535, &n, error)) {
      return false;
    }
    if (client) {
      out->ro.remote_port = static_cast<int>(n);
    } else {
      out->ro.bind_port = static_cast<int>(n);
    }
  }
  if (client) {
    if (!f.host.given || host.empty()) {
      *error = "--host=IP[:PORT] is required on the client";
      return false;
    }
    out->ro.remote_host = host;
    if (f.bind.given) {
      *error = "--bind is a server option; the client listens with --listen";
      return false;
    }
    if (f.listen.given && f.listen.value.empty()) {
      *error = "--listen needs an address (default 127.0.0.1)";
      return false;
    }
  } else {
    if (f.host.given) {
      *error = "--host is a client option; the server binds with --bind";
      return false;
    }
    if (f.listen.given || f.local_port.given) {
      *error = "--listen/--local-port are client options; the server only binds UDP";
      return false;
    }
    if (f.bind.given) {
      if (!bind_has_port && bind.empty()) {
        *error = "--bind needs an address (default 0.0.0.0)";
        return false;
      }
      if (!bind.empty()) {
        out->ro.bind_addr = bind;
      }
    }
  }
  return true;
}

// --log=off | stats[:ms] | verbose. `off` keeps the default of no periodic
// line (exit summary only); `stats` without a period uses kDefaultStatsMs.
bool ApplyLog(const std::string& value, ProxyArgs* out, std::string* error) {
  if (value == "off") {
    out->ro.stats_ms = 0;
    return true;
  }
  if (value == "verbose") {
    out->ro.verbose = true;
    return true;
  }
  if (value == "stats") {
    out->ro.stats_ms = kDefaultStatsMs;
    return true;
  }
  if (value.rfind("stats:", 0) == 0) {
    long n = 0;
    if (!tools::ParseLong("--log=stats", value.c_str() + 6, 1, 86400000, &n, error)) {
      return false;
    }
    out->ro.stats_ms = static_cast<int64_t>(n);
    return true;
  }
  *error = "--log must be off, stats[:ms] or verbose (got '" + value + "')";
  return false;
}

// One accepted or dialed TCP socket per tunnel; the UDP sockets are fixed.
constexpr size_t kReservedFds = 32;
constexpr size_t kPerSessionBookkeepingBytes = 64 * 1024;

ResourceLimits CurrentResourceLimits() {
  ResourceLimits limits;
#ifndef _WIN32
  struct rlimit rl {};
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
    limits.open_files = static_cast<long>(rl.rlim_cur);
  }
  if (getrlimit(RLIMIT_AS, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
    limits.address_space = static_cast<long>(rl.rlim_cur);
  }
#endif
  return limits;
}

// MTU of the largest up, non-loopback IPv4 interface. 0 = unknown. The largest
// (not the smallest) is deliberate: an unbound listener has no route yet, and
// a VPN adapter at 1280 next to eth0 at 1500 must not tax every LAN client.
// Hosts that really do reach this process over a lower-MTU interface pass
// --mtu. Only the startup default is adjusted; an explicit --mtu wins.
size_t InterfaceMtu() {
#ifdef _WIN32
  ULONG buf_len = 15 * 1024;
  std::vector<uint8_t> buf(buf_len);
  IP_ADAPTER_ADDRESSES* list = nullptr;
  ULONG rc = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
    list = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    rc = GetAdaptersAddresses(AF_INET,
                              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER,
                              nullptr, list, &buf_len);
    if (rc == ERROR_BUFFER_OVERFLOW) {
      buf.resize(buf_len);
    }
  }
  if (rc != NO_ERROR) {
    return 0;
  }
  size_t best = 0;
  for (IP_ADAPTER_ADDRESSES* a = list; a != nullptr; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = a->Luid;
    if (GetIfEntry2(&row) != NO_ERROR || row.Mtu == 0) {
      continue;
    }
    if (row.Mtu > best) {
      best = row.Mtu;
    }
  }
  return best;
#else
  struct ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return 0;
  }
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  size_t best = 0;
  for (struct ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
    if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET ||
        a->ifa_name == nullptr || fd < 0) {
      continue;
    }
    if ((a->ifa_flags & IFF_UP) == 0 || (a->ifa_flags & IFF_LOOPBACK) != 0) {
      continue;
    }
    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, a->ifa_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
      continue;
    }
    const size_t mtu = static_cast<size_t>(ifr.ifr_mtu);
    if (mtu > best) {
      best = mtu;
    }
  }
  if (fd >= 0) {
    close(fd);
  }
  freeifaddrs(list);
  return best;
#endif
}

void ApplyEnvironmentDefaults(ProxyArgs* args) {
  // Always: even with an explicit --mtu this has to look at the interface, to
  // turn PMTUD (and with it DF) off when the explicit size cannot leave the
  // host at all.
  ApplyInterfaceMtu(InterfaceMtu(), args);
  const ResourceLimits limits = CurrentResourceLimits();
  const std::vector<std::string> notes = ResourceNotes(args->ec.role, args->ec, limits);
  args->notes.insert(args->notes.end(), notes.begin(), notes.end());
}

std::string JsonEscape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (unsigned char c : in) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

std::string BenchSampleJson(const bench::Sample& s) {
  // "wireMbps" is the sender's best one-second offered (framer) rate; "mbps"
  // is the receiver's best one-second delivered rate, post-FEC and post-dedup.
  // The gap between them is FEC redundancy plus whatever the direction lost.
  const double wire_mbps = static_cast<double>(s.wire_bps) / 1e6;
  char buf[320];
  std::snprintf(buf, sizeof(buf),
                "{\"mbps\":%.2f,\"wireMbps\":%.2f,\"bytes\":%llu,\"lostBytes\":%llu,"
                "\"seconds\":%.2f,\"acked\":%s,\"lossPpm\":%u,\"lossN\":%u}",
                std::isfinite(s.mbps) ? s.mbps : 0.0,
                std::isfinite(wire_mbps) ? wire_mbps : 0.0,
                static_cast<unsigned long long>(s.bytes),
                static_cast<unsigned long long>(s.lost_bytes), s.seconds,
                s.acked ? "true" : "false", s.loss_ppm, s.loss_n);
  return buf;
}

// One-shot client bench. Everything the desktop reads is one JSON object per
// line prefixed with "@speedtest"; regular diagnostics stay on stderr so the
// stdout reader never has to guess.
int RunBench(const ProxyArgs& args) {
  bench::ClientOptions opt;
  opt.host = args.ro.remote_host;
  opt.port = static_cast<uint16_t>(args.ro.remote_port);
  std::memcpy(opt.key, args.ec.key, sizeof(opt.key));
  opt.seconds = static_cast<uint16_t>(args.speedtest_seconds);
  opt.mtu = args.ec.mtu;
  opt.ip_hdr_len = args.ec.ip_hdr_len;

  auto progress = [](const char* direction, uint64_t bytes, int64_t elapsed_ms) {
    std::printf(
        "@speedtest {\"event\":\"progress\",\"direction\":\"%s\",\"bytes\":%llu,"
        "\"elapsedMs\":%lld}\n",
        direction, static_cast<unsigned long long>(bytes),
        static_cast<long long>(elapsed_ms));
    std::fflush(stdout);
  };

  bench::Result result;
  bench::RunClient(opt, progress, &result);
  std::string json = "{\"event\":\"done\",\"seconds\":";
  json += std::to_string(args.speedtest_seconds);
  json += ",\"download\":";
  json += result.have_download ? BenchSampleJson(result.download) : "null";
  json += ",\"upload\":";
  json += result.have_upload ? BenchSampleJson(result.upload) : "null";
  json += ",\"setupMs\":";
  json += std::to_string(result.setup_ms);
  json += ",\"rttN\":";
  json += std::to_string(result.rtt.n);
  json += ",\"rttMinMs\":";
  json += std::to_string(result.rtt.min_ms);
  json += ",\"rttAvgMs\":";
  json += std::to_string(result.rtt.avg_ms);
  json += ",\"rttMaxMs\":";
  json += std::to_string(result.rtt.max_ms);
  json += ",\"error\":";
  json += result.error.empty() ? "null" : "\"" + JsonEscape(result.error) + "\"";
  json += "}";
  std::printf("@speedtest %s\n", json.c_str());
  std::fflush(stdout);
  if (!result.error.empty()) {
    std::fprintf(stderr, "speedtest: %s\n", result.error.c_str());
  }
  return result.have_download ? 0 : 2;
}

}  // namespace

uint16_t MtuForInterface(uint16_t configured, size_t interface_mtu) {
  // Both values are the same unit: the size of one IP packet. `configured`
  // already includes the IP+UDP headers (compute_mtu_limits() subtracts them
  // when deriving the payload), and SIOCGIFMTU/GetIfEntry2 report the largest
  // IP packet on the interface, so subtracting the headers a second time here
  // would silently give up 28 usable bytes.
  // Below 256 the codec cannot frame a symbol; leave the configured value and
  // let the engine's own validation explain the failure.
  if (interface_mtu < 256 || interface_mtu >= configured) {
    return configured;
  }
  return static_cast<uint16_t>(interface_mtu);
}

void ApplyInterfaceMtu(size_t interface_mtu, ProxyArgs* args) {
  const uint16_t adjusted = MtuForInterface(args->ec.mtu, interface_mtu);
  if (adjusted >= args->ec.mtu) {
    // A larger (or unqueryable) interface leaves both values alone: probing
    // from the configured MTU up to --pmtu-max is exactly the point.
    return;
  }
  if (args->mtu_explicit) {
    // The operator asked for more than this host's largest interface can carry.
    // That used to still work -- without DF the kernel fragments the datagram
    // -- but PMTUD now sets DF on the whole tunnel socket, and with DF every
    // send of that size comes back EMSGSIZE: handshake and data both black-hole.
    // Keep the explicit MTU (the operator may know the path better than the
    // interface table) and give up PMTUD instead, which also leaves DF off, so
    // the kernel fragments exactly as it did before.
    if (args->ec.pmtud) {
      args->ec.pmtud = false;
      args->notes.push_back(
          "[fcp] note: --mtu " + std::to_string(args->ec.mtu) +
          " exceeds the largest local interface MTU " + std::to_string(interface_mtu) +
          "; PMTUD disabled (DF would make every datagram EMSGSIZE), "
          "the kernel will fragment instead");
    }
    return;
  }
  args->notes.push_back("[fcp] note: MTU lowered to " + std::to_string(adjusted) +
                        " bytes (default " + std::to_string(args->ec.mtu) +
                        ") to fit the largest local interface MTU " +
                        std::to_string(interface_mtu) + " (IP+UDP headers included)");
  args->ec.mtu = adjusted;
  // A probe above the local interface can only produce EMSGSIZE: the kernel
  // refuses to hand the datagram to the interface at all.
  if (args->ec.pmtu_max_mtu > adjusted) {
    args->ec.pmtu_max_mtu = adjusted;
  }
}

std::vector<std::string> ResourceNotes(EngineRole role, const EngineConfig& ec,
                                       const ResourceLimits& limits) {
  (void)role;  // both ends hold one tunnel socket per session
  std::vector<std::string> notes;
  const uint64_t needed_fds =
      static_cast<uint64_t>(ec.max_sessions) + static_cast<uint64_t>(kReservedFds);
  if (limits.open_files > 0 &&
      needed_fds > static_cast<uint64_t>(limits.open_files)) {
    notes.push_back("[fcp] warning: --max-sessions=" + std::to_string(ec.max_sessions) +
                    " needs about " + std::to_string(needed_fds) +
                    " file descriptors (one per tunnel plus " +
                    std::to_string(kReservedFds) + " reserved), but the process limit is " +
                    std::to_string(limits.open_files) +
                    "; sessions beyond it will fail to open");
  }
  // Worst-case buffers, not reserved up front: the receive capacity the window
  // promises plus the window the sender may grow into.
  // The auto ceiling (window_ceiling_bytes) is a per-session possibility, so
  // the worst case has to use it, not the configured MAX.
  const size_t win_ceiling =
      std::max(ec.window_max_bytes, ec.window_ceiling_bytes);
  const size_t rcv_cap = ec.auto_window ? (ec.rcv_buf_bytes > win_ceiling ? ec.rcv_buf_bytes
                                                                          : win_ceiling)
                                        : ec.rcv_buf_bytes;
  const size_t send_cap = ec.auto_window ? win_ceiling : ec.send_window_bytes;
  // FrameRx holds the symbols of the sets it has not decoded yet. A working
  // session's symbol buffer tracks the data in flight, so it is estimated at
  // rcv+send window; the hard ceiling kMaxRxSymbolBytes (which an adversarial
  // peer can reach with 256 incomplete sets) is the bound the kernel enforces,
  // not what every healthy session costs. Leaving both out understated a wide
  // window by an order of magnitude.
  const size_t rx_symbols =
      std::min<size_t>(kMaxRxSymbolBytes, rcv_cap + send_cap);
  const uint64_t per_session = static_cast<uint64_t>(rcv_cap) +
                               static_cast<uint64_t>(send_cap) +
                               static_cast<uint64_t>(rx_symbols) +
                               static_cast<uint64_t>(kPerSessionBookkeepingBytes);
  const uint64_t total = per_session * static_cast<uint64_t>(ec.max_sessions);
  if (limits.address_space > 0) {
    const uint64_t limit = static_cast<uint64_t>(limits.address_space);
    if (total > limit / 4 * 3) {
      notes.push_back("[fcp] warning: --max-sessions=" + std::to_string(ec.max_sessions) +
                      " with this window can hold about " +
                      std::to_string(total / (1024 * 1024)) +
                      " MiB of stream buffers (worst case, committed as connections "
                      "arrive); the address-space limit is " +
                      std::to_string(limit / (1024 * 1024)) + " MiB");
    }
  }
  return notes;
}

bool parse_proxy_args(EngineRole role, int argc, char** argv, ProxyArgs* out,
                      std::string* error) {
  out->ec = EngineConfig{};
  out->ro = ReactorOptions{};
  out->help = false;
  out->version = false;
  out->mtu_explicit = false;
  out->notes.clear();
  // Placeholder fallbacks below test error->empty(); a caller that reuses the
  // same string must not see a previous failure's text.
  if (error != nullptr) {
    error->clear();
  }

  // Both halves, always: the engine decides who births a session (EngineConfig
  // defaults to kClient, so a server that forgets this listens, prints
  // "server: fcp on", and then drops every HELLO as unknown_salt), the reactor
  // decides which sockets exist.
  out->ec.role = role;
  out->ro.role = role;

  // Pass 1: match every argument and reject ambiguous command lines. Values are
  // not touched yet, so --help/--version win over an invalid value elsewhere in
  // a long scripted command line -- and `--version` never needs a PSK, which is
  // what the package self-test relies on.
  std::vector<tools::Match> matched;
  std::vector<std::string> seen;
  std::string key_spelling;
  matched.reserve(static_cast<size_t>(argc));
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    // Short spellings are rewritten to their long form: one code path per
    // option. A value option takes the next argument ("-k psk") or an attached
    // one ("-k=psk", "-kpsk"), so a short command stays short.
    if (arg.size() >= 2 && arg[0] == '-' && arg[1] != '-') {
      const ShortOption* option = FindShortOption(arg[1]);
      if (option == nullptr) {
        *error = "unknown argument: " + arg;
        return false;
      }
      std::string rest = arg.substr(2);
      if (!option->takes_value) {
        if (!rest.empty()) {
          *error = std::string("-") + option->flag + " takes no value; got '" + arg + "'";
          return false;
        }
        arg = option->long_name;
      } else {
        std::string value;
        if (!rest.empty()) {
          value = rest[0] == '=' ? rest.substr(1) : rest;
        } else if (i + 1 < argc) {
          value = argv[++i];
        } else {
          *error = std::string("-") + option->flag + " (" + option->long_name +
                   ") requires a value";
          return false;
        }
        if (value.empty()) {
          *error = std::string("-") + option->flag + " (" + option->long_name +
                   ") requires a value";
          return false;
        }
        arg = std::string(option->long_name) + "=" + value;
      }
    }
    if (arg.rfind("--", 0) != 0) {
      *error = "unknown argument: " + arg;
      return false;
    }
    tools::Match m;
    if (!tools::MatchOption(OptionAliases(), arg, &m, error)) {
      return false;
    }
    const std::string name = m.name;
    if (name == "--help" || name == "--version") {
      (name == "--help" ? out->help : out->version) = true;
      matched.push_back(std::move(m));
      continue;
    }
    // Duplicate detection is per option group, not per spelling: --key,
    // --key-file and --key-env are one setting. -v is rewritten to
    // --log=verbose, so it shares that group too.
    const char* group = name.c_str() + 2;
    const bool key_option =
        name == "--key" || name == "--key-file" || name == "--key-env";
    if (key_option) {
      group = "key";
    }
    if (!tools::MarkSeen(&seen, group, error)) {
      if (key_option) {
        *error = key_spelling == name
                     ? name + " given more than once"
                     : std::string("--key, --key-file and --key-env are alternatives; "
                                   "give one of them");
      }
      return false;
    }
    if (key_option) {
      key_spelling = name;
    }
    matched.push_back(std::move(m));
  }
  if (out->help || out->version) {
    return true;
  }

  // Pass 2: apply the values, in command-line order.
  ProxyFlags given;
  ParsedWindows windows;
  for (const tools::Match& m : matched) {
    if (m.name == nullptr || std::strcmp(m.name, "--help") == 0 ||
        std::strcmp(m.name, "--version") == 0) {
      continue;
    }
    if (!ApplyValue(m, &given, &windows, out, error)) {
      return false;
    }
  }

  // The three key sources share the "key" group, so giving two already failed
  // pass 1 with "given more than once".
  if (given.key_file.given) {
    if (!ParseKeyFile(given.key_file.value, out->ec.key, error)) {
      return false;
    }
  } else if (given.key_env.given) {
    // A DynamicUser unit cannot read a root-owned 0600 file, but systemd reads
    // EnvironmentFile as the manager and passes the variables to the service,
    // where only the service user (and root) can read /proc/<pid>/environ.
    // That makes an environment variable the one key source the packaged unit
    // can use without loosening /etc/fcp's permissions or switching user model.
    if (given.key_env.value.empty()) {
      *error = "--key-env requires an environment variable name";
      return false;
    }
    const char* value = std::getenv(given.key_env.value.c_str());
    if (value == nullptr) {
      *error = "--key-env: environment variable " + given.key_env.value + " is not set";
      return false;
    }
    if (!ParseKey(value, out->ec.key)) {
      // Never echo the value: it is the secret.
      *error = "--key-env: " + given.key_env.value +
               " must hold 32 hex digits (16 bytes) and nothing else";
      return false;
    }
  } else if (given.key.given) {
    out->key_in_argv = true;
    if (!ParseKey(given.key.value, out->ec.key)) {
      *error = given.key.value.size() == 32
                   ? "--key must contain only hex digits (0-9, a-f)"
                   : "--key must be 32 hex digits (16 bytes), got " +
                         std::to_string(given.key.value.size()) + " characters";
      return false;
    }
  } else {
    *error = "--key=HEX32, --key-file=FILE or --key-env=VAR is required";
    return false;
  }

  // --connect-timeout is the per-address TCP budget inside the engine's
  // whole-dial --dial-timeout (reactor.cc sets each attempt's deadline from
  // it); a name with more than one address may spend it per record. It is not
  // merged into --dial-timeout because the two bound different levels.
  if (given.connect_timeout.given) {
    long n = 0;
    if (!tools::ParseLong("--connect-timeout", given.connect_timeout.value.c_str(), 1, 600000,
                          &n, error)) {
      return false;
    }
    out->ro.connect_timeout_ms = static_cast<int64_t>(n);
  }

  if (given.mtu.given) {
    // 256..65535: below that the codec has no room for even one symbol, above
    // it the value no longer fits the uint16 wire/field and would wrap.
    long n = 0;
    if (!tools::ParseLong("--mtu", given.mtu.value.c_str(), 256, 65535, &n, error)) {
      return false;
    }
    out->ec.mtu = static_cast<uint16_t>(n);
    out->mtu_explicit = true;
  }
  if (given.pmtu_max.given) {
    long n = 0;
    if (!tools::ParseLong("--pmtu-max", given.pmtu_max.value.c_str(), 1280, 9000, &n,
                          error)) {
      return false;
    }
    out->ec.pmtu_max_mtu = static_cast<uint16_t>(n);
  }
  // A ceiling below the starting MTU means "never probe upward": the ladder
  // only climbs. This also covers --mtu 9000 with the default 1500 ceiling.
  if (out->ec.pmtu_max_mtu < out->ec.mtu) {
    out->ec.pmtu_max_mtu = out->ec.mtu;
  }
  if (given.p_max.given) {
    long n = 0;
    if (!tools::ParseLong("--p-max", given.p_max.value.c_str(), 0, 7, &n, error)) {
      return false;
    }
    out->ec.p_max = static_cast<uint8_t>(n);
  }
  if (given.k.given) {
    long n = 0;
    if (!tools::ParseLong("--k", given.k.value.c_str(), -1, 7, &n, error)) {
      return false;
    }
    out->ec.pinned_k = static_cast<int>(n);
  }
  if (given.fec_budget.given) {
    // P6' N12: the controller's domain is R in [0,1] (0 = off). A value above
    // 1 used to pass and silently disable the cap (the ratio can never exceed it).
    double r = 0.0;
    if (!tools::ParseDouble("--fec-budget", given.fec_budget.value.c_str(), 0.0, 1.0, &r,
                            error)) {
      return false;
    }
    out->ec.fec_budget = r;
  }
  if (given.trace.given) {
    out->ec.trace_prefix = given.trace.value;
  }
  if (given.idle.given) {
    long n = 0;
    if (!tools::ParseLong("--idle", given.idle.value.c_str(), 1, 86400000, &n, error)) {
      return false;
    }
    out->ec.idle_timeout_ms = static_cast<int64_t>(n);
  }
  if (given.dial_timeout.given) {
    long n = 0;
    if (!tools::ParseLong("--dial-timeout", given.dial_timeout.value.c_str(), 1, 600000, &n,
                          error)) {
      return false;
    }
    out->ec.dial_timeout_ms = static_cast<int64_t>(n);
  }
  if (given.max_sessions.given) {
    long n = 0;
    if (!tools::ParseLong("--max-sessions", given.max_sessions.value.c_str(), 1, 65536, &n,
                          error)) {
      return false;
    }
    out->ec.max_sessions = static_cast<size_t>(n);
  }
  if (given.prewarm_off) {
    out->ec.prewarm = false;
  }
  if (given.pmtud_off) {
    out->ec.pmtud = false;
  }

  // P8-4: D + P <= 256 is a protocol hard limit (the symbol table index is
  // u8); each flag is in range above, but the pair can still be illegal. Fail
  // at startup instead of on every tunnel's first handshake.
  if (static_cast<uint16_t>(out->ec.d) + out->ec.p > 256) {
    *error = "--fec D+P must not exceed 256 (got " +
             std::to_string(static_cast<unsigned>(out->ec.d)) + " + " +
             std::to_string(static_cast<unsigned>(out->ec.p)) + ")";
    return false;
  }
  // A pinned k above min(--p, --p-max) is not merely "negotiation may lower
  // it": the local session clamps it before the peer is even involved, so the
  // operator would measure a k they did not configure. (`--p-max` exists for
  // exactly this: the spec's Pmax=5..7 range is unreachable at its 4 default.)
  if (out->ec.pinned_k >= 0) {
    const int ceiling = std::min<int>(out->ec.p, out->ec.p_max);
    if (out->ec.pinned_k > ceiling) {
      *error = "--k=" + std::to_string(out->ec.pinned_k) +
               " can never be honoured: it exceeds min(--p=" +
               std::to_string(static_cast<unsigned>(out->ec.p)) + ", --p-max=" +
               std::to_string(static_cast<unsigned>(out->ec.p_max)) +
               "); lower --k or raise those";
      return false;
    }
  }

  if (given.no_auto_window) {
    out->ec.auto_window = false;
  }
  // UDP GRO (kernel-side receive aggregation) defaults on: it pairs with the
  // GSO batch sender and the reactor drops it quietly when the kernel cannot
  // -- but a benchmarked-gainful environment can retire it here instead of
  // recompiling (docs/交付历史.md §32 saw loopback CPU-side regressions).
  out->ro.udp_gro = !given.no_udp_gro;
  out->ec.window_probe = !given.no_window_probe;
  // BBR is the default congestion controller for the adaptive window. The
  // epoch controller (--no-bbr) is kept for comparison and for reproducing
  // pre-#51 behaviour; a fixed window ignores either.
  out->ec.bbr = !given.no_bbr;
  if (given.bbr_version.given) {
    if (!out->ec.bbr) {
      *error = "--bbr-version only applies while BBR is enabled (drop --no-bbr)";
      return false;
    }
    long version = 0;
    if (!tools::ParseLong("--bbr-version", given.bbr_version.value.c_str(), 1, 2, &version,
                          error)) {
      return false;
    }
    out->ec.bbr_version = static_cast<int>(version);
    if (!out->ec.auto_window) {
      out->notes.push_back(
          "[fcp] note: --bbr-version only applies to the adaptive window; "
          "the fixed window has no congestion controller (drop --no-auto-window)");
    }
  }
  if (out->ec.bbr && given.no_window_probe) {
    out->notes.push_back(
        "[fcp] note: --no-window-probe only affects the epoch controller; "
        "BBR is on (add --no-bbr to use the epoch controller)");
  }
  // windows.start == 0 means ":MAX" was used: the ceiling is pinned and the
  // start stays at the default, which the prewarm prior may still replace.
  const bool start_given = windows.start > 0;
  if (windows.start > 0) {
    if (out->ec.auto_window) {
      // The autotune domain, not the fixed-window one: below the engine floor
      // the start would be silently raised, above 4 MiB it cannot be the start
      // of a ceiling that is capped at 4096. The floor is not just
      // window_min_bytes: Stream also needs room for two segments, which only
      // exceeds 64 KiB at unusually large --mtu values.
      const MtuLimits limits = compute_mtu_limits(out->ec.mtu, out->ec.ip_hdr_len);
      const size_t floor_bytes =
          std::max(out->ec.window_min_bytes,
                   limits.valid ? 2 * limits.payload_max : static_cast<size_t>(0));
      const size_t floor_kib = (floor_bytes + 1023u) / 1024u;
      if (windows.start < floor_kib || windows.start > 4096u) {
        *error = "--window START must be " + std::to_string(floor_kib) +
                 "..4096 KiB while the adaptive window is on; add --no-auto-window "
                 "for a larger fixed window";
        return false;
      }
    }
    out->ec.send_window_bytes = windows.start * 1024u;
    // Explicit beats the prewarm prior (see StreamConfig::send_window_explicit).
    out->ec.window_explicit = true;
    if (!out->ec.auto_window) {
      // A fixed window below two segments cannot make progress: pump() admits a
      // segment only while in_flight + wire_len fits, so a smaller window
      // accepts the app's bytes and never puts one on the wire (the live
      // `--no-auto-window --window=1` freeze). Stream floors it as well; the
      // CLI refuses instead of silently using a different number.
      // Only the segment size matters here: window_min_bytes is an autotune
      // concept, and the fixed window has always accepted values well below it.
      const MtuLimits limits = compute_mtu_limits(out->ec.mtu, out->ec.ip_hdr_len);
      const size_t floor_bytes =
          limits.valid ? 2 * limits.payload_max : static_cast<size_t>(0);
      if (out->ec.send_window_bytes < floor_bytes) {
        *error = "--window START under --no-auto-window must be at least " +
                 std::to_string((floor_bytes + 1023u) / 1024u) +
                 " KiB (two segments at this --mtu)";
        return false;
      }
    }
  }
  if (windows.ceiling > 0) {
    if (!out->ec.auto_window) {
      // A ceiling is meaningless without autotune: it used to be accepted and
      // ignored, which reads as "configured" in a script.
      *error = "--window MAX only applies to the adaptive window; "
               "drop --no-auto-window or remove the MAX";
      return false;
    }
    out->ec.window_max_bytes = windows.ceiling * 1024u;
  }
  if (!start_given && out->ec.auto_window && windows.ceiling > 0 &&
      out->ec.send_window_bytes > out->ec.window_max_bytes) {
    // A ceiling-only "--window=:MAX" below the 256 KiB default start: closing
    // the range would fail exactly the memory-constrained deployments the form
    // exists for. No START was named, so lowering the default to the
    // operator's own ceiling is not a silent override of a choice. (An
    // explicit START above MAX is still an error.)
    out->ec.send_window_bytes = out->ec.window_max_bytes;
    out->notes.push_back(
        "[fcp] note: --window=:MAX lowered the default adaptive start from " +
        std::to_string(kDefaultSendWindowBytes / 1024) + " KiB to " +
        std::to_string(out->ec.window_max_bytes / 1024) + " KiB");
  }
  // Wire-side defaults that do not need an operator decision:
  //   * the adaptive ceiling follows the measured BDP up to 4 MiB unless a MAX
  //     was pinned (an explicit MAX is a decision, and the prewarm prior must
  //     keep applying to the start);
  //   * ACKs are coalesced two per ACK on the wire. The unit tests keep
  //     per-segment ACKs (EngineConfig::ack_every stays 1); production is what
  //     pays the 81-byte ACK packet per segment.
  out->ec.ack_every = 2;
  if (out->ec.auto_window && out->ec.bbr && windows.ceiling == 0 &&
      !out->ec.window_explicit) {
    // The ceiling may follow the measured BDP, but the deployment guide's
    // worst-case memory promise (2 x window x sessions ~= 512 MiB) must hold:
    // one session's share shrinks as --max-sessions grows. The 256-session
    // default therefore keeps today's 1 MiB ceiling; the high-throughput
    // server recipe (--max-sessions=64) gets the full 4 MiB.
    constexpr size_t kWindowBudgetBytes = 512u * 1024u * 1024u;
    const size_t share = out->ec.max_sessions > 0
                             ? kWindowBudgetBytes / out->ec.max_sessions / 2
                             : kDefaultWindowCeilingBytes;
    const size_t ceiling = std::min(kDefaultWindowCeilingBytes, share);
    if (ceiling > out->ec.window_max_bytes) {
      out->ec.window_ceiling_bytes = ceiling;
    }
  }
  if (out->ec.auto_window && out->ec.send_window_bytes > out->ec.window_max_bytes) {
    // A range whose explicit START is above its own MAX is a mistake, and
    // saying so is shorter than explaining the clamp in a log line nobody reads.
    *error = "--window START " + std::to_string(out->ec.send_window_bytes / 1024) +
             " KiB is above MAX " + std::to_string(out->ec.window_max_bytes / 1024) +
             " KiB; give --window=START:MAX or --no-auto-window";
    return false;
  }
  if (given.rcv_buf.given) {
    if (out->ec.auto_window) {
      // Autotune sizes the advertised capacity from the ceiling; a --rcv-buf
      // value here would look configured and change nothing.
      *error = "--rcv-buf only applies to the fixed window (--no-auto-window); "
               "with autotune the receive capacity follows the --window MAX";
      return false;
    }
    long n = 0;
    if (!tools::ParseLong("--rcv-buf", given.rcv_buf.value.c_str(), 1, 1048576, &n, error)) {
      return false;
    }
    out->ec.rcv_buf_bytes = static_cast<size_t>(n) * 1024u;
  } else if (!out->ec.auto_window) {
    // A fixed window larger than the default 256 KiB receive buffer is the
    // normal reason to reach for --no-auto-window, and the peer's sender is
    // clamped by what we advertise. Follow the window unless overridden.
    if (out->ec.send_window_bytes > out->ec.rcv_buf_bytes) {
      out->ec.rcv_buf_bytes = out->ec.send_window_bytes;
    }
  }
  if (out->ec.auto_window && out->ec.rcv_buf_bytes < out->ec.window_max_bytes) {
    // The receive capacity follows the ceiling; say it out loud so the default
    // command line does not silently advertise 1 MiB instead of 256 KiB.
    out->notes.push_back(
        "[fcp] note: adaptive window sets the advertised receive capacity to the "
        "--window MAX (" + std::to_string(out->ec.window_max_bytes / 1024) +
        " KiB), not the fixed-mode default " +
        std::to_string(out->ec.rcv_buf_bytes / 1024) + " KiB per connection");
  }

  if (!ApplyHostPort(role, given, out, error)) {
    return false;
  }
  std::string listen_addr = given.listen.given ? given.listen.value : std::string();
  std::string listen_port;
  const bool listen_has_port =
      given.listen.given && SplitAddressPort(given.listen.value, &listen_addr, &listen_port);
  if (given.listen.given && !listen_addr.empty()) {
    out->ro.listen_addr = listen_addr;
  }
  if (given.local_port.given) {
    if (listen_has_port) {
      *error = "the local proxy port is given twice: --local-port and the address "
               "suffix; drop one";
      return false;
    }
    long n = 0;
    if (!tools::ParseLong("--local-port", given.local_port.value.c_str(), 1, 65535, &n, error)) {
      return false;
    }
    out->ro.listen_port = static_cast<int>(n);
  } else if (listen_has_port) {
    long n = 0;
    if (!tools::ParseLong("--listen", listen_port.c_str(), 1, 65535, &n, error)) {
      return false;
    }
    out->ro.listen_port = static_cast<int>(n);
  }
  if (given.log.given) {
    if (!ApplyLog(given.log.value, out, error)) {
      return false;
    }
  }
  if (given.log.given && given.log.value == "verbose") {
    out->ro.verbose = true;
  }
  // --speedtest means different things by role: the server turns on the
  // frame-layer responder on its UDP port, the client runs one bench and
  // exits. --speedtest-seconds only belongs to the client's one-shot mode.
  if (given.speedtest) {
    if (role == EngineRole::kServer) {
      out->ro.speedtest = true;
    } else {
      out->speedtest = true;
    }
  }
  if (given.speedtest_seconds.given) {
    if (role != EngineRole::kClient || !given.speedtest) {
      *error = "--speedtest-seconds only applies to the client's --speedtest run";
      return false;
    }
    long n = 0;
    if (!tools::ParseLong("--speedtest-seconds", given.speedtest_seconds.value.c_str(),
                          bench::kMinSeconds, bench::kMaxSeconds, &n, error)) {
      return false;
    }
    out->speedtest_seconds = static_cast<int>(n);
  }
  // --stall-ms belongs to the client: the tunnel's inbound stream is watched
  // from the end that keeps pushing traffic into it, and every deployment has
  // the client pushing (the server only relays back). One client-side flag is
  // the whole picture.
  if (given.stall_ms.given) {
    if (role != EngineRole::kClient) {
      *error = "--stall-ms only applies to the client";
      return false;
    }
    long n = 0;
    if (!tools::ParseLong("--stall-ms", given.stall_ms.value.c_str(), 0, 86400000, &n, error)) {
      return false;
    }
    out->ro.stall_ms = static_cast<int64_t>(n);
  }
  // --rate-limit=UP[:DOWN] Mbps. Each end shapes only the direction it sends:
  // the client takes the UP half, the server the DOWN half. The other half is
  // parsed and echoed in a note because arguments do not cross the wire --
  // the far end needs its own --rate-limit to enforce them.
  if (given.rate_limit.given) {
    // Client one-shot only: there is no tunnel to shape, so the flag has
    // nothing to apply to. The server's --speedtest is different -- it merely
    // ADDS the bench responder while the proxy keeps running, so --rate-limit
    // stays meaningful there (it shapes the tunnels; the responder measures
    // raw throughput by design and is deliberately unshaped).
    if (role == EngineRole::kClient && given.speedtest) {
      *error = "--rate-limit does not apply to the one-shot --speedtest run "
               "(it measures raw link throughput)";
      return false;
    }
    const auto mbps = [](double v) {
      std::string s = std::to_string(v);  // fixed 6 decimals
      s = s.substr(0, s.find('.') + 7);   // keep all 6: halves can be tiny
      while (s.back() == '0') {
        s.pop_back();
      }
      if (s.back() == '.') {
        s.pop_back();
      }
      return s;
    };
    const std::vector<std::string> parts = tools::SplitFields(given.rate_limit.value);
    if (parts.empty() || parts.size() > 2) {
      *error = "--rate-limit takes UP or UP:DOWN (got '" + given.rate_limit.value + "')";
      return false;
    }
    double rate[2] = {0.0, 0.0};
    for (size_t i = 0; i < parts.size(); ++i) {
      if (parts[i].empty()) {
        *error = "--rate-limit half " + std::to_string(i + 1) + " is empty (got '" +
                 given.rate_limit.value + "')";
        return false;
      }
      if (!tools::ParseDouble(i == 0 ? "--rate-limit UP" : "--rate-limit DOWN",
                              parts[i].c_str(), 0.0, 100000.0, &rate[i], error)) {
        return false;
      }
    }
    const size_t mine = role == EngineRole::kClient ? 0 : 1;
    if (rate[mine] <= 0.0) {
      *error = "--rate-limit shapes nothing here: the " +
               std::string(mine == 0 ? "client applies UP" : "server applies DOWN") +
               ", so '" + given.rate_limit.value + "' leaves this end unshaped "
               "(shown in Mbps)";
      return false;
    }
    const uint64_t bytes_per_sec = static_cast<uint64_t>(rate[mine] * 125000.0 + 0.5);
    if (bytes_per_sec < static_cast<uint64_t>(out->ec.mtu)) {
      // One second of budget must admit at least one full datagram; below
      // that the shaper's >budget passthrough fires on every symbol and the
      // link runs unshaped while the config line still prints a rate.
      *error = "--rate-limit " + given.rate_limit.value +
               " is too small to shape anything: one second of budget (" +
               std::to_string(bytes_per_sec) +
               " B/s) is below one datagram at --mtu=" +
               std::to_string(static_cast<int>(out->ec.mtu)) +
               "; raise the rate";
      return false;
    }
    if (mine == 0) {
      out->ro.rate_up_bytes = bytes_per_sec;
      if (rate[1] > 0.0) {
        out->notes.push_back("[fcp] note: --rate-limit DOWN=" + mbps(rate[1]) +
                             " Mbps is enforced by the server; give the server its "
                             "own --rate-limit=<UP>:DOWN");
      }
    } else {
      out->ro.rate_down_bytes = bytes_per_sec;
      if (rate[0] > 0.0) {
        out->notes.push_back("[fcp] note: --rate-limit UP=" + mbps(rate[0]) +
                             " Mbps is enforced by the client; give the client its "
                             "own --rate-limit=UP[:DOWN]");
      }
    }
  }
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
    std::printf("%s %s\n", role == EngineRole::kClient ? "fcp-client" : "fcp-server",
                kProductVersion);
    return 0;
  }
  if (args.help) {
    Usage(role, argv[0]);
    return 0;
  }
  // Interface MTU and process limits are facts about this host, not argv; they
  // are applied here so parsing stays pure and testable.
  ApplyEnvironmentDefaults(&args);
  if (args.key_in_argv) {
    // The help already says --key-file keeps the key out of 'ps'; say it where
    // an operator will actually see it (C-18).
    std::fprintf(stderr,
                 "[fcp] warning: --key is visible in the process command line "
                 "(ps, /proc/<pid>/cmdline, Windows task manager); prefer "
                 "--key-file or --key-env\n");
  }
  for (const std::string& note : args.notes) {
    std::fprintf(stderr, "%s\n", note.c_str());
  }
  if (role == EngineRole::kClient && args.speedtest) {
    return RunBench(args);
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
