#include "cli.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

#include "cli_parse.h"
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

// The accepted spellings of every option, in the order --help lists them.
// Compound forms (--window=START:MAX, --fec=D:P) and their legacy single-value
// aliases are separate entries that land in the same EngineConfig fields, so a
// deployment written against the old names keeps its meaning. Matching is
// longest-prefix, so --window-cap and --key-file never collapse to their
// shorter siblings.
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
      {"--d", true},
      {"--p", true},
      {"--fec", true},
      {"--p-max", true},
      {"--k", true},
      {"--fec-budget", true},
      {"--trace", true},
      {"--window", true},
      {"--window-cap", true},
      {"--rcv-buf", true},
      {"--auto-window", false},
      {"--no-auto-window", false},
      {"--idle", true},
      {"--dial-timeout", true},
      {"--connect-timeout", true},
      {"--max-sessions", true},
      {"--no-prewarm", false},
      {"--stats", true},
      {"--log", true},
      {"--verbose", false},
      {"--help", false},
      {"--version", false},
  };
  return kAliases;
}

void Usage(EngineRole role, const char* argv0) {
  const bool client = role == EngineRole::kClient;
  std::printf(
      "usage: %s %s\n"
      "  --key=HEX32          16-byte pre-shared key (one of --key/--key-file/\n"
      "                       --key-env; both ends equal)\n"
      "  --key-file=FILE      read the key from FILE instead (keeps it out of `ps`)\n"
      "  --key-env=VAR        read the key from environment variable VAR (for the\n"
      "                       packaged unit: a DynamicUser cannot read a 0600\n"
      "                       file, but systemd hands the service its env)\n",
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
      "  --mtu=N              IP packet budget incl. IP+UDP headers (default 1400;\n"
      "                       lowered to fit the largest local interface MTU)\n"
      "  --fec=D:P            frame geometry (default 10:3; --d/--p still work)\n"
      "  --p-max=N            controller parity ceiling 0..7 (default 4; the\n"
      "                       documented 5..7 range needs this raised)\n"
      "  --k=N                pinned parity per set, -1 = adaptive (default -1;\n"
      "                       must not exceed min(--p, --p-max))\n"
      "  --fec-budget=R       redundancy ceiling parity/data per report, 0 = off (default 0.5)\n"
      "  --trace=PREFIX       per-session controller trace JSONL (calibration)\n"
      "  --window=START:MAX   send window KiB; autotune start + ceiling\n"
      "                       (default 256:1024; START 64..4096 in autotune,\n"
      "                       1..1048576 fixed; --window-cap still works)\n"
      "  --no-auto-window     fixed --window instead of autotune (autotune is\n"
      "                       the default; --auto-window still accepted)\n"
      "  --rcv-buf=KiB        fixed-mode receive buffer (default: the fixed\n"
      "                       --window, at least 256; --no-auto-window only)\n"
      "  --idle=ms            tunnel idle teardown (default 300000)\n"
      "  --dial-timeout=ms    whole-dial budget: resolve + every connect\n"
      "                       attempt (default 5000)\n"
      "  --connect-timeout=ms per-address TCP connect budget (default 5000)\n"
      "  --max-sessions=N     concurrent sessions (default 256; warns when the fd\n"
      "                       or address-space limit cannot cover the worst case)\n"
      "  --no-prewarm         start every session cold (default: reuse RTT/k/window priors)\n"
      "  --log=LEVEL          off (default; exit summary only) |\n"
      "                       stats[:ms] (periodic line) | verbose\n"
      "  -v                   alias of --log=verbose; --stats=ms still works\n"
      "  --version            print the release version and exit\n");
}

// Values shared by the compound (--window=START:MAX) and legacy
// (--window / --window-cap) spellings. 0 = not given; the parsers never
// accept a 0, so it is unambiguous. The two source flags say which spelling
// supplied the ceiling, so mixing spellings can be rejected instead of one
// silently replacing the other.
struct ParsedWindows {
  size_t start = 0;
  size_t ceiling = 0;
  bool max_from_window = false;  // --window=START:MAX
  bool max_from_cap = false;     // --window-cap=MAX
};

// START and MAX have different domains: MAX is autotune-only and bounded to
// 64..4096 KiB (below that the engine would silently raise it; above it one
// connection could promise 4+ GiB, times --max-sessions). START is also a
// fixed-mode window, which has always accepted up to 1 GiB, so its narrow
// 64..4096 autotune range is enforced later, once --no-auto-window is known.
bool ParseWindowValue(const std::string& flag, const std::string& value, ParsedWindows* w,
                      std::string* error) {
  const std::string what = "--" + flag + " must be START or START:MAX, START 1..1048576 "
                                        "KiB and MAX 64..4096 KiB (got '" + value + "')";
  const std::vector<std::string> parts = tools::SplitFields(value);
  if (parts.size() > 2) {
    *error = what;
    return false;
  }
  long start = 0;
  long ceiling = 0;
  const std::string flag_start = "--" + flag;
  const std::string flag_max = "--" + flag + " (MAX)";
  if (parts[0].empty() ||
      !tools::ParseLong(flag_start.c_str(), parts[0].c_str(), 1, 1048576, &start, error)) {
    if (error->empty()) {
      *error = what;
    }
    return false;
  }
  if (parts.size() == 2) {
    if (parts[1].empty() ||
        !tools::ParseLong(flag_max.c_str(), parts[1].c_str(), 64, 4096, &ceiling, error)) {
      if (error->empty()) {
        *error = what;
      }
      return false;
    }
    w->ceiling = static_cast<size_t>(ceiling);
    w->max_from_window = true;
  }
  w->start = static_cast<size_t>(start);
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
  SeenValue log;
  SeenValue stats;
  SeenValue rcv_buf;
  SeenValue fec_budget;
  SeenValue p_max;
  SeenValue k;
  SeenValue mtu;
  bool prewarm_off = false;
  bool auto_window = false;
  bool no_auto_window = false;
  bool verbose = false;
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
  } else if (name == "--log") {
    f->log = {true, v};
  } else if (name == "--stats") {
    f->stats = {true, v};
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
  } else if (name == "--no-prewarm") {
    f->prewarm_off = true;
  } else if (name == "--auto-window") {
    f->auto_window = true;
  } else if (name == "--no-auto-window") {
    f->no_auto_window = true;
  } else if (name == "--verbose") {
    f->verbose = true;
  } else if (name == "--fec" || name == "--d" || name == "--p") {
    // --fec=D:P is the pair, --d/--p set one half; the pair limit (D+P <= 256)
    // is checked once both halves are known.
    if (name == "--p") {
      if (!tools::ParseLong("--p", v.c_str(), 0, 7, &n, error)) {
        return false;
      }
      out->ec.p = static_cast<uint8_t>(n);
      return true;
    }
    if (name == "--d") {
      if (!tools::ParseLong("--d", v.c_str(), 1, 255, &n, error)) {
        return false;
      }
      out->ec.d = static_cast<uint8_t>(n);
      return true;
    }
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
  } else if (name == "--window" || name == "--window-cap") {
    const std::string flag = name.substr(2);
    if (name == "--window-cap") {
      // Legacy spelling: the ceiling alone, always a single number. It may be
      // combined with a single-valued --window (the docs' old incantation), but
      // not with the compound, which already carries a MAX.
      if (windows->max_from_window) {
        *error = "--window=START:MAX already sets the ceiling; drop --window-cap";
        return false;
      }
      if (!tools::ParseLong(name.c_str(), v.c_str(), 64, 4096, &n, error)) {
        return false;
      }
      windows->ceiling = static_cast<size_t>(n);
      windows->max_from_cap = true;
      return true;
    }
    if (!ParseWindowValue(flag, v, windows, error)) {
      return false;
    }
    if (windows->max_from_window && windows->max_from_cap) {
      *error = "--window=START:MAX already sets the ceiling; drop --window-cap";
      return false;
    }
  } else {
    *error = "internal: unhandled option " + name;
    return false;
  }
  return true;
}

bool ApplyHostPort(EngineRole role, const ProxyFlags& f, ProxyArgs* out, std::string* error) {
  const bool client = role == EngineRole::kClient;
  long n = 0;
  if (f.port.given) {
    if (!tools::ParseLong("--port", f.port.value.c_str(), 1, 65535, &n, error)) {
      return false;
    }
    if (client) {
      out->ro.remote_port = static_cast<int>(n);
    } else {
      out->ro.bind_port = static_cast<int>(n);
    }
  }
  if (client) {
    if (!f.host.given || f.host.value.empty()) {
      *error = "--host=IP is required on the client";
      return false;
    }
    out->ro.remote_host = f.host.value;
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
      if (f.bind.value.empty()) {
        *error = "--bind needs an address (default 0.0.0.0)";
        return false;
      }
      out->ro.bind_addr = f.bind.value;
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
  if (!args->mtu_explicit) {
    const size_t if_mtu = InterfaceMtu();
    const uint16_t adjusted = MtuForInterface(args->ec.mtu, if_mtu);
    if (adjusted < args->ec.mtu) {
      args->notes.push_back("[fcp] note: MTU lowered to " + std::to_string(adjusted) +
                            " bytes (default " + std::to_string(args->ec.mtu) +
                            ") to fit the largest local interface MTU " +
                            std::to_string(if_mtu) + " (IP+UDP headers included)");
      args->ec.mtu = adjusted;
    }
  }
  const ResourceLimits limits = CurrentResourceLimits();
  const std::vector<std::string> notes = ResourceNotes(args->ec.role, args->ec, limits);
  args->notes.insert(args->notes.end(), notes.begin(), notes.end());
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
  const size_t rcv_cap =
      ec.auto_window ? (ec.rcv_buf_bytes > ec.window_max_bytes ? ec.rcv_buf_bytes
                                                               : ec.window_max_bytes)
                     : ec.rcv_buf_bytes;
  const size_t send_cap = ec.auto_window ? ec.window_max_bytes : ec.send_window_bytes;
  const uint64_t per_session = static_cast<uint64_t>(rcv_cap) +
                               static_cast<uint64_t>(send_cap) +
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
  bool fec_form = false;
  bool d_form = false;
  bool p_form = false;
  bool log_form = false;
  bool verbose_form = false;
  bool stats_form = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    // Short spellings are rewritten to their long form: one code path per option.
    if (arg == "-h") {
      arg = "--help";
    } else if (arg == "-V") {
      arg = "--version";
    } else if (arg == "-v") {
      arg = "--verbose";
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
    // --key-file and --key-env are one setting, as are --window/--window-cap.
    // -v and --stats stay independent of each other (the deploy docs use them
    // together) but cannot be mixed with --log, which is checked after the loop.
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
    if (name == "--fec") {
      fec_form = true;
    } else if (name == "--d") {
      d_form = true;
    } else if (name == "--p") {
      p_form = true;
    } else if (name == "--log") {
      log_form = true;
    } else if (name == "--verbose") {
      verbose_form = true;
    } else if (name == "--stats") {
      stats_form = true;
    }
    matched.push_back(std::move(m));
  }
  if (out->help || out->version) {
    return true;
  }
  // --fec=D:P is one option for the pair; --d/--p are the pair split over two
  // options. Mixing the forms is the same setting given twice.
  if (fec_form && (d_form || p_form)) {
    *error = "--fec and --d/--p are two spellings of the geometry; give one form";
    return false;
  }
  // --log already says both things, so it cannot be combined with either
  // spelling it replaces.
  if (log_form && (verbose_form || stats_form)) {
    *error = "--log already selects the logging; drop -v/--stats";
    return false;
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

  if (given.auto_window && given.no_auto_window) {
    *error = "--auto-window and --no-auto-window are mutually exclusive";
    return false;
  }
  if (given.no_auto_window) {
    out->ec.auto_window = false;
  }
  // --auto-window has nothing to set: autotune is the default and is the only
  // way the window grows, so the flag is accepted for scripts and ignored.
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
    // A lone legacy --window-cap below the 256 KiB default start used to clamp
    // the start to the cap; failing such a command line would break exactly the
    // memory-constrained deployments the flag exists for. No START was named,
    // so lowering the default to the operator's own ceiling is not a silent
    // override of a choice. (An explicit START above MAX is still an error.)
    out->ec.send_window_bytes = out->ec.window_max_bytes;
    out->notes.push_back(
        "[fcp] note: --window-cap lowered the default adaptive start from " +
        std::to_string(kDefaultSendWindowBytes / 1024) + " KiB to " +
        std::to_string(out->ec.window_max_bytes / 1024) + " KiB");
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
  if (given.listen.given) {
    out->ro.listen_addr = given.listen.value;
  }
  if (given.local_port.given) {
    long n = 0;
    if (!tools::ParseLong("--local-port", given.local_port.value.c_str(), 1, 65535, &n, error)) {
      return false;
    }
    out->ro.listen_port = static_cast<int>(n);
  }
  if (given.log.given) {
    if (!ApplyLog(given.log.value, out, error)) {
      return false;
    }
  }
  if (given.stats.given) {
    long n = 0;
    if (!tools::ParseLong("--stats", given.stats.value.c_str(), 0, 86400000, &n, error)) {
      return false;
    }
    out->ro.stats_ms = static_cast<int64_t>(n);
  }
  if (given.verbose || (given.log.given && given.log.value == "verbose")) {
    out->ro.verbose = true;
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
