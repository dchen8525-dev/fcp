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
#include "fcp/log_level.h"
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

// Short spellings. Every one is rewritten to its long form before matching, so
// there is still exactly one code path per option. The list is deliberately
// small: only the flags a startup command cannot avoid.
struct ShortOption {
  char flag;
  const char* long_name;
  bool takes_value;
};

constexpr ShortOption kShortOptions[] = {
    {'h', "--help", false},
    {'b', "--bind", true},
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
// Compound forms (--fec=D:P) land in the EngineConfig
// fields their halves name. Matching is longest-prefix, so --key-env never
// collapses into --key. --speedtest is a flag whose value is optional: the
// bare form runs the default duration, --speedtest=SEC names one.
const std::vector<tools::Alias>& OptionAliases() {
  static const std::vector<tools::Alias> kAliases = {
      {"--key", true},
      {"--peer", true},
      {"--bind", true},
      {"--mtu", true},
      {"--fec", true},
      {"--metrics", true},
      {"--window-min", true},
      {"--no-pmtud", false},
      {"--no-udp-gro", false},
      {"--idle", true},
      {"--dial-timeout", true},
      {"--max-sessions", true},
      {"--hs-concurrency", true},
      {"--speedtest", false, true},
      {"--stall-ms", true},
      {"--no-prewarm", false},
      {"--log-level", true},
      {"--stats", true},
      {"--log-file", true},
      {"--help", false},
  };
  return kAliases;
}

void Usage(EngineRole role, const char* argv0) {
  const bool client = role == EngineRole::kClient;
  // The first line carries the release version; -h is the only way to ask.
  std::printf(
      "%s %s\n"
      "usage: %s %s\n"
      "\n"
      "Key (required, both ends equal):\n"
      "  --key=HEX32          16-byte pre-shared key, 32 hex digits.\n"
      "\n",
      client ? "fcp-client" : "fcp-server", kProductVersion, argv0,
      client ? "[--peer=IP[:P]] [-b IP[:P]] [options]" : "[-b IP[:P]] [options]");
  if (client) {
    std::printf(
        "Client:\n"
        "  --peer=IP[:P]        FCP server address (required; port defaults to 4460)\n"
        "  -b, --bind=IP[:P]    local proxy bind (default 127.0.0.1:1080); one port\n"
        "                       speaks SOCKS5, HTTP CONNECT (HTTPS) and absolute-form\n"
        "                       HTTP forward requests\n"
        "  --speedtest[=SEC]    run one raw FCP link speed test against --peer and\n"
        "                       exit (no local proxy); SEC is seconds per direction,\n"
        "                       3..30 (default 8)\n"
        "  --hs-concurrency=N   client handshake concurrency cap (default 4; 0 =\n"
        "                       unlimited): sessions between start and established;\n"
        "                       excess local connections queue instead of racing\n"
        "                       their HELLOs on a lossy path\n"
        "  --stall-ms=N         client dead-path watchdog: log a stall when TX\n"
        "                       keeps moving but nothing comes back for N ms\n"
        "                       (0 = off, default 60000)\n");
  } else {
    std::printf(
        "Server:\n"
        "  -b, --bind=IP[:P]    UDP bind address (default 0.0.0.0:4460); an empty\n"
        "                       address (-b :40000) keeps 0.0.0.0\n"
        "  --speedtest          also answer the desktop link speed test on the same\n"
        "                       UDP port (off by default; PSK-authenticated)\n");
  }
  std::printf(
      "Transport:\n"
      "  --mtu=N              datagram bytes incl. 20B IP + 8B UDP headers where\n"
      "                       the probe walk STARTS (default 1400; 256..65535).\n"
      "                       With --no-pmtud this is the fixed budget; with\n"
      "                       probing on, the walk climbs to the built-in\n"
      "                       ceiling (1500, raised to N when N is higher)\n"
      "  --no-pmtud           disable probing and pin the budget at --mtu\n"
      "  --no-udp-gro         disable kernel UDP GRO receive aggregation (Linux\n"
      "                       only; on by default, dropped quietly if the kernel\n"
      "                       cannot)\n"
      "  --fec=D:P            frame geometry (default 10:3); P is also the parity\n"
      "                       ceiling the adaptive controller may climb to\n"
      "  --metrics=PREFIX     per-session controller metrics JSONL (calibration)\n"
      "  --window-min=KIB     send-window floor (default 2048; 1..1048576). BBR\n"
      "                       keeps the window in [floor, 2x floor]; there is no\n"
      "                       separate ceiling. The floor must cover two segments\n"
      "                       at this --mtu, and the error names the value\n"
      "  --idle=ms            tunnel idle teardown (default 300000)\n"
      "  --dial-timeout=ms    whole-dial budget: resolve + every connect\n"
      "                       attempt (default 5000)\n"
      "  --max-sessions=N     concurrent sessions (default 256; warns when the fd\n"
      "                       or address-space limit cannot cover the worst case)\n"
      "  --no-prewarm         start every session cold (default: reuse RTT/k/window priors)\n"
      "  --log-level=LEVEL    what reaches stderr AND --log-file (one shared\n"
      "                       threshold): off | error | warn | info | debug\n"
      "                       (default debug)\n"
      "  --stats=MS           periodic stats line every MS ms (0 = off, default off)\n"
      "  --log-file=PATH      persistent log with timestamps (same level threshold\n"
      "                       as stderr; rotation 32 MiB -> PATH.1); a trailing\n"
      "                       separator or an existing directory writes\n"
      "                       fcp-<role>-<pid>.log inside\n"
      "  -h, --help           this text; the first line carries the release version\n");
}

// --window-min=KIIB. 0 means "not given"; the parsers reject 0, so the flag is
// the only way in.
struct ParsedWindows {
  size_t start = 0;
  bool start_given = false;
};

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
  SeenValue peer;
  SeenValue bind;
  SeenValue metrics;
  SeenValue idle;
  SeenValue dial_timeout;
  SeenValue max_sessions;
  SeenValue hs_concurrency;
  bool speedtest = false;
  SeenValue speedtest_seconds;
  SeenValue stall_ms;
  SeenValue log_level;
  SeenValue stats;
  SeenValue log_file;
  SeenValue mtu;
  bool pmtud_off = false;
  bool prewarm_off = false;
  bool no_udp_gro = false;
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
  } else if (name == "--peer") {
    f->peer = {true, v};
  } else if (name == "--bind") {
    f->bind = {true, v};
  } else if (name == "--metrics") {
    f->metrics = {true, v};
  } else if (name == "--idle") {
    f->idle = {true, v};
  } else if (name == "--dial-timeout") {
    f->dial_timeout = {true, v};
  } else if (name == "--max-sessions") {
    f->max_sessions = {true, v};
  } else if (name == "--hs-concurrency") {
    f->hs_concurrency = {true, v};
  } else if (name == "--speedtest") {
    f->speedtest = true;
    if (m.has_value) {
      f->speedtest_seconds = {true, v};
    }
  } else if (name == "--stall-ms") {
    f->stall_ms = {true, v};
  } else if (name == "--log-level") {
    f->log_level = {true, v};
  } else if (name == "--log-file") {
    f->log_file = {true, v};
  } else if (name == "--stats") {
    f->stats = {true, v};
  } else if (name == "--mtu") {
    f->mtu = {true, v};
  } else if (name == "--no-pmtud") {
    f->pmtud_off = true;
  } else if (name == "--no-prewarm") {
    f->prewarm_off = true;
  } else if (name == "--no-udp-gro") {
    f->no_udp_gro = true;
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
  } else if (name == "--window-min") {
    windows->start_given = true;
    long n = 0;
    if (!tools::ParseLong("--window-min", v.c_str(), 1, 1048576, &n, error)) {
      return false;
    }
    windows->start = static_cast<size_t>(n);
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
  // One rule now: an address carries its own port. -b/--bind always means
  // "listen locally" (server: UDP; client: the SOCKS/HTTP proxy port) and
  // --peer always means "connect there", so the role decides only which of the
  // two reactor endpoints the address lands in.
  std::string peer = f.peer.given ? f.peer.value : std::string();
  std::string peer_port;
  const bool peer_has_port = f.peer.given && SplitAddressPort(f.peer.value, &peer, &peer_port);
  std::string bind = f.bind.given ? f.bind.value : std::string();
  std::string bind_port;
  const bool bind_has_port = f.bind.given && SplitAddressPort(f.bind.value, &bind, &bind_port);

  if (client) {
    if (!f.peer.given || peer.empty()) {
      *error = "client requires --peer=IP[:P] (the FCP server address)";
      return false;
    }
    out->ro.remote_host = peer;
    if (peer_has_port) {
      if (!tools::ParseLong("--peer", peer_port.c_str(), 1, 65535, &n, error)) {
        return false;
      }
      out->ro.remote_port = static_cast<int>(n);
    }
    if (f.bind.given) {
      if (!bind_has_port && bind.empty()) {
        *error = "--bind needs an address (default 127.0.0.1)";
        return false;
      }
      if (!bind.empty()) {
        out->ro.listen_addr = bind;
      }
      if (bind_has_port) {
        if (!tools::ParseLong("--bind", bind_port.c_str(), 1, 65535, &n, error)) {
          return false;
        }
        out->ro.listen_port = static_cast<int>(n);
      }
    }
    return true;
  }

  if (f.peer.given) {
    *error = "--peer is a client option; the server binds with --bind";
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
    if (bind_has_port) {
      if (!tools::ParseLong("--bind", bind_port.c_str(), 1, 65535, &n, error)) {
        return false;
      }
      out->ro.bind_port = static_cast<int>(n);
    }
  }
  return true;
}

// --log-level=LEVEL：off | error | warn | info | debug。默认 debug：排障是
// 常态，安静是显式选择。周期统计行拆到 --stats=MS（0 = 关），互不干扰。
bool ApplyLog(const std::string& value, ProxyArgs* out, std::string* error) {
  const std::string& level = value;
  if (level == "off") {
    out->ro.log_level = LogLevel::kOff;
    return true;
  }
  if (level == "error") {
    out->ro.log_level = LogLevel::kError;
    return true;
  }
  if (level == "warn") {
    out->ro.log_level = LogLevel::kWarn;
    return true;
  }
  if (level == "info") {
    out->ro.log_level = LogLevel::kInfo;
    return true;
  }
  if (level == "debug") {
    out->ro.log_level = LogLevel::kDebug;
    return true;
  }
  *error = "--log-level must be off, error, warn, info or debug (got '" + value + "')";
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
// --mtu. Only the startup default is adjusted; an explicit value wins.
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
  // "adaptive" marks a run whose rate controller converged to a delivery
  // ceiling: wireMbps then sits just above mbps, and the residual lostBytes is
  // the climb's own overshoot rather than a path problem.
  const double wire_mbps = static_cast<double>(s.wire_bps) / 1e6;
  char buf[352];
  std::snprintf(buf, sizeof(buf),
                "{\"mbps\":%.2f,\"wireMbps\":%.2f,\"bytes\":%llu,\"lostBytes\":%llu,"
                "\"seconds\":%.2f,\"acked\":%s,\"lossPpm\":%u,\"lossN\":%u,"
                "\"adaptive\":%s}",
                std::isfinite(s.mbps) ? s.mbps : 0.0,
                std::isfinite(wire_mbps) ? wire_mbps : 0.0,
                static_cast<unsigned long long>(s.bytes),
                static_cast<unsigned long long>(s.lost_bytes), s.seconds,
                s.acked ? "true" : "false", s.loss_ppm, s.loss_n,
                s.adaptive ? "true" : "false");
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
    // from the configured MTU up to the built-in ceiling is exactly the point.
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
  // promises (the ceiling, 2x the floor) plus the ceiling the sender may grow
  // into. window_max_bytes is not in EngineConfig any more -- the ceiling is
  // 2 x window_min_bytes, derived per stream.
  const size_t win_ceiling = 2 * ec.window_min_bytes;
  const size_t rcv_cap = ec.rcv_buf_bytes > win_ceiling ? ec.rcv_buf_bytes : win_ceiling;
  const size_t send_cap = win_ceiling;
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
  // not touched yet, so --help wins over an invalid value elsewhere in a long
  // scripted command line -- and it never needs a PSK, which is what the
  // package self-test relies on.
  std::vector<tools::Match> matched;
  std::vector<std::string> seen;
  matched.reserve(static_cast<size_t>(argc));
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    // Short spellings are rewritten to their long form: one code path per
    // option. A value option takes the next argument ("-b addr") or an attached
    // one ("-b=addr", "-baddr"), so a short command stays short.
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
    if (name == "--help") {
      out->help = true;
      matched.push_back(std::move(m));
      continue;
    }
    // Duplicate detection is per option group, not per spelling.
    const char* group = name.c_str() + 2;
    if (!tools::MarkSeen(&seen, group, error)) {
      return false;
    }
    matched.push_back(std::move(m));
  }
  if (out->help) {
    return true;
  }

  // Pass 2: apply the values, in command-line order.
  ProxyFlags given;
  ParsedWindows windows;
  for (const tools::Match& m : matched) {
    if (m.name == nullptr || std::strcmp(m.name, "--help") == 0) {
      continue;
    }
    if (!ApplyValue(m, &given, &windows, out, error)) {
      return false;
    }
  }

  // The key is one inline value.
  if (!given.key.given) {
    *error = "--key is required: 32 hex chars (16-byte PSK), identical on both ends";
    return false;
  }
  if (!ParseKey(given.key.value, out->ec.key)) {
    *error = given.key.value.size() == 32
                 ? "--key must contain only hex digits (0-9, a-f)"
                 : "--key must be 32 hex digits (16 bytes), got " +
                       std::to_string(given.key.value.size()) + " characters";
    return false;
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
    // The probe ceiling follows the floor when the floor is raised past the
    // built-in 1500: `--mtu=9000` alone is a legal configuration (the walk
    // has nothing to climb), and the built-in absolute cap kPmtuAbsoluteMaxMtu
    // still bounds it.
    if (out->ec.pmtu_max_mtu < out->ec.mtu) {
      out->ec.pmtu_max_mtu = std::min<uint16_t>(out->ec.mtu,
                                                static_cast<uint16_t>(kPmtuAbsoluteMaxMtu));
    }
  }
  if (given.metrics.given) {
    out->ec.trace_prefix = given.metrics.value;
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
  // The reactor's per-address connect timer is the same budget. Splitting it
  // into a second flag meant `--dial-timeout=20000` still failed each address
  // after 5 s unless the operator remembered the other name.
  out->ro.connect_timeout_ms = out->ec.dial_timeout_ms;
  if (given.max_sessions.given) {
    long n = 0;
    if (!tools::ParseLong("--max-sessions", given.max_sessions.value.c_str(), 1, 65536, &n,
                          error)) {
      return false;
    }
    out->ec.max_sessions = static_cast<size_t>(n);
  }
  if (given.hs_concurrency.given) {
    long n = 0;
    if (!tools::ParseLong("--hs-concurrency", given.hs_concurrency.value.c_str(), 0, 1024,
                          &n, error)) {
      return false;
    }
    out->ec.hs_concurrency = static_cast<uint32_t>(n);
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
  // --k (pinned parity) and --p-max are gone: P from --fec is the only
  // ceiling. Mirroring it here makes session.cc's min(p_max, negotiated P')
  // equal to the negotiated P', so an explicit --fec=10:7 is no longer
  // silently held at the old hidden 6.
  out->ec.p_max = out->ec.p;
  out->ec.pinned_k = -1;

  // UDP GRO (kernel-side receive aggregation) defaults on: it pairs with the
  // GSO batch sender and the reactor drops it quietly when the kernel cannot
  // -- but a benchmarked-gainful environment can retire it here instead of
  // recompiling (docs/交付历史.md §32 saw loopback CPU-side regressions).
  out->ro.udp_gro = !given.no_udp_gro;
  // BBR is the only congestion controller.
  out->ec.bbr_version = 2;
  // One window knob: --window-min names the floor BBR never goes below; the
  // ceiling is twice that floor, derived per stream. The memory promise is
  // still bounded by --max-sessions via the per-connection worst case
  // (floor + ceiling = 3 x floor).
  if (windows.start_given) {
    // The floor is not just window_min_bytes: Stream needs room for two
    // segments, which only exceeds the configured floor at unusually large
    // --mtu values (the floor rises with --mtu above ~2 KiB).
    const MtuLimits limits = compute_mtu_limits(out->ec.mtu, out->ec.ip_hdr_len);
    const size_t floor_bytes =
        limits.valid ? 2 * limits.payload_max : static_cast<size_t>(0);
    if (windows.start * 1024u < floor_bytes) {
      const size_t floor_kib = (floor_bytes + 1023u) / 1024u;
      *error = "--window-min must be at least " + std::to_string(floor_kib) +
               " KiB (two segments at this --mtu)";
      return false;
    }
    out->ec.window_min_bytes = windows.start * 1024u;
    out->ec.window_explicit = true;
    out->ec.send_window_bytes = out->ec.window_min_bytes;
  }
  // ACKs are coalesced two per ACK on the wire. The unit tests keep
  // per-segment ACKs (EngineConfig::ack_every stays 1); production is what
  // pays the 81-byte ACK packet per segment.
  out->ec.ack_every = 2;

  if (!ApplyHostPort(role, given, out, error)) {
    return false;
  }
  if (given.log_level.given) {
    if (!ApplyLog(given.log_level.value, out, error)) {
      return false;
    }
  }
  // 周期统计行的间隔（毫秒）：0 = 不打（退出摘要照旧）；默认关，deb 的
  // fcp.env 与 GUI sidecar 自行给值。
  if (given.stats.given) {
    long n = 0;
    if (!tools::ParseLong("--stats", given.stats.value.c_str(), 0, 86400000, &n, error)) {
      return false;
    }
    out->ro.stats_ms = static_cast<int64_t>(n);
  }
  if (given.log_file.given) {
    out->ro.log_file = given.log_file.value;
  }
  // --speedtest means different things by role: the server turns on the
  // frame-layer responder on its UDP port, the client runs one bench and
  // exits. The optional value only belongs to the client's one-shot mode.
  if (given.speedtest) {
    if (role == EngineRole::kServer) {
      out->ro.speedtest = true;
    } else {
      out->speedtest = true;
    }
  }
  if (given.speedtest_seconds.given) {
    if (role != EngineRole::kClient) {
      *error = "--speedtest=SECONDS only applies to the client's one-shot run";
      return false;
    }
    long n = 0;
    if (!tools::ParseLong("--speedtest", given.speedtest_seconds.value.c_str(),
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
  if (args.help) {
    Usage(role, argv[0]);
    return 0;
  }
  // Interface MTU and process limits are facts about this host, not argv; they
  // are applied here so parsing stays pure and testable.
  ApplyEnvironmentDefaults(&args);
  // 启动期的提示与警告也必须走同一把 --log 阈值尺（运行期日志由
  // Reactor::log_line/note 把关，这里在 reactor 起来之前，得自己判）。
  // 否则 --log-level=off 仍是满屏 note，--log-level=error 也压不住 info 提示。
  const int log_floor = Severity(args.ro.log_level);
  auto say = [log_floor](int severity, const std::string& body) {
    if (!Wanted(severity, log_floor)) return;
    std::fprintf(stderr, "%s\n", LogLine(severity, body).c_str());
  };
  // 解析期的提示与警告和运行期日志同一排版：时间戳 + 级别 + 正文。
  for (const std::string& note : args.notes) {
    int severity = Severity(LogLevel::kInfo);
    std::string body = note;
    constexpr const char* kWarnPrefix = "[fcp] warning: ";
    constexpr const char* kNotePrefix = "[fcp] note: ";
    if (body.rfind(kWarnPrefix, 0) == 0) {
      severity = Severity(LogLevel::kWarn);
      body.erase(0, std::strlen(kWarnPrefix));
    } else if (body.rfind(kNotePrefix, 0) == 0) {
      body.erase(0, std::strlen(kNotePrefix));
    }
    say(severity, body);
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
