// CLI argument parsing (apps/cli/cli.cc), T-cli.
//
// Every range check in the CLI exists because a typo used to be silently
// wrapped or clamped: --mtu=70000 became 4464 (uint16 wrap), an oversized
// --fec pair used to reach the handshake, a fec-budget above 1 silently
// disabled the cap, plain atoi() turned "abc" into 0. These tests pin the
// loud-failure contract: bad input returns false with a reason, good input
// lands in EngineConfig/ReactorOptions verbatim, and defaults survive an
// option-less command line.
//
// Like fcp-node, the CLI has exactly one spelling per setting now
// (--key, --peer, -b/--bind, --mtu, --fec=D:P, --log-level). The
// removed spellings are rejected with the replacement named: a silently
// accepted dead flag reads as "configured" in a script while the run uses a
// default nobody chose.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "bench.h"
#include "cli.h"
#include "fcp/log_level.h"
#include "test_util.h"

namespace {

using fcp::EngineRole;
using fcp::LogLevel;
using fcp::ProxyArgs;
using fcp::Severity;
using fcp::Wanted;

// Builds argv the way main() would see it; argv[0] is a placeholder since the
// parser never reads it (only run_proxy's Usage does).
struct Argv {
  std::vector<std::string> store;
  std::vector<char*> ptrs;

  explicit Argv(const std::vector<std::string>& args) : store(args) {
    ptrs.push_back(const_cast<char*>("fcp"));
    for (const std::string& a : store) {
      ptrs.push_back(const_cast<char*>(a.c_str()));
    }
  }
  char** data() { return ptrs.data(); }
  int argc() { return static_cast<int>(ptrs.size()); }
};

constexpr const char* kGoodKey = "000102030405060708090A0B0C0D0E0F";

bool TryParse(EngineRole role, const std::vector<std::string>& args,
              ProxyArgs* out, std::string* error) {
  Argv argv(args);
  return fcp::parse_proxy_args(role, argv.argc(), argv.data(), out, error);
}

// Ok/Fail prefill the required options (--key on both roles, --peer on the
// client) so the range tests can pass only the option under test. Tests that
// deliberately probe a missing requirement call TryParse directly.
std::string TempPath(const char* leaf) {
  // The file is only needed for the key-file tests, which remove it again; the
  // build directory is writable on every platform the suite runs on.
  return std::string("fcp_cli_test_") + leaf;
}

bool WriteFile(const std::string& path, const std::string& text) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) {
    return false;
  }
  const size_t n = std::fwrite(text.data(), 1, text.size(), f);
  return std::fclose(f) == 0 && n == text.size();
}

bool Ok(EngineRole role, const std::vector<std::string>& args,
        ProxyArgs* out, std::string* error) {
  std::vector<std::string> all = {"--key=" + std::string(kGoodKey)};
  if (role == EngineRole::kClient) {
    all.push_back("--peer=10.0.0.1");
  }
  all.insert(all.end(), args.begin(), args.end());
  return TryParse(role, all, out, error);
}

void TestKeyValidation() {
  ProxyArgs a;
  std::string error;
  // Uppercase and lowercase both decode; wrong length and non-hex reject.
  CHECK(TryParse(EngineRole::kServer, {"--key=0f1e2d3c4b5a69788796a5b4c3d2e1f0"}, &a, &error));
  CHECK_EQ(a.ec.key[0], 0x0f);
  CHECK_EQ(a.ec.key[15], 0xf0);
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e0f0"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer, {"--key="}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e0g"}, &a, &error));
  // Missing entirely names the one source that is left.
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK(error.find("--key is required") != std::string::npos);
  // The same spelling twice is still a duplicate.
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key=" + std::string(kGoodKey), "--key=" + std::string(kGoodKey)}, &a,
                  &error));
  CHECK(error.find("more than once") != std::string::npos);
}

// Old spellings are gone with no compatibility shim: they now fail as plain
// unknown options, and --help is not a license to ignore them.
void TestUnknownOldSpellings() {
  ProxyArgs a;
  std::string error;
  const std::string key = "--key=" + std::string(kGoodKey);
  const char* kOld[] = {"--key-file=/tmp/psk", "-k/tmp/psk", "--host=10.0.0.1",
                        "--port=5000",           "--k=3",          "--p-max=6",
                        "--rate-limit=8",        "--log=debug",    "-v",
                        "--version",             "-V"};
  for (const char* arg : kOld) {
    CHECK(!TryParse(EngineRole::kServer, {key, arg}, &a, &error));
    CHECK(error.find("unknown argument") != std::string::npos);
    CHECK(error.find(arg) != std::string::npos);
  }
  CHECK(!TryParse(EngineRole::kServer, {"--help", "--version"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "--host=x"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
}

// The old autotune notes ("receive capacity follows the MAX", ":MAX lowered
// the start") are gone with the ceiling: one knob, one derived ceiling, no
// silent overrides left to explain. A clean default command line stays quiet.
void TestAutotuneNotes() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };
  CHECK(ok({}));
  CHECK(a.notes.empty());
  CHECK(ok({"--window-min=512"}));
  CHECK(a.notes.empty());
}
// Address semantics after #91: one spelling per concept, the port travels
// inside the address. --peer is client-only, -b/--bind is the local side.
void TestRoleRequirements() {
  ProxyArgs a;
  std::string error;
  const std::string key = "--key=" + std::string(kGoodKey);

  // The client needs somewhere to connect; the server does not.
  CHECK(!TryParse(EngineRole::kClient, {key}, &a, &error));
  CHECK(error.find("--peer") != std::string::npos);
  CHECK(TryParse(EngineRole::kServer, {key}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("0.0.0.0"));
  CHECK_EQ(a.ro.bind_port, 4460);

  // Client: peer + local proxy bind, both address-shaped.
  CHECK(TryParse(EngineRole::kClient,
                 {key, "--peer=203.0.113.7:5000", "-b", "127.0.0.1:1180"},
                 &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("203.0.113.7"));
  CHECK_EQ(a.ro.remote_port, 5000);
  CHECK_EQ(a.ro.listen_addr, std::string("127.0.0.1"));
  CHECK_EQ(a.ro.listen_port, 1180);

  // Server: UDP bind, address carries its port.
  CHECK(TryParse(EngineRole::kServer, {key, "--bind=192.168.1.1:5001"}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("192.168.1.1"));
  CHECK_EQ(a.ro.bind_port, 5001);

  // Role-specific options are errors on the other side.
  CHECK(!TryParse(EngineRole::kServer,
                  {key, "--peer=10.0.0.1:40000"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer,
                  {key, "-b", "127.0.0.1:1080", "--stall-ms=1000"}, &a, &error));
  CHECK(error.find("--stall-ms") != std::string::npos);
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=10.0.0.1:40000", "--speedtest"},
                 &a, &error));  // the bare one-shot form is client-only
  CHECK(!TryParse(EngineRole::kServer,
                  {key, "--speedtest=5"}, &a, &error));
  CHECK(error.find("one-shot") != std::string::npos);  // =SECONDS names a run
}
void TestShortAndCompoundAddresses() {
  ProxyArgs a;
  std::string error;
  const std::string key = "--key=" + std::string(kGoodKey);

  // Separate, attached and =value forms of a value option (-b only: -H/-l/-m
  // are gone with #91; --peer has no short form).
  CHECK(TryParse(EngineRole::kServer, {key, "-b", "127.0.0.1:1180"}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("127.0.0.1"));
  CHECK_EQ(a.ro.bind_port, 1180);
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=198.51.100.9:4700"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("198.51.100.9"));
  CHECK_EQ(a.ro.remote_port, 4700);
  CHECK(TryParse(EngineRole::kServer, {key, "--mtu=1500"}, &a, &error));
  CHECK_EQ(a.ec.mtu, 1500);

  // Attached-value form works for the surviving short option (-b).
  CHECK(TryParse(EngineRole::kServer, {key, "-b:1180"}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("0.0.0.0"));
  CHECK_EQ(a.ro.bind_port, 1180);

  // -b :PORT keeps the default address; the server needs nothing else but keys.
  CHECK(TryParse(EngineRole::kServer, {key, "-b", ":40000"}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("0.0.0.0"));
  CHECK_EQ(a.ro.bind_port, 40000);

  // -k was --key-file: both are gone, and the short form must not become a
  // way to put the PSK back into `ps`.
  CHECK(!TryParse(EngineRole::kServer, {"-k", "some-path"}, &a, &error));
  CHECK(error.find("unknown") != std::string::npos);

  // The address carries its own port; repeating it via a separate spelling is
  // impossible now -- there is no --port to conflict with.
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=host.example"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("host.example"));
  CHECK_EQ(a.ro.remote_port, 4460);
  // Several colons are an IPv6 literal (unsupported: the tunnel socket is
  // AF_INET), not host:port -- it must not be split into ":" plus port 1.
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=::1:4000"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("::1:4000"));
  CHECK_EQ(a.ro.remote_port, 4460);

  // A non-numeric suffix is not a port: the whole value stays the address.
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=host.example:abc"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("host.example:abc"));
  CHECK_EQ(a.ro.remote_port, 4460);
  // Several colons are an IPv6 literal (unsupported: the tunnel socket is
  // AF_INET), not host:port -- it must not be split into ":" plus port 1.
  CHECK(TryParse(EngineRole::kClient, {key, "--peer=::1:4000"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("::1:4000"));
  CHECK_EQ(a.ro.remote_port, 4460);  // several colons: kept whole, default port

  // Short-option errors name the short spelling and the value it needs.
  CHECK(!TryParse(EngineRole::kServer, {key, "-b"}, &a, &error));
  CHECK(error.find("-b") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "-vx"}, &a, &error));
  CHECK(error.find("takes no value") != std::string::npos ||
        error.find("unknown") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "-z"}, &a, &error));
  CHECK(error.find("unknown") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "--mtu=70000"}, &a, &error));
  CHECK(error.find("--mtu") != std::string::npos);
}

void TestNumericRanges() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // --mtu: below the codec minimum and above the uint16 wire field.
  CHECK(!ok({"--mtu=255"}));
  CHECK(!ok({"--mtu=70000"}));   // used to wrap to 4464
  CHECK(ok({"--mtu=256"}));
  CHECK_EQ(a.ec.mtu, 256);
  CHECK(ok({"--mtu=1400"}));
  CHECK(a.mtu_explicit);  // blocks the interface-derived default at startup
  CHECK(ok({}));
  CHECK(!a.mtu_explicit);  // a reused ProxyArgs must not keep the old flag

  // The pair limit (P8-4) on the one spelling there is. --d/--p were removed
  // with the 0.0.1 parameter cleanup: --p would also collide with -p (port).
  CHECK(!ok({"--fec=250:7"}));  // 257 > 256
  CHECK(ok({"--fec=249:7"}));   // exactly 256
  CHECK(!ok({"--d=10"}));
  CHECK(error.find("unknown") != std::string::npos);
  CHECK(!ok({"--p=3"}));
  CHECK(error.find("unknown") != std::string::npos);

  // --k and --fec-budget are gone (controller adaptive; decision #91 + the
  // FEC formula change): every spelling is an unknown argument.
  CHECK(!ok({"--k=3"}));
  CHECK(!ok({"--fec-budget=0.5"}));
  CHECK(error.find("unknown") != std::string::npos);

  // --window-min: one knob, 1..1048576 KiB, floored by two segments at this
  // --mtu (default 1400 -> 2672 B, so 1 KiB is refused and 4 KiB accepted).
  CHECK(!ok({"--window-min=1"}));
  CHECK(ok({"--window-min=4"}));
  CHECK_EQ(a.ec.window_min_bytes, 4u * 1024);
  CHECK(!ok({"--window-min=1048577"}));
  CHECK(!ok({"--window-min=512:1024"}));
  CHECK(!ok({"--window-min=:"}));
  CHECK(!ok({"--window-min:"}));
  CHECK(!ok({"--window-min"}));  // a value option given bare
  // Every parse failure must come with a message, not an empty line.
  CHECK(!error.empty());

  // --max-sessions / --idle / --dial-timeout bounds.
  CHECK(!ok({"--max-sessions=0"}));
  CHECK(ok({"--max-sessions=65536"}));
  CHECK(!ok({"--idle=0"}));
  CHECK(!ok({"--dial-timeout=0"}));

  // Ports: 0 and 65536 reject on either side.
  const auto okc = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kClient, args, &a, &error);
  };
  // The port travels inside the address (--peer=IP:P); --port is gone.
  CHECK(!okc({"--port=65535"}));
  CHECK(error.find("unknown") != std::string::npos);
  CHECK(!okc({"--local-port=1180"}));
  CHECK(error.find("unknown") != std::string::npos);

  // Full-string parse: trailing junk after the number is not a number.
  CHECK(!ok({"--mtu=1400x"}));
}

void TestFecAliases() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // The compound form sets both halves in one option.
  CHECK(ok({"--fec=10:3"}));
  CHECK_EQ(a.ec.d, 10);
  CHECK_EQ(a.ec.p, 3);
  CHECK(ok({"--fec=20:5"}));
  CHECK_EQ(a.ec.d, 20);
  CHECK_EQ(a.ec.p, 5);
  // D alone is legal: P keeps its default.
  CHECK(ok({"--fec=30"}));
  CHECK_EQ(a.ec.d, 30);
  CHECK_EQ(a.ec.p, 3);

  // Both halves are range-checked, and their sum has the protocol limit.
  CHECK(!ok({"--fec=0:3"}));
  CHECK(!ok({"--fec=10:8"}));
  CHECK(!ok({"--fec=250:7"}));
  CHECK(!ok({"--fec=10:3:1"}));
  CHECK(!ok({"--fec=10:"}));
  CHECK(!error.empty());  // a bare colon must not become a blank diagnostic
  CHECK(!ok({"--fec=:3"}));
  CHECK(!error.empty());
  CHECK(!ok({"--fec="}));
  CHECK(!error.empty());

  CHECK(!ok({"--fec=10:3", "--fec=10:4"}));
  CHECK(error.find("more than once") != std::string::npos);

  // --p-max and --k are gone: P from --fec is the only ceiling, the
  // controller adapts k. Every spelling is an unknown argument.
  CHECK(!ok({"--p-max=7"}));
  CHECK(!ok({"--k=4"}));
  CHECK(error.find("unknown") != std::string::npos);
}

// --window-min: one knob. The ceiling is derived (2x the floor), so there is
// no START/MAX pair, no ":MAX", and no fixed-window mode to spell out.
void TestWindowForms() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };
  if (!ok({"--window-min=512"})) {
    std::fprintf(stderr, "DBG window-min error: %s\n", error.c_str());
  }
  CHECK(ok({"--window-min=512"}));
  CHECK_EQ(a.ec.window_min_bytes, 512u * 1024);
  CHECK_EQ(a.ec.send_window_bytes, 512u * 1024);
  CHECK(a.ec.window_explicit);  // the prewarm prior must not replace it

  // Removed spellings are unknown arguments.
  CHECK(!ok({"--window=512"}));
  CHECK(!ok({"--window=512:2048"}));
  CHECK(!ok({"--window=:2048"}));
  CHECK(!ok({"--no-auto-window"}));
  CHECK(!ok({"--auto-window"}));
  CHECK(!ok({"--window-cap=2048"}));
  CHECK(error.find("unknown argument") != std::string::npos);

  // Floor bounds: must cover two segments at this --mtu (default 1400 ->
  // payload 1336 x 2 = 2672 B, so 1 KiB is refused and 4 KiB is accepted).
  CHECK(!ok({"--window-min=1"}));
  CHECK(ok({"--window-min=4"}));
  CHECK_EQ(a.ec.window_min_bytes, 4u * 1024);

  // Repeats and non-numeric values are the usual loud failures.
  CHECK(!ok({"--window-min=512", "--window-min=1024"}));
  CHECK(error.find("more than once") != std::string::npos);
  CHECK(!ok({"--window-min=abc"}));
  CHECK(!error.empty());

  // Default: 2 MiB floor, ceiling derived per stream (2 x), nothing explicit.
  ProxyArgs d;
  CHECK(Ok(EngineRole::kServer, {}, &d, &error));
  CHECK_EQ(d.ec.window_min_bytes, 2u * 1024 * 1024);
  CHECK_EQ(d.ec.send_window_bytes, 2u * 1024 * 1024);
  CHECK(!d.ec.window_explicit);
}
void TestLogFileFlag() {
  ProxyArgs a;
  std::string error;

  CHECK(Ok(EngineRole::kServer, {}, &a, &error));
  CHECK(a.ro.log_file.empty());
  CHECK(Ok(EngineRole::kClient, {"--log-file=/var/log/fcp"}, &a, &error));
  CHECK_EQ(a.ro.log_file, "/var/log/fcp");
  CHECK(Ok(EngineRole::kServer, {"--log-file=C:\\logs\\server.log"}, &a, &error));
  CHECK_EQ(a.ro.log_file, "C:\\logs\\server.log");
  CHECK(!Ok(EngineRole::kClient, {"--log-file=a", "--log-file=b"}, &a, &error));
  CHECK(error.find("more than once") != std::string::npos);
}

void TestDefaultsSurvive() {
  ProxyArgs a;
  std::string error;
  CHECK(Ok(EngineRole::kClient, {}, &a, &error));
  CHECK_EQ(a.ec.mtu, 1400);
  CHECK_EQ(a.ec.d, 10);
  CHECK_EQ(a.ec.p, 3);
  CHECK_EQ(a.ec.pinned_k, -1);
  CHECK_EQ(a.ec.fec_budget, 0.80);
  CHECK_EQ(a.ec.send_window_bytes, 2u * 1024 * 1024);
  CHECK_EQ(a.ec.window_min_bytes, 2u * 1024 * 1024);
  CHECK_EQ(a.ec.rcv_buf_bytes, 256u * 1024);
  CHECK_EQ(a.ec.max_sessions, 256u);
  CHECK_EQ(a.ec.idle_timeout_ms, 300000);
  CHECK_EQ(a.ec.dial_timeout_ms, 5000);
  CHECK(a.ec.prewarm);
  CHECK(a.ro.remote_port == 4460 && a.ro.listen_port == 1080);
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));  // 默认 debug
  CHECK_EQ(a.ro.stats_ms, 0);
  CHECK_EQ(a.ro.connect_timeout_ms, 5000);
  CHECK(a.ec.trace_prefix.empty());
  // Wire-side defaults: coalesced ACKs. The ceiling is derived per stream
  // (2 x --window-min), so --max-sessions now only bounds the count.
  CHECK_EQ(static_cast<int>(a.ec.ack_every), 2);
  ProxyArgs few;
  CHECK(Ok(EngineRole::kServer, {"--max-sessions=64"}, &few, &error));
  CHECK_EQ(few.ec.window_min_bytes, 2u * 1024 * 1024);

  // Upward PMTUD is on with the built-in 1500 ceiling; --no-pmtud turns it
  // off; the positive spelling never existed.
  CHECK(a.ec.pmtud);
  CHECK_EQ(a.ec.pmtu_max_mtu, 1500);
  ProxyArgs no_pmtu;
  CHECK(Ok(EngineRole::kClient, {"--no-pmtud"}, &no_pmtu, &error));
  CHECK(!no_pmtu.ec.pmtud);
  // The ladder only climbs, so an --mtu at or above the built-in ceiling
  // leaves nothing to discover (the config clamps ceiling to the start).
  ProxyArgs big_mtu;
  CHECK(Ok(EngineRole::kClient, {"--mtu=2000"}, &big_mtu, &error));
  CHECK_EQ(big_mtu.ec.pmtu_max_mtu, 2000u);
  CHECK(!Ok(EngineRole::kClient, {"--pmtu-max=1500"}, &no_pmtu, &error));
  // The positive spelling is gone: PMTUD is on unless told otherwise.
  CHECK(!Ok(EngineRole::kClient, {"--pmtud"}, &no_pmtu, &error));
  CHECK(error.find("unknown") != std::string::npos);

  // UDP GRO receive aggregation defaults on; the flag retires it for hosts
  // where the benchmark says the deep copies cost more than the interrupts.
  CHECK(a.ro.udp_gro);
  ProxyArgs no_gro;
  CHECK(Ok(EngineRole::kClient, {"--no-udp-gro"}, &no_gro, &error));
  CHECK(!no_gro.ro.udp_gro);
}

void TestMetaFlagsWinOverBadValues() {
  ProxyArgs a;
  std::string error;

  // --help short-circuits before any value is parsed: scripts append it to a
  // long line and a stale value elsewhere in that line must not turn a
  // diagnostic into a usage error. In particular no PSK is required.
  CHECK(TryParse(EngineRole::kServer, {"--help", "--stall-ms=abc"}, &a, &error));
  CHECK(a.help);
  CHECK(TryParse(EngineRole::kServer, {"--stall-ms=abc", "--help"}, &a, &error));
  CHECK(a.help);
  // Removed spellings are checked first on purpose, so --version explains
  // itself instead of being swallowed by the usage text (fcp-node contract).
  CHECK(!TryParse(EngineRole::kServer, {"--help", "--version"}, &a, &error));
  CHECK(error.find("--version") != std::string::npos);

  // Everything else fails loudly, and every failure carries a message (an
  // empty one would print a blank line before the usage block).
  CHECK(!TryParse(EngineRole::kServer, {"-x"}, &a, &error));
  CHECK(error.find("-x") != std::string::npos);
  CHECK(!TryParse(EngineRole::kServer, {"--"}, &a, &error));
  CHECK(!error.empty());
}

void TestFlagsAndValues() {
  ProxyArgs a;
  std::string error;
  CHECK(Ok(EngineRole::kServer,
           {"--no-prewarm", "--metrics=/tmp/calib", "--dial-timeout=2500"},
           &a, &error));
  CHECK(!a.ec.prewarm);
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));  // default
  CHECK_EQ(a.ec.trace_prefix, std::string("/tmp/calib"));
  // One dial budget feeds the reactor's per-address connect timer too.
  CHECK_EQ(a.ec.dial_timeout_ms, 2500);
  CHECK_EQ(a.ro.connect_timeout_ms, 2500);
  CHECK(Ok(EngineRole::kServer,
           {"--max-sessions=512", "--idle=1000", "--no-prewarm"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));
  CHECK(!a.ec.prewarm);
  CHECK_EQ(a.ec.max_sessions, 512u);
  CHECK_EQ(a.ec.idle_timeout_ms, 1000);
  // --stats 回来了，且是独立旋钮（0 = 关）。
  CHECK(Ok(EngineRole::kServer, {"--stats=1000"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 1000);
  CHECK(Ok(EngineRole::kServer, {"--stats=0"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 0);
  CHECK(!Ok(EngineRole::kServer, {"--stats=-1"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--stats=abc"}, &a, &error));

  // Outside help, a value error always has a message.
  CHECK(!Ok(EngineRole::kServer, {"--mtu=abc"}, &a, &error));
  CHECK(error.find("--mtu") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--log-level=chatty"}, &a, &error));
  CHECK(error.find("--log-level") != std::string::npos);

  // --log-level=LEVEL 四个阈值（verbose 别名已删除）；周期统计归 --stats。
  CHECK(Ok(EngineRole::kServer, {"--log-level=off"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kOff));
  CHECK_EQ(a.ro.stats_ms, 0);  // --log 不再影响统计
  CHECK(Ok(EngineRole::kServer, {"--log-level=off", "--stats=5000"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 5000);
  CHECK(Ok(EngineRole::kServer, {"--log-level=error"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kError));
  CHECK(Ok(EngineRole::kServer, {"--log-level=warn"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kWarn));
  CHECK(Ok(EngineRole::kServer, {"--log-level=info"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kInfo));
  CHECK(Ok(EngineRole::kServer, {"--log-level=debug"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));
  CHECK(!Ok(EngineRole::kServer, {"--log-level=verbose"}, &a, &error));
  CHECK(error.find("--log-level") != std::string::npos);
  CHECK(Ok(EngineRole::kServer, {"--log-level=debug", "--stats=1500"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));
  CHECK_EQ(a.ro.stats_ms, 1500);
  CHECK(!Ok(EngineRole::kServer, {"--log-level=chatty"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log-level=debug", "--log-level=off"}, &a, &error));

  // 阈值判定的唯一实现：启动期提示（cli main）、汇集点与文件存档共用。
  // 这组断言盯的正是"note()/启动提示绕过 --log"那类回归。
  CHECK(Wanted(Severity(LogLevel::kWarn), Severity(LogLevel::kWarn)));
  CHECK(!Wanted(Severity(LogLevel::kInfo), Severity(LogLevel::kWarn)));
  CHECK(!Wanted(Severity(LogLevel::kError), Severity(LogLevel::kOff)));
  CHECK(!Wanted(Severity(LogLevel::kDebug), Severity(LogLevel::kInfo)));
  CHECK(Wanted(Severity(LogLevel::kInfo), Severity(LogLevel::kDebug)));

  // --help short-circuits into out->help instead of a key error.
  CHECK(TryParse(EngineRole::kServer, {"--help"}, &a, &error));
  CHECK(a.help);
  CHECK(TryParse(EngineRole::kClient, {"-h"}, &a, &error));
  CHECK(a.help);

  // --version/-V are gone; -h is the single place to ask, and its first line
  // carries the release version. Old spellings are plain unknown options.
  CHECK(!TryParse(EngineRole::kServer, {"--version"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
  CHECK(error.find("--version") != std::string::npos);
  CHECK(!TryParse(EngineRole::kServer, {"-V"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);

    // Positional junk is a usage error, not a silently ignored token.
  CHECK(!TryParse(EngineRole::kServer, {"stray"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
  // An unknown long option names itself, and a value on a bare flag is a typo.
  CHECK(!Ok(EngineRole::kServer, {"--nonsense=1"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--no-prewarm=1"}, &a, &error));
}

void TestSpeedTestFlags() {
  ProxyArgs a;
  std::string error;

  // Server: the bare flag enables the frame-layer responder on the FCP port.
  CHECK(Ok(EngineRole::kServer, {"--speedtest"}, &a, &error));
  CHECK(a.ro.speedtest);
  // A duration belongs to the client's one-shot run only.
  CHECK(!Ok(EngineRole::kServer, {"--speedtest=8"}, &a, &error));
  CHECK(error.find("client") != std::string::npos);

  // Client: --speedtest switches to one bench run and leaves the proxy alone.
  CHECK(Ok(EngineRole::kClient, {"--speedtest"}, &a, &error));
  CHECK(a.speedtest);
  CHECK_EQ(a.speedtest_seconds, 8);
  CHECK(Ok(EngineRole::kClient, {"--speedtest=12"}, &a, &error));
  CHECK_EQ(a.speedtest_seconds, 12);

  // The optional value is attached with '=' only; the old separate spelling
  // is now a removed option, not a silent second way to say the same thing.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest="}, &a, &error));
  CHECK(error.find("value after '='") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--speedtest-port=9001"}, &a, &error));
  // Range guards: the run takes 2 x N seconds, so the window is bounded.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest=1"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--speedtest=2"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--speedtest=31"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--speedtest=abc"}, &a, &error));
}

void TestStallFlag() {
  ProxyArgs a;
  std::string error;

  // The watchdog is a client flag: the server's inbound stream is watched
  // from the end that feeds it.
  CHECK(Ok(EngineRole::kClient, {}, &a, &error));
  CHECK_EQ(a.ro.stall_ms, 60000);
  CHECK(Ok(EngineRole::kClient, {"--stall-ms=15000"}, &a, &error));
  CHECK_EQ(a.ro.stall_ms, 15000);
  CHECK(Ok(EngineRole::kClient, {"--stall-ms=0"}, &a, &error));
  CHECK_EQ(a.ro.stall_ms, 0);
  CHECK(!Ok(EngineRole::kServer, {"--stall-ms=15000"}, &a, &error));
  CHECK(error.find("client") != std::string::npos);
  CHECK(!Ok(EngineRole::kClient, {"--stall-ms=-1"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--stall-ms=abc"}, &a, &error));

  // --rate-limit is gone; there is no compatibility shim.
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=8"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
  CHECK(error.find("--rate-limit") != std::string::npos);
}

void TestCcFlag() {
  ProxyArgs a;
  std::string error;

  // BBR is the only adaptive-window controller; --cc was removed with the
  // epoch controller, so every spelling of it is now an unknown argument.
  CHECK(Ok(EngineRole::kServer, {}, &a, &error));
  CHECK_EQ(a.ec.bbr_version, 2);
  CHECK(!Ok(EngineRole::kServer, {"--cc=bbr2"}, &a, &error));
  CHECK(error.find("--cc") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--cc=epoch"}, &a, &error));
  // The window-probe switch went with the same controller.
  CHECK(!Ok(EngineRole::kServer, {"--no-window-probe"}, &a, &error));
}

void TestBenchCodec() {
  using namespace fcp::bench;

  uint8_t salt[kSaltLen] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t rendezvous[kRendezvousLen] = {};
  CHECK(EncodeRendezvous(salt, 8, rendezvous));
  uint8_t got_salt[kSaltLen] = {};
  uint16_t seconds = 0;
  CHECK(DecodeRendezvous(rendezvous, sizeof(rendezvous), got_salt, &seconds));
  CHECK(std::memcmp(salt, got_salt, sizeof(salt)) == 0);
  CHECK_EQ(seconds, 8);
  // A short datagram, or a 20-byte one that is not the magic, is not ours.
  CHECK(!DecodeRendezvous(rendezvous, sizeof(rendezvous) - 1, got_salt, &seconds));
  uint8_t junk[kRendezvousLen] = {};
  CHECK(!DecodeRendezvous(junk, sizeof(junk), got_salt, &seconds));
  // The echo is exactly the 8-byte magic, not the full rendezvous.
  CHECK(IsMagic(kMagic, kMagicLen));
  CHECK(!IsMagic(rendezvous, sizeof(rendezvous)));
  CHECK(!IsMagic(rendezvous, kMagicLen - 1));
  // The server tells complete from truncated rendezvous apart with the prefix
  // test; IsMagic must not blur the two.
  CHECK(IsMagicPrefix(rendezvous, sizeof(rendezvous)));
  CHECK(IsMagicPrefix(rendezvous, kMagicLen + 3));
  CHECK(!IsMagicPrefix(rendezvous, kMagicLen - 1));
  CHECK(!IsMagicPrefix(nullptr, kMagicLen));

  const uint64_t user = UserBytes(kDataPayloadLen);
  CHECK_EQ(user, static_cast<uint64_t>(kDataPayloadLen - kHeaderLen));

  uint8_t payload[kDataPayloadLen] = {};
  EncodeData(42, payload, sizeof(payload));
  DecodedPayload decoded;
  CHECK(DecodePayload(payload, sizeof(payload), &decoded));
  CHECK(decoded.type == PayloadType::kData);
  CHECK_EQ(decoded.sn, 42u);
  CHECK_EQ(decoded.delivered, 0ull);

  uint8_t report[kReportPayloadLen] = {};
  EncodeReport(7, 123456789ull, 987654321ull, 424242ull, 555666ull, 987654u, true,
               report, sizeof(report));
  CHECK(DecodePayload(report, sizeof(report), &decoded));
  CHECK(decoded.type == PayloadType::kReport);
  CHECK_EQ(decoded.sn, 7u);
  CHECK_EQ(decoded.delivered, 123456789ull);
  CHECK_EQ(decoded.best_bps, 987654321ull);
  CHECK_EQ(decoded.down_wire_bps, 424242ull);
  CHECK_EQ(decoded.down_sent, 555666ull);
  CHECK_EQ(decoded.capped_ratio_ppm, 987654u);
  CHECK(decoded.capped);
  // Truncated report, truncated header, and a wrong version are all rejected.
  CHECK(!DecodePayload(report, kReportPayloadLen - 1, &decoded));
  CHECK(!DecodePayload(report, kHeaderLen + 4, &decoded));
  CHECK(!DecodePayload(report, kHeaderLen - 1, &decoded));
  uint8_t bad_version[kReportPayloadLen];
  std::memcpy(bad_version, report, sizeof(report));
  bad_version[kMagicLen] = static_cast<uint8_t>(bad_version[kMagicLen] ^ 0xFF);
  CHECK(!DecodePayload(bad_version, sizeof(bad_version), &decoded));

  // Down report: the client's delivery evidence for the server's controller.
  uint8_t down_report[kDownReportPayloadLen] = {};
  EncodeDownReport(11, 987654321ull, 123456ull, down_report, sizeof(down_report));
  CHECK(DecodePayload(down_report, sizeof(down_report), &decoded));
  CHECK(decoded.type == PayloadType::kDownReport);
  CHECK_EQ(decoded.sn, 11u);
  CHECK_EQ(decoded.delivered, 987654321ull);
  CHECK_EQ(decoded.best_bps, 123456ull);
  CHECK_EQ(decoded.down_sent, 0ull);
  CHECK(!decoded.capped);
  CHECK(!DecodePayload(down_report, kDownReportPayloadLen - 1, &decoded));

  // Ping payloads are kHeaderLen + ts; the echo flips only the type byte.
  uint8_t ping[kPingPayloadLen] = {};
  EncodePing(9, 1234567890123ull, ping, sizeof(ping));
  CHECK(DecodePayload(ping, sizeof(ping), &decoded));
  CHECK(decoded.type == PayloadType::kPing);
  CHECK_EQ(decoded.sn, 9u);
  CHECK_EQ(decoded.timestamp, 1234567890123ull);
  CHECK_EQ(decoded.delivered, 0ull);
  EncodePingEcho(9, 1234567890123ull, ping, sizeof(ping));
  CHECK(DecodePayload(ping, sizeof(ping), &decoded));
  CHECK(decoded.type == PayloadType::kPingEcho);
  CHECK_EQ(decoded.timestamp, 1234567890123ull);
  // A ping with only its header is rejected.
  CHECK(!DecodePayload(ping, kHeaderLen, &decoded));

  // RateController against a lagged capped path: arrivals answer the PREVIOUS
  // epoch's offer (one RTT late), so the controller's lag-tolerant ratio
  // (got / previous offer) must read a healthy climb as healthy, and converge
  // exactly when the offered size first exceeds the path's cap. The naive
  // current-epoch ratio would read the climb itself as loss and converge on
  // the first ramp step.
  struct LagPath {
    double cap;       // bits/s the path can deliver
    uint64_t sent = 0;
    uint64_t got = 0;
    uint64_t prev_offered = 0;  // bytes offered last epoch
    int64_t now = 0;
    double Feed(RateController& ctrl, double offered_bps) {
      now += 250;
      const uint64_t offered = static_cast<uint64_t>(offered_bps / 8.0 * 0.25);
      const uint64_t deliverable = static_cast<uint64_t>(cap / 8.0 * 0.25);
      const uint64_t arrive = std::min(prev_offered, deliverable);
      prev_offered = offered;
      sent += offered;
      got += arrive;
      return ctrl.Feed(now, sent, got);
    }
  };

  // The real-shaped case: 52.5 Mbps uplink (measured on the WAN test path).
  {
    LagPath path{52.5e6};
    RateController ctrl;
    ctrl.Reset(0);
    double rate = ctrl.rate();
    double max_seen = 0.0;
    double min_after_cap = 1e12;
    bool saw_capped = false;
    bool saw_healthy_window = false;
    for (int i = 0; i < 24; ++i) {  // 6 seconds
      rate = path.Feed(ctrl, rate);
      max_seen = std::max(max_seen, rate);
      if (saw_capped) {
        min_after_cap = std::min(min_after_cap, rate);
        // The hold windows read no alarm-worthy loss (backlog washes out);
        // probe epochs dilute the ratio by design, so any healthy window
        // counts, not the last one.
        saw_healthy_window = saw_healthy_window || ctrl.capped_ratio_ppm() > 900000;
      }
      saw_capped = saw_capped || ctrl.state() == RateController::State::kCapped;
    }
    CHECK(saw_capped);
    // After the first convergence the controller keeps returning to the cap
    // (probes above it, re-converges on the loss it sees there).
    CHECK(min_after_cap <= 52.5e6 * 1.06);
    // And it does probe above the cap: the ceiling is re-checked, not frozen.
    CHECK(max_seen > 52.5e6 * 1.2);
    CHECK(max_seen <= kMaxBps);
    CHECK(saw_healthy_window);
  }

  // An uncapped path climbs all the way and reports no ceiling.
  {
    LagPath path{1e10};
    RateController ctrl;
    ctrl.Reset(0);
    double rate = ctrl.rate();
    for (int i = 1; i <= 12; ++i) {
      rate = path.Feed(ctrl, rate);
      // During a pure healthy climb (no cap) the controller must never
      // converge -- this is the premature-convergence regression.
      if (i <= 8) {
        CHECK(ctrl.state() == RateController::State::kProbing);
      }
    }
    CHECK(ctrl.state() == RateController::State::kMaxed);
    CHECK(ctrl.rate() == kMaxBps);
    CHECK(ctrl.capped_ratio_ppm() == 0);
  }

  // No offering between reports: nothing learned, nothing changed.
  {
    LagPath path{52.5e6};
    RateController ctrl;
    ctrl.Reset(0);
    path.Feed(ctrl, kStartBps);
    const double frozen = ctrl.rate();
    const uint32_t ppm = ctrl.capped_ratio_ppm();
    ctrl.Feed(1750, path.sent, path.got);  // same totals: no delta
    CHECK(ctrl.rate() == frozen);
    CHECK(ctrl.capped_ratio_ppm() == ppm);
  }

  // A path that carries everything up to the probe ceiling ends kMaxed.
  RateController maxed;
  maxed.Reset(0);
  uint64_t sent = 0;
  uint64_t got = 0;
  for (int i = 1; i <= 16; ++i) {
    const double rate = maxed.rate();
    sent += static_cast<uint64_t>(rate / 8.0 * 0.25);
    got = sent;
    maxed.Feed(i * 250, sent, got);
  }
  CHECK(maxed.state() == RateController::State::kMaxed);
  CHECK(maxed.rate() == kMaxBps);
  CHECK(maxed.capped_ratio_ppm() == 0);

  // RateWindow: 1000 bytes per 100ms for one second = 80000 bps. A single
  // burst narrower than half a window must not set a peak.
  RateWindow window;
  for (int i = 0; i < 10; ++i) {
    window.Add(i * 100, 1000);
  }
  CHECK_EQ(window.total_bytes(), 10000ull);
  CHECK_EQ(window.best_bps(), 80000ull);
  RateWindow burst;
  burst.Add(0, 100000);
  CHECK_EQ(burst.best_bps(), 0ull);
  // A gap only narrows the span over slots that still hold data, so a
  // stalled-then-resumed receiver is not credited with a rate it never ran.
  RateWindow gap;
  for (int i = 0; i < 10; ++i) {
    gap.Add(i * 100, 1000);
  }
  gap.Add(5000, 1000);  // 4s of silence, then a lone slot
  CHECK_EQ(gap.best_bps(), 80000ull);
  CHECK_EQ(gap.total_bytes(), 11000ull);

  // The bench gate admits exactly one run at a time in a process.
  std::string gate_error;
  CHECK(BenchGate(&gate_error));
  CHECK(!BenchGate(&gate_error));
  CHECK(!gate_error.empty());
  BenchRelease();
  CHECK(BenchGate(&gate_error));
  BenchRelease();
}

void TestEnvironmentDefaults() {
  using fcp::MtuForInterface;
  // Both arguments are IP packet sizes, so the adjustment is a plain min; the
  // codec subtracts IP+UDP once, from compute_mtu_limits().
  CHECK_EQ(MtuForInterface(1400, 1500), 1400);  // interface has room
  CHECK_EQ(MtuForInterface(1400, 1428), 1400);  // interface above the budget
  CHECK_EQ(MtuForInterface(1400, 1420), 1400);  // still room for 1400
  CHECK_EQ(MtuForInterface(1400, 1280), 1280);  // IPv6 minimum link
  CHECK_EQ(MtuForInterface(1200, 1500), 1200);  // explicit lower stays
  CHECK_EQ(MtuForInterface(1400, 0), 1400);     // query failed
  CHECK_EQ(MtuForInterface(1400, 100), 1400);   // no valid budget

  // The interface only ever lowers the start; when it does, the PMTUD ceiling
  // follows it down (a probe above the local interface is an EMSGSIZE). A
  // larger interface must leave the ladder intact -- clamping the ceiling on
  // every run silently disabled PMTUD on the usual 1500 interfaces.
  ProxyArgs on_lan;
  fcp::ApplyInterfaceMtu(1500, &on_lan);
  CHECK_EQ(on_lan.ec.mtu, 1400);
  CHECK_EQ(on_lan.ec.pmtu_max_mtu, 1500);
  CHECK(on_lan.notes.empty());
  ProxyArgs on_vpn;
  fcp::ApplyInterfaceMtu(1280, &on_vpn);
  CHECK_EQ(on_vpn.ec.mtu, 1280);
  CHECK_EQ(on_vpn.ec.pmtu_max_mtu, 1280);
  CHECK_EQ(on_vpn.notes.size(), 1u);

  // An explicit --mtu above the interface is the operator's call and is kept,
  // but PMTUD has to go: DF is set on the whole socket, so every datagram at
  // that size would come back EMSGSIZE instead of being fragmented.
  ProxyArgs explicit_too_big;
  explicit_too_big.mtu_explicit = true;
  explicit_too_big.ec.pmtu_max_mtu = 1500;
  fcp::ApplyInterfaceMtu(1280, &explicit_too_big);
  CHECK_EQ(explicit_too_big.ec.mtu, 1400);
  CHECK(!explicit_too_big.ec.pmtud);
  CHECK_EQ(explicit_too_big.notes.size(), 1u);
  CHECK(explicit_too_big.notes[0].find("PMTUD disabled") != std::string::npos);
  // Already off: saying it twice helps nobody.
  fcp::ApplyInterfaceMtu(1280, &explicit_too_big);
  CHECK_EQ(explicit_too_big.notes.size(), 1u);

  // Explicit but fitting: PMTUD stays, and the ceiling is untouched.
  ProxyArgs explicit_fits;
  explicit_fits.mtu_explicit = true;
  fcp::ApplyInterfaceMtu(1500, &explicit_fits);
  CHECK(explicit_fits.ec.pmtud);
  CHECK_EQ(explicit_fits.ec.pmtu_max_mtu, 1500);
  CHECK(explicit_fits.notes.empty());

  fcp::ResourceLimits unknown;  // -1 = platform has no equivalent (Windows)
  fcp::EngineConfig ec;         // auto window, 2 MiB floor, derived ceiling
  // The 512 MiB budget promise does not exist any more (the ceiling is derived
  // per stream, not budgeted through --max-sessions), so this test picks a
  // floor that keeps the worst case under the 128 MiB address space used below.
  ec.window_min_bytes = 64 * 1024;
  ec.rcv_buf_bytes = 64 * 1024;
  CHECK(fcp::ResourceNotes(fcp::EngineRole::kServer, ec, unknown).empty());

  fcp::ResourceLimits fds;
  fds.open_files = 100;
  std::vector<std::string> notes =
      fcp::ResourceNotes(fcp::EngineRole::kServer, ec, fds);
  CHECK_EQ(notes.size(), 1u);
  CHECK(notes[0].find("file descriptors") != std::string::npos);

  fds.open_files = 4096;
  CHECK(fcp::ResourceNotes(fcp::EngineRole::kServer, ec, fds).empty());

  // Worst case is ~2 MiB per session at the default 1 MiB ceiling: 256 of
  // those exceed a 128 MiB address space even though nothing is reserved yet.
  fcp::ResourceLimits mem;
  mem.open_files = 4096;
  mem.address_space = 128L * 1024 * 1024;
  notes = fcp::ResourceNotes(fcp::EngineRole::kServer, ec, mem);
  CHECK_EQ(notes.size(), 1u);
  CHECK(notes[0].find("address-space") != std::string::npos);

  // A small window floor fits the same limit: floor 4 KiB, ceiling 8 KiB,
  // symbols bounded by rcv+send, bookkeeping 64 KiB -> ~22 MiB over 256
  // sessions, under the 3/4 threshold the estimator applies to 128 MiB.
  ec.window_min_bytes = 4 * 1024;
  ec.rcv_buf_bytes = 4 * 1024;
  CHECK(fcp::ResourceNotes(fcp::EngineRole::kServer, ec, mem).empty());
}

}  // namespace

int main() {
  TestKeyValidation();
  TestUnknownOldSpellings();
  TestNumericRanges();
  TestFecAliases();
  TestWindowForms();
  TestAutotuneNotes();
  TestRoleRequirements();
  TestDefaultsSurvive();
  TestMetaFlagsWinOverBadValues();
  TestFlagsAndValues();
  TestSpeedTestFlags();
  TestStallFlag();
  TestLogFileFlag();
  TestCcFlag();
  TestBenchCodec();
  TestEnvironmentDefaults();
  TestShortAndCompoundAddresses();
  return fcp_test::finish();
}
