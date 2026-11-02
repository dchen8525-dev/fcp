// CLI argument parsing (apps/fcp-proxy/cli.cc), T-cli.
//
// Every range check in the CLI exists because a typo used to be silently
// wrapped or clamped: --mtu=70000 became 4464 (uint16 wrap), --d=266 became
// 10, a fec-budget above 1 silently disabled the cap, plain atoi() turned
// "abc" into 0. These tests pin the loud-failure contract: bad input returns
// false with a reason, good input lands in EngineConfig/ReactorOptions
// verbatim, and defaults survive an option-less command line.
//
// The alias tests pin the 2026-11-02 merge: --fec=D:P is --d/--p,
// --window=START:MAX is --window/--window-cap, --log is --stats/-v. The
// legacy spellings stay valid because deployments and the deb's conffile are
// written against them; what must not stay is the silent last-one-wins when
// two spellings of one setting are combined.

#include <cstdio>
#include <string>
#include <vector>

#include "cli.h"
#include "test_util.h"

namespace {

using fcp::EngineRole;
using fcp::ProxyArgs;

// Builds argv the way main() would see it; argv[0] is a placeholder since the
// parser never reads it (only run_proxy's Usage does).
struct Argv {
  std::vector<std::string> store;
  std::vector<char*> ptrs;

  explicit Argv(const std::vector<std::string>& args) : store(args) {
    ptrs.push_back(const_cast<char*>("fcp-proxy"));
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

// Ok/Fail prefill the required options (--key on both roles, --host on the
// client) so the range tests can pass only the option under test. Tests that
// deliberately probe a missing requirement call TryParse directly.
bool Ok(EngineRole role, const std::vector<std::string>& args,
        ProxyArgs* out, std::string* error) {
  std::vector<std::string> all = {"--key=" + std::string(kGoodKey)};
  if (role == EngineRole::kClient) {
    all.push_back("--host=10.0.0.1");
  }
  all.insert(all.end(), args.begin(), args.end());
  return TryParse(role, all, out, error);
}

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
  // Missing entirely names every source, not just --key.
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK(error.find("--key-file") != std::string::npos);
  CHECK(error.find("--key-env") != std::string::npos);
}

void TestKeyFile() {
  ProxyArgs a;
  std::string error;
  const std::string path = TempPath("psk");
  // Trailing newline (what `openssl rand -hex 16 > psk` writes) is accepted.
  CHECK(WriteFile(path, "0f1e2d3c4b5a69788796a5b4c3d2e1f0\r\n"));
  CHECK(TryParse(EngineRole::kServer, {"--key-file=" + path}, &a, &error));
  CHECK_EQ(a.ec.key[0], 0x0f);
  CHECK_EQ(a.ec.key[15], 0xf0);

  // Both spellings at once is ambiguous, and the key must not leak into argv.
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key=" + std::string(kGoodKey), "--key-file=" + path}, &a, &error));
  CHECK(error.find("alternatives") != std::string::npos);
  // The same spelling twice is a plain duplicate, not an ambiguity.
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key-file=" + path, "--key-file=" + path}, &a, &error));
  CHECK(error.find("more than once") != std::string::npos);

  // A file with anything but 32 hex digits is a loud error, not a zero key.
  CHECK(WriteFile(path, "not a key"));
  CHECK(!TryParse(EngineRole::kServer, {"--key-file=" + path}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer, {"--key-file=" + path + ".missing"}, &a, &error));

  // A valid key with a second key after it must not be silently truncated to
  // the first one: pointing at the wrong (multi-key) file has to fail.
  CHECK(WriteFile(path, "0f1e2d3c4b5a69788796a5b4c3d2e1f0\n"
                        "11223344556677889900aabbccddeeff\n"));
  CHECK(!TryParse(EngineRole::kServer, {"--key-file=" + path}, &a, &error));
  // ...and a file far larger than one key is rejected without parsing it.
  CHECK(WriteFile(path, std::string(5000, 'a')));
  CHECK(!TryParse(EngineRole::kServer, {"--key-file=" + path}, &a, &error));
  CHECK(error.find("larger than") != std::string::npos);
  std::remove(path.c_str());
}

bool SetEnv(const char* name, const char* value) {
#ifdef _WIN32
  return _putenv_s(name, value) == 0;
#else
  return setenv(name, value, 1) == 0;
#endif
}

bool UnsetEnv(const char* name) {
#ifdef _WIN32
  return _putenv_s(name, "") == 0;
#else
  return unsetenv(name) == 0;
#endif
}

// --key-env is the source the packaged systemd unit can actually use: a
// DynamicUser cannot read a root-owned 0600 key file, but EnvironmentFile is
// read by the manager and handed to the service as environment.
void TestKeyEnv() {
  ProxyArgs a;
  std::string error;
  UnsetEnv("FCP_TEST_PSK");

  CHECK(!TryParse(EngineRole::kServer, {"--key-env=FCP_TEST_PSK"}, &a, &error));
  CHECK(error.find("not set") != std::string::npos);

  CHECK(SetEnv("FCP_TEST_PSK", "0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
  CHECK(TryParse(EngineRole::kServer, {"--key-env=FCP_TEST_PSK"}, &a, &error));
  CHECK_EQ(a.ec.key[0], 0x0f);
  CHECK_EQ(a.ec.key[15], 0xf0);

  // Same value checks as --key, and the secret must not appear in the reason.
  CHECK(SetEnv("FCP_TEST_PSK", "not a key"));
  CHECK(!TryParse(EngineRole::kServer, {"--key-env=FCP_TEST_PSK"}, &a, &error));
  CHECK(error.find("not a key") == std::string::npos);

  // All three sources share one slot; two of them is ambiguous, one twice is
  // a duplicate, and an empty variable name is not a source at all.
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key=" + std::string(kGoodKey), "--key-env=FCP_TEST_PSK"}, &a, &error));
  CHECK(error.find("alternatives") != std::string::npos);
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key-env=FCP_TEST_PSK", "--key-env=FCP_TEST_PSK"}, &a, &error));
  CHECK(error.find("more than once") != std::string::npos);
  CHECK(!TryParse(EngineRole::kServer, {"--key-env="}, &a, &error));
  UnsetEnv("FCP_TEST_PSK");
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

  // --d / --p individual ranges, then the pair limit (P8-4).
  CHECK(!ok({"--d=0"}));
  CHECK(!ok({"--d=266"}));       // used to wrap to 10
  CHECK(!ok({"--p=8"}));
  CHECK(!ok({"--d=250", "--p=7"}));  // 257 > 256
  CHECK(ok({"--d=249", "--p=7"}));   // exactly 256

  // --k: -1 is adaptive, 0..7 pins, 8 rejects.
  CHECK(ok({"--k=-1"}));
  CHECK_EQ(a.ec.pinned_k, -1);
  CHECK(ok({"--k=3"}));
  CHECK_EQ(a.ec.pinned_k, 3);
  CHECK(!ok({"--k=8"}));

  // --fec-budget: domain is [0,1]; non-finite and junk reject.
  CHECK(!ok({"--fec-budget=1.5"}));  // used to silently disable the cap
  CHECK(!ok({"--fec-budget=-0.1"}));
  CHECK(!ok({"--fec-budget=abc"}));
  CHECK(!ok({"--fec-budget=nan"}));
  CHECK(!ok({"--fec-budget=inf"}));
  CHECK(ok({"--fec-budget=0"}));
  CHECK_EQ(a.ec.fec_budget, 0.0);
  CHECK(ok({"--fec-budget=1"}));

  // --window: the autotune domain is [64, 4096] KiB for both fields.
  CHECK(!ok({"--window=63"}));
  CHECK(!ok({"--window=4097"}));
  CHECK(ok({"--window=64"}));
  CHECK_EQ(a.ec.send_window_bytes, 64u * 1024);
  CHECK(!ok({"--window=256:63"}));
  CHECK(!ok({"--window=63:1024"}));
  // START above MAX passes the field range but fails the cross-field check.
  CHECK(!ok({"--window=1024:256"}));
  CHECK(error.find("above MAX") != std::string::npos);
  CHECK(ok({"--window=4096:4096"}));
  CHECK(!ok({"--window=8192"}));  // autotune start above the 4096 ceiling
  CHECK(!ok({"--window=256:1024:2048"}));
  CHECK(!ok({"--window=256:"}));
  CHECK(!ok({"--window:"}));
  CHECK(!ok({"--window"}));  // a value option given bare
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
  CHECK(!okc({"--port=0"}));
  CHECK(!okc({"--port=65536"}));
  CHECK(okc({"--port=65535"}));
  CHECK_EQ(a.ro.remote_port, 65535);
  CHECK(!okc({"--local-port=0"}));
  CHECK(!ok({"--port=0"}));

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

  // Same ranges and the same pair limit as the legacy halves.
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

  // Mixing spellings of the pair is one setting given twice: reject rather
  // than let whichever came last win silently.
  CHECK(!ok({"--fec=10:3", "--p=2"}));
  CHECK(!ok({"--d=10", "--fec=10:3"}));
  CHECK(!ok({"--d=10", "--d=10"}));

  // --p-max is the controller's ceiling, not dead config: the spec's 5..7
  // range is unreachable at its default 4. A pinned k above either bound would
  // be clamped by the local session before negotiation, so it is an error --
  // the operator would otherwise measure a k they did not configure.
  CHECK(ok({"--p-max=7"}));
  CHECK_EQ(a.ec.p_max, 7);
  CHECK(!ok({"--p-max=8"}));
  CHECK(ok({"--p-max=7", "--p=7", "--k=7"}));
  CHECK_EQ(a.ec.pinned_k, 7);
  CHECK(!ok({"--k=4"}));  // default --p=3 caps it even though --p-max is 4
  CHECK(error.find("--k=4") != std::string::npos);
  CHECK(!ok({"--p=7", "--k=5"}));  // --p-max still 4
  CHECK(!ok({"--p-max=5", "--p=5", "--k=6"}));
  CHECK(ok({"--p-max=5", "--p=5", "--k=5"}));
  CHECK(ok({"--k=0"}));  // pinning OFF is always representable
  CHECK(ok({"--p-max=0"}));
  CHECK(!ok({"--p-max=0", "--k=1"}));
}

void TestWindowAliases() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // Compound: start and ceiling together.
  CHECK(ok({"--window=512:2048"}));
  CHECK_EQ(a.ec.send_window_bytes, 512u * 1024);
  CHECK_EQ(a.ec.window_max_bytes, 2048u * 1024);
  CHECK(a.ec.auto_window);

  // A single value sets the start only; the ceiling stays at its default.
  CHECK(ok({"--window=512"}));
  CHECK_EQ(a.ec.send_window_bytes, 512u * 1024);
  CHECK_EQ(a.ec.window_max_bytes, 1024u * 1024);

  // The legacy spellings land in the same fields.
  CHECK(ok({"--window-cap=2048"}));
  CHECK_EQ(a.ec.window_max_bytes, 2048u * 1024);
  CHECK(ok({"--window=512", "--window-cap=2048"}));
  CHECK_EQ(a.ec.send_window_bytes, 512u * 1024);
  CHECK_EQ(a.ec.window_max_bytes, 2048u * 1024);
  // ...and combining one with the compound is still one setting given twice.
  CHECK(!ok({"--window=256:1024", "--window-cap=2048"}));
  CHECK(error.find("--window-cap") != std::string::npos);
  // ...in either order.
  CHECK(!ok({"--window-cap=2048", "--window=256:1024"}));
  CHECK(error.find("--window-cap") != std::string::npos);
  CHECK(!ok({"--window-cap=512", "--window-cap=1024"}));
  CHECK(error.find("more than once") != std::string::npos);

  // Below the engine's autotune floor used to be silently raised.
  CHECK(!ok({"--window=32"}));

  // --no-auto-window keeps a single fixed --window, but a MAX is dead config.
  CHECK(ok({"--no-auto-window", "--window=512"}));
  CHECK(!a.ec.auto_window);
  CHECK(!ok({"--no-auto-window", "--window=512:2048"}));
  CHECK(!ok({"--no-auto-window", "--window-cap=2048"}));
  // The fixed window keeps its old 1 GiB range; only autotune is 64..4096.
  CHECK(ok({"--no-auto-window", "--window=8192"}));
  CHECK_EQ(a.ec.send_window_bytes, 8192u * 1024);
  CHECK(a.ec.window_explicit);  // the prewarm prior must not replace it
  // The receive capacity follows the fixed window: otherwise the peer's sender
  // is clamped at the 256 KiB default while our own window is 8 MiB.
  CHECK_EQ(a.ec.rcv_buf_bytes, 8192u * 1024);
  // An explicit --rcv-buf still wins (memory-constrained hosts).
  CHECK(ok({"--no-auto-window", "--window=8192", "--rcv-buf=512"}));
  CHECK_EQ(a.ec.rcv_buf_bytes, 512u * 1024);
  // A small fixed window leaves the default 256 KiB receive buffer alone.
  CHECK(ok({"--no-auto-window", "--window=128"}));
  CHECK_EQ(a.ec.rcv_buf_bytes, 256u * 1024);
  CHECK(!ok({"--window=8192"}));  // autotune start must fit under MAX 4096

  // --auto-window is the default spelled out; it only has to not conflict.
  CHECK(ok({"--auto-window"}));
  CHECK(a.ec.auto_window);
  CHECK(!ok({"--auto-window", "--no-auto-window"}));
  CHECK(!ok({"--auto-window=1"}));  // bare flag: a value is a typo

  // --rcv-buf survives as the fixed-mode receive buffer (removing it outright
  // would take away the only way to size the receive side of a fixed window),
  // but it is dead config under autotune.
  CHECK(!ok({"--rcv-buf=256"}));
  CHECK(error.find("--no-auto-window") != std::string::npos);
  CHECK(ok({"--no-auto-window", "--rcv-buf=512"}));
  CHECK_EQ(a.ec.rcv_buf_bytes, 512u * 1024);
  CHECK(!ok({"--no-auto-window", "--rcv-buf=0"}));
}

void TestAutotuneNotes() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // Nothing is raised when the ceiling equals the fixed-mode buffer: the note
  // only exists to say that autotune overrides the configured 256 KiB.
  CHECK(ok({}));
  CHECK_EQ(a.notes.size(), 1u);
  CHECK(a.notes[0].find("receive capacity") != std::string::npos);
  CHECK(ok({"--window=256:256"}));
  CHECK(a.notes.empty());

  // A start above the ceiling is a mistake, not a note: the old code clamped
  // it silently, which is exactly the class of flag this rewrite removed.
  CHECK(!ok({"--window=4096:1024"}));
  CHECK(error.find("above MAX") != std::string::npos);
  CHECK(!ok({"--window=2048"}));  // start 2048 > default MAX 1024
  CHECK(ok({"--window=2048:2048"}));

  // Fixed mode never notes anything: nothing is overridden.
  CHECK(ok({"--no-auto-window"}));
  CHECK(a.notes.empty());
}

void TestRoleRequirements() {
  ProxyArgs a;
  std::string error;

  // The client needs somewhere to connect; the server does not.
  CHECK(!TryParse(EngineRole::kClient, {"--key=" + std::string(kGoodKey)}, &a, &error));
  CHECK(error.find("--host") != std::string::npos);
  CHECK(TryParse(EngineRole::kServer, {"--key=" + std::string(kGoodKey)}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("0.0.0.0"));
  CHECK_EQ(a.ro.bind_port, 4460);

  CHECK(TryParse(EngineRole::kClient,
                 {"--key=" + std::string(kGoodKey), "--host=203.0.113.7",
                  "--port=5000", "--listen=127.0.0.1", "--local-port=1180"},
                 &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("203.0.113.7"));
  CHECK_EQ(a.ro.remote_port, 5000);
  CHECK_EQ(a.ro.listen_addr, std::string("127.0.0.1"));
  CHECK_EQ(a.ro.listen_port, 1180);

  // Server-side flags land in the reactor options verbatim.
  CHECK(TryParse(EngineRole::kServer,
                 {"--key=" + std::string(kGoodKey), "--bind=192.168.1.1", "--port=5001"},
                 &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("192.168.1.1"));
  CHECK_EQ(a.ro.bind_port, 5001);

  // Role-specific options are errors on the other side: they used to be
  // accepted and quietly ignored, which reads as "configured" in a script.
  CHECK(!Ok(EngineRole::kServer, {"--local-port=1080"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key=" + std::string(kGoodKey), "--listen=127.0.0.1"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer,
                  {"--key=" + std::string(kGoodKey), "--host=10.0.0.1"}, &a, &error));
  CHECK(!TryParse(EngineRole::kClient,
                  {"--key=" + std::string(kGoodKey), "--host=10.0.0.1", "--bind=0.0.0.0"},
                  &a, &error));
  // An explicit empty address is a typo, not "use the default".
  CHECK(!Ok(EngineRole::kServer, {"--bind="}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--listen="}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--host="}, &a, &error));

  // The role has to reach BOTH halves. EngineConfig::role defaults to kClient,
  // so a server that only fills ReactorOptions still prints "server: fcp on"
  // and yet runs a client-side engine: it never births a session from a peer's
  // datagram and silently drops every HELLO as unknown_salt. This is exactly
  // what a 0.0.1 deb on a live host did.
  CHECK_EQ(static_cast<int>(a.ec.role), static_cast<int>(EngineRole::kClient));
  CHECK_EQ(static_cast<int>(a.ro.role), static_cast<int>(EngineRole::kClient));
  CHECK(Ok(EngineRole::kClient, {}, &a, &error));
  CHECK_EQ(static_cast<int>(a.ec.role), static_cast<int>(EngineRole::kClient));
  CHECK(TryParse(EngineRole::kServer, {"--key=" + std::string(kGoodKey)}, &a, &error));
  CHECK_EQ(static_cast<int>(a.ec.role), static_cast<int>(EngineRole::kServer));
  CHECK_EQ(static_cast<int>(a.ro.role), static_cast<int>(EngineRole::kServer));
}

void TestDefaultsSurvive() {
  ProxyArgs a;
  std::string error;
  CHECK(Ok(EngineRole::kClient, {}, &a, &error));
  CHECK_EQ(a.ec.mtu, 1400);
  CHECK_EQ(a.ec.d, 10);
  CHECK_EQ(a.ec.p, 3);
  CHECK_EQ(a.ec.pinned_k, -1);
  CHECK_EQ(a.ec.fec_budget, 0.50);
  CHECK_EQ(a.ec.send_window_bytes, 256u * 1024);
  CHECK_EQ(a.ec.rcv_buf_bytes, 256u * 1024);
  CHECK(a.ec.auto_window);
  CHECK_EQ(a.ec.max_sessions, 256u);
  CHECK_EQ(a.ec.idle_timeout_ms, 300000);
  CHECK_EQ(a.ec.dial_timeout_ms, 5000);
  CHECK(a.ec.prewarm);
  CHECK(a.ro.remote_port == 4460 && a.ro.listen_port == 1080);
  CHECK(!a.ro.verbose);
  CHECK_EQ(a.ro.stats_ms, 0);
  CHECK_EQ(a.ro.connect_timeout_ms, 5000);
  CHECK(a.ec.trace_prefix.empty());
}

void TestMetaFlagsWinOverBadValues() {
  ProxyArgs a;
  std::string error;

  // --help/--version short-circuit before any value is parsed: the package
  // self-test runs the bare flag, but scripts append it to a long line and a
  // stale value elsewhere in that line must not turn a diagnostic into a usage
  // error. In particular no PSK is required.
  CHECK(TryParse(EngineRole::kServer, {"--version", "--mtu=abc"}, &a, &error));
  CHECK(a.version);
  CHECK(TryParse(EngineRole::kServer, {"--mtu=abc", "--help"}, &a, &error));
  CHECK(a.help);
  CHECK(TryParse(EngineRole::kServer, {"--key-file=/nonexistent", "--version"}, &a, &error));
  CHECK(a.version);

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
           {"--no-prewarm", "-v", "--trace=/tmp/calib", "--stats=1000",
            "--connect-timeout=2500"},
           &a, &error));
  CHECK(!a.ec.prewarm);
  CHECK(a.ro.verbose);
  CHECK_EQ(a.ec.trace_prefix, std::string("/tmp/calib"));
  CHECK_EQ(a.ro.stats_ms, 1000);
  CHECK_EQ(a.ro.connect_timeout_ms, 2500);
  CHECK(Ok(EngineRole::kServer,
           {"-v", "--stats=10000", "--max-sessions=512", "--idle=1000", "--no-prewarm"},
           &a, &error));
  CHECK(a.ro.verbose);
  CHECK(!a.ec.prewarm);
  CHECK_EQ(a.ec.max_sessions, 512u);
  CHECK_EQ(a.ec.idle_timeout_ms, 1000);
  CHECK(!Ok(EngineRole::kServer, {"--stats=1000", "--log=off"}, &a, &error));
  CHECK(error.find("--log already") != std::string::npos);

  // Outside help/version, a value error always has a message.
  CHECK(!Ok(EngineRole::kServer, {"--mtu=abc"}, &a, &error));
  CHECK(error.find("--mtu") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--log=stats:abc"}, &a, &error));
  CHECK(error.find("--log") != std::string::npos);

  // --log is the merged form: off / stats[:ms] / verbose.
  CHECK(Ok(EngineRole::kServer, {"--log=off"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 0);
  CHECK(!a.ro.verbose);
  CHECK(Ok(EngineRole::kServer, {"--log=stats"}, &a, &error));
  CHECK(a.ro.stats_ms > 0);
  CHECK(Ok(EngineRole::kServer, {"--log=stats:2500"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 2500);
  CHECK(Ok(EngineRole::kServer, {"--log=verbose"}, &a, &error));
  CHECK(a.ro.verbose);
  CHECK(!Ok(EngineRole::kServer, {"--log=chatty"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log=stats:0"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log=stats:"}, &a, &error));
  // --stats keeps its old range (0 = off), unlike --log=stats:ms.
  CHECK(Ok(EngineRole::kServer, {"--stats=0"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 0);
  // -v and --stats stay independent (the deploy docs use them together)...
  CHECK(Ok(EngineRole::kServer, {"-v", "--stats=1000"}, &a, &error));
  CHECK(a.ro.verbose);
  CHECK_EQ(a.ro.stats_ms, 1000);
  // ...but --log already says both, so mixing it with either is ambiguous.
  CHECK(!Ok(EngineRole::kServer, {"--log=verbose", "--stats=1000"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log=stats:1000", "-v"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log=verbose", "--log=off"}, &a, &error));

  // --help short-circuits into out->help instead of a key error.
  CHECK(TryParse(EngineRole::kServer, {"--help"}, &a, &error));
  CHECK(a.help);
  CHECK(TryParse(EngineRole::kClient, {"-h"}, &a, &error));
  CHECK(a.help);

  // --version does the same: an installed package must answer
  // `fcp-proxy-server --version` without being handed a PSK.
  CHECK(TryParse(EngineRole::kServer, {"--version"}, &a, &error));
  CHECK(a.version);
  CHECK(!a.help);
  CHECK(TryParse(EngineRole::kServer, {"-V"}, &a, &error));
  CHECK(a.version);

    // Positional junk is a usage error, not a silently ignored token.
  CHECK(!TryParse(EngineRole::kServer, {"stray"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
  // An unknown long option names itself, and a value on a bare flag is a typo.
  CHECK(!Ok(EngineRole::kServer, {"--nonsense=1"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--no-prewarm=1"}, &a, &error));
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

  fcp::ResourceLimits unknown;  // -1 = platform has no equivalent (Windows)
  fcp::EngineConfig ec;         // auto window, 256 sessions, 1 MiB ceiling
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

  // A small fixed window fits the same limit.
  ec.auto_window = false;
  ec.send_window_bytes = 64 * 1024;
  ec.rcv_buf_bytes = 64 * 1024;
  CHECK(fcp::ResourceNotes(fcp::EngineRole::kServer, ec, mem).empty());
}

}  // namespace

int main() {
  TestKeyValidation();
  TestKeyFile();
  TestKeyEnv();
  TestNumericRanges();
  TestFecAliases();
  TestWindowAliases();
  TestAutotuneNotes();
  TestRoleRequirements();
  TestDefaultsSurvive();
  TestMetaFlagsWinOverBadValues();
  TestFlagsAndValues();
  TestEnvironmentDefaults();
  return fcp_test::finish();
}
