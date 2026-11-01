// CLI argument parsing (apps/fcp-proxy/cli.cc), T-cli.
//
// Every range check in the CLI exists because a typo used to be silently
// wrapped or clamped: --mtu=70000 became 4464 (uint16 wrap), --d=266 became
// 10, a fec-budget above 1 silently disabled the cap, plain atoi() turned
// "abc" into 0. These tests pin the loud-failure contract: bad input returns
// false with a reason, good input lands in EngineConfig/ReactorOptions
// verbatim, and defaults survive an option-less command line.

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

void TestKeyValidation() {
  ProxyArgs a;
  std::string error;
  CHECK(TryParse(EngineRole::kClient, {"--key=" + std::string(kGoodKey), "--host=10.0.0.1"}, &a, &error));
  for (int i = 0; i < 16; ++i) {
    CHECK_EQ(a.ec.key[i], static_cast<uint8_t>(i));  // uppercase hex, big-endian pairs
  }

  // Lowercase is equally valid.
  CHECK(TryParse(EngineRole::kServer, {"--key=0f1e2d3c4b5a69788796a5b4c3d2e1f0"}, &a, &error));
  CHECK_EQ(a.ec.key[0], 0x0f);
  CHECK_EQ(a.ec.key[15], 0xf0);

  // Wrong length: 31 and 33 hex digits both reject (truncation used to pass).
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e"}, &a, &error));
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e0f0"}, &a, &error));
  // Non-hex digit.
  CHECK(!TryParse(EngineRole::kServer, {"--key=000102030405060708090a0b0c0d0e0g"}, &a, &error));
  // Missing entirely.
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK(error.find("--key") != std::string::npos);
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

  // --window-cap: below the autotune floor and above the advertised-cap ceiling.
  CHECK(!ok({"--window-cap=63"}));
  CHECK(!ok({"--window-cap=4097"}));
  CHECK(ok({"--window-cap=64"}));
  CHECK_EQ(a.ec.window_max_bytes, 64u * 1024);

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

void TestAutoWindowRules() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // --auto-window is a bare flag; a value on it is a typo worth rejecting.
  CHECK(!ok({"--auto-window=1"}));
  // The two switches are mutually exclusive.
  CHECK(!ok({"--auto-window", "--no-auto-window"}));
  // --no-auto-window wins and turns autotune off.
  CHECK(ok({"--no-auto-window"}));
  CHECK(!a.ec.auto_window);
  // A cap without autotune would be dead config: reject instead of ignoring.
  CHECK(!ok({"--no-auto-window", "--window-cap=512"}));
  CHECK(ok({"--window-cap=512"}));
  CHECK_EQ(a.ec.window_max_bytes, 512u * 1024);
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
  CHECK(a.ec.trace_prefix.empty());
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

  // Positional junk is a usage error, not a silently ignored token.
  CHECK(!TryParse(EngineRole::kServer, {"stray"}, &a, &error));
  CHECK(error.find("unknown argument") != std::string::npos);
}

void TestAutotuneNotes() {
  ProxyArgs a;
  std::string error;
  const auto ok = [&](const std::vector<std::string>& args) {
    return Ok(EngineRole::kServer, args, &a, &error);
  };

  // Default rcv-buf (256) is below the default cap (1024): the note must say
  // so instead of the autotune silently overriding the config.
  CHECK(ok({}));
  CHECK_EQ(a.notes.size(), 1u);
  CHECK(a.notes[0].find("receive capacity") != std::string::npos);

  // Raising rcv-buf to the cap removes the note; --window above the ceiling
  // adds the other one.
  CHECK(ok({"--rcv-buf=1024", "--window=4096"}));
  CHECK_EQ(a.notes.size(), 1u);
  CHECK(a.notes[0].find("above the autotune ceiling") != std::string::npos);

  // Fixed window mode never notes anything: nothing is overridden.
  CHECK(ok({"--no-auto-window"}));
  CHECK(a.notes.empty());
}

}  // namespace

int main() {
  TestKeyValidation();
  TestNumericRanges();
  TestAutoWindowRules();
  TestRoleRequirements();
  TestDefaultsSurvive();
  TestFlagsAndValues();
  TestAutotuneNotes();
  return fcp_test::finish();
}
