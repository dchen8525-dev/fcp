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
// 0.0.1 has exactly one spelling per setting (--fec=D:P, --window=START[:MAX],
// --log=LEVEL/-v) and the removed aliases must stay removed: a silently
// accepted dead flag reads as "configured" in a script.

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

// 无任何 --key* 参数时默认读 FCP_PSK 环境变量：这是 deb 包的 /etc/fcp/fcp.env
// 只写一行 `FCP_PSK=…` 的依据（unit 是 DynamicUser，systemd 以 root 读
// EnvironmentFile 后注入进程环境，进程无参数、ps 里也没有密钥）。
void TestKeyDefaultsToFcpPskEnv() {
  ProxyArgs a;
  std::string error;
  UnsetEnv("FCP_PSK");

  // 什么来源都没有 → 报错原因必须点到 FCP_PSK，运维不用翻 --help。
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK(error.find("FCP_PSK") != std::string::npos);

  // 设置了就直接生效，等价于 --key-env=FCP_PSK；config 回显要标出来源。
  CHECK(SetEnv("FCP_PSK", kGoodKey));
  CHECK(TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK_EQ(a.ec.key[0], 0x00);
  CHECK_EQ(a.ec.key[15], 0x0f);
  CHECK(a.ro.psk_from_default_env);

  // 空变量不是"已配置"——与未设置走同一条响亮失败路径。
  CHECK(SetEnv("FCP_PSK", ""));
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));

  // 显式来源优先：给了 --key-env=别的名字，FCP_PSK 的有无都不干扰，
  // 也不算隐式来源。
  UnsetEnv("FCP_PSK");
  CHECK(SetEnv("FCP_TEST_PSK2", kGoodKey));
  CHECK(TryParse(EngineRole::kServer, {"--key-env=FCP_TEST_PSK2"}, &a, &error));
  CHECK(!a.ro.psk_from_default_env);
  UnsetEnv("FCP_TEST_PSK2");

  // FCP_PSK 内容坏了要报错，且原因里不回显值本身。
  CHECK(SetEnv("FCP_PSK", "not a key"));
  CHECK(!TryParse(EngineRole::kServer, {}, &a, &error));
  CHECK(error.find("not a key") == std::string::npos);
  UnsetEnv("FCP_PSK");
}

// --log-file=PATH：路径或目录名原样进 ReactorOptions；重复给两次按"同一参数
// 只能出现一次"的组规则响亮报错。
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
  // A fixed window below two segments cannot put one segment on the wire, so
  // the stream would accept the app's bytes and never send them.
  CHECK(!ok({"--no-auto-window", "--window=1"}));
  CHECK(error.find("two segments") != std::string::npos);
  CHECK(!ok({"--no-auto-window", "--window=2"}));
  CHECK(ok({"--no-auto-window", "--window=4"}));
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

  // --p-max is the controller's ceiling, not dead config: the spec's 5..7
  // range is unreachable at its default 4. A pinned k above either bound would
  // be clamped by the local session before negotiation, so it is an error --
  // the operator would otherwise measure a k they did not configure.
  CHECK(ok({"--p-max=7"}));
  CHECK_EQ(a.ec.p_max, 7);
  CHECK(!ok({"--p-max=8"}));
  CHECK(ok({"--p-max=7", "--fec=10:7", "--k=7"}));
  CHECK_EQ(a.ec.pinned_k, 7);
  CHECK(!ok({"--k=4"}));  // default p=3 caps it even though --p-max is 4
  CHECK(error.find("--k=4") != std::string::npos);
  CHECK(!ok({"--fec=10:7", "--k=5"}));  // --p-max still 4
  CHECK(!ok({"--p-max=5", "--fec=10:5", "--k=6"}));
  CHECK(ok({"--p-max=5", "--fec=10:5", "--k=5"}));
  CHECK(ok({"--k=0"}));  // pinning OFF is always representable
  CHECK(ok({"--p-max=0"}));
  CHECK(!ok({"--p-max=0", "--k=1"}));
}

void TestWindowForms() {
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

  // ":MAX" pins the ceiling and leaves the start implicit, so the prewarm
  // prior can still replace it (this is what the GUI passes).
  CHECK(ok({"--window=:2048"}));
  CHECK_EQ(a.ec.window_max_bytes, 2048u * 1024);
  CHECK_EQ(a.ec.send_window_bytes, 256u * 1024);
  CHECK(!a.ec.window_explicit);
  CHECK_EQ(a.ec.window_ceiling_bytes, 0u);  // a pinned MAX is a decision
  // --window-cap is gone: one spelling, no alias to keep in sync.
  CHECK(!ok({"--window-cap=2048"}));
  CHECK(error.find("unknown") != std::string::npos);
  CHECK(!ok({"--window=512", "--window=1024"}));
  CHECK(error.find("more than once") != std::string::npos);
  CHECK(!ok({"--window=:"}));  // no field at all
  CHECK(!error.empty());

  // Below the engine's autotune floor used to be silently raised.
  CHECK(!ok({"--window=32"}));

  // --no-auto-window keeps a single fixed --window, but a MAX is dead config.
  CHECK(ok({"--no-auto-window", "--window=512"}));
  CHECK(!a.ec.auto_window);
  CHECK(!ok({"--no-auto-window", "--window=512:2048"}));
  CHECK(!ok({"--no-auto-window", "--window=:2048"}));
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

  // --auto-window is the default spelled out, so it is gone too: there is no
  // way to make autotune "more on", and a dead flag reads as configured.
  CHECK(!ok({"--auto-window"}));
  CHECK(error.find("unknown") != std::string::npos);

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

// Short spellings and ADDR:PORT. Both are pure ergonomics: the same options,
// one argument shorter. They must land in exactly the same fields as the long
// form (there is one ApplyValue, reached after the rewrite), and combining the
// two port sources has to fail rather than silently pick one.
void TestShortAndCompoundAddresses() {
  ProxyArgs a;
  std::string error;
  const std::string key = "--key=" + std::string(kGoodKey);

  // Separate, attached and =value forms of a value option.
  CHECK(TryParse(EngineRole::kClient,
                 {key, "-H", "198.51.100.9:4700", "-l", "127.0.0.1:1180", "-m", "1500"},
                 &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("198.51.100.9"));
  CHECK_EQ(a.ro.remote_port, 4700);
  CHECK_EQ(a.ro.listen_addr, std::string("127.0.0.1"));
  CHECK_EQ(a.ro.listen_port, 1180);
  CHECK_EQ(a.ec.mtu, 1500);

  CHECK(TryParse(EngineRole::kClient, {key, "-H=203.0.113.7", "-p5000"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("203.0.113.7"));
  CHECK_EQ(a.ro.remote_port, 5000);

  // -b :PORT keeps the default address; the server needs nothing else but keys.
  CHECK(TryParse(EngineRole::kServer, {key, "-b", ":40000"}, &a, &error));
  CHECK_EQ(a.ro.bind_addr, std::string("0.0.0.0"));
  CHECK_EQ(a.ro.bind_port, 40000);

  // -k is --key-file (a path, not the key itself): the short form must not
  // become a way to put the PSK back into `ps`.
  const std::string path = TempPath("short_key");
  CHECK(WriteFile(path, kGoodKey));
  CHECK(TryParse(EngineRole::kServer, {"-k", path}, &a, &error));
  std::remove(path.c_str());

  // One port, one source.
  CHECK(!TryParse(EngineRole::kClient, {key, "-H", "10.0.0.1:5000", "-p", "6000"}, &a,
                  &error));
  CHECK(error.find("twice") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient,
                  {key, "--host=10.0.0.1", "-l", "127.0.0.1:1180", "--local-port=1190"},
                  &a, &error));
  CHECK(error.find("twice") != std::string::npos);

  // A non-numeric suffix is not a port: the whole value stays the address.
  CHECK(TryParse(EngineRole::kClient, {key, "-H", "host.example"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("host.example"));
  CHECK_EQ(a.ro.remote_port, 4460);
  // Several colons are an IPv6 literal (unsupported: the tunnel socket is
  // AF_INET), not host:port -- it must not be split into ":" plus port 1.
  CHECK(TryParse(EngineRole::kClient, {key, "--host=::1", "--port=4000"}, &a, &error));
  CHECK_EQ(a.ro.remote_host, std::string("::1"));
  CHECK_EQ(a.ro.remote_port, 4000);

  // Short-option errors name the short spelling and the value it needs.
  CHECK(!TryParse(EngineRole::kServer, {key, "-k"}, &a, &error));
  CHECK(error.find("-k") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "--host=10.0.0.1", "-vx"}, &a, &error));
  CHECK(error.find("takes no value") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "--host=10.0.0.1", "-z"}, &a, &error));
  CHECK(error.find("unknown") != std::string::npos);
  CHECK(!TryParse(EngineRole::kClient, {key, "--host=10.0.0.1", "-m", "70000"}, &a, &error));
  CHECK(error.find("--mtu") != std::string::npos);
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
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));  // 默认 debug
  CHECK_EQ(a.ro.stats_ms, 0);
  CHECK_EQ(a.ro.connect_timeout_ms, 5000);
  CHECK(a.ec.trace_prefix.empty());
  // Wire-side defaults: coalesced ACKs. The BDP-following ceiling scales with
  // --max-sessions so the documented 512 MiB worst case does not move: 256
  // sessions get no extra room over the 1 MiB MAX, 64 sessions get 4 MiB.
  CHECK_EQ(static_cast<int>(a.ec.ack_every), 2);
  CHECK_EQ(a.ec.window_ceiling_bytes, 0u);
  ProxyArgs few;
  CHECK(Ok(EngineRole::kServer, {"--max-sessions=64"}, &few, &error));
  CHECK_EQ(few.ec.window_ceiling_bytes, 4u * 1024 * 1024);

  // Pinning the ceiling is a decision: the default does not raise it, and the
  // ACK ratio is independent of the window mode.
  ProxyArgs pinned;
  CHECK(Ok(EngineRole::kClient, {"--window=:2048"}, &pinned, &error));
  CHECK_EQ(pinned.ec.window_max_bytes, 2048u * 1024);
  CHECK_EQ(pinned.ec.window_ceiling_bytes, 0u);
  CHECK_EQ(static_cast<int>(pinned.ec.ack_every), 2);
  ProxyArgs fixed;
  CHECK(Ok(EngineRole::kClient, {"--no-auto-window", "--window=4096"}, &fixed, &error));
  CHECK_EQ(fixed.ec.window_ceiling_bytes, 0u);
  CHECK_EQ(static_cast<int>(fixed.ec.ack_every), 2);

  // Upward PMTUD is on with a 1500 ceiling; --no-pmtud turns it off, and a
  // ceiling at or below the configured MTU is clamped to "do not probe".
  CHECK(a.ec.pmtud);
  CHECK_EQ(a.ec.pmtu_max_mtu, 1500);
  ProxyArgs no_pmtu;
  CHECK(Ok(EngineRole::kClient, {"--no-pmtud"}, &no_pmtu, &error));
  CHECK(!no_pmtu.ec.pmtud);
  ProxyArgs jumbo;
  CHECK(Ok(EngineRole::kClient, {"--pmtu-max=9000"}, &jumbo, &error));
  CHECK_EQ(jumbo.ec.pmtu_max_mtu, 9000);
  ProxyArgs below;
  CHECK(Ok(EngineRole::kClient, {"--mtu=1500", "--pmtu-max=1280"}, &below, &error));
  CHECK_EQ(below.ec.pmtu_max_mtu, 1500u);  // clamped to the starting MTU
  ProxyArgs big_mtu;
  CHECK(Ok(EngineRole::kClient, {"--mtu=2000"}, &big_mtu, &error));
  CHECK_EQ(big_mtu.ec.pmtu_max_mtu, 2000u);  // default ceiling follows the start
  CHECK(!Ok(EngineRole::kClient, {"--pmtu-max=1000"}, &no_pmtu, &error));
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
           {"--no-prewarm", "-v", "--trace=/tmp/calib", "--connect-timeout=2500"},
           &a, &error));
  CHECK(!a.ec.prewarm);
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));  // -v = debug 别名
  CHECK_EQ(a.ec.trace_prefix, std::string("/tmp/calib"));
  CHECK_EQ(a.ro.connect_timeout_ms, 2500);
  CHECK(Ok(EngineRole::kServer,
           {"-v", "--max-sessions=512", "--idle=1000", "--no-prewarm"}, &a, &error));
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
  CHECK(!Ok(EngineRole::kServer, {"-v", "--log=off"}, &a, &error));
  CHECK(error.find("more than once") != std::string::npos);

  // Outside help/version, a value error always has a message.
  CHECK(!Ok(EngineRole::kServer, {"--mtu=abc"}, &a, &error));
  CHECK(error.find("--mtu") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--log=chatty"}, &a, &error));
  CHECK(error.find("--log") != std::string::npos);

  // --log=LEVEL 四个阈值 + verbose 别名；周期统计归 --stats，两者互不干扰。
  CHECK(Ok(EngineRole::kServer, {"--log=off"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kOff));
  CHECK_EQ(a.ro.stats_ms, 0);  // --log 不再影响统计
  CHECK(Ok(EngineRole::kServer, {"--log=off", "--stats=5000"}, &a, &error));
  CHECK_EQ(a.ro.stats_ms, 5000);
  CHECK(Ok(EngineRole::kServer, {"--log=error"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kError));
  CHECK(Ok(EngineRole::kServer, {"--log=warn"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kWarn));
  CHECK(Ok(EngineRole::kServer, {"--log=info"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kInfo));
  CHECK(Ok(EngineRole::kServer, {"--log=debug"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));
  CHECK(Ok(EngineRole::kServer, {"--log=verbose", "--stats=1500"}, &a, &error));
  CHECK_EQ(Severity(a.ro.log_level), Severity(LogLevel::kDebug));
  CHECK_EQ(a.ro.stats_ms, 1500);
  CHECK(!Ok(EngineRole::kServer, {"--log=chatty"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--log=debug", "--log=off"}, &a, &error));

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

  // --version does the same: an installed package must answer
  // `fcp-server --version` without being handed a PSK.
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

void TestSpeedTestFlags() {
  ProxyArgs a;
  std::string error;

  // Server: the bare flag enables the frame-layer responder on the FCP port.
  CHECK(Ok(EngineRole::kServer, {"--speedtest"}, &a, &error));
  CHECK(a.ro.speedtest);
  // --speedtest-seconds belongs to the client's one-shot run only.
  CHECK(!Ok(EngineRole::kServer, {"--speedtest", "--speedtest-seconds=8"}, &a, &error));
  CHECK(error.find("client") != std::string::npos);

  // Client: --speedtest switches to one bench run and leaves the proxy alone.
  CHECK(Ok(EngineRole::kClient, {"--speedtest"}, &a, &error));
  CHECK(a.speedtest);
  CHECK_EQ(a.speedtest_seconds, 8);
  CHECK(Ok(EngineRole::kClient, {"--speedtest", "--speedtest-seconds=12"}, &a, &error));
  CHECK_EQ(a.speedtest_seconds, 12);

  // Seconds without the mode flag would be silently ignored.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest-seconds=12"}, &a, &error));
  // Bare flags take no value, and the old --speedtest-port spelling is gone.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest=1"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--speedtest-port=9001"}, &a, &error));
  // Range guards: the run takes 2 x N seconds, so the window is bounded.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest", "--speedtest-seconds=2"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--speedtest", "--speedtest-seconds=31"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--speedtest", "--speedtest-seconds=abc"}, &a, &error));
}

void TestStallAndRateFlags() {
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

  // --rate-limit=UP[:DOWN] Mbps; the client shapes its upload.
  CHECK(Ok(EngineRole::kClient, {"--rate-limit=8"}, &a, &error));
  CHECK_EQ(a.ro.rate_up_bytes, 1000000);  // 8 Mbps = 1 MB/s
  CHECK_EQ(a.ro.rate_down_bytes, 0);
  CHECK(Ok(EngineRole::kClient, {"--rate-limit=8:20"}, &a, &error));
  CHECK_EQ(a.ro.rate_up_bytes, 1000000);
  // The DOWN half is the server's setting; the client locally unshaped.
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=0:20"}, &a, &error));
  CHECK(error.find("UP") != std::string::npos);
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit="}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=8:"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=8:20:5"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=abc:20"}, &a, &error));
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=100001"}, &a, &error));
  // One second of budget must cover one full datagram: below that the shaper
  // passes everything through and the link runs unshaped behind a rate line.
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=0.0000001"}, &a, &error));
  CHECK(error.find("too small to shape") != std::string::npos);
  CHECK(!Ok(EngineRole::kClient, {"--rate-limit=0.01"}, &a, &error));  // 1250 B/s < mtu 1400
  CHECK(error.find("one datagram") != std::string::npos);
  // Just above the floor shapes for real.
  CHECK(Ok(EngineRole::kClient, {"--rate-limit=0.05"}, &a, &error));  // 6250 B/s
  CHECK_EQ(a.ro.rate_up_bytes, 6250);
  // The one-shot bench measures raw throughput; shaping is meaningless there.
  CHECK(!Ok(EngineRole::kClient, {"--speedtest", "--rate-limit=8"}, &a, &error));
  CHECK(error.find("--speedtest") != std::string::npos);

  // The server enforces the DOWN half (it serves the download).
  CHECK(Ok(EngineRole::kServer, {"--rate-limit=0:5"}, &a, &error));
  CHECK_EQ(a.ro.rate_down_bytes, 625000);
  CHECK_EQ(a.ro.rate_up_bytes, 0);
  CHECK(!Ok(EngineRole::kServer, {"--rate-limit=5:0"}, &a, &error));
  CHECK(error.find("DOWN") != std::string::npos);
  // A server bar one half ("=5") shapes nothing: DOWN is its half.
  CHECK(!Ok(EngineRole::kServer, {"--rate-limit=5"}, &a, &error));
  CHECK(error.find("shapes nothing") != std::string::npos);
}

void TestBbrFlags() {
  ProxyArgs a;
  std::string error;

  // BBR owns the adaptive window by default; v2 is the shipping version
  // (it learns the path's own loss floor before treating loss as congestion).
  CHECK(Ok(EngineRole::kServer, {}, &a, &error));
  CHECK(a.ec.bbr);
  CHECK_EQ(a.ec.bbr_version, 2);

  // v1 stays selectable for comparison.
  CHECK(Ok(EngineRole::kServer, {"--bbr-version=1"}, &a, &error));
  CHECK_EQ(a.ec.bbr_version, 1);
  CHECK(!Ok(EngineRole::kServer, {"--bbr-version=3"}, &a, &error));
  CHECK(error.find("--bbr-version") != std::string::npos);
  CHECK(!Ok(EngineRole::kServer, {"--bbr-version=v2"}, &a, &error));

  // The epoch controller is the fallback; a version with no controller to
  // apply it to is a mistake, not a silent no-op.
  CHECK(Ok(EngineRole::kServer, {"--no-bbr"}, &a, &error));
  CHECK(!a.ec.bbr);
  CHECK(!Ok(EngineRole::kServer, {"--no-bbr", "--bbr-version=1"}, &a, &error));
  CHECK(!Ok(EngineRole::kServer, {"--bbr"}, &a, &error));  // removed: BBR is the default
  CHECK(error.find("unknown") != std::string::npos);

  // A fixed window has no controller either; --bbr-version is then only
  // noted, because --no-auto-window is the deliberate flag.
  CHECK(Ok(EngineRole::kServer,
           {"--no-auto-window", "--window=512", "--bbr-version=1"}, &a, &error));
  bool noted = false;
  for (const std::string& n : a.notes) {
    if (n.find("--bbr-version") != std::string::npos) {
      noted = true;
    }
  }
  CHECK(noted);
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
  EncodeReport(7, 123456789ull, 987654321ull, 424242ull, report, sizeof(report));
  CHECK(DecodePayload(report, sizeof(report), &decoded));
  CHECK(decoded.type == PayloadType::kReport);
  CHECK_EQ(decoded.sn, 7u);
  CHECK_EQ(decoded.delivered, 123456789ull);
  CHECK_EQ(decoded.best_bps, 987654321ull);
  CHECK_EQ(decoded.down_wire_bps, 424242ull);
  // Truncated report, truncated header, and a wrong version are all rejected.
  CHECK(!DecodePayload(report, kReportPayloadLen - 1, &decoded));
  CHECK(!DecodePayload(report, kHeaderLen + 4, &decoded));
  CHECK(!DecodePayload(report, kHeaderLen - 1, &decoded));
  uint8_t bad_version[kReportPayloadLen];
  std::memcpy(bad_version, report, sizeof(report));
  bad_version[kMagicLen] = static_cast<uint8_t>(bad_version[kMagicLen] ^ 0xFF);
  CHECK(!DecodePayload(bad_version, sizeof(bad_version), &decoded));

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

  // Ramp: x1.5 per interval, saturating at the ceiling.
  Ramp ramp;
  CHECK(ramp.bps() == kStartBps);
  ramp.Advance();
  CHECK(ramp.bps() == kStartBps * 1.5);
  for (int i = 0; i < 100; ++i) {
    ramp.Advance();
  }
  CHECK(ramp.bps() == kMaxBps);

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
  TestKeyDefaultsToFcpPskEnv();
  TestNumericRanges();
  TestFecAliases();
  TestWindowForms();
  TestAutotuneNotes();
  TestRoleRequirements();
  TestDefaultsSurvive();
  TestMetaFlagsWinOverBadValues();
  TestFlagsAndValues();
  TestSpeedTestFlags();
  TestStallAndRateFlags();
  TestLogFileFlag();
  TestBbrFlags();
  TestBenchCodec();
  TestEnvironmentDefaults();
  TestShortAndCompoundAddresses();
  return fcp_test::finish();
}
