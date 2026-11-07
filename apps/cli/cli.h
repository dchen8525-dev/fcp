// Shared command line for the two proxy executables.
//
// Both ends configure the same EngineConfig and the same Reactor; only the
// role and the socket options differ, so the parsing lives here once and
// main_client.cc / main_server.cc stay one-line wrappers.
//
// The parsing is exposed as a pure function (parse_proxy_args) so the test
// suite can cover it directly: every range check here exists because a typo
// used to be silently wrapped or clamped (--mtu=70000 became 4464, a
// fec-budget above 1 silently disabled the cap), and untested guards rot.

#ifndef FCP_PROXY_CLI_H_
#define FCP_PROXY_CLI_H_

#include <string>
#include <vector>

#include "proxy/proxy_engine.h"
#include "reactor.h"

namespace fcp {

// Everything the command line produced. `notes` holds the informational
// stderr lines (autotune overrides) that run_proxy prints on the caller's
// behalf; they are data here so tests can assert on them.
struct ProxyArgs {
  EngineConfig ec;
  ReactorOptions ro;
  bool help = false;
  bool version = false;  // --version：打印发布版本后退出（安装包自检/排障用）
  // Client only: --speedtest turns this process into a one-shot frame-layer
  // bench (bench.h) instead of a proxy. The server side enables its responder
  // through ro.speedtest.
  bool speedtest = false;
  int speedtest_seconds = 8;
  // An explicit --mtu wins over the interface-derived default applied just
  // before startup; parsing must not distinguish the two otherwise.
  bool mtu_explicit = false;
  // The PSK came in through --key, so it is visible in the process command
  // line. run_proxy warns about it; --key-file/--key-env do not set this.
  bool key_in_argv = false;
  std::vector<std::string> notes;
};

// Process ceilings used by ResourceNotes(). -1 means the platform has no
// equivalent (Windows) or the value is unlimited.
struct ResourceLimits {
  long open_files = -1;
  long address_space = -1;
};

// Worst-case resource arithmetic, pure so tests can pin it without depending
// on the host's limits. Returns human-readable warning lines (empty when the
// configuration fits). Called by run_proxy after parsing.
std::vector<std::string> ResourceNotes(EngineRole role, const EngineConfig& ec,
                                       const ResourceLimits& limits);

// Lowers `configured` so the IP packet stays within `interface_mtu`. Both are
// IP packet sizes (the configured budget already includes IP+UDP headers, and
// the interface MTU is the largest IP packet it carries), so this is a plain
// min. Never raises the configured value and returns it unchanged when the
// interface is too small to produce a valid MTU.
uint16_t MtuForInterface(uint16_t configured, size_t interface_mtu);

// The interface-MTU half of ApplyEnvironmentDefaults, pure so it can be
// tested: a smaller interface lowers both the configured MTU and the PMTUD
// ceiling (probing above the local interface can only produce EMSGSIZE). A
// larger interface changes nothing -- the ladder from the configured MTU up
// to the built-in ceiling is exactly what upward PMTUD is for. An *explicit*
// --mtu above the interface is kept but disables PMTUD: DF would reject every
// datagram at that size, while without it the kernel still fragments and the
// tunnel works.
void ApplyInterfaceMtu(size_t interface_mtu, ProxyArgs* args);

// Pure argv parsing: no I/O, no engine construction, no process exit. Returns
// false on a usage error with a one-line reason in *error (the same text
// run_proxy prints). --help is not an error: it fills out->help.
bool parse_proxy_args(EngineRole role, int argc, char** argv, ProxyArgs* out,
                      std::string* error);

// Parses argv, builds the engine and the reactor, and runs the loop. Returns
// the process exit code (0 clean, 1 usage or setup failure).
int run_proxy(EngineRole role, int argc, char** argv);

}  // namespace fcp

#endif  // FCP_PROXY_CLI_H_
