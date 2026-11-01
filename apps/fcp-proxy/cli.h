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
  std::vector<std::string> notes;
};

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
