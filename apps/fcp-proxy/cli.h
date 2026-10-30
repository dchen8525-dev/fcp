// Shared command line for the two proxy executables.
//
// Both ends configure the same EngineConfig and the same Reactor; only the
// role and the socket options differ, so the parsing lives here once and
// main_client.cc / main_server.cc stay one-line wrappers.

#ifndef FCP_PROXY_CLI_H_
#define FCP_PROXY_CLI_H_

#include "engine.h"

namespace fcp {

// Parses argv, builds the engine and the reactor, and runs the loop. Returns
// the process exit code (0 clean, 1 usage or setup failure).
int run_proxy(EngineRole role, int argc, char** argv);

}  // namespace fcp

#endif  // FCP_PROXY_CLI_H_
