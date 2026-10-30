// fcp-proxy-server: the far end of an FCP tunnel. It terminates sessions,
// resolves the target names itself (§4.3) and dials them over plain TCP.
// See docs/FCP_M2_PROXY.md §4 and §6; --help lists the options.
#include "cli.h"

int main(int argc, char** argv) { return fcp::run_proxy(fcp::EngineRole::kServer, argc, argv); }
