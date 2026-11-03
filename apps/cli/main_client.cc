// fcp-client: local SOCKS5 / HTTP CONNECT listener in front of an FCP
// tunnel. See M2代理设计.md §4 and §6; --help lists the options.
#include "cli.h"

int main(int argc, char** argv) { return fcp::run_proxy(fcp::EngineRole::kClient, argc, argv); }
