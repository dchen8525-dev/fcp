# Everything that runs on the host: the CLI (M2代理设计.md §6) and the offline
# tools. The proxy half -- ProxyEngine and the SOCKS5/HTTP-CONNECT/OPEN codecs
# -- is fcp_proxy_core in src/proxy, defined at the top level next to libfcp
# because ctest links the same library. The Tauri desktop client does not link
# it: it runs fcp-client as a sidecar.

# Tools (FCP_BUILD_TOOLS, on by default). No sockets in fcp-replay; fcp-bench
# drives the pure library directly.
if(FCP_BUILD_TOOLS)
  add_executable(fcp-bench fcp-bench.cc)
  target_link_libraries(fcp-bench PRIVATE fcp)
  if(WIN32)
    target_link_libraries(fcp-bench PRIVATE ws2_32)
  endif()

  # Offline controller replay (M3控制设计.md §5, #28). No sockets: the tool
  # only reads traces and drives the pure strategy.
  add_executable(fcp-replay fcp-replay.cc)
  target_link_libraries(fcp-replay PRIVATE fcp)
endif()

if(FCP_BUILD_PROXY)
  find_package(Threads REQUIRED)

  # cli.cc is shared, and both roles can reach the bench unit: the server hosts
  # the frame-layer responder in its reactor, the client runs one bench in
  # --speedtest mode. cli_parse.h (argv splitting and range checks) sits in this
  # directory, next to its users.
  add_executable(fcp-client main_client.cc cli.cc reactor.cc bench.cc)
  target_link_libraries(fcp-client PRIVATE fcp_proxy_core Threads::Threads)

  add_executable(fcp-server main_server.cc cli.cc reactor.cc bench.cc)
  target_link_libraries(fcp-server PRIVATE fcp_proxy_core Threads::Threads)

  if(WIN32)
    # iphlpapi: the startup MTU default reads the local interface table.
    # winmm: timeBeginPeriod/timeEndPeriod around the reactor loop (P1-1).
    target_link_libraries(fcp-client PRIVATE ws2_32 iphlpapi winmm)
    target_link_libraries(fcp-server PRIVATE ws2_32 iphlpapi winmm)
  endif()

  # deb 包里只有这两个可执行文件（packaging/debian 的 spec），别的一个都不装：
  # 工具、测试、静态库、systemd unit 的落点都在 packaging/FCPPackaging.cmake。
  install(TARGETS fcp-server fcp-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
