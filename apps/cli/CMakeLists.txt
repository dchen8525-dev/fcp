# The FCP CLI (M2代理设计.md §6): fcp-server and fcp-client.
#
# This directory is only the host side: the select reactor, the shared argv
# parser and the two one-line mains. The protocol half -- ProxyEngine and the
# SOCKS5/HTTP-CONNECT/OPEN codecs -- is fcp_proxy_core in src/proxy, defined at
# the top level next to libfcp because ctest links the same library. The Tauri
# desktop client does not link it: it runs fcp-client as a sidecar.

find_package(Threads REQUIRED)

# cli.cc is shared, and both roles can reach the bench unit: the server hosts
# the frame-layer responder in its reactor, the client runs one bench in
# --speedtest mode.
add_executable(fcp-client main_client.cc cli.cc reactor.cc bench.cc)
target_link_libraries(fcp-client PRIVATE fcp_proxy_core Threads::Threads)

add_executable(fcp-server main_server.cc cli.cc reactor.cc bench.cc)
target_link_libraries(fcp-server PRIVATE fcp_proxy_core Threads::Threads)

# tools/cli_parse.h: the argv splitting and range checks shared with the tools.
target_include_directories(fcp-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../tools)
target_include_directories(fcp-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../tools)

if(WIN32)
  # iphlpapi: the startup MTU default reads the local interface table.
  target_link_libraries(fcp-client PRIVATE ws2_32 iphlpapi)
  target_link_libraries(fcp-server PRIVATE ws2_32 iphlpapi)
endif()

# deb 包里只有这两个可执行文件（packaging/debian 的 spec），别的一个都不装：
# 工具、测试、静态库、systemd unit 的落点都在 cmake/FCPPackaging.cmake。
install(TARGETS fcp-server fcp-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
