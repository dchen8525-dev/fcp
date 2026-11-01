# The FCP proxy CLI (M2代理设计.md §6).
#
# This directory is only the host side: the select reactor, the shared argv
# parser and the two one-line mains. The protocol half -- ProxyEngine and the
# SOCKS5/HTTP-CONNECT/OPEN codecs -- is fcp_proxy_core in src/proxy, defined at
# the top level next to libfcp because the Qt client links the same library.

find_package(Threads REQUIRED)

add_executable(fcp-proxy-client main_client.cc cli.cc reactor.cc)
target_link_libraries(fcp-proxy-client PRIVATE fcp_proxy_core Threads::Threads)

add_executable(fcp-proxy-server main_server.cc cli.cc reactor.cc)
target_link_libraries(fcp-proxy-server PRIVATE fcp_proxy_core Threads::Threads)

if(WIN32)
  target_link_libraries(fcp-proxy-client PRIVATE ws2_32)
  target_link_libraries(fcp-proxy-server PRIVATE ws2_32)
endif()

# deb 包里只有这两个可执行文件（packaging/debian 的 spec），别的一个都不装：
# 工具、测试、静态库、systemd unit 的落点都在 cmake/FCPPackaging.cmake。
install(TARGETS fcp-proxy-server fcp-proxy-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
