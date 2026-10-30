# Proxy (docs/FCP_M2_PROXY.md §6).
#
# The engine is split out as a static library because it is the part with no
# sockets in it: the CLI executables below and the Qt adapter (task #23) link
# the same object file, and ctest drives it directly (tests/proxy_engine_test.cc).
# That is why the library is outside FCP_BUILD_PROXY, whose default is OFF: the
# gate covers the reactor and the two mains, not the protocol.

add_library(fcp_proxy_core STATIC engine.cc)
target_include_directories(fcp_proxy_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fcp_proxy_core PUBLIC fcp)

if(FCP_BUILD_PROXY)
  find_package(Threads REQUIRED)

  add_executable(fcp-proxy-client main_client.cc cli.cc reactor.cc)
  target_link_libraries(fcp-proxy-client PRIVATE fcp_proxy_core Threads::Threads)

  add_executable(fcp-proxy-server main_server.cc cli.cc reactor.cc)
  target_link_libraries(fcp-proxy-server PRIVATE fcp_proxy_core Threads::Threads)

  if(WIN32)
    target_link_libraries(fcp-proxy-client PRIVATE ws2_32)
    target_link_libraries(fcp-proxy-server PRIVATE ws2_32)
  endif()
endif()
