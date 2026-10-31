# FCP 测试。手写 CHECK 宏，与 kcp-cpp 风格一致，无第三方依赖。
# 每个测试一个独立可执行文件，ctest 并行跑、失败互不干扰。

set(FCP_TEST_NAMES
  gf256_test
  cauchy_test
  rs_test
  aes_test
  ghash_test
  gcm_test
  envelope_test
  hdr_test
  fecstat_test
  kfor_test
  strategy_test
  handshake_test
  frame_tx_test
  frame_rx_test
  settle_test
  reporter_test
  session_test
  replay_test
  stream_test
  stream_e2e_test
  prewarm_test
  proxy_proto_test
  proxy_engine_test
  e2e_test
  soak_test
  adv_test
)

foreach(name IN LISTS FCP_TEST_NAMES)
  add_executable(fcp_${name} ${name}.cc)
  target_link_libraries(fcp_${name} PRIVATE fcp)
  add_test(NAME ${name} COMMAND fcp_${name})
endforeach()

# P10' N16: without a timeout a hung loopback test blocks CI forever. The soak
# test gets its own larger bound (the C3 acceptance run uses FCP_SOAK_MS).
set_tests_properties(${FCP_TEST_NAMES} PROPERTIES TIMEOUT 300)
set_tests_properties(soak_test PROPERTIES TIMEOUT 900)

# The proxy engine lives under apps/ as a library of its own rather than in
# libfcp, because it is the socket-free half the Qt client also links; its test
# is the only one that needs that target (docs/FCP_M2_PROXY.md §6).
target_link_libraries(fcp_proxy_engine_test PRIVATE fcp_proxy_core)

# Loopback UDP sockets need Winsock on Windows. The soak test runs for 8s of
# simulated time in the default configuration; the C3 acceptance run uses
# FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1 (see docs/FCP_M1_ACCEPTANCE.md).
if(WIN32)
  foreach(name e2e_test soak_test adv_test stream_e2e_test prewarm_test)
    if(TARGET fcp_${name})
      target_link_libraries(fcp_${name} PRIVATE ws2_32)
    endif()
  endforeach()
endif()

# fcp_replay smoke (tools/, #28): replay the checked-in golden trace and make
# sure the tool loads it and prints its summary. --dump exercises the bare-flag
# path (it used to be documented but rejected as "bad argument"), and
# --require-exact turns the golden into a real determinism guard: a controller
# change that stops reproducing the recording now fails the suite. The golden is
# regenerated with `set FCP_WRITE_TRACE_GOLDEN=<path>` before running
# replay_test.
add_test(NAME replay_tool_smoke
         COMMAND fcp_replay --trace=${CMAKE_CURRENT_SOURCE_DIR}/replay_golden.jsonl
                 --dump --require-exact)
# P10' N10: PASS_REGULAR_EXPRESSION makes CTest ignore the exit code, so a
# divergence (fcp_replay returns 1 after printing the summary) still passed.
# Rely on the exit status and treat the divergence marker as a hard failure.
set_tests_properties(replay_tool_smoke PROPERTIES
         TIMEOUT 120
         FAIL_REGULAR_EXPRESSION "replay diverged")
