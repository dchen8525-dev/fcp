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
  stream_test
  stream_e2e_test
  prewarm_test
  e2e_test
  soak_test
  adv_test
)

foreach(name IN LISTS FCP_TEST_NAMES)
  add_executable(fcp_${name} ${name}.cc)
  target_link_libraries(fcp_${name} PRIVATE fcp)
  add_test(NAME ${name} COMMAND fcp_${name})
endforeach()

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
