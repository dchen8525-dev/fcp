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
  random_test
  hdr_test
  wire_test
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

# The proxy layer is its own library (src/proxy, defined at the top level):
# ProxyEngine plus the entry codecs, shared with the CLI
# (M2代理设计.md §6). Both proxy tests link it rather than libfcp.
target_link_libraries(fcp_proxy_engine_test PRIVATE fcp_proxy_core)
target_link_libraries(fcp_proxy_proto_test PRIVATE fcp_proxy_core)

# CLI argument parsing (apps/cli/cli.cc, T-cli). cli.cc is not in
# fcp_proxy_core (only the executables compile it, under FCP_BUILD_PROXY), so
# the test compiles it directly together with reactor.cc — run_proxy references
# Reactor symbols, and the pure parser would otherwise be ungated until someone
# built the CLI. This keeps the parse guards (uint16 wrap, fec-budget domain,
# d+p pair limit) under the default test gate.
add_executable(fcp_cli_test cli_test.cc
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli/cli.cc
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli/reactor.cc)
target_include_directories(fcp_cli_test PRIVATE
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli
               ${CMAKE_CURRENT_SOURCE_DIR}/../tools)
target_link_libraries(fcp_cli_test PRIVATE fcp_proxy_core)
if(WIN32)
  target_link_libraries(fcp_cli_test PRIVATE ws2_32 iphlpapi)
endif()
add_test(NAME cli_test COMMAND fcp_cli_test)
set_tests_properties(cli_test PROPERTIES TIMEOUT 300)

# Loopback UDP sockets need Winsock on Windows. The soak test runs for 8s of
# simulated time in the default configuration; the C3 acceptance run uses
# FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1 (see M1验收记录.md).
if(WIN32)
  foreach(name e2e_test soak_test adv_test stream_e2e_test prewarm_test)
    if(TARGET fcp_${name})
      target_link_libraries(fcp_${name} PRIVATE ws2_32)
    endif()
  endforeach()
endif()

# fcp-replay smoke (tools/, #28): replay the checked-in golden trace and make
# sure the tool loads it and prints its summary. --dump exercises the bare-flag
# path (it used to be documented but rejected as "bad argument"), and
# --require-exact turns the golden into a real determinism guard: a controller
# change that stops reproducing the recording now fails the suite. The golden is
# regenerated with `set FCP_WRITE_TRACE_GOLDEN=<path>` before running
# replay_test.
# FCP_BUILD_TOOLS=OFF is a legal combination with FCP_BUILD_TESTS=ON. Guard on
# the targets: a bare `COMMAND fcp-replay` registers fine at configure time and
# then fails at run time as "Unable to find executable" (C-03).
set(FCP_TOOL_GUARDS)
if(TARGET fcp-replay)
  add_test(NAME replay_tool_smoke
           COMMAND fcp-replay --trace=${CMAKE_CURRENT_SOURCE_DIR}/replay_golden.jsonl
                   --dump --require-exact)
  # P10' N10: PASS_REGULAR_EXPRESSION makes CTest ignore the exit code, so a
  # divergence (fcp-replay returns 1 after printing the summary) still passed.
  # Rely on the exit status and treat the divergence marker as a hard failure.
  set_tests_properties(replay_tool_smoke PROPERTIES
           TIMEOUT 120
           FAIL_REGULAR_EXPRESSION "replay diverged")

  # Tool argument guards. Both parsers used to accept unknown or repeated
  # options silently (the last one won), and fcp-replay used to print a pinned k
  # that FecStrategy had already clamped. Every line below must fail before any
  # network I/O, so WILL_FAIL is safe: these exit immediately with code 1.
  add_test(NAME replay_rejects_unknown_option
           COMMAND fcp-replay --trace=${CMAKE_CURRENT_SOURCE_DIR}/replay_golden.jsonl
                   --targe=0.9)
  add_test(NAME replay_rejects_k_above_pmax
           COMMAND fcp-replay --trace=${CMAKE_CURRENT_SOURCE_DIR}/replay_golden.jsonl
                   --p-max=2 --k=5)
  list(APPEND FCP_TOOL_GUARDS replay_rejects_unknown_option replay_rejects_k_above_pmax)
endif()
if(TARGET fcp-bench)
  add_test(NAME bench_rejects_host_on_server
           COMMAND fcp-bench server --host=10.0.0.1
                   --key=000102030405060708090a0b0c0d0e0f)
  add_test(NAME bench_rejects_ambiguous_seg
           COMMAND fcp-bench server --seg=34
                   --key=000102030405060708090a0b0c0d0e0f)
  list(APPEND FCP_TOOL_GUARDS bench_rejects_host_on_server bench_rejects_ambiguous_seg)
endif()
if(FCP_TOOL_GUARDS)
  set_tests_properties(${FCP_TOOL_GUARDS} PROPERTIES
           WILL_FAIL TRUE TIMEOUT 30)
endif()

# 重构护栏：ctest 全绿只证明"没坏"，不证明"断言还在"。这一步把测试套件的
# 形状钉住（每个测试二进制的测试函数数与 CHECK 数只许涨不许跌），防止重构
# 过程中靠删断言把红灯变绿。基线 tests/test_baseline.json 随代码评审。
# 缺 python3 时跳过而不是失败：VPS 门禁机器不一定装了 Python，而"没跑护栏"
# 比"门禁因为缺解释器挂掉"好查得多。
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME test_baseline
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/test_baseline.py)
  set_tests_properties(test_baseline PROPERTIES TIMEOUT 60)
else()
  message(STATUS "python3 未找到；跳过 test_baseline 护栏")
endif()

# 打包器自检（scripts/build_deb.py）：用 --self-test 跑纯逻辑单元（control 段落
# 规则、ar 头、架构/版本校验），不需要已构建的二进制，也不写任何产物，
# 两个平台都跑。真正的出包由 scripts/release_build_linux.sh 做。
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME build_deb_self_test
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/build_deb.py --self-test)
  set_tests_properties(build_deb_self_test PROPERTIES TIMEOUT 60)
else()
  message(STATUS "Python3 未找到：跳过 build_deb_self_test（deb 打包器自检）")
endif()
