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
  pmtu_test
  frame_tx_test
  frame_rx_test
  settle_test
  reporter_test
  log_test
  defensive_test
  session_edges_test
  stream_edges_test
  codec_edges_test
  control_edges_test
  session_test
  replay_test
  bbr_test
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
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli/reactor.cc
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli/bench.cc)
target_include_directories(fcp_cli_test PRIVATE
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli)
target_link_libraries(fcp_cli_test PRIVATE fcp_proxy_core)
if(WIN32)
  # Same libs as fcp-client/server (iphlpapi: MTU default; winmm: the reactor's
  # timeBeginPeriod around the select loop, P1-1).
  target_link_libraries(fcp_cli_test PRIVATE ws2_32 iphlpapi winmm)
endif()
add_test(NAME cli_test COMMAND fcp_cli_test)
set_tests_properties(cli_test PROPERTIES TIMEOUT 300)

# fuzz 冒烟（tests/fuzz_test.cc）：确定性种子的进程内变异，覆盖公网解析面
# （会话 on_wire 全链 + bench/pmtu/fecstat 编解码 + 握手阶段）。不是 fuzzing
# 战役，是 CI 门禁里的绊线；需要 bench.cc 的编解码器，链接方式同 cli_test。
add_executable(fcp_fuzz_test fuzz_test.cc
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli/bench.cc)
target_include_directories(fcp_fuzz_test PRIVATE
               ${CMAKE_CURRENT_SOURCE_DIR}/../apps/cli)
target_link_libraries(fcp_fuzz_test PRIVATE fcp_proxy_core)
if(WIN32)
  target_link_libraries(fcp_fuzz_test PRIVATE ws2_32 iphlpapi winmm)
endif()
add_test(NAME fuzz_test COMMAND fcp_fuzz_test)
set_tests_properties(fuzz_test PROPERTIES TIMEOUT 120)

# Loopback UDP sockets need Winsock on Windows. The soak test runs for 8s of
# simulated time in the default configuration; the C3 acceptance run uses
# FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1 (see M1验收记录.md).
if(WIN32)
  foreach(name e2e_test soak_test adv_test stream_e2e_test prewarm_test pmtu_test)
    if(TARGET fcp_${name})
      target_link_libraries(fcp_${name} PRIVATE ws2_32)
    endif()
  endforeach()
endif()

# fcp-replay smoke (apps/cli/, #28): replay the checked-in golden trace and make
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
# 过程中靠删断言把红灯变绿。基线 tests/test_baseline.txt 随代码评审。
# 解释器是 bash（POSIX sh 友好的 awk）；CI Windows runner 与开发机都自带 Git
# Bash。缺 bash 时跳过而不是失败："没跑护栏"比"门禁因为缺解释器挂掉"好查。
find_program(BASH bash QUIET)
if(BASH)
  add_test(NAME test_baseline
           COMMAND ${BASH}
                   ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/test_baseline.sh)
  if(WIN32)
    # ctest 常从 PowerShell/CMD 启动，其 PATH 里没有 Git Bash 的 usr/bin：
    # 脚本第 28 行的 dirname 和后面的 sort/comm/awk 会全部 command not found，
    # 然后误报 baseline missing。从 ${BASH} 的绝对路径推导并前置到 PATH。
    # 分号必须转义，否则 CMake 会把整条 PATH 拆成多个 ENVIRONMENT 项。
    get_filename_component(FCP_BASH_BIN "${BASH}" DIRECTORY)
    string(REPLACE ";" "\\;" FCP_TEST_PATH "${FCP_BASH_BIN};$ENV{PATH}")
    set_tests_properties(test_baseline PROPERTIES
                         TIMEOUT 60
                         ENVIRONMENT "PATH=${FCP_TEST_PATH}")
  else()
    set_tests_properties(test_baseline PROPERTIES TIMEOUT 60)
  endif()
else()
  message(STATUS "bash 未找到；跳过 test_baseline 护栏")
endif()

# deb 打包器（scripts/build_deb.sh）只用 dpkg-deb，没有可跨平台跑的纯逻辑单测；
# 这里在 Linux 上做语法检查，真正的出包与结构校验由 release_build_linux.sh
# （CI 的 linux-deb job）在打包机上执行。
if(UNIX)
  find_program(BASH_PROGRAM bash)
  if(BASH_PROGRAM)
    add_test(NAME build_deb_syntax
             COMMAND ${BASH_PROGRAM} -n
                     ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/build_deb.sh)
    set_tests_properties(build_deb_syntax PROPERTIES TIMEOUT 30)
  endif()
endif()
