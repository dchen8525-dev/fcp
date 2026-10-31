cmake_minimum_required(VERSION 3.16)

project(fcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

option(FCP_BUILD_TESTS "Build FCP tests" ON)
option(FCP_BUILD_TOOLS "Build FCP tools (benchmark harness)" ON)
option(FCP_BUILD_APP "Build the Qt desktop client" OFF)
option(FCP_BUILD_PROXY "Build the FCP proxy CLI (client and server)" OFF)

add_library(fcp
  src/fcp/gf256.cc
  src/fcp/cauchy.cc
  src/fcp/rs.cc
  src/fcp/aes.cc
  src/fcp/ghash.cc
  src/fcp/gcm.cc
  src/fcp/envelope.cc
  src/fcp/hdr.cc
  src/fcp/fecstat.cc
  src/fcp/frame_tx.cc
  src/fcp/frame_rx.cc
  src/fcp/settle.cc
  src/fcp/reporter.cc
  src/fcp/strategy.cc
  src/fcp/handshake.cc
  src/fcp/session.cc
  src/fcp/stream.cc
  src/fcp/prewarm.cc
  src/fcp/trace.cc
  src/fcp/proxy_proto.cc
)

target_include_directories(fcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# AES-NI intrinsics. MSVC enables them for x64 by default; GCC/Clang need -maes.
if(NOT MSVC AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")
  target_compile_options(fcp PRIVATE -maes)
endif()

# 覆盖率门禁：line ≥ 90 / branch ≥ 80（gcc/clang；MSVC 用 OpenCPP 或单独跑）。
# 部署级 flag：静态库自身没有链接步骤，PRIVATE link option 不会传给测试，
# 因此这里用目录级 add_compile_options/add_link_options。
option(FCP_COVERAGE "Enable coverage instrumentation" OFF)
if(FCP_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
  endif()
endif()

if(FCP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(FCP_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

# The socket-free engine is a library of its own: the Qt client links it even
# when the CLI executables are not configured (apps/fcp-proxy/CMakeLists.txt),
# and ctest drives it directly -- so it is built whenever tests or an app are.
if(FCP_BUILD_PROXY OR FCP_BUILD_APP OR FCP_BUILD_TESTS)
  add_subdirectory(apps/fcp-proxy)
endif()

if(FCP_BUILD_APP)
  add_subdirectory(apps/fcp-client)
endif()
