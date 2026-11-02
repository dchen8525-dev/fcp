cmake_minimum_required(VERSION 3.16)

# 发布版本号的唯一真源是仓库根的 VERSION 文件；打 tag 时发布工作流把 tag 名
# （去掉前导 v）传进 FCP_RELEASE_VERSION 覆盖它，并拒绝与 VERSION 不一致的 tag。
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" FCP_VERSION_RAW LIMIT_COUNT 1)
string(STRIP "${FCP_VERSION_RAW}" FCP_VERSION)
if(FCP_RELEASE_VERSION)
  set(FCP_VERSION "${FCP_RELEASE_VERSION}")
endif()
if(NOT FCP_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got '${FCP_VERSION}'")
endif()

project(fcp VERSION ${FCP_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)

# 打包元数据：唯一真源是 packaging/debian/metadata.env（scripts/build_deb.py 也读它）。
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/metadata.env"
     FCP_METADATA_LINES REGEX "^FCP_")
foreach(line IN LISTS FCP_METADATA_LINES)
  if(line MATCHES "^(FCP_[A-Z_]+)=(.*)$")
    set(${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
  endif()
endforeach()
if(NOT FCP_HOMEPAGE OR NOT FCP_MAINTAINER)
  message(FATAL_ERROR "packaging/debian/metadata.env 必须给出 FCP_HOMEPAGE 与 FCP_MAINTAINER")
endif()

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

file(GLOB fcp_headers CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/fcp/*.h)

add_library(fcp
  src/fcp/gf256.cc
  src/fcp/cauchy.cc
  src/fcp/rs.cc
  src/fcp/aes.cc
  src/fcp/ghash.cc
  src/fcp/gcm.cc
  src/fcp/envelope.cc
  src/fcp/random.cc
  src/fcp/hdr.cc
  src/fcp/fecstat.cc
  src/fcp/frame_tx.cc
  src/fcp/frame_rx.cc
  src/fcp/frame_rx_decode.cc
  src/fcp/settle.cc
  src/fcp/reporter.cc
  src/fcp/strategy.cc
  src/fcp/handshake.cc
  src/fcp/session.cc
  src/fcp/session_log.cc
  src/fcp/stream.cc
  src/fcp/stream_recv.cc
  src/fcp/stream_send.cc
  src/fcp/stream_window.cc
  src/fcp/prewarm.cc
  src/fcp/trace.cc
)

target_include_directories(fcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# version.h 的 kProductVersion（CLI --version）；PUBLIC 让宿主与测试都拿到。
target_compile_definitions(fcp PUBLIC FCP_PRODUCT_VERSION="${FCP_VERSION}")

# AES-NI intrinsics. MSVC enables them for x64 by default; GCC/Clang need -maes.
if(NOT MSVC AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")
  target_compile_options(fcp PRIVATE -maes)
endif()

# random.cc uses the OS CSPRNG: BCryptGenRandom on Windows, /dev/urandom
# elsewhere. Public because the proxy/Qt/tools hosts link this library and may
# call random_bytes() for their own salts.
if(WIN32)
  target_link_libraries(fcp PUBLIC bcrypt)
endif()

# The proxy application layer: the socket-free ProxyEngine (M2代理设计.md §6) and
# the SOCKS5/HTTP-CONNECT/OPEN entry codecs (§4). Neither belongs in libfcp --
# libfcp is the protocol (crypto, FEC, transport, control) and never parses a
# proxy message -- and both are shared by the CLI executables, the Qt client and
# ctest, which is why the pair lives in src/ rather than inside one app.
if(FCP_BUILD_PROXY OR FCP_BUILD_APP OR FCP_BUILD_TESTS)
  add_library(fcp_proxy_core STATIC
    src/proxy/proxy_engine.cc
    src/proxy/proxy_proto.cc
  )
  target_include_directories(fcp_proxy_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(fcp_proxy_core PUBLIC fcp)
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

# The CLI host (select reactor, argv parsing, the two mains). The protocol half
# it drives is fcp_proxy_core above; only these executables are gated by
# FCP_BUILD_PROXY. tests/cli_test.cc compiles cli.cc and reactor.cc directly so
# the argv guards stay under the default test gate.
if(FCP_BUILD_PROXY)
  add_subdirectory(apps/fcp-proxy)
endif()

if(FCP_BUILD_APP)
  add_subdirectory(apps/fcp-client)
endif()

# 发布打包（Linux deb）：只有同时构建代理 CLI 时才有意义 —— Windows 侧走
# Inno Setup，由 .github/workflows/release.yml 直接组装，不经过 CPack。
# 该文件自身也会再判一次平台与开关，这里保留条件只为让"为什么没生成 deb"显式。
if(FCP_BUILD_PROXY)
  include(cmake/FCPPackaging.cmake)
endif()
