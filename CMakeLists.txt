cmake_minimum_required(VERSION 3.20)

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

# 打包元数据：唯一真源是 packaging/debian/metadata.env（scripts/build_deb.sh 也读它）。
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
option(FCP_BUILD_PROXY "Build the FCP proxy CLI (client and server)" OFF)
option(FCP_BUILD_GUI "Build the Qt desktop client (requires Qt 6 Widgets)" OFF)

# 覆盖率门禁：line ≥ 90 / branch ≥ 80（gcc/clang；MSVC 用 OpenCPP 或单独跑）。
# 部署级 flag：静态库自身没有链接步骤，PRIVATE link option 不会传给测试，
# 因此这里用目录级 add_compile_options/add_link_options。必须放在任何
# add_library 之前：add_compile_options 只影响之后创建的目标，而 fcp /
# fcp_proxy_core 定义在下面（C-01）。
option(FCP_COVERAGE "Enable coverage instrumentation" OFF)
if(FCP_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
  endif()
endif()

add_library(fcp STATIC
  src/fcp/gf256.cc
  src/fcp/cauchy.cc
  src/fcp/rs.cc
  src/fcp/aes.cc
  src/fcp/ghash.cc
  src/fcp/gcm.cc
  src/fcp/envelope.cc
  src/fcp/random.cc
  src/fcp/hdr.cc
  src/fcp/pmtu.cc
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
  src/fcp/bbr.cc
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
# elsewhere. Public because the proxy/tools/test hosts link this library and may
# call random_bytes() for their own salts.
if(WIN32)
  target_link_libraries(fcp PUBLIC bcrypt)
endif()

# The proxy application layer: the socket-free ProxyEngine (M2代理设计.md §6) and
# the SOCKS5/HTTP-CONNECT/OPEN entry codecs (§4). Neither belongs in libfcp --
# libfcp is the protocol (crypto, FEC, transport, control) and never parses a
# proxy message -- and both are shared by the CLI executables and ctest, which is
# why the pair lives in src/ rather than inside one app.
if(FCP_BUILD_PROXY OR FCP_BUILD_TESTS)
  add_library(fcp_proxy_core STATIC
    src/proxy/proxy_engine.cc
    src/proxy/proxy_proto.cc
  )
  target_include_directories(fcp_proxy_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(fcp_proxy_core PUBLIC fcp)
endif()

if(FCP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# The CLI host (select reactor, argv parsing, the two mains) and the tools
# (fcp-bench, fcp-replay) share one directory. The protocol half the host drives
# is fcp_proxy_core above; only those executables are gated by FCP_BUILD_PROXY,
# the tools by FCP_BUILD_TOOLS. tests/cli_test.cc compiles cli.cc and reactor.cc
# directly so the argv guards stay under the default test gate.
if(FCP_BUILD_PROXY OR FCP_BUILD_TOOLS)
  add_subdirectory(apps/cli)
endif()

# 桌面客户端是 Qt 6 Widgets 壳，默认不构建（Qt 不在 vcpkg manifest 里，装上
# 会让默认的 CLI/测试构建变重）。单独构建也行：
#   cmake -S apps/desktop -B build/gui -DCMAKE_PREFIX_PATH=<Qt6 前缀>
# 隧道仍由 CLI 的 fcp-client 以 sidecar 承载（见 apps/desktop/README.md）。
if(FCP_BUILD_GUI)
  add_subdirectory(apps/desktop)
endif()

# 发布打包（Linux 服务端 deb）：只有同时构建代理 CLI 时才有意义。桌面客户端的
# 单文件 exe / AppImage 由 scripts/desktop 组装，不经过 CPack。该文件自身
# 也会再判一次平台与开关，这里保留条件只为让"为什么没生成 deb"显式。
if(FCP_BUILD_PROXY)
  include(packaging/FCPPackaging.cmake)
endif()
