# FCP 单文件引导器（Windows-only）。
# 独立工程：打包脚本用 cmake -DAPP_VERSION=<x.y.z> 独立配置，不依赖主树。
# 产物 fcp-launcher.exe 静态 CRT、无 DLL 依赖，是便携包的第一个拼接段。
cmake_minimum_required(VERSION 3.21)
project(fcp-launcher LANGUAGES C CXX)
# project() 之后 CMAKE_SYSTEM_NAME 才就位，判断只能放这里。
if(NOT CMAKE_SYSTEM_NAME MATCHES "^Windows$")
  message(FATAL_ERROR "fcp-launcher 只在 Windows 上构建（打包脚本按需调用）")
endif()

set(APP_VERSION "0.0.0" CACHE STRING "写进 VERSIONINFO 的版本号")
# VERSIONINFO 的 FILEVERSION/PRODUCTVERSION 只要数字段：取主版本前三段。
string(REGEX REPLACE "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+).*" "\\1,\\2,\\3,0"
       APP_VERSION_COMMA "${APP_VERSION}")
set(FCP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/../assets/fcp.ico")

# rc 文件里的注释含中文：rc.exe 按 UTF-8（代码页 65001）读。
if(MSVC)
  set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /c 65001")
endif()

# rc 用 configure_file 生成：图标路径与版本号经 @VAR@ 替换写入，
# 必须在 add_executable 前完成（VS 生成器要求源文件已存在）。
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/launcher.rc.in
               ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc @ONLY)

add_executable(fcp-launcher WIN32
  launcher.cc
  miniz/miniz.c          # amalgamated 全量实现（tinfl+tdefl+zip）
  lzma/LzmaDec.c         # 7-Zip LZMA SDK 解码器（public domain，仅解码）
  ${CMAKE_CURRENT_BINARY_DIR}/launcher.rc
)

target_include_directories(fcp-launcher PRIVATE miniz lzma)
# bcrypt：载荷 SHA-256 校验走 CNG（系统自带，Vista 起就有）。shell32 给
# SHFileOperationW 的目录删除。
target_link_libraries(fcp-launcher PRIVATE shell32 bcrypt)

# miniz 只用得到 zip 读取：关掉写归档端。其余剪裁宏不能开 ——
# 整个 miniz_zip.c 包在 MINIZ_NO_ARCHIVE_APIS 里、extract_to_file 走
# MZ_FOPEN（MINIZ_NO_STDIO 会把它砍掉）。必须对 miniz.c 生效，
# 所以用 target 级定义而不是源内 #define。
target_compile_definitions(fcp-launcher PRIVATE MINIZ_NO_ARCHIVE_WRITING_APIS)

set_target_properties(fcp-launcher PROPERTIES
  C_STANDARD 11
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  MSVC_RUNTIME_LIBRARY "MultiThreaded"   # 静态 CRT：零 DLL 依赖
)

# /SUBSYSTEM:WINDOWS + /ENTRY:wmainCRTStartup：无控制台窗口，同时保留
# wmain(int, wchar_t**) 的标准签名（CI 自检靠自检报告文件，不靠 stdout）。
if(MSVC)
  target_compile_options(fcp-launcher PRIVATE /W4 /permissive- /utf-8)
  target_link_options(fcp-launcher PRIVATE
    /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup)
endif()
