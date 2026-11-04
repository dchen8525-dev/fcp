# FCP 桌面客户端（Qt 6 Widgets）。
#
# 传输面不在这里：真正跑隧道的是同一份 fcp-client（apps/cli 的 reactor CLI）。
# 这个壳只负责启动/停止 sidecar、解析它的 stats 行、把数字画到界面上，以及
# 托盘/关窗隐藏。协议、CLI 参数、测速协议都与壳无关。
#
# 这个目录可以单独构建（发布脚本就是这么用的），也可以由顶层 CMake 在
# FCP_BUILD_GUI=ON 时 add_subdirectory 进来：
#
#   cmake -S apps/desktop -B build/gui -DCMAKE_PREFIX_PATH=<Qt6 前缀>
#   cmake --build build/gui --config Release
#
# Qt 不在 vcpkg 的 manifest 依赖里（装上 Qt 会让默认的 CLI/测试构建变重），
# 由调用方通过 CMAKE_PREFIX_PATH 指定。

cmake_minimum_required(VERSION 3.20)
project(fcp_gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)

add_executable(fcp_gui WIN32
  src/main.cpp
  src/mainwindow.cpp
  src/mainwindow.h
  src/sidecar.cpp
  src/sidecar.h
  src/sparkline.cpp
  src/sparkline.h
  assets/resources.qrc
)

set_target_properties(fcp_gui PROPERTIES OUTPUT_NAME FCP)

if(WIN32)
  target_sources(fcp_gui PRIVATE assets/fcp.rc)
elseif(APPLE)
  set_target_properties(fcp_gui PROPERTIES MACOSX_BUNDLE TRUE)
endif()

target_link_libraries(fcp_gui PRIVATE Qt6::Widgets)

# 开发树里的 FCP.exe 直接双击能跑：POST_BUILD 把 sidecar 与 Qt 运行库收进
# 输出目录。发布的完整打包（依赖清点 + 单文件封装）仍走
# scripts/desktop/build_windows.ps1，这里只保证本地运行不缺 DLL。
if(TARGET fcp-client)
  add_custom_command(TARGET fcp_gui POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:fcp-client>" "$<TARGET_FILE_DIR:fcp_gui>"
    COMMENT "拷贝 sidecar fcp-client 到 GUI 输出目录"
    VERBATIM)
endif()

option(FCP_GUI_AUTO_DEPLOY "POST_BUILD 收集 Qt 运行库（Windows，开发构建直接可跑）" ON)
if(WIN32 AND FCP_GUI_AUTO_DEPLOY)
  # Qt6_DIR 的层级随发行方不同：vcpkg 在 <prefix>/share/Qt6，官方安装包在
  # <prefix>/lib/cmake/Qt6。用"哪个上跳层级下有 Qt6Core.dll"来定位 Qt bin，
  # windeployqt 再从 bin 与 tools/Qt6/bin（vcpkg 的放法）里找。
  set(FCP_QT_BIN "")
  foreach(_candidate "${Qt6_DIR}/../../bin" "${Qt6_DIR}/../../../bin")
    if(EXISTS "${_candidate}/Qt6Core.dll")
      get_filename_component(FCP_QT_BIN "${_candidate}" ABSOLUTE)
      break()
    endif()
  endforeach()
  # 注意别先 set() 空值：find_program 对已定义的变量直接跳过不执行。
  if(FCP_QT_BIN)
    find_program(FCP_WINDEPLOYQT_EXE NAMES windeployqt
      HINTS "${FCP_QT_BIN}" "${FCP_QT_BIN}/../tools/Qt6/bin" NO_DEFAULT_PATH)
  endif()
  if(FCP_QT_BIN AND FCP_WINDEPLOYQT_EXE)
    add_custom_command(TARGET fcp_gui POST_BUILD
      COMMAND "${CMAKE_COMMAND}"
              -DEXE="$<TARGET_FILE:fcp_gui>"
              -DQT_BIN="${FCP_QT_BIN}"
              -DWINDEPLOYQT="${FCP_WINDEPLOYQT_EXE}"
              -DCFG="$<IF:$<CONFIG:Debug>,debug,release>"
              -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/win_autodeploy.cmake"
      COMMENT "收集 Qt 运行库到 GUI 输出目录"
      VERBATIM)
  else()
    message(STATUS "找不到 Qt bin/windeployqt（Qt6_DIR=${Qt6_DIR}），跳过 POST_BUILD 部署"
                   "（开发时需自行把 Qt bin 加入 PATH）")
  endif()
endif()

if(MSVC)
  target_compile_options(fcp_gui PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(fcp_gui PRIVATE -Wall -Wextra -Wpedantic)
endif()

# 便携包把 FCP 和 fcp-client 放在同一层；install 规则给 Linux AppImage 用
# （DESTDIR=<AppDir> 时落到 <AppDir>/usr/bin）。
install(TARGETS fcp_gui RUNTIME DESTINATION bin)
