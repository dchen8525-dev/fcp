find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

qt_standard_project_setup()

# 发布版本来自根 CMakeLists 的 project(fcp VERSION ...)，见 VERSION 文件。
set(FCP_APP_VERSION "${PROJECT_VERSION}")

qt_add_executable(fcp_client
  main.cc
  main_window.cc
  main_window.h
  bench_engine.cc
  bench_engine.h
  proxy_host.cc
  proxy_host.h
  sparkline.cc
  sparkline.h
)

qt_add_resources(fcp_client "fcp_client_resources"
  PREFIX "/"
  FILES theme.qss
)

# fcp_proxy_core is the socket-free ProxyEngine (src/proxy, top-level
# CMakeLists.txt) shared with the CLI binaries; the Qt host drives the same
# object (M2 §6).
target_link_libraries(fcp_client PRIVATE fcp fcp_proxy_core Qt6::Widgets Qt6::Network)

# FrameTx has a method named emit(); Qt's keyword macros would mangle it, so
# the whole target is compiled with QT_NO_KEYWORDS (Q_SIGNALS/Q_EMIT instead).
target_compile_definitions(fcp_client PRIVATE QT_NO_KEYWORDS)

# main.cc 把它塞进 QApplication::setApplicationVersion（发布物/关于对话框用）。
target_compile_definitions(fcp_client PRIVATE FCP_APP_VERSION="${FCP_APP_VERSION}")

if(WIN32)
  set_target_properties(fcp_client PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
