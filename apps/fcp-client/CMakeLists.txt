find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

qt_standard_project_setup()

qt_add_executable(fcp_client
  main.cpp
  main_window.cpp
  main_window.h
  bench_engine.cpp
  bench_engine.h
  sparkline.cpp
  sparkline.h
)

qt_add_resources(fcp_client "fcp_client_resources"
  PREFIX "/"
  FILES theme.qss
)

target_link_libraries(fcp_client PRIVATE fcp Qt6::Widgets Qt6::Network)

# FrameTx has a method named emit(); Qt's keyword macros would mangle it, so
# the whole target is compiled with QT_NO_KEYWORDS (Q_SIGNALS/Q_EMIT instead).
target_compile_definitions(fcp_client PRIVATE QT_NO_KEYWORDS)

if(WIN32)
  set_target_properties(fcp_client PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
