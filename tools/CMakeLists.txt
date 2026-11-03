add_executable(fcp-bench fcp-bench.cc)
target_link_libraries(fcp-bench PRIVATE fcp)
if(WIN32)
  target_link_libraries(fcp-bench PRIVATE ws2_32)
endif()

# Offline controller replay (M3控制设计.md §5, #28). No sockets: the tool
# only reads traces and drives the pure strategy.
add_executable(fcp-replay fcp-replay.cc)
target_link_libraries(fcp-replay PRIVATE fcp)
