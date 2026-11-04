# POST_BUILD 部署：把 Qt 运行库收进构建目录，让开发树里的 FCP.exe
# 直接双击就能跑（发布路径仍走 scripts/desktop/build_windows.ps1，那边有
# 更完整的依赖清点和单文件封装）。
#
# 由 apps/desktop/CMakeLists.txt 的 add_custom_command 调用：
#   cmake -DEXE=<FCP.exe> -DQT_BIN=<Qt bin> -DWINDEPLOYQT=<windeployqt> -P 本脚本
#
# 参数经由 ninja 的 cmd /C 包裹传递，MSVC CRT 会把 \" 解析成字面引号，
# 所以这里收到的值可能带着引号字符——先剥掉，免得拼出 ""..."" 找不到文件。
foreach(_var EXE QT_BIN WINDEPLOYQT CFG)
  if(DEFINED ${_var})
    string(REPLACE "\"" "" ${_var} "${${_var}}")
  endif()
endforeach()

get_filename_component(EXE_DIR "${EXE}" DIRECTORY)

# windeployqt 自身链接 Qt DLL，先让它能找到。
set(ENV{PATH} "${QT_BIN};$ENV{PATH}")
# spawn 偶发 "no such file or directory"（杀软对新产物的瞬时锁定），
# 有限次重试，仍失败才告警。
set(deploy_rc "")
foreach(_attempt RANGE 1 3)
  execute_process(
    COMMAND "${WINDEPLOYQT}" --${CFG} --no-translations --no-opengl-sw
            --no-system-d3d-compiler --no-compiler-runtime --dir "${EXE_DIR}" "${EXE}"
    RESULT_VARIABLE deploy_rc
    ERROR_VARIABLE deploy_err
    OUTPUT_VARIABLE deploy_out)
  if(deploy_rc EQUAL 0)
    break()
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" -E sleep 1)
endforeach()
if(NOT deploy_rc EQUAL 0)
  # vcpkg 只有 release 的 Qt DLL，Debug 构建到这里会失败——别把构建卡死。
  message(WARNING "windeployqt 失败（rc=${deploy_rc}）\n${deploy_err}${deploy_out}"
                  "\n构建目录可能缺 Qt 运行库")
endif()

# vcpkg 的 Qt 还链着 zlib/zstd/pcre2/icu 等第三方 DLL，windeployqt 不认识。
# 把 Qt bin 里目标目录还没有的 DLL 全部补齐（Qt6*.dll 上一步已收齐，会跳过）。
file(GLOB _deps "${QT_BIN}/*.dll")
foreach(_dll IN LISTS _deps)
  get_filename_component(_name "${_dll}" NAME)
  if(NOT EXISTS "${EXE_DIR}/${_name}")
    file(COPY "${_dll}" DESTINATION "${EXE_DIR}")
  endif()
endforeach()
