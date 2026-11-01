# 发布打包：Ubuntu 下的 fcp-proxy deb。
#
# 目标（与 release 工作流一一对应）：
#   cpack -G DEB --config <build>/CPackConfig.cmake
#     -> <build>/packages/fcp-proxy_<VERSION>_<ARCH>.deb
#
# 只用 CPack 的 DEB 生成器 + 一份显式的"装什么"清单，不引 debhelper /
# dpkg-buildpackage：包内文件就六项（两个可执行文件、systemd unit、conffile、
# 文档、copyright），FHS 落点全部写在下面的 install() 里，审包时一眼到底。
#
# 依赖：dpkg、dpkg-dev、fakeroot（ubuntu runner 默认都有；shlibdeps 要 dpkg-shlibdeps）。
# 平台：Windows/macOS 构建里本文件什么也不做（返回在 include(CPack) 之前，
# 因此不会留下半配置的 CPack）。顶层 CMakeLists 在 FCP_BUILD_PROXY 下 include。

if(WIN32 OR APPLE)
  return()
endif()

# --- 包内文件 -----------------------------------------------------------------

# systemd unit：相对路径 -> <prefix>/lib/systemd/system=/usr/lib/systemd/system，
# 是 systemd 的规范位置（/lib/systemd/system 在 Ubuntu 上是它的符号链接）。
install(FILES packaging/debian/fcp-proxy.service
        DESTINATION lib/systemd/system)
# 启动参数：**绝对路径 /etc**。CMAKE_INSTALL_FULL_SYSCONFDIR 在 prefix=/usr 时
# 会算成 /usr/etc（GNUInstallDirs 不做 Debian 特判），而 dpkg 只把 /etc 下的
# 文件认成 conffile —— 落错地方会让"升级不覆盖运维配置"这条承诺静默失效。
# 绝对 DESTINATION 在 CPack DEB 下由 DESTDIR 机制正确接管（CPackDeb 置
# CPACK_SET_DESTDIR=ON）。
install(FILES packaging/debian/fcp-proxy.env
        DESTINATION /etc/fcp)

# 文档与版权：通配 docs/*.md，新增文档自动进包（文档索引.md 是阅读入口）。
# 装到 /usr/share/doc/fcp-proxy/，与 cpkg 的 doc 落点一致。
file(GLOB FCP_DOCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/docs/*.md)
install(FILES ${FCP_DOCS} VERSION
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/fcp-proxy)

# --- 打包元数据 ---------------------------------------------------------------
#
# control 文件不手写：CPack 用下面的变量生成，个别段落（Description 的
# 完整文本、copyright、maintainer scripts）走 packaging/debian 下的文件。
# packaging/debian/control.in 是同样内容的可读版本，供审阅；改了变量记得
# 同步它，反之亦然。

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "fcp-proxy")
set(CPACK_PACKAGE_VENDOR "dchen8525-dev")
set(CPACK_PACKAGE_VERSION "${FCP_VERSION}")
# 版本号是 X.Y.Z，没有 Debian 修订号；上游版本直接当包版本。
set(CPACK_DEBIAN_PACKAGE_VERSION "${FCP_VERSION}")
set(CPACK_PACKAGE_CONTACT "${FCP_MAINTAINER}")
set(CPACK_PACKAGE_HOMEPAGE_URL "${FCP_HOMEPAGE}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "FCP proxy server and client (UDP tunnel with adaptive FEC)")
set(CPACK_PACKAGE_DESCRIPTION_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/description")
set(CPACK_RESOURCE_FILE_LICENSE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/copyright")

set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
# 依赖显式写死，不用 CPACK_DEBIAN_PACKAGE_SHLIBDEPS=ON 自动推导：
#   * 自动推导依赖 dpkg-shlibdeps 的结果，missing 时会静默退化成"无依赖"；
#     显式写死的话，装到缺库的系统上会在启动时报缺 .so，而不是装完什么都没有。
#   * 两个可执行文件只动态依赖 libc/libstdc++（fcp 与 fcp_proxy_core 都是静态库），
#     清单短到能一眼看完，没有自动推导的必要。
# 下限对齐构建机：ubuntu-22.04 = glibc 2.35、gcc 11（GLIBCXX_3.4.29）。
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libstdc++6 (>= 11), libc6 (>= 2.35)")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "ca-certificates")
# conffiles 显式给出，不赌 CPack 的自动推断：dpkg 只认 control.tar 里的这份
# 清单，漏了它，"升级保留运维修改"就静默失效（/etc 下改了参数的下一次
# apt upgrade 会被覆盖，而且没人会收到提示）。conffiles 里每条都必须是包内
# 的绝对路径，install() 与此处任何一处改动都要同步。
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/conffiles;"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postinst;"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/prerm;"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postrm")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
# 架构由 CPack 从工具链推出（amd64 / arm64），不硬编码。

set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_BINARY_DIR}/packages")
set(CPACK_STRIP_FILES ON)

include(CPack)
