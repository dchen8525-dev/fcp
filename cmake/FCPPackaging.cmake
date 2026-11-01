# 包内文件清单（install 规则）。**打包本身不在这里**：.deb 由
# scripts/mkdeb.py 生成（纯 Python 标准库，Windows/Linux 同一条命令，
# 不需要 cpack / dpkg-deb / fakeroot）。
#
# 本文件只回答一个问题：发布包里的文件落在 FHS 的什么位置。两条路径都读它
#   * `cmake --install` → DESTDIR 自检树（release_build_linux.sh 用）
#   * scripts/mkdeb.py 自己有一套等价的落点表（见该脚本的
#     iter_package_files()，与这里逐条对齐，改一边要改另一边）
#
# 平台：Windows/macOS 构建里本文件什么也不做。
# 顶层 CMakeLists 在 FCP_BUILD_PROXY 下 include。

if(WIN32 OR APPLE)
  return()
endif()

# systemd unit：相对路径 -> <prefix>/lib/systemd/system=/usr/lib/systemd/system，
# 是 systemd 的规范位置（/lib/systemd/system 在 Ubuntu 上是它的符号链接）。
install(FILES packaging/debian/fcp-proxy.service
        DESTINATION lib/systemd/system)

# 启动参数：**绝对路径 /etc**。CMAKE_INSTALL_FULL_SYSCONFDIR 在 prefix=/usr 时
# 会算成 /usr/etc（GNUInstallDirs 不做 Debian 特判），而 dpkg 只把 /etc 下的
# 文件认成 conffile —— 落错地方会让"升级不覆盖运维配置"这条承诺静默失效。
install(FILES packaging/debian/fcp-proxy.env
        DESTINATION /etc/fcp)

# 文档与版权：通配 docs/*.md，新增文档自动进包（文档索引.md 是阅读入口）。
# 装到 /usr/share/doc/fcp-proxy/，与 mkdeb.py 的落点一致。
file(GLOB FCP_DOCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/docs/*.md)
install(FILES ${FCP_DOCS} VERSION
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/fcp-proxy)

# dpkg 的规范落点是 /usr/share/doc/<pkg>/copyright。
install(FILES packaging/debian/copyright
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/fcp-proxy)
