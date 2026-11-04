# 包内文件清单（install 规则）。**打包本身不在这里**：.deb 由
# scripts/build_deb.sh 调 dpkg-deb 打成（Linux 标准工具，不需要 cpack /
# fakeroot / python）。
#
# 本文件是这个包**唯一**的落点真源：`cmake --install` 按它装出一棵 DESTDIR
# 树，scripts/build_deb.sh 直接把这棵树打成 .deb（只补 DEBIAN/ 元数据），
# 所以不存在"打包器另抄一份文件表、改一边忘另一边"的漂移。
#
# 平台：Windows/macOS 构建里本文件什么也不做。
# 顶层 CMakeLists 在 FCP_BUILD_PROXY 下 include。

if(WIN32 OR APPLE)
  return()
endif()

# systemd unit：相对路径 -> <prefix>/lib/systemd/system=/usr/lib/systemd/system，
# 是 systemd 的规范位置（/lib/systemd/system 在 Ubuntu 上是它的符号链接）。
install(FILES packaging/debian/fcp.service
        DESTINATION lib/systemd/system)

# 启动参数：**绝对路径 /etc**。CMAKE_INSTALL_FULL_SYSCONFDIR 在 prefix=/usr 时
# 会算成 /usr/etc（GNUInstallDirs 不做 Debian 特判），而 dpkg 只把 /etc 下的
# 文件认成 conffile —— 落错地方会让"升级不覆盖运维配置"这条承诺静默失效。
install(FILES packaging/debian/fcp.env
        DESTINATION /etc/fcp)

# 文档与版权：通配 docs/*.md，新增文档自动进包（文档索引.md 是阅读入口）。
# 落点必须是 /usr/share/doc/<包名>/，也就是 fcp-server —— deb 包名 #57 改过，
# 这里若还写 fcp，DESTDIR 自检与安装冒烟都会找不到文档。
file(GLOB FCP_DOCS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/docs/*.md)
install(FILES ${FCP_DOCS} VERSION
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/fcp-server)

# dpkg 的规范落点是 /usr/share/doc/<pkg>/copyright。
install(FILES packaging/debian/copyright
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/fcp-server)
