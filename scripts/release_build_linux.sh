#!/usr/bin/env bash
# Linux 发布构建：configure → build → ctest → cpack -G DEB。
#
# 发布工作流（.github/workflows/release.yml 的 linux-deb job）就是跑这个脚本，
# 本地（Linux / WSL / 容器）可以跑同一条命令复现，两边不会漂。
#
# 用法：
#   scripts/release_build_linux.sh [build-dir] [version]
#
#   version 缺省取仓库根 VERSION 文件；CI 传 tag 去掉前导 v 的版本号，
#   CMake 侧会再次校验格式（顶层 CMakeLists 的 FCP_RELEASE_VERSION）。
#
# 产出：<build>/packages/fcp-proxy_<version>_<arch>.deb
#
# 需要：build-essential cmake ninja-build dpkg-dev（见 docs/发布流程.md §2）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-$ROOT/build/release}"
VERSION="${2:-$(tr -d '[:space:]' < "$ROOT/VERSION")}"
STAGE_DIR="$BUILD_DIR/release-deploy"

echo "== fcp ${VERSION} release build"
echo "   build: $BUILD_DIR"

cmake -S "$ROOT" -B "$BUILD_DIR" -G "${CMAKE_GENERATOR:-Ninja}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DFCP_RELEASE_VERSION="$VERSION" \
  -DFCP_BUILD_PROXY=ON \
  -DFCP_BUILD_TESTS=ON \
  -DFCP_BUILD_TOOLS=ON \
  -DCMAKE_INSTALL_PREFIX=/usr

cmake --build "$BUILD_DIR" --parallel "$(nproc)"

echo "== ctest（发布门禁）"
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "== cpack"
(cd "$BUILD_DIR" && cpack -G DEB --config CPackConfig.cmake)

# 出厂自检：把包内文件按 install() 规则单独装到一棵临时树里，再跑一次。
# 这一步与 deb 的内容是同一批文件（同一条 install 规则），目标是提前抓住
#   * 版本号没注入（--version 输出对不上 tag）；
#   * 二进制起不来（缺动态库、RPATH 写错）——CPack 只看文件在不在，不看能不能跑。
# 真正的 dpkg 安装冒烟在工作流里做（需要 root 与 dpkg）。
echo "== 安装自检（install 规则 + --version）"
# 必须用 DESTDIR 而不是 `--prefix`：conffile 的落点是绝对路径 /etc/fcp，
# `--prefix` 挪不动绝对路径，会把文件写到真实的 /etc 里（非 root 直接失败，
# root 下更糟——污染构建机）。DESTDIR 给所有路径（含绝对路径）加前缀，
# 与 CPack 造 deb 时用的是同一套机制。
rm -rf "$STAGE_DIR"
DESTDIR="$STAGE_DIR" cmake --install "$BUILD_DIR" --strip >/dev/null
for bin in fcp-proxy-server fcp-proxy-client; do
  ver="$("$STAGE_DIR/usr/bin/$bin" --version | awk '{print $2}')"
  if [ "$ver" != "$VERSION" ]; then
    echo "::error::$bin 报出版本 '$ver'，期望 '$VERSION'" >&2
    exit 1
  fi
  echo "   $bin $ver"
done
test -f "$STAGE_DIR/etc/fcp/fcp-proxy.env"
test -f "$STAGE_DIR/usr/lib/systemd/system/fcp-proxy.service"
test -f "$STAGE_DIR/usr/share/doc/fcp-proxy/部署运维指南.md"

echo "== 产出"
dpkg-deb --info "$BUILD_DIR"/packages/*.deb
ls -l "$BUILD_DIR"/packages/
