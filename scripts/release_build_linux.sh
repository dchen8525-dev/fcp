#!/usr/bin/env bash
# Linux 发布构建：configure → build → ctest → scripts/build_deb.py 打 deb。
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
# 需要：build-essential cmake ninja-build python3（见 docs/发布流程.md §2）。
# 打包本身不依赖 dpkg-dev / fakeroot / cpack —— 那些只在本脚本最后一步
# 用 dpkg-deb 做交叉校验时才需要，缺了会跳过。
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

# 出厂自检：把包内文件按 install() 规则单独装到一棵临时树里，再跑一次。
# 这一步与 deb 的内容是同一批文件（同一条 install 规则），目标是提前抓住
#   * 版本号没注入（--version 输出对不上 tag）；
#   * 二进制起不来（缺动态库、RPATH 写错）——打包器只看文件在不在，不看能不能跑。
# 放在打包之前：跑不起来的二进制没有打成分发产物的必要。
# 真正的 dpkg 安装冒烟在工作流里做（需要 root 与 dpkg）。
echo "== 安装自检（install 规则 + --version）"
# 必须用 DESTDIR 而不是 `--prefix`：conffile 的落点是绝对路径 /etc/fcp，
# `--prefix` 挪不动绝对路径，会把文件写到真实的 /etc 里（非 root 直接失败，
# root 下更糟——污染构建机）。DESTDIR 给所有路径（含绝对路径）加前缀，
# 与 build_deb.py 造 deb 时用的是同一套落点。
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

# 打包：scripts/build_deb.py 用标准库直接写 ar + tar.gz，Windows 上也能跑同一条命令。
# 它自带结构自检（成员齐全、control 单段落、落点齐全），这里再补一道外部校验。
echo "== build_deb"
case "$(uname -m)" in
  x86_64|amd64) DEB_ARCH=amd64 ;;
  aarch64|arm64) DEB_ARCH=arm64 ;;
  *) DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)" ;;
esac
python3 "$ROOT/scripts/build_deb.py" \
  --bin-dir "$BUILD_DIR/apps/fcp-proxy" \
  --build-dir "$BUILD_DIR" \
  --version "$VERSION" \
  --arch "$DEB_ARCH"

# control 结构校验：出包就跑，别等到安装冒烟才发现。
# 起因是首跑 v0.0.1：description 文件以换行结尾，生成器把 Installed-Size
# 顶成了第二段落，`dpkg -i` 报 "missing 'Package' field"。
# dpkg-deb --info 会把这种包照样打印出来（不报错），所以这里必须自己看结构。
# build_deb.py 已经查过一遍；这里用 dpkg-deb 复核，确认包是 dpkg 眼里的合法 deb。
deb="$(ls "$BUILD_DIR"/packages/*.deb)"
if command -v dpkg-deb >/dev/null; then
  control_file="$BUILD_DIR/packages/control.txt"
  dpkg-deb --ctrl-tarfile "$deb" | tar -xO ./control > "$control_file"
  cat "$control_file"
  # 段落只允许一个，也就是**一个空行都不许有**：control 以最后一个字段的
  # 结尾换行收尾，多一个空行就是第二个段落，dpkg 会在那里截断。
  # （CPack 时代末尾会补一个空行，所以那时的期望是 1；build_deb.py 不补，期望是 0。）
  # 数文件而不是管道接命令替换：$(...) 会吃掉结尾换行，会把 1 数成 0。
  # 计数器用 awk 不用 grep -c：grep -c 零匹配返回 1，与 set -e 相加会变成假警报。
  blank_lines="$(awk '$0 == "" { n++ } END { print n + 0 }' "$control_file")"
  if [ "$blank_lines" -ne 0 ]; then
    echo "::error::control 里有 $blank_lines 个空行（应为 0）：会顶出多余段落" >&2
    exit 1
  fi
  for field in Package Version Architecture Maintainer Description; do
    if ! grep -q "^${field}:" "$control_file"; then
      echo "::error::control 缺 ${field} 字段" >&2
      exit 1
    fi
  done
else
  echo "::notice::没有 dpkg-deb，跳过外部复核（build_deb.py 的自检已通过）"
fi

echo "== 产出"
if command -v dpkg-deb >/dev/null; then
  dpkg-deb --info "$deb"
fi
ls -l "$BUILD_DIR"/packages/
