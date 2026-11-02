#!/usr/bin/env bash
# Linux 桌面客户端 AppImage：configure → build → ctest → AppDir → AppImage → 冒烟。
#
# AppImage 是单文件、双击即运行、无需安装的分发格式：Qt 运行时与插件都打进
# 同一个文件，删除文件就是卸载。发布工作流（.github/workflows/release.yml 的
# linux-appimage job）跑的就是这个脚本，本地可用同一条命令复现。
#
# 用法：
#   scripts/release_build_linux_appimage.sh [build-dir] [version]
#
# 环境变量：
#   QT_ROOT_DIR   可选。Qt6 前缀（aqtinstall / 自编译）；给出时作为
#                 CMAKE_PREFIX_PATH，并优先用它的 qmake 给 linuxdeploy-plugin-qt。
#   QMAKE         可选。显式指定 qmake（优先级最高）。
#
# 产出：dist/FCP-Client-<version>-x86_64.AppImage
#
# 首次运行会把 linuxdeploy / linuxdeploy-plugin-qt / appimagetool 下载到
# <build-dir>/appimage-tools（之后复用，不重复下载）。
#
# 依赖：build-essential cmake ninja-build curl file librsvg2-bin
#       （冒烟还需要 xvfb；没有 xvfb 时退回 Qt offscreen 平台）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-$ROOT/build/release-appimage}"
VERSION="${2:-$(tr -d '[:space:]' < "$ROOT/VERSION")}"
DIST="$ROOT/dist"
APPDIR="$BUILD_DIR/AppDir"
TOOLS="$BUILD_DIR/appimage-tools"
OUT="$DIST/FCP-Client-${VERSION}-x86_64.AppImage"

echo "== fcp ${VERSION} Linux AppImage"
echo "   build: $BUILD_DIR"

cmake -S "$ROOT" -B "$BUILD_DIR" -G "${CMAKE_GENERATOR:-Ninja}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DFCP_RELEASE_VERSION="$VERSION" \
  -DFCP_BUILD_APP=ON \
  -DFCP_BUILD_PROXY=ON \
  -DFCP_BUILD_TESTS=ON \
  -DFCP_BUILD_TOOLS=ON \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_PREFIX_PATH="${QT_ROOT_DIR:-}"

cmake --build "$BUILD_DIR" --parallel "$(nproc)"

echo "== ctest（发布门禁）"
ctest --test-dir "$BUILD_DIR" --output-on-failure

EXE="$(find "$BUILD_DIR" -type f -name fcp_client -not -path '*/CMakeFiles/*' -print -quit)"
if [ -z "$EXE" ]; then
  echo "::error::找不到 fcp_client 可执行文件" >&2
  exit 1
fi

# --- AppDir ------------------------------------------------------------------
# 只装客户端本体与文档；服务端二进制、systemd unit、deb conffile 都不进来。
echo "== 组装 AppDir"
rm -rf "$APPDIR"
install -Dm755 "$EXE" "$APPDIR/usr/bin/fcp_client"
install -Dm644 "$ROOT/packaging/linux/fcp-client.desktop" \
  "$APPDIR/usr/share/applications/fcp-client.desktop"
install -Dm644 "$ROOT/docs/部署运维指南.md" \
  "$APPDIR/usr/share/doc/fcp-client/部署运维指南.md"

ICON="$BUILD_DIR/fcp-client.png"
if command -v rsvg-convert >/dev/null; then
  rsvg-convert -w 256 -h 256 "$ROOT/packaging/linux/fcp-client.svg" -o "$ICON"
elif command -v convert >/dev/null; then
  convert -background none "$ROOT/packaging/linux/fcp-client.svg" -resize 256x256 "$ICON"
else
  echo "::error::需要 rsvg-convert（librsvg2-bin）或 ImageMagick 把 SVG 图标转成 PNG" >&2
  exit 1
fi
install -Dm644 "$ICON" \
  "$APPDIR/usr/share/icons/hicolor/256x256/apps/fcp-client.png"

# --- linuxdeploy / appimagetool ---------------------------------------------
mkdir -p "$TOOLS"
fetch() {
  local url="$1" dest="$2"
  if [ ! -x "$dest" ]; then
    echo "  下载 $(basename "$dest")"
    curl -fsSL --retry 3 -o "$dest" "$url"
    chmod +x "$dest"
  fi
}
fetch "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
  "$TOOLS/linuxdeploy-x86_64.AppImage"
fetch "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage" \
  "$TOOLS/linuxdeploy-plugin-qt-x86_64.AppImage"
fetch "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
  "$TOOLS/appimagetool-x86_64.AppImage"

# linuxdeploy 按名字在 PATH 里找插件；包一层脚本，避免依赖 FUSE/可执行位细节。
cat > "$TOOLS/linuxdeploy-plugin-qt" <<EOF
#!/bin/sh
exec "$TOOLS/linuxdeploy-plugin-qt-x86_64.AppImage" --appimage-extract-and-run "\$@"
EOF
chmod +x "$TOOLS/linuxdeploy-plugin-qt"

if [ -z "${QMAKE:-}" ]; then
  for q in "${QT_ROOT_DIR:-}/bin/qmake" "$(command -v qmake6 || true)" \
           /usr/lib/qt6/bin/qmake6 "$(command -v qmake || true)"; do
    if [ -n "$q" ] && [ -x "$q" ]; then
      QMAKE="$q"
      break
    fi
  done
fi
if [ -z "${QMAKE:-}" ] || [ ! -x "$QMAKE" ]; then
  echo "::error::找不到 qmake6/qmake；请设置 QMAKE 或安装 qt6-base-dev-tools" >&2
  exit 1
fi
export QMAKE

echo "== linuxdeploy（Qt 插件：$QMAKE）"
# CI 容器/精简系统不一定有 FUSE；让所有 AppImage 工具都走解包执行。
export APPIMAGE_EXTRACT_AND_RUN=1
PATH="$TOOLS:$PATH" "$TOOLS/linuxdeploy-x86_64.AppImage" \
  --appimage-extract-and-run \
  --appdir "$APPDIR" \
  --executable "$APPDIR/usr/bin/fcp_client" \
  --desktop-file "$APPDIR/usr/share/applications/fcp-client.desktop" \
  --icon-file "$ICON" \
  --plugin qt

echo "== appimagetool"
mkdir -p "$DIST"
rm -f "$OUT"
ARCH=x86_64 VERSION="$VERSION" "$TOOLS/appimagetool-x86_64.AppImage" \
  --appimage-extract-and-run "$APPDIR" "$OUT"

# --- 冒烟：解包运行，窗口进程必须活过 6 秒 ----------------------------------
# AppImage 默认走 FUSE；CI 容器里可能没有，统一用 APPIMAGE_EXTRACT_AND_RUN=1。
echo "== 启动冒烟（6 秒）"
set +e
if command -v xvfb-run >/dev/null; then
  timeout 8 xvfb-run -a env APPIMAGE_EXTRACT_AND_RUN=1 "$OUT" >/dev/null 2>&1
else
  timeout 8 env APPIMAGE_EXTRACT_AND_RUN=1 QT_QPA_PLATFORM=offscreen \
    "$OUT" >/dev/null 2>&1
fi
status=$?
set -e
if [ "$status" -ne 124 ]; then
  echo "::error::AppImage 启动即退出（exit $status）；多半缺 Qt 插件或运行库" >&2
  exit 1
fi

echo "== 产出"
ls -l "$OUT"
