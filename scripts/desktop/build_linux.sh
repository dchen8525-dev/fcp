#!/bin/bash
# Linux 侧构建（在 VPS / CI 上跑）：CMake 出 fcp-client → CMake 出 Qt GUI
# → linuxdeploy（Qt 插件）打成 .AppImage（便携、双击运行，不需要安装）。
#
# 用法：在仓库根执行
#   bash scripts/desktop/build_linux.sh [--skip-fcp]
#
# 环境：Qt 6 Widgets 开发包（Ubuntu 22.04: qt6-base-dev）、cmake、ninja、
# patchelf、libgl1-mesa-dev、curl。CLI 另需 vcpkg（见 docs/发布流程.md）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
CLI_BUILD="$ROOT/build/linux-release"
GUI_BUILD="$ROOT/build/linux-gui"
APPDIR="$ROOT/build/appimage/AppDir"
WORK="$ROOT/build/appimage"
TOOLS="$ROOT/build/appimage/tools"
SKIP_FCP=0
[ "${1:-}" = "--skip-fcp" ] && SKIP_FCP=1

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
mkdir -p "$WORK" "$TOOLS"

if [ "$SKIP_FCP" = 0 ]; then
  echo "== CMake: release fcp-client"
  if [ -z "${VCPKG_ROOT:-}" ] || [ ! -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]; then
    echo "缺少 VCPKG_ROOT：先 bootstrap vcpkg 并 export VCPKG_ROOT（docs/部署运维指南.md §1）" >&2
    exit 1
  fi
  cmake -S "$ROOT" -B "$CLI_BUILD" \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DFCP_BUILD_PROXY=ON -DFCP_BUILD_TESTS=OFF -DFCP_BUILD_TOOLS=OFF >/dev/null
  cmake --build "$CLI_BUILD" --parallel --target fcp-client
fi

BIN="$CLI_BUILD/apps/cli/fcp-client"
[ -x "$BIN" ] || { echo "缺少可执行文件：$BIN"; exit 1; }

# ---------------------------------------------------------------- Qt GUI
echo "== CMake: Qt GUI"
cmake -S "$ROOT/apps/desktop" -B "$GUI_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$GUI_BUILD" --parallel

# ---------------------------------------------------------------- AppDir
echo "== AppDir"
rm -rf "$APPDIR"
DESTDIR="$APPDIR" cmake --install "$GUI_BUILD"
install -Dm755 "$BIN" "$APPDIR/usr/bin/fcp-client"
install -Dm644 "$ROOT/apps/desktop/assets/fcp.desktop" \
  "$APPDIR/usr/share/applications/fcp.desktop"
install -Dm644 "$ROOT/apps/desktop/assets/fcp.png" \
  "$APPDIR/usr/share/icons/hicolor/512x512/apps/fcp.png"
# linuxdeploy 既接受 AppDir 根下的图标，也接受 hicolor 布局；两处都放一份。
install -Dm644 "$ROOT/apps/desktop/assets/fcp.png" "$APPDIR/fcp.png"

# ---------------------------------------------------------------- linuxdeploy
fetch() {
  local url="$1" out="$2"
  if [ ! -x "$out" ]; then
    echo "== 下载 $(basename "$out")"
    curl -fsSL --retry 3 -o "$out" "$url"
    chmod +x "$out"
  fi
}
fetch "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
  "$TOOLS/linuxdeploy"
fetch "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage" \
  "$TOOLS/linuxdeploy-plugin-qt"

# CI 的容器里没有 FUSE；让 AppImage 自解压运行。
export APPIMAGE_EXTRACT_AND_RUN=1
# Qt 插件通过 QMAKE 找 Qt 安装；Ubuntu 的 qmake6 在 /usr/bin。
if [ -z "${QMAKE:-}" ]; then
  QMAKE="$(command -v qmake6 || command -v qmake || echo /usr/lib/qt6/bin/qmake)"
fi
export QMAKE

echo "== linuxdeploy（Qt 插件）"
cd "$WORK"
"$TOOLS/linuxdeploy" --appdir "$APPDIR" --plugin qt --output appimage \
  --desktop-file "$APPDIR/usr/share/applications/fcp.desktop" \
  --icon-file "$ROOT/apps/desktop/assets/fcp.png"

SRC="$(ls -1t "$WORK"/*.AppImage | head -1)"
[ -f "$SRC" ] || { echo "没有生成 AppImage"; exit 1; }
mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/fcp-client-gui-$VERSION-linux-amd64.AppImage"
cp "$SRC" "$OUT"
chmod +x "$OUT"

echo "== 产物："
ls -la "$OUT"
sha256sum "$OUT"
