#!/bin/bash
# Linux 侧构建（在 VPS / CI 上跑）：CMake 出 fcp-client → CMake 出 Qt GUI
# → linuxdeploy（Qt 插件）→ 裁掉无用插件 → appimagetool（xz）打成 .AppImage
# （便携、双击运行，不需要安装）。
#
# 用法：在仓库根执行
#   bash scripts/desktop/build_linux.sh [--skip-fcp]
#
# 环境变量：
#   FCP_QT_PREFIX  可选，自编 Qt 的前缀（例如 CI 里 -no-icu 的 Qt）；
#                  不给就用系统 Qt（Ubuntu: qt6-base-dev）。自编 Qt 必须
#                  提供 bin/qmake，linuxdeploy-plugin-qt 靠它找插件。
#
# 环境：cmake、ninja、patchelf、libgl1-mesa-dev、curl、binutils(strip)。
# CLI 另需 vcpkg（见 docs/发布流程.md）。
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
echo "== CMake: Qt GUI${FCP_QT_PREFIX:+ (prefix=$FCP_QT_PREFIX)}"
GUI_CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr)
if [ -n "${FCP_QT_PREFIX:-}" ]; then
  GUI_CMAKE_ARGS+=(-DCMAKE_PREFIX_PATH="$FCP_QT_PREFIX")
fi
cmake -S "$ROOT/apps/desktop" -B "$GUI_BUILD" "${GUI_CMAKE_ARGS[@]}"
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
# linuxdeploy 只 strip 它自己部署的库；这两个是我们 install 进来的。
strip --strip-all "$APPDIR/usr/bin/fcp-client" "$APPDIR/usr/bin/FCP"

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
# linuxdeploy 自带的 appimagetool 只出 zstd；这里单独用它选 xz。
fetch "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
  "$TOOLS/appimagetool"

# CI 的容器里没有 FUSE；让 AppImage 自解压运行。
export APPIMAGE_EXTRACT_AND_RUN=1
# Qt 插件通过 QMAKE 找 Qt 安装；自编 Qt 用它的 qmake，系统 Qt 用 qmake6。
if [ -n "${FCP_QT_PREFIX:-}" ] && [ -x "$FCP_QT_PREFIX/bin/qmake" ]; then
  QMAKE="$FCP_QT_PREFIX/bin/qmake"
elif [ -z "${QMAKE:-}" ]; then
  QMAKE="$(command -v qmake6 || command -v qmake || echo /usr/lib/qt6/bin/qmake)"
fi
export QMAKE
# 自编 Qt 不在系统库路径里，linuxdeploy 用 ldd 解析 ELF 依赖时找不到
# libQt6Widgets.so.6（CI 首次跑就失败在这里）。把前缀的 lib 加进搜索路径，
# 也顺带保证 plugin-qt 找到的是同一份 Qt。
if [ -n "${FCP_QT_PREFIX:-}" ]; then
  export LD_LIBRARY_PATH="$FCP_QT_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

echo "== linuxdeploy（Qt 插件）"
cd "$WORK"
"$TOOLS/linuxdeploy" --appdir "$APPDIR" --plugin qt \
  --desktop-file "$APPDIR/usr/share/applications/fcp.desktop" \
  --icon-file "$ROOT/apps/desktop/assets/fcp.png"

# 裁掉用不到的 Qt 插件：PNG 解码内建于 Qt6Gui，GUI 里没有 GIF/ICO/JPEG
# 资源；输入法插件（ibus/compose）必须保留，否则中文输入失效。
rm -rf "$APPDIR/usr/plugins/imageformats" \
       "$APPDIR/usr/translations" "$APPDIR/usr/qt6/translations"

mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/fcp-client-gui-$VERSION-linux-amd64.AppImage"
echo "== appimagetool（xz）"
ARCH=x86_64 "$TOOLS/appimagetool" --comp xz --no-appstream "$APPDIR" "$OUT"
chmod +x "$OUT"

echo "== 产物："
ls -la "$OUT"
sha256sum "$OUT"
