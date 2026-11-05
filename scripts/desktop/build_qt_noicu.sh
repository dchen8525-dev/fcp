#!/bin/bash
# 构建 AppImage 用的 Qt（只 qtbase，关掉 ICU/OpenSSL/DBus）。
#
# 为什么：发行版 Qt 的 Qt6Core 依赖 libicu*，ICU 数据在 AppImage 里占
# ~35 MiB（解包后，压缩后约 10 MiB），超过整个包体的一半。FCP 的界面只用
# UTF-8 字符串与 Qt Widgets，不需要 ICU 的本地化排序/转码；关掉 ICU 后
# AppImage 预计从 ~25 MiB 降到 ~13 MiB。OpenSSL 与 DBus 也没被用到。
#
# 用法：
#   bash scripts/desktop/build_qt_noicu.sh [PREFIX]
#
# PREFIX 默认 ~/qt-noicu-6.8.3；已存在 bin/qmake 时直接跳过（CI 缓存命中）。
# 依赖（Ubuntu 22.04）：build-essential cmake ninja-build perl python3
#   libgl1-mesa-dev libxkbcommon-dev libxkbcommon-x11-dev libfontconfig1-dev
#   libfreetype6-dev libx11-dev libx11-xcb-dev libxext-dev libxfixes-dev
#   libxi-dev libxrender-dev libxcb1-dev libxcb-cursor-dev libxcb-glx0-dev
#   libxcb-icccm4-dev libxcb-image0-dev libxcb-keysyms1-dev
#   libxcb-randr0-dev libxcb-render-util0-dev libxcb-shape0-dev
#   libxcb-shm0-dev libxcb-sync-dev libxcb-util-dev libxcb-xfixes0-dev
#   libxcb-xinerama0-dev libxcb-xkb-dev libxkbcommon-x11-dev
set -euo pipefail

QT_VERSION="6.8.3"
PREFIX="${1:-$HOME/qt-noicu-$QT_VERSION}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_PARENT="$ROOT/build/qt-src"
TARBALL="$SRC_PARENT/qtbase-everywhere-src-$QT_VERSION.tar.xz"
SRC="$SRC_PARENT/qtbase-everywhere-src-$QT_VERSION"
URL="https://download.qt.io/archive/qt/6.8/$QT_VERSION/submodules/qtbase-everywhere-src-$QT_VERSION.tar.xz"

if [ -x "$PREFIX/bin/qmake" ]; then
  echo "== Qt $QT_VERSION 已存在：$PREFIX"
  exit 0
fi

for tool in cmake ninja perl; do
  command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 1; }
done

mkdir -p "$SRC_PARENT"
if [ ! -f "$TARBALL" ]; then
  echo "== 下载 Qt $QT_VERSION (qtbase)"
  curl -fL --retry 3 -o "$TARBALL" "$URL"
fi
if [ ! -d "$SRC" ]; then
  echo "== 解包"
  tar -xJf "$TARBALL" -C "$SRC_PARENT"
fi

BUILD="$SRC/build-noicu"
rm -rf "$BUILD"
mkdir -p "$BUILD"
cd "$BUILD"

echo "== configure（-no-icu -no-openssl -no-dbus）"
"$SRC/configure" \
  -prefix "$PREFIX" \
  -release \
  -opensource -confirm-license \
  -nomake examples -nomake tests \
  -no-icu -no-openssl -no-dbus

echo "== build"
cmake --build . --parallel

echo "== install"
cmake --install .

# 源码树很大，装完就删；失败也不影响结果。
cd /
rm -rf "$SRC"

echo "== 完成：$PREFIX"
"$PREFIX/bin/qmake" -query QT_VERSION
du -sh "$PREFIX"
