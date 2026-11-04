#!/bin/bash
# Linux 侧构建（在 VPS / CI 上跑）：CMake 出 fcp-client → 放进 sidecar 目录
# → tauri build 出 .AppImage（便携、双击运行，不需要安装）。
#
# 用法：在仓库根执行
#   FCP_TAURI_DIR=apps/desktop bash apps/desktop/scripts/build_linux.sh [--skip-fcp]
#
# 环境：Rust（cargo）、Node/npm、webkit2gtk-4.1、gtk3、librsvg、patchelf、cmake、
# 编译器。见 docs/发布流程.md。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TAURI_DIR="$ROOT/apps/desktop"
TARGET="x86_64-unknown-linux-gnu"
SKIP_FCP=0
[ "${1:-}" = "--skip-fcp" ] && SKIP_FCP=1

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

if [ "$SKIP_FCP" = 0 ]; then
  echo "== CMake: release fcp-client"
  if [ -z "${VCPKG_ROOT:-}" ] || [ ! -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]; then
    echo "缺少 VCPKG_ROOT：先 bootstrap vcpkg 并 export VCPKG_ROOT（docs/部署运维指南.md §1）" >&2
    exit 1
  fi
  cmake -S "$ROOT" -B "$ROOT/build/linux-release" \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DFCP_BUILD_PROXY=ON -DFCP_BUILD_TESTS=OFF -DFCP_BUILD_TOOLS=OFF >/dev/null
  cmake --build "$ROOT/build/linux-release" --parallel --target fcp-client
fi

BIN="$ROOT/build/linux-release/apps/cli/fcp-client"
[ -x "$BIN" ] || { echo "缺少可执行文件：$BIN"; exit 1; }
mkdir -p "$TAURI_DIR/src-tauri/binaries"
cp "$BIN" "$TAURI_DIR/src-tauri/binaries/fcp-client-$TARGET"
chmod +x "$TAURI_DIR/src-tauri/binaries/fcp-client-$TARGET"

echo "== Tauri: build AppImage"
cd "$TAURI_DIR"
[ -d node_modules ] || npm install --no-audit --no-fund
npx tauri build --target "$TARGET" --bundles appimage

SRC="$(ls -1 "$TAURI_DIR"/src-tauri/target/"$TARGET"/release/bundle/appimage/*.AppImage | head -1)"
[ -f "$SRC" ] || { echo "没有生成 AppImage"; exit 1; }
# 版本号的唯一真源是仓库根的 VERSION（tauri.conf.json 在发布流水线里先同步）。
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/fcp-client-$VERSION-linux-amd64.AppImage"
cp "$SRC" "$OUT"
chmod +x "$OUT"

echo "== 产物："
ls -la "$OUT"
sha256sum "$OUT"
