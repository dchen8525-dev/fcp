#!/usr/bin/env bash
# Coverage gate for FCP (task C3 item ②): line >= 90%, branch >= 80%.
#
# Runs on Linux/macOS with gcc or clang, gcov and gcovr. The Windows dev box
# (VS Community) ships no native code-coverage tool, so this script is the
# authoritative gate and is meant to run in CI:
#
#   sudo apt-get install -y g++ cmake ninja-build python3-pip
#   pip3 install gcovr
#   ./scripts/coverage.sh
#
# Exit status is non-zero when either threshold is missed.
set -euo pipefail

cd "$(dirname "$0")/.."

BUILD_DIR=build/coverage
LINE_MIN=90
BRANCH_MIN=80

if [ -z "${VCPKG_ROOT:-}" ] || [ ! -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]; then
  echo "[coverage] VCPKG_ROOT 未设置或不是 vcpkg checkout；见 docs/部署运维指南.md §1" >&2
  exit 1
fi

cmake -S . -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DFCP_BUILD_TESTS=ON \
  -DFCP_COVERAGE=ON
cmake --build "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" --output-on-failure

# Every ctest process leaves its .gcda next to the object files, so one report
# over the build tree sees the union of all test binaries.
gcovr --root . --filter 'src/fcp/' "$BUILD_DIR" \
  --txt \
  --fail-under-line "$LINE_MIN" \
  --fail-under-branch "$BRANCH_MIN"

echo "[coverage] gate passed: line >= ${LINE_MIN}%, branch >= ${BRANCH_MIN}%"
