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

# A reused build tree unions this run's .gcda with the previous run's, so a
# green number can be built from stale counters. Start from scratch every time.
rm -rf "$BUILD_DIR"

cmake -S . -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DFCP_BUILD_TESTS=ON \
  -DFCP_COVERAGE=ON
cmake --build "$BUILD_DIR"
ctest --test-dir "$BUILD_DIR" --output-on-failure

# Every ctest process leaves its .gcda next to the object files, so one report
# over the build tree sees the union of all test binaries.
#
# The blocking gate is the protocol core (src/fcp) — the T0 decision 3 scope.
# tests/ is excluded: it is the instrument, not the product.
#
# Print the branch report first: gcovr's "Missing" column then names the
# uncovered branch lines, so a red gate points straight at what needs a test
# instead of at a percentage. (-b is the gcovr 5.0 spelling CI ships; newer
# gcovr deprecates it in favour of --txt-metric, hence the `|| true`.)
gcovr --root . --filter 'src/fcp/' "$BUILD_DIR" --txt -b || true
gcovr --root . --filter 'src/fcp/' "$BUILD_DIR" \
  --txt \
  --fail-under-line "$LINE_MIN" \
  --fail-under-branch "$BRANCH_MIN"

# The proxy engine and CLI host ship too, so their numbers are printed for
# tracking, but they do not gate yet: the M1 decision was taken on src/fcp and
# widening the blocking scope here (M-04) turned every release red on code that
# never carried that gate. Promote them to the gate once their own numbers are
# established and recorded in docs/发布流程.md §2.
gcovr --root . --filter 'src/proxy/' --filter 'apps/cli/' --exclude 'tests/' \
  "$BUILD_DIR" --txt || true
echo "[coverage] src/proxy + apps/cli above are informational (not gated)"

echo "[coverage] gate passed: line >= ${LINE_MIN}%, branch >= ${BRANCH_MIN}%"
