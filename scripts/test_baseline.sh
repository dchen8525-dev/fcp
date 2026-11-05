#!/bin/sh
# Test-suite baseline guard for the src/fcp refactor.（原 scripts/test_baseline.py
# 去 Python 化，2026-11-05：仓库的工程脚本统一 shell/C++。）
#
# WHY THIS EXISTS
# ---------------
# src/fcp 重写保持协议与线格式冻结，测试套件就是等价契约：每一步重构都必须
# 让 ctest 保持全绿且不改断言。单看"全绿"证明不了这一点——删断言、删整个
# 测试函数、删整个测试二进制同样全绿。本脚本把套件的"形状"钉住，让那种静默
# 侵蚀响亮失败。
#
# WHAT IT CHECKS
#   1. tests/CMakeLists.txt 列出的每个测试二进制都还存在
#   2. 每个二进制的测试函数数 >= 基线（只许涨不许跌）
#   3. 每个二进制的 CHECK/CHECK_EQ 数 >= 基线
#
# 基线 tests/test_baseline.txt（纯文本：`<test> <functions> <checks>`，# 开
# 头是注释），随代码评审：降低数字的提交必须说明原因。
#
#   scripts/test_baseline.sh --write   # 记录/刷新基线
#   scripts/test_baseline.sh           # 校验
#
# 无 CMake、无解释器依赖之外的假设；实现是 awk（Linux/Windows Git Bash 都
# 自带）。set -u + 固定路径，别找捷径。

set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TESTS="$REPO/tests"
BASELINE="$TESTS/test_baseline.txt"
CMAKE="$TESTS/CMakeLists.txt"

# 测试函数 = 无参、无返回值的自由函数：void TestSomething() {
# （套件刻意不用测试框架，这就是全部契约。）
# CHECK(...) / CHECK_EQ(...)；个别文件带 fcp_test:: / ::fcp_test:: 前缀。
AWK_PROG='
BEGIN { fn=0; chk=0 } # 已计入 read_code 的空行都注释化处理
/^void[ \t]+[A-Za-z_][A-Za-z_0-9]*\(\)[ \t]*\{/ { fn++ }
/CHECK(_EQ)?[ \t]*\(/ { chk++ }
END { printf "%d %d\n", fn, chk }'

# 1) 从 CMakeLists 文本里挖测试名（故意不 invoke cmake：这脚本要在没有
#    CMake 的机器上也能审）。set(FCP_TEST_NAMES ...) 列表 + 列表外的
#    add_executable(fcp_<name> ...)（如 cli_test）。
list_binaries() {
  awk '
    /set\(\s*FCP_TEST_NAMES/ { inlist=1 }
    inlist {
      # list 以第一个空行前的 ")" 结束（CMakeLists 里的列表就写成一行）
      if (match($0, /FCP_TEST_NAMES[ \t]*/)) {
        rest = substr($0, RSTART + RLENGTH)
        n = split(rest, toks, /[ \t)]+/)
        for (i = 1; i <= n; i++)
          if (toks[i] != "" && toks[i] !~ /^#/) print toks[i]
      } else {
        n = split($0, toks, /[ \t)]+/)
        for (i = 1; i <= n; i++)
          if (toks[i] != "" && toks[i] !~ /^#/) print toks[i]
      }
      if (inlist && /\)/) inlist=0
      next
    }
    /add_executable\(\s*fcp_[A-Za-z_0-9]+/ {
      match($0, /fcp_[A-Za-z_0-9]+/)
      print substr($0, RSTART + 4, RLENGTH - 4)
    }
  ' "$CMAKE" | sort -u
}

# 2) 数形状：<file> <functions> <checks>
measure() {
  for name in $(list_binaries); do
    file="$TESTS/$name.cc"
    if [ ! -f "$file" ]; then
      echo "ERROR: tests/$name.cc 在 CMakeLists.txt 里但文件不存在" >&2
      exit 2
    fi
    awk "$AWK_PROG" "$file" | awk -v n="$name" '{ printf "%s %s %s\n", n, $1, $2 }'
  done
}

# unlisted 的 *_test.cc 报告但不失败：半接线的实验不该把门禁卡死。
note_unlisted() {
  found="$(ls "$TESTS"/*_test.cc 2>/dev/null | xargs -n1 basename 2>/dev/null | sed s/.cc$//)"
  listed="$(list_binaries)"
  unlisted=$(printf "%s\n%s\n" "$found" "$listed" | sort -u | comm -23 /dev/stdin <(echo "$listed") | tr '\n' ' ')
  for name in $unlisted; do
    [ -f "$TESTS/$name.cc" ] && echo "note: not built by ctest: $name"
  done
}

write_baseline() {
  measure > "$BASELINE.tmp"
  {
    echo "# 由 scripts/test_baseline.sh --write 生成。数字是地板：重构只许加"
    echo "# 测试，不许减。降低某个数字的提交必须说明原因。格式："
    echo "# <test> <functions> <checks>"
    echo "#"
    cat "$BASELINE.tmp"
  } > "$BASELINE"
  rm -f "$BASELINE.tmp"
  total_f=$(awk '{ f+=$2 } END { print f }' "$BASELINE")
  total_c=$(awk '{ c+=$3 } END { print c }' "$BASELINE")
  n=$(grep -cv '^[[:space:]]*#' "$BASELINE")
  echo "baseline written: $n binaries, $total_f test functions, $total_c CHECKs"
}

verify() {
  if [ ! -f "$BASELINE" ]; then
    echo "ERROR: tests/test_baseline.txt missing; run --write once"
    return 2
  fi
  measure > "$REPO/.baseline.current.$$"
  note_unlisted
  status=0
  awk '!/^[[:space:]]*#/ && $1 != "" { print }' "$BASELINE" > "$REPO/.baseline.floors.$$"
  while read -r name base_f base_c; do
    row=$(awk -v n="$name" '$1 == n { print $2, $3 }' "$REPO/.baseline.current.$$")
    case "$row" in
      "") echo "FAIL $name: test binary disappeared"; status=1 ;;
    esac
    cur_f=$(echo "$row" | awk "{print \$1}")
    cur_c=$(echo "$row" | awk "{print \$2}")
    if [ "$cur_f" -lt "$base_f" ] 2>/dev/null; then
      echo "FAIL $name: test functions $base_f -> $cur_f ($((base_f - cur_f)) removed)"
      status=1
    fi
    if [ "$cur_c" -lt "$base_c" ] 2>/dev/null; then
      echo "FAIL $name: CHECKs $base_c -> $cur_c ($((base_c - cur_c)) removed)"
      status=1
    fi
  done < "$REPO/.baseline.floors.$$"
  # 新出现的二进制：提示刷新基线，不算失败。
  retained_names=$(awk '!/^[[:space:]]*#/ { print $1 }' "$BASELINE")
  current_names=$(awk '$1 != "" { print $1 }' "$REPO/.baseline.current.$$")
  for name in $(printf "%s\n%s\n" "$current_names" "$retained_names" | sort -u | \
                comm -23 <(printf "%s\n" "$current_names" | sort -u) <(printf "%s\n" "$retained_names" | sort -u)); do
    echo "note: new test binaries (refresh the baseline): $name"
  done
  rm -f "$REPO/.baseline.current.$$"
  if [ "$status" != 0 ]; then
    echo
    echo "regression(s): the suite shrank. A refactor that needs an assertion"
    echo "gone has to justify it explicitly."
    return 1
  fi
  total_f=$(awk '{ f+=$2 } END { print f }' "$REPO/.baseline.floors.$$")
  total_c=$(awk '{ c+=$3 } END { print c }' "$REPO/.baseline.floors.$$")
  n=$(awk '{ c++ } END { print c }' "$REPO/.baseline.floors.$$")
  rm -f "$REPO/.baseline.floors.$$"
  echo "OK: $n binaries, $total_f test functions, $total_c CHECKs (baseline met or exceeded)"
  return 0
}

case "${1:-}" in
  --write) write_baseline ;;
  "") verify ;;
  *)
    echo "usage: test_baseline.sh [--write]" >&2
    exit 64
    ;;
esac
