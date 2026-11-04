#!/usr/bin/env bash
# 把 `cmake --install` 的 DESTDIR 安装树打成交付 .deb。
#
# 用 dpkg-deb（dpkg 自带，Ubuntu/Debian 构建机必有），不再自己拼 ar/tar：
#   * 包内文件落点由 cmake/FCPPackaging.cmake 的 install() 唯一决定；
#   * 本脚本只补 DEBIAN/ 元数据（control、conffiles、维护者脚本）并交给 dpkg-deb。
# 所以不存在"Python 落点表与 install() 漂移"这一类问题。
#
# 用法：
#   scripts/build_deb.sh --stage DIR [--out-dir DIR] [--version V] [--arch A]
#
#   DIR        已按 FHS 装好的树（DESTDIR 前缀），含 usr/bin、etc、usr/share/doc。
#   产出       <out-dir>/fcp-server_<version>_<arch>.deb
#              默认 out-dir = <stage>/../packages
#
# 需要：dpkg-deb（dpkg 自带），以及构建机上已生成的 Linux 可执行文件。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE=fcp-server
SUMMARY='FCP proxy server and client (UDP tunnel with adaptive FEC)'
DEPENDS='libstdc++6 (>= 11), libc6 (>= 2.35)'
RECOMMENDS=ca-certificates

STAGE="" OUT_DIR="" VERSION_ARG="" ARCH_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --stage)    STAGE="${2:?--stage 需要目录}"; shift 2 ;;
    --out-dir)  OUT_DIR="${2:?--out-dir 需要目录}"; shift 2 ;;
    --version)  VERSION_ARG="${2:?--version 需要版本号}"; shift 2 ;;
    --arch)     ARCH_ARG="${2:?--arch 需要架构名}"; shift 2 ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

command -v dpkg-deb >/dev/null 2>&1 || {
  echo "需要 dpkg-deb（dpkg 自带；Ubuntu/Debian 构建机默认就有）" >&2
  exit 1
}
[ -n "$STAGE" ] && [ -d "$STAGE" ] || { echo "缺少 --stage <install-tree>" >&2; exit 2; }
STAGE="$(cd "$STAGE" && pwd)"

VERSION="${VERSION_ARG:-$(tr -d '[:space:]' < "$ROOT/VERSION")}"
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
  echo "VERSION 必须是 MAJOR.MINOR.PATCH，实际是 '$VERSION'" >&2
  exit 1
}

ARCH="${ARCH_ARG:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"
case "$ARCH" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac
case "$ARCH" in
  amd64|arm64|i386|armhf|riscv64|ppc64el|s390x) ;;
  *) echo "未知架构 $ARCH" >&2; exit 1 ;;
esac

OUT_DIR="${OUT_DIR:-$STAGE/../packages}"
mkdir -p "$OUT_DIR"

# ---- 安装树必须齐全（缺了就是 cmake --install 没跑或落点漂了） --------------
for f in usr/bin/fcp-server usr/bin/fcp-client \
         usr/lib/systemd/system/fcp.service etc/fcp/fcp.env; do
  [ -f "$STAGE/$f" ] || {
    echo "安装树缺少 /$f；先跑 cmake --install（DESTDIR=$STAGE）" >&2
    exit 1
  }
done
[ -d "$STAGE/usr/share/doc/$PACKAGE" ] || {
  echo "安装树缺少 /usr/share/doc/$PACKAGE；检查 cmake/FCPPackaging.cmake 的文档落点" >&2
  exit 1
}

# conffile 里有运维填的 FCP_ARGS（通常含 --key=PSK），0600 起步；systemd 以
# PID 1 读 EnvironmentFile 后注入，服务进程本身（DynamicUser）从不打开它。
chmod 0600 "$STAGE/etc/fcp/fcp.env"

# Installed-Size（KiB）。只算载荷，DEBIAN/ 不参与。
INSTALLED_KIB="$(du -sk "$STAGE/usr" "$STAGE/etc" 2>/dev/null | awk '{s+=$1} END{print s+0}')"

# ---- DEBIAN/ 元数据 --------------------------------------------------------
rm -rf "$STAGE/DEBIAN"
mkdir -p "$STAGE/DEBIAN"

meta() {
  # tr -d '\r'：Windows 工作区的文件是 CRLF，而 dpkg 的字段值不认行尾 CR。
  grep -E "^$1=" "$ROOT/packaging/debian/metadata.env" | head -n1 | cut -d= -f2- | tr -d '\r'
}
MAINTAINER="$(meta FCP_MAINTAINER)"
HOMEPAGE="$(meta FCP_HOMEPAGE)"
[ -n "$MAINTAINER" ] || { echo "metadata.env 缺 FCP_MAINTAINER" >&2; exit 1; }
[ -n "$HOMEPAGE" ] || { echo "metadata.env 缺 FCP_HOMEPAGE" >&2; exit 1; }

{
  printf 'Package: %s\n'      "$PACKAGE"
  printf 'Version: %s\n'      "$VERSION"
  printf 'Architecture: %s\n' "$ARCH"
  printf 'Maintainer: %s\n'   "$MAINTAINER"
  printf 'Installed-Size: %s\n' "$INSTALLED_KIB"
  printf 'Depends: %s\n'      "$DEPENDS"
  printf 'Recommends: %s\n'   "$RECOMMENDS"
  printf 'Section: net\n'
  printf 'Priority: optional\n'
  printf 'Homepage: %s\n'     "$HOMEPAGE"
  printf 'Description: %s\n'  "$SUMMARY"
  # description 按 deb-control(5) 规范化的形式（首行摘要之后）：
  # 续行缩进一格，空行写成 " ."，且不保留首尾空行。
  awk '
    { line[NR] = $0 }
    END {
      first = 1; last = NR
      while (first <= NR && line[first] ~ /^[ \t]*$/) first++
      while (last >= 1  && line[last]  ~ /^[ \t]*$/) last--
      for (i = first; i <= last; i++) {
        l = line[i]; gsub(/\r/, "", l)
        sub(/^[ \t]+/, "", l); sub(/[ \t]+$/, "", l)
        if (l == "") print " ."; else print " " l
      }
    }' "$ROOT/packaging/debian/description"
} > "$STAGE/DEBIAN/control"
chmod 0644 "$STAGE/DEBIAN/control"

# control 必须是单个段落：dpkg 按空行分段，多一个空行就报 missing 'Package'。
if grep -qE '^[[:space:]]*$' "$STAGE/DEBIAN/control"; then
  echo "control 里出现空行（dpkg 会拆成第二段落）" >&2
  exit 1
fi

# conffiles：dpkg 只认 control.tar 里这份清单，漏了"升级保留运维修改"会静默失效。
# 行尾 CR 会让 dpkg-deb 把 "\r" 当成路径的一部分（"does not appear in package"），
# 空行则会被当成一个空路径（"conffile name '' is not an absolute pathname"）。
# awk 'NF { print }' 每个非空行各输出一行（恰好一个换行），空行直接丢掉。
tr -d '\r' < "$ROOT/packaging/debian/conffiles" \
  | sed -e 's/[[:space:]]*$//' | awk 'NF { print }' > "$STAGE/DEBIAN/conffiles"
chmod 0644 "$STAGE/DEBIAN/conffiles"
[ -s "$STAGE/DEBIAN/conffiles" ] || { echo "conffiles 为空" >&2; exit 1; }

# 维护者脚本：dpkg 直接 exec，必须可执行；同样要去掉 CR，否则 shebang 行
# 变成 "#!/bin/sh\r" 会在 Linux 上报 bad interpreter。
for s in preinst postinst prerm postrm; do
  src="$ROOT/packaging/debian/$s"
  [ -f "$src" ] || continue
  tr -d '\r' < "$src" > "$STAGE/DEBIAN/$s"
  chmod 0755 "$STAGE/DEBIAN/$s"
done

# ---- 出包 ------------------------------------------------------------------
DEB="$OUT_DIR/${PACKAGE}_${VERSION}_${ARCH}.deb"
rm -f "$DEB"
# 固定时间戳，同一输入两次打包一致（便于 diff 与复现）。
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" \
  dpkg-deb --root-owner-group --build "$STAGE" "$DEB"

# ---- 出包即校验 ------------------------------------------------------------
# 先整体取回再比对：`dpkg-deb | grep -q` 会让 grep 提前关闭管道，dpkg-deb
# 收到 SIGPIPE，在 `set -o pipefail` 下把成功的检查误判成失败。
control="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -xO ./control)"
printf '%s\n' "$control"
grep -qx "Package: $PACKAGE"   <<<"$control"
grep -qx "Version: $VERSION"   <<<"$control"
grep -qx "Architecture: $ARCH" <<<"$control"
grep -qx "Description: $SUMMARY" <<<"$control"
if grep -qE '^[[:space:]]*$' <<<"$control"; then
  echo "出包后 control 出现空行" >&2; exit 1
fi

ctrl_names="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -t)"
grep -qx './conffiles' <<<"$ctrl_names"
for s in postinst prerm postrm; do
  grep -qx "./$s" <<<"$ctrl_names"
done

contents="$(dpkg-deb --contents "$DEB")"
for f in usr/bin/fcp-server usr/bin/fcp-client \
         usr/lib/systemd/system/fcp.service etc/fcp/fcp.env; do
  grep -q "\./$f$" <<<"$contents"
done

echo "== 产出 $DEB（Installed-Size ${INSTALLED_KIB} KiB）"
dpkg-deb --contents "$DEB"
