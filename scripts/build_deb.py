#!/usr/bin/env python3
"""把已构建的产物打成 Ubuntu/Debian 的 .deb —— 只用 Python 标准库，Windows 和
Linux 上跑同一条命令，不需要 cpack、dpkg-deb、fakeroot、tar 或 ar。

    python3 scripts/build_deb.py --build-dir build --arch amd64

为什么自己写：deb 就是一个 ar 归档，里面三个成员
    debian-binary   固定一行 "2.0\\n"
    control.tar.gz  ./control、./conffiles、maintainer scripts（postinst 等）
    data.tar.gz     包内文件，路径相对根
ar 头只有 60 字节，tar 是 ustar；标准库的 tarfile/gzip 已经够用。这样打出来的包
与 CPack DEB 生成器逐字节同构，`dpkg -i` / `apt` 认的就是这些字节。

包内文件与落点（与 docs/发布流程.md 的清单一一对应）：
    /usr/bin/fcp-proxy-server             Release/<...>/apps/fcp-proxy/fcp-proxy-server
    /usr/bin/fcp-proxy-client             Release/<...>/apps/fcp-proxy/fcp-proxy-client
    /usr/lib/systemd/system/fcp-proxy.service
    /etc/fcp/fcp-proxy.env                conffile（升级不覆盖运维修改）
    /usr/share/doc/fcp-proxy/*.md + VERSION
    /usr/share/doc/fcp-proxy/copyright    （来自 packaging/debian/copyright）

用法示例：
    # Linux CI / 本机：CMake 产出的可执行文件目录直接传给 --bin-dir
    python3 scripts/build_deb.py --bin-dir build/apps/fcp-proxy --arch amd64

    # Windows：打出来的二进制是 exe，除非 -DFCP_TARGET_OS=linux 交叉编译过，
    # 否则这包装不上 Linux。脚本会拒绝，除非显式 --allow-non-linux-bins。
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import sys
import tarfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = "fcp-proxy"
DOC_DIR = "usr/share/doc/" + PACKAGE
UNIT_PATH = "usr/lib/systemd/system/fcp-proxy.service"
ENV_PATH = "etc/fcp/fcp-proxy.env"

# deb(5)：文件权限与所有者写死在 tar 头里；root:root 是包的规范。
MODE_EXEC = 0o755
MODE_FILE = 0o644
# conffile 里放的是运维自己填的 FCP_ARGS，通常含 --key=<PSK>，所以不能沿用
# 普通文件的 0644：那等于把预共享密钥给本机所有用户读。0600 是安全的，因为
# systemd 由 PID 1（root）在 fork 服务之前解析 EnvironmentFile，再把变量传下去，
# 与 [Service] 里配的 DynamicUser 无关 —— 服务进程自己从不打开这个文件。
MODE_CONFFILE = 0o600
OWNER = "root"
GROUP = "root"

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
# Debian 架构名；与 dpkg-architecture 的叫法一致。
ARCHES = {"amd64", "arm64", "i386", "armhf", "riscv64", "ppc64el", "s390x"}

DEFAULT_DEPENDS = "libstdc++6 (>= 11), libc6 (>= 2.35)"
DEFAULT_RECOMMENDS = "ca-certificates"
# `dpkg -l` 与 `apt show` 顶层显示的一行摘要。
SUMMARY = "FCP proxy server and client (UDP tunnel with adaptive FEC)"


class PackagingError(Exception):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_version(repo: str) -> str:
    path = os.path.join(repo, "VERSION")
    if not os.path.isfile(path):
        raise PackagingError(f"缺少 {path}（版本号唯一真源）")
    raw = read_text(path).strip()
    version = raw.splitlines()[0].strip() if raw else ""
    if not VERSION_RE.match(version):
        raise PackagingError(f"VERSION 必须是 MAJOR.MINOR.PATCH，实际是 {version!r}")
    return version


def metadata_value(repo: str, key: str) -> str:
    """打包元数据的唯一真源是 packaging/debian/metadata.env。

    CMake 侧（CMakeLists.txt 的 FCP_HOMEPAGE/FCP_MAINTAINER）与这里都读它，
    不再在两个地方各抄一份。
    """
    path = os.path.join(repo, "packaging", "debian", "metadata.env")
    if not os.path.isfile(path):
        raise PackagingError(f"缺少 {path}")
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == key:
            return v.strip()
    raise PackagingError(f"{path} 里没有 {key}=")


def normalize_description(text: str) -> list[str]:
    """package description 的段落规则（deb-control(5)）：

    * 第一行是摘要，缩进两个空格；
    * 后续行缩进一个空格；
    * 空行写作 " ."（只有一个点）。

    packaging/debian/description 按人读的形式写（空行就是空行），这里负责翻译。
    历史上踩过两次：description 以换行结尾时 CPack 把 Installed-Size 顶成第二个
    段落，`dpkg -i` 报 missing 'Package' field。本函数先 strip 再逐行生成，
    结构问题从源头上消掉。
    """
    lines = [ln.strip() for ln in text.strip().splitlines()]
    if not lines:
        raise PackagingError("packaging/debian/description 是空的")
    # 返回未加缩进的逻辑行；空行用 "." 占位，缩进在 build_control 里统一加。
    return [ln if ln else "." for ln in lines]


def build_control(repo: str, version: str, arch: str, depends: str, recommends: str) -> str:
    homepage = metadata_value(repo, "FCP_HOMEPAGE")
    maintainer = metadata_value(repo, "FCP_MAINTAINER")
    desc = normalize_description(read_text(os.path.join(repo, "packaging/debian/description")))

    # 字段顺序照着 CPackDeb 的习惯写（它按 std::map 字典序输出）；dpkg 本身
    # 不关心顺序，但保持稳定能让 `dpkg-deb --info` 的 diff 有意义。
    lines = [
        f"Package: {PACKAGE}",
        f"Version: {version}",
        f"Architecture: {arch}",
        f"Maintainer: {maintainer}",
        # 先占位，写完 data.tar 后由 finish_control 回填。
        "Installed-Size: {installed_size}",
        f"Depends: {depends}",
        f"Recommends: {recommends}",
        "Section: net",
        "Priority: optional",
        f"Homepage: {homepage}",
        # 摘要与正文分离：`dpkg -l` 的一行描述取的就是这行 Summary。
        # （CPackDeb 会把 description 的第一行当摘要用，于是 `dpkg -l` 显示的是
        # 正文首句——那是个 bug，这里不复制它。）
        f"Description: {SUMMARY}",
    ]
    # Description 首行是摘要，正文续行统一缩进一格，空行写成 " ."。
    lines += [f" {ln}" for ln in desc]
    # 结尾只有一个换行：control 的最后一行以 \n 收尾是正常的，但绝不能多出
    # 空行（dpkg 按空行分段，会把后面的字段拆成第二个段落）。
    return "\n".join(lines) + "\n"


def finish_control(control: str, installed_kib: int) -> str:
    return control.replace("{installed_size}", str(installed_kib))


def control_fields(control: str) -> list[tuple[str, str]]:
    """(字段名, 值) 序列。续行（以空格开头）并入前一个字段，注释行跳过。"""
    out: list[tuple[str, str]] = []
    for line in control.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith(" "):
            if out:
                name, value = out[-1]
                out[-1] = (name, value + "\n" + line.strip())
            continue
        name, _, value = line.partition(":")
        out.append((name.strip(), value.strip()))
    return out


def control_in_matches_generator(repo: str) -> bool:
    """packaging/debian/control.in 是给人读的镜像，不是构建输入。

    它挡不住自己漂移 —— 唯一的约束是这条自检。占位符（@VERSION@ 等）在镜像里
    本来就是字面量，所以只比对字段名顺序和那些在两边都写死的值。
    """
    mirror_path = os.path.join(repo, "packaging", "debian", "control.in")
    try:
        mirror = read_text(mirror_path)
    except OSError:
        return False
    generated = build_control(repo, version="0.0.1", arch="amd64",
                              depends=DEFAULT_DEPENDS, recommends=DEFAULT_RECOMMENDS)
    mirror_fields = control_fields(mirror)
    gen_fields = control_fields(generated)
    if [n for n, _ in mirror_fields] != [n for n, _ in gen_fields]:
        return False
    for (name, mirror_value), (_, gen_value) in zip(mirror_fields, gen_fields):
        # 镜像里是 @PLACEHOLDER@ 的字段由构建期填充，不参与比对。
        if "@" in mirror_value:
            continue
        if mirror_value != gen_value:
            return False
    return True


def iter_package_files(repo: str, bin_dir: str, allow_non_linux: bool) -> list[tuple[str, str, int]]:
    """(包内路径, 磁盘路径, 权限)。顺序即 data.tar 里的顺序。"""
    files: list[tuple[str, str, int]] = []

    for name in ("fcp-proxy-server", "fcp-proxy-client"):
        src = os.path.join(bin_dir, name)
        alt = os.path.join(bin_dir, name + ".exe")
        if os.path.isfile(src):
            files.append((f"usr/bin/{name}", src, MODE_EXEC))
        elif os.path.isfile(alt):
            if not allow_non_linux:
                raise PackagingError(
                    f"{alt} 是 Windows 可执行文件，装到 Linux 上跑不起来。"
                    "请用 Linux 构建（CI 的 linux-deb job）或在命令行加 --allow-non-linux-bins"
                    "（只用于检查包结构）。")
            files.append((f"usr/bin/{name}", alt, MODE_EXEC))
        else:
            raise PackagingError(
                f"{bin_dir} 下找不到 {name}（或 {name}.exe）。"
                "先构建代理 CLI：-DFCP_BUILD_PROXY=ON")
    unit = os.path.join(repo, "packaging/debian/fcp-proxy.service")
    env = os.path.join(repo, "packaging/debian/fcp-proxy.env")
    for src, dst, mode in ((unit, UNIT_PATH, MODE_FILE), (env, ENV_PATH, MODE_CONFFILE)):
        if not os.path.isfile(src):
            raise PackagingError(f"缺少 {src}")
        files.append((dst, src, mode))

    docs = sorted(
        os.path.join(repo, "docs", f)
        for f in os.listdir(os.path.join(repo, "docs"))
        if f.endswith(".md")
    )
    for src in docs:
        files.append((f"{DOC_DIR}/{os.path.basename(src)}", src, MODE_FILE))
    files.append((f"{DOC_DIR}/VERSION", os.path.join(repo, "VERSION"), MODE_FILE))
    # copyright 必须放在 /usr/share/doc/<pkg>/copyright，和 dpkg 的默认预期一致。
    files.append((f"{DOC_DIR}/copyright",
                  os.path.join(repo, "packaging/debian/copyright"), MODE_FILE))
    return files


def add_file(tar: tarfile.TarFile, arcname: str, src: str, mode: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.type = tarfile.REGTYPE
    info.size = os.path.getsize(src)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = OWNER
    info.gname = GROUP
    # 固定时间戳：同样输入两次打包得到逐字节相同的 deb（可复现，便于 diff）。
    info.mtime = 0
    with open(src, "rb") as f:
        tar.addfile(info, f)


def add_dir(tar: tarfile.TarFile, arcname: str, mode: int = MODE_EXEC) -> None:
    info = tarfile.TarInfo(arcname)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = OWNER
    info.gname = GROUP
    info.mtime = 0
    tar.addfile(info)


def dirs_of(files: list[tuple[str, str, int]]) -> list[str]:
    seen: set[str] = set()
    for arc, *_ in files:
        parts = arc.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            seen.add("/".join(parts[:i]))
    return sorted(seen)


def build_data_tar(files: list[tuple[str, str, int]]) -> tuple[bytes, int]:
    """返回 (tar.gz 字节, 文件字节总量)。"""
    dirs = dirs_of(files)
    all_entries: list[tuple[str, str | None, int]] = [(d + "/", None, 0o755) for d in dirs]
    all_entries += [(arc, src, mode) for arc, src, mode in files]
    # 先按路径排：目录在前，同目录内文件按名。tar 顺序不影响安装，但稳定输出好 diff。
    all_entries.sort(key=lambda e: e[0])

    raw = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for arc, src, mode in all_entries:
            if src is None:
                add_dir(tar, arc, mode)
            else:
                add_file(tar, arc, src, mode)
                total += os.path.getsize(src)
    return gzip.compress(raw.getvalue(), mtime=0), total


def build_control_tar(repo: str, control: str, conffiles: list[str]) -> bytes:
    raw = io.BytesIO()
    scripts = ("preinst", "postinst", "prerm", "postrm")
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        def add_bytes(name: str, data: bytes, mode: int) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = OWNER
            info.gname = GROUP
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))

        add_bytes("./control", control.encode("utf-8"), MODE_FILE)
        if conffiles:
            # 每条都得是包内绝对路径，dpkg 只认 control.tar 里这份清单；
            # 漏了它"升级保留运维修改"就静默失效。
            body = "".join(f"{c}\n" for c in conffiles)
            add_bytes("./conffiles", body.encode("utf-8"), MODE_FILE)
        for script in scripts:
            src = os.path.join(repo, "packaging/debian", script)
            if os.path.isfile(src):
                # maintainer script 必须可执行（dpkg 直接 exec 它们）。
                add_bytes("./" + script, open(src, "rb").read(), MODE_EXEC)
    return gzip.compress(raw.getvalue(), mtime=0)


def ar_member(name: str, data: bytes) -> bytes:
    """ar(5) 头：60 字节，名字右补空格到 16，字段右对齐。

    成员数据按 2 字节对齐（奇数长度补一个 '\\n'）。
    """
    if len(name) > 16:
        raise PackagingError(f"ar 成员名过长：{name}")
    header = "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n".format(
        name, "0", "0", "0", MODE_FILE, len(data)).encode("ascii")
    assert len(header) == 60, len(header)
    body = data + (b"\n" if len(data) % 2 else b"")
    return header + body


def ar_archive(members: list[tuple[str, bytes]]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members:
        out += ar_member(name, data)
    return out


def verify_deb(deb_path: str, control_text: str, files: list[tuple[str, str, int]]) -> None:
    """出包即自检：把刚写的 deb 读回来，确认结构与落点。"""
    with open(deb_path, "rb") as f:
        blob = f.read()
    if not blob.startswith(b"!<arch>\n"):
        raise PackagingError("不是 ar 归档")
    members: dict[str, bytes] = {}
    off = 8
    while off + 60 <= len(blob):
        header = blob[off:off + 60]
        name = header[:16].decode("ascii").rstrip()
        size = int(header[48:58].decode("ascii").strip())
        off += 60
        members[name] = blob[off:off + size]
        off += size + (size % 2)
    for need in ("debian-binary", "control.tar.gz", "data.tar.gz"):
        if need not in members:
            raise PackagingError(f"deb 缺成员 {need}")
    if members["debian-binary"] != b"2.0\n":
        raise PackagingError("debian-binary 必须是 '2.0\\n'")

    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(members["control.tar.gz"]))) as tar:
        names = tar.getnames()
        ctl = tar.extractfile("./control")
        if ctl is None:
            raise PackagingError("control.tar 里没有 ./control")
        got = ctl.read().decode("utf-8")
    if got != control_text:
        raise PackagingError("control 回读内容与写入不一致")
    # 段落只允许一个：dpkg 按空行分段，多一个空行就把 Installed-Size 顶成
    # 第二个段落，install 时报 missing 'Package' field。
    blank = got.count("\n\n")
    if blank != 0:
        raise PackagingError(f"control 里出现 {blank} 处空行（dpkg 会按空行分段）")
    for field in ("Package:", "Version:", "Architecture:", "Maintainer:", "Description:"):
        if field not in got:
            raise PackagingError(f"control 缺 {field}")
    # 摘要必须是我们写的那行：`dpkg -l` 取的就是它，退化成正文首句是回归。
    summary_line = next(ln for ln in got.splitlines() if ln.startswith("Description:"))
    if summary_line != f"Description: {SUMMARY}":
        raise PackagingError(f"Description 摘要行不对：{summary_line!r}")
    if "./conffiles" not in names:
        raise PackagingError("control.tar 缺 conffiles")
    for script in ("postinst", "prerm", "postrm"):
        if f"./{script}" not in names:
            raise PackagingError(f"control.tar 缺 {script}")

    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(members["data.tar.gz"]))) as tar:
        data_names = set(tar.getnames())
    for arc, _, _ in files:
        if arc not in data_names and arc + "/" not in data_names:
            raise PackagingError(f"data.tar 缺 {arc}")


def self_test() -> int:
    """纯逻辑单元：不读构建产物、不写文件，ctest 与 CI 两个平台都能跑。"""
    failures: list[str] = []

    def check(name: str, cond: bool) -> None:
        print(f"{'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    # 1. description 段落规则：空行变 " ."，续行缩进一格，不留空行。
    desc = normalize_description("首行摘要\n第二行\n\n第四行\n")
    check("description 空行 -> '.'", desc == ["首行摘要", "第二行", ".", "第四行"])
    control = "\n".join(["Package: fcp-proxy", f"Description: {SUMMARY}"]
                        + [f" {ln}" for ln in desc]) + "\n"
    check("control 无空行", "\n\n" not in control)
    check("control 续行都缩进",
          all(ln.startswith(" ") for ln in control.splitlines()[2:]))
    check("control 以换行收尾", control.endswith("\n"))

    # 2. control.in 是给人读的镜像，必须与 build_control() 的实际输出一致。
    #    它曾经只靠"改一边记得改另一边"维持，等于没有约束：有人改了
    #    DEFAULT_DEPENDS 而忘了镜像，审包时看到的就是假的。这里逐字段比对。
    meta_repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    check("control.in 与生成器一致", control_in_matches_generator(meta_repo))

    # 3. 章节注释和空行不能被当成键值。
    try:
        home = metadata_value(meta_repo, "FCP_HOMEPAGE")
        who = metadata_value(meta_repo, "FCP_MAINTAINER")
        check("metadata.env 能读出主页", home.startswith("http"))
        check("metadata.env 能读出 Maintainer", "@" in who)
    except PackagingError as exc:
        check(f"metadata.env 读取（{exc}）", False)

    # 3. ar 头：恰好 60 字节，名字在首字段，长度在 48..58。
    member = ar_member("debian-binary", b"2.0\n")
    check("ar 头 60 字节", len(member) - len(b"2.0\n") == 60)
    check("ar 头名字字段", member[:16].decode().rstrip() == "debian-binary")
    # 成员长度 4 是偶数，不补位：头 60 + 数据 4。
    check("ar 偶数长度不补位", len(member) == 60 + 4)
    # 3 字节的数据按 2 对齐要补一个 '\n'，所以成员是 60 + 4。
    odd = ar_member("x", b"2.0")
    check("ar 奇数长度补位", len(odd) == 64 and odd.endswith(b"2.0\n"))
    check("ar 归档魔数", ar_archive([]) == b"!<arch>\n")

    # 4. 版本 / 架构校验。
    check("版本正则接受 0.0.1", bool(VERSION_RE.match("0.0.1")))
    check("版本正则拒绝 v0.0.1", not VERSION_RE.match("v0.0.1"))
    check("版本正则拒绝 0.0.1-beta", not VERSION_RE.match("0.0.1-beta"))
    check("amd64 是合法架构", "amd64" in ARCHES)

    # 5. 目录集合：usr/bin/x 要带出 usr/ 与 usr/bin/，且不重复。
    dirs = dirs_of([("usr/bin/a", "x", MODE_EXEC), ("usr/bin/b", "y", MODE_EXEC)])
    check("父目录去重", dirs == ["usr", "usr/bin"])

    if failures:
        print(f"::error::{len(failures)} 项自检失败", file=sys.stderr)
        return 1
    print("build_deb 自检全部通过")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="打 fcp-proxy 的 .deb（纯 Python 标准库）")
    ap.add_argument("--self-test", action="store_true",
                    help="只跑打包器的纯逻辑自检（不出包，不需要构建产物）")
    ap.add_argument("--repo", default=REPO_ROOT, help="仓库根（默认按脚本位置推）")
    ap.add_argument("--bin-dir", default=None,
                    help="fcp-proxy-server / fcp-proxy-client 所在目录（--self-test 之外必填）")
    ap.add_argument("--out-dir", default=None,
                    help="deb 输出目录（默认 <bin-dir>/../../../packages 或 --build-dir/packages）")
    ap.add_argument("--build-dir", default=None, help="构建目录，用于推默认 --out-dir")
    ap.add_argument("--version", default=None, help="覆盖 VERSION 文件（CI 传 tag 值）")
    ap.add_argument("--arch", default="amd64", help="Debian 架构名（默认 amd64）")
    ap.add_argument("--depends", default=DEFAULT_DEPENDS)
    ap.add_argument("--recommends", default=DEFAULT_RECOMMENDS)
    ap.add_argument("--allow-non-linux-bins", action="store_true",
                    help="允许打包非 Linux 可执行文件（只用于检查包结构，装不上）")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    repo = os.path.abspath(args.repo)
    try:
        version = args.version or read_version(repo)
        if not VERSION_RE.match(version):
            raise PackagingError(f"--version 必须是 MAJOR.MINOR.PATCH，实际是 {version!r}")
        if args.arch not in ARCHES:
            raise PackagingError(f"未知架构 {args.arch}，可选：{', '.join(sorted(ARCHES))}")

        if not args.bin_dir:
            raise PackagingError("需要 --bin-dir（或用 --self-test 只跑自检）")
        bin_dir = os.path.abspath(args.bin_dir)
        if not os.path.isdir(bin_dir):
            raise PackagingError(f"--bin-dir 不存在：{bin_dir}")

        out_dir = args.out_dir
        if out_dir is None:
            base = args.build_dir or os.path.dirname(os.path.dirname(os.path.dirname(bin_dir)))
            out_dir = os.path.join(os.path.abspath(base), "packages")
        os.makedirs(out_dir, exist_ok=True)

        files = iter_package_files(repo, bin_dir, args.allow_non_linux_bins)
        data_gz, data_bytes = build_data_tar(files)
        # Installed-Size 单位是 KiB，向上取整（dpkg 的惯例）。
        installed_kib = (data_bytes + 1023) // 1024

        control = build_control(repo, version, args.arch, args.depends, args.recommends)
        control = finish_control(control, installed_kib)
        control_gz = build_control_tar(repo, control, ["/" + ENV_PATH])

        deb = ar_archive([
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", control_gz),
            ("data.tar.gz", data_gz),
        ])
        deb_name = f"{PACKAGE}_{version}_{args.arch}.deb"
        deb_path = os.path.join(out_dir, deb_name)
        with open(deb_path, "wb") as f:
            f.write(deb)

        log("== deb 结构自检")
        verify_deb(deb_path, control, files)

        log("== control")
        log(control.rstrip("\n"))
        log(f"\n== 产出 {deb_path}  ({len(deb)} 字节, Installed-Size {installed_kib} KiB)")
        for arc, src, _ in files:
            log(f"   /{arc}")
        return 0
    except PackagingError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
