#!/usr/bin/env python3
"""AB 定案①（施工单 5/6 后）：#76-#86 相对基线 003987c 在 WAN 丢包路径的 A/B。

分腿方法（沿用 #33/#34 惯例）：
  - VPS 并排两构建树：/root/ab/head（基线 003987c）与 /root/ab/new（HEAD）。
  - 同端口 4460 交替启动 server fcp-bench，其余条件不动，两端同 rate 下行更公平。
  - 本机跑 fcp-bench client（一次运行 = 上行 7s + 下行 7s，双向都进 RESULT）。
指标（client RESULT 行为唯一评分口，server.log 留档）：
  上/下行交付 MB、retx/duprec/settle 计数、（identity 违例恒 0）。

前置：
  本机 Release 构建两套 fcp-bench.exe：
    build/base-r0/apps/cli/Release/fcp-bench.exe（基线）
    build/windows-x64/apps/cli/Release/fcp-bench.exe（工作区 HEAD）
  VPS 需要 g++/cmake/ninja（现有）。

跑法（Git Bash，或已 export FCP_VPS_PW 的终端）：
  py -I scripts/ab_wan.py --rounds 4
"""
import argparse
import os
import subprocess
import sys
import time

import paramiko

HOST = "144.34.186.164"
USER = "root"
PASSWORD = os.environ.get("FCP_VPS_PW", "")
PORT = 4460
DEFAULT_KEY = "a1b2c3d4e5f601020304050607080910a1b2c3d4e5f601020304050607080910a"


def run(ssh, cmd, timeout=120):
    _, out, err = ssh.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    return o, e, rc


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def vps_build(ssh, tree):
    o, e, rc = run(ssh,
        f"cd /root/ab/{tree} && cmake -B build/rel -DCMAKE_BUILD_TYPE=Release "
        "-DFCP_BUILD_PROXY=ON >/dev/null 2>&1; "
        "cmake --build build/rel --target fcp-bench -j2 >/dev/null 2>&1; "
        "echo BUILD_RC=$?", timeout=1800)
    if "BUILD_RC=0" not in o:
        log(f"{tree} build failed:\n{o[-400:]}\n{e[-300:]}")
        return False
    # gate: the hot four in Release
    o2, _, _ = run(ssh, f"cd /root/ab/{tree} && cmake --build build/rel -j2 "
                        ">/dev/null 2>&1 && cd build/rel && "
                        "ctest -C Release -R "
                        "'handshake|envelope|session|stream' 2>&1 | tail -2",
                   timeout=900)
    log(f"{tree} gate: {o2.strip().replace(chr(10), ' | ')}")
    return "100% tests passed" in o2


def vps_setup(ssh, base_rev):
    subprocess.run("git archive HEAD | gzip > /tmp/fcp-ab-new.tgz",
                   shell=True, check=True)
    subprocess.run(f"git archive {base_rev} | gzip > /tmp/fcp-ab-base.tgz",
                   shell=True, check=True)
    sftp = ssh.open_sftp()
    sftp.put("/tmp/fcp-ab-new.tgz", "/root/fcp-ab-new.tgz")
    sftp.put("/tmp/fcp-ab-base.tgz", "/root/fcp-ab-base.tgz")
    sftp.close()
    run(ssh, "rm -rf /root/ab/new /root/ab/head && mkdir -p /root/ab/new "
             "/root/ab/head && tar -C /root/ab/new -xzf /root/fcp-ab-new.tgz && "
             "tar -C /root/ab/head -xzf /root/fcp-ab-base.tgz", timeout=180)
    for tree in ("head", "new"):
        if not vps_build(ssh, tree):
            return False
    return True


def vps_start_server(ssh, tree, key):
    run(ssh, "pkill -x fcp-bench; sleep 0.3", timeout=30)
    cmd = (f"cd /root/ab/{tree} && setsid nohup "
           "./build/rel/apps/cli/fcp-bench server "
           f"--port={PORT} --key={key} --mbps=30 --seg=1200 "
           "</dev/null >/root/ab/" + tree + "/server.log 2>&1 &")
    run(ssh, cmd, timeout=60)
    time.sleep(1.0)
    o, _, _ = run(ssh, "pgrep -x fcp-bench | wc -l")
    return o.strip() == "1"


def vps_fetch_result(ssh, tree):
    o, _, _ = run(ssh, f"grep -h RESULT /root/ab/{tree}/server.log | tail -1")
    return o.strip()


def local_client(exe, key, mbps, seg):
    cmd = [exe, "client", f"--host={HOST}", f"--port={PORT}", f"--key={key}",
           f"--mbps={mbps}", f"--seg={seg}", "--progress"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        for line in r.stdout.splitlines():
            if line.strip().startswith("RESULT"):
                return line.strip()
        return "NORESULT " + (r.stdout[-150:] + r.stderr[-100:]).replace("\n", " ")
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--mbps", type=float, default=12.0)
    ap.add_argument("--seg", type=int, default=1200)
    ap.add_argument("--base-rev", default="003987c")
    ap.add_argument("--key", default=DEFAULT_KEY)
    args = ap.parse_args()
    if not PASSWORD:
        print("Set FCP_VPS_PW", file=sys.stderr)
        return 2

    local = {
        "head": "build/windows-x64/apps/cli/Release/fcp-bench.exe",
        "new": "build/windows-x64/apps/cli/Release/fcp-bench.exe",
    }
    # Baseline build lives in its own worktree (git worktree 003987c).
    base = "../fcp-base-r0/build/windows-x64/apps/cli/Release/fcp-bench.exe"
    if os.path.exists(base):
        local["head"] = base
    else:
        print(f"baseline bench missing: {base}", file=sys.stderr)
        return 3
    for name, exe in local.items():
        if not os.path.exists(exe):
            print(f"missing local bench {name}: {exe}", file=sys.stderr)
            return 3

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD, timeout=30)
    log("preparing VPS legs (HEAD-vs-003987c)")
    if not vps_setup(ssh, args.base_rev):
        log("VPS setup failed")
        ssh.close()
        return 4
    log("VPS built both legs clean")

    out = {"head": [], "new": []}
    for rnd in range(1, args.rounds + 1):
        for name in ("head", "new"):
            if not vps_start_server(ssh, name, args.key):
                log(f"round {rnd} {name}: server start failed — skip")
                continue
            log(f"ROUND {rnd} {name}")
            up_res = local_client(local[name], args.key, args.mbps, args.seg)
            time.sleep(2)
            srv_res = vps_fetch_result(ssh, name)
            out.setdefault(name, []).append((up_res, srv_res))
            log(f"  up={up_res}")
            log(f"  srv={srv_res}")

    log("===== SUMMARY =====")
    for name, rounds in out.items():
        log(f"--- {name} ---")
        for i, (a, b) in enumerate(rounds, 1):
            log(f"  r{i}:")
            log(f"    client: {a}")
            log(f"    server: {b}")
    with open("ab_results.txt", "a", encoding="utf-8") as f:
        f.write(f"\n## {time.strftime('%Y-%m-%d %H:%M')}\n")
        for name, rounds in out.items():
            f.write(f"### {name}\n")
            for i, (a, b) in enumerate(rounds, 1):
                f.write(f"r{i} client: {a}\nr{i} server: {b}\n")
    log("results appended to ab_results.txt")
    ssh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
