"""Upload one local file to the WAN VPS (SFTP is unavailable there).

Usage: py scripts/vps_put.py <local-path> <remote-path>

The file is streamed as base64 through `base64 -d >>`, in chunks small enough
that a single exec_command stays well inside the channel timeout.
"""

import base64
import os
import sys
import paramiko

HOST = "144.34.186.164"
CHUNK = 32 * 1024  # raw bytes per command; Linux MAX_ARG_STRLEN caps the base64 line


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    local, remote = sys.argv[1], sys.argv[2]
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username="root", password="CVDUkNtgC8W0", timeout=30)

    def run(cmd: str) -> None:
        _, out, err = ssh.exec_command(cmd, timeout=120)
        out.channel.recv_exit_status()
        text = err.read().decode(errors="replace").strip()
        if text:
            print(text, file=sys.stderr)

    run(f": > {remote}")
    sent = 0
    with open(local, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            b64 = base64.b64encode(block).decode("ascii")
            run(f"printf '%s' '{b64}' | base64 -d >> {remote}")
            sent += len(block)
    _, out, _ = ssh.exec_command(f"wc -c < {remote}", timeout=30)
    remote_size = int(out.read().decode().strip() or 0)
    ssh.close()
    print(f"uploaded {local} -> {remote}: local {sent} B, remote {remote_size} B")
    return 0 if sent == remote_size == os.path.getsize(local) else 1


if __name__ == "__main__":
    sys.exit(main())
