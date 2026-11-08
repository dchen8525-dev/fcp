"""Run a shell command on the WAN VPS and stream its output.

Usage: py scripts/vps_ssh.py "<remote command>"

Long remote jobs must be launched detached (setsid nohup ... > log 2>&1 &) and
polled: paramiko's exec_command times out a single call that outlives its
channel, so this helper is for short commands only.
"""

import sys
import paramiko

HOST = "144.34.186.164"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username="root", password="CVDUkNtgC8W0", timeout=30)
    _, out, err = ssh.exec_command(sys.argv[1], timeout=120)
    sys.stdout.write(out.read().decode(errors="replace"))
    sys.stderr.write(err.read().decode(errors="replace"))
    code = out.channel.recv_exit_status()
    ssh.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
