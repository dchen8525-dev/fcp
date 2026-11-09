#!/usr/bin/env python3
"""Real-process e2e for the local HTTP forward proxy (M2代理设计.md §4.2).

Starts a real HTTP origin server, fcp-server and fcp-client, then drives the
local proxy port with raw TCP requests. Unlike tests/proxy_engine_test.cc this
exercises the actual CLI reactor, real sockets, real DNS/dial and real FIN
propagation.

Covers:
  * absolute-form GET/POST rewritten into origin-form, hop-by-hop headers
    stripped, request body forwarded untouched
  * the origin's status line is the FIRST byte the application sees (no
    synthetic "200 Connection Established" on the forward path)
  * chunked responses and CONNECT/HTTPS regression
  * a real TLS handshake over CONNECT against a local HTTPS origin, with
    CA + hostname verification (T32 regression, no public network needed)
  * local refusals (https:// absolute-form, disagreeing Host)
  * the documented limitation: an origin that ignores Connection: close and
    keeps its socket open leaves the local connection open until idle teardown

The TLS check needs either `openssl` on PATH or the `cryptography` Python
package to mint a throwaway self-signed certificate at runtime; if neither is
available, the TLS checks are reported as SKIP (visible in the output).

Usage:
  python scripts/http_forward_e2e.py [--client PATH] [--server PATH]
"""

import argparse
import datetime
import ipaddress
import os
import queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PSK = "0123456789abcdef0123456789abcdef"
ROOT = Path(__file__).resolve().parent.parent


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def default_bin(name):
    exe = name + (".exe" if os.name == "nt" else "")
    for rel in (
        "build/windows-x64/apps/cli/Debug",
        "build/windows-x64/apps/cli/Release",
        "build/linux-x64/apps/cli",
        "build/rel/apps/cli",
    ):
        p = ROOT / rel / exe
        if p.is_file():
            return str(p)
    return None


class Origin:
    """One-request-per-connection HTTP server with controllable close policy."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.requests = queue.Queue()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        conn.settimeout(3.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if b"\r\n\r\n" in data:
                head, body = data.split(b"\r\n\r\n", 1)
                content_length = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        content_length = int(line.split(b":", 1)[1].strip())
                while len(body) < content_length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                data = head + b"\r\n\r\n" + body
        except (socket.timeout, ValueError):
            pass
        self.requests.put(data)

        parts = data.split(b"\r\n", 1)[0].split(b" ") if data else []
        path = parts[1] if len(parts) > 1 else b"/"
        hold = path.startswith(b"/hold")
        if path.startswith(b"/chunked"):
            payload = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
            resp = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n" + payload)
        elif path.startswith(b"/echo"):
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                    b"\r\nConnection: close\r\n\r\n" + body)
        else:
            body = b"hello-forward"
            resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                    b"\r\nConnection: " + (b"keep-alive" if hold else b"close") +
                    b"\r\n\r\n" + body)
        try:
            conn.sendall(resp)
        except OSError:
            pass
        if not hold:
            conn.close()
        # /hold deliberately leaves the socket open: an origin that ignores
        # Connection: close. See the limitation checked below.

    def close(self):
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass


def make_test_cert():
    """Mint a throwaway self-signed CA cert with a localhost SAN.

    Returns (cert_path, key_path, tmpdir_handle), or (None, None, None) when
    neither openssl nor cryptography is available. The caller must keep the
    tmpdir handle alive until every TLS socket is done with the files. These
    are test-only dependencies -- the proxy itself needs neither.
    """
    tmp = tempfile.TemporaryDirectory(prefix="fcp-tls-e2e-")
    cert = os.path.join(tmp.name, "cert.pem")
    key = os.path.join(tmp.name, "key.pem")

    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", key, "-out", cert, "-days", "1", "-nodes",
           "-subj", "/CN=localhost",
           "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
           "-addext", "basicConstraints=critical,CA:TRUE"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30)
        if proc.returncode == 0 and os.path.isfile(cert) and os.path.isfile(key):
            return cert, key, tmp
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Fallback: optional `cryptography` package. Releases before 42 expose
    # not_valid_before/after; newer ones require the *_utc variants.
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(private.public_key())
                   .serial_number(x509.random_serial_number()))
        before = now - datetime.timedelta(minutes=1)
        after = now + datetime.timedelta(days=1)
        if hasattr(builder, "not_valid_before_utc"):
            builder = builder.not_valid_before_utc(before).not_valid_after_utc(after)
        else:
            builder = builder.not_valid_before(before).not_valid_after(after)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
        crt = builder.sign(private, hashes.SHA256())
        with open(cert, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
        with open(key, "wb") as f:
            f.write(private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        return cert, key, tmp
    except Exception:  # optional fallback: report SKIP instead of crashing
        tmp.cleanup()
        return None, None, None


class TlsOrigin:
    """One-request-per-connection HTTPS origin behind the CONNECT tunnel."""

    def __init__(self, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.requests = queue.Queue()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        tls = None
        try:
            conn.settimeout(3.0)
            tls = self.ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.requests.put(data)
            body = b"tls-hello"
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                        str(len(body)).encode() +
                        b"\r\nConnection: close\r\n\r\n" + body)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                (tls or conn).close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass


def wait_port(port, timeout=12.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def start_proc(path, args, log_path):
    env = os.environ.copy()
    env["FCP_PSK"] = PSK
    log = open(log_path, "w", encoding="utf-8", errors="replace")
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen([path] + args, stdout=log,
                            stderr=subprocess.STDOUT, env=env, **kwargs)
    return proc, log


def read_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    out = b""
    saw_eof = False
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            saw_eof = True
            break
        out += chunk
    return out, saw_eof


def proxy_request(port, payload, timeout=2.0):
    s = socket.create_connection(("127.0.0.1", port), 3.0)
    s.sendall(payload)
    out, eof = read_all(s, timeout)
    s.close()
    return out, eof


def tls_connect_request(proxy_port, authority, cert_path):
    """CONNECT, then a fully verified TLS handshake and an HTTPS GET.

    The CONNECT reply is read one byte at a time on purpose: a larger recv()
    could swallow the first ClientHello bytes and poison wrap_socket's buffer.
    """
    s = socket.create_connection(("127.0.0.1", proxy_port), 3.0)
    s.settimeout(5.0)
    s.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\n"
              b"Host: " + authority + b"\r\n\r\n")
    head = b""
    while not head.endswith(b"\r\n\r\n") and len(head) < 8192:
        byte = s.recv(1)
        if not byte:
            break
        head += byte

    ctx = ssl.create_default_context(cafile=cert_path)
    tls = ctx.wrap_socket(s, server_hostname="localhost")
    try:
        version = tls.version()
        peer = tls.getpeercert()
        tls.sendall(b"GET /tls HTTP/1.1\r\nHost: localhost\r\n"
                    b"Connection: close\r\n\r\n")
        out, _ = read_all(tls, timeout=2.0)
        return head, version, peer, out
    finally:
        try:
            tls.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", default=default_bin("fcp-client"))
    ap.add_argument("--server", default=default_bin("fcp-server"))
    args = ap.parse_args()
    if not args.client or not args.server or not Path(args.client).is_file() or \
            not Path(args.server).is_file():
        print("FAIL: pass --client and --server pointing at built CLI binaries")
        return 1

    udp_port, local_port = free_port(), free_port()
    origin = Origin()
    server_log = ROOT / "build" / "http_forward_e2e_server.log"
    client_log = ROOT / "build" / "http_forward_e2e_client.log"
    server_log.parent.mkdir(exist_ok=True)
    procs, logs = [], []
    try:
        p, f = start_proc(args.server,
                          ["--bind=127.0.0.1", "--port=%d" % udp_port, "--log=warn"],
                          str(server_log))
        procs.append(p)
        logs.append(f)
        p, f = start_proc(args.client,
                          ["--host=127.0.0.1", "--port=%d" % udp_port,
                           "--listen=127.0.0.1", "--local-port=%d" % local_port,
                           "--log=warn"],
                          str(client_log))
        procs.append(p)
        logs.append(f)
        if not wait_port(local_port):
            print("FAIL: fcp-client did not open the local proxy port")
            return 1

        failures = []
        skipped = []
        authority = ("127.0.0.1:%d" % origin.port).encode()

        def check(name, cond, detail=""):
            print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))
            if not cond:
                failures.append(name)

        # 1. absolute-form GET, rewritten head, response bytes unchanged.
        req = (b"GET http://" + authority + b"/ HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n"
               b"Proxy-Authorization: Basic secret\r\n"
               b"X-Test: yes\r\n\r\n")
        out, eof = proxy_request(local_port, req)
        try:
            origin_req = origin.requests.get(timeout=3.0)
        except queue.Empty:
            origin_req = b""
        check("GET status line is the origin's",
              out.startswith(b"HTTP/1.1 200 OK\r\n") and b"hello-forward" in out)
        check("GET has no synthetic 200 Connection Established",
              b"Connection Established" not in out)
        check("GET origin saw origin-form request",
              origin_req.startswith(b"GET / HTTP/1.1\r\n"))
        check("GET origin saw forced Connection: close",
              b"Connection: close\r\n" in origin_req)
        check("GET proxy-only headers stripped",
              b"Proxy-Authorization" not in origin_req and b"http://" not in origin_req)
        check("GET kept ordinary headers", b"X-Test: yes" in origin_req)
        check("GET ended on the origin's FIN", eof)

        # 2. POST body arrives untouched.
        body = b"payload"
        req = (b"POST http://" + authority + b"/echo HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n"
               b"Content-Length: 7\r\n\r\n" + body)
        out, _ = proxy_request(local_port, req)
        try:
            origin_req = origin.requests.get(timeout=3.0)
        except queue.Empty:
            origin_req = b""
        check("POST body forwarded unchanged", out.endswith(body))
        check("POST Content-Length preserved", b"Content-Length: 7" in origin_req)

        # 3. chunked response is relayed byte-for-byte.
        req = (b"GET http://" + authority + b"/chunked HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n\r\n")
        out, _ = proxy_request(local_port, req)
        origin.requests.get(timeout=3.0)
        check("chunked response relayed",
              b"Transfer-Encoding: chunked" in out and b"abc" in out and
              b"defg" in out and out.endswith(b"0\r\n\r\n"))

        # 4. CONNECT (HTTPS path) still works after the entry split.
        req = (b"CONNECT " + authority + b" HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n\r\n"
               b"GET /raw HTTP/1.1\r\nHost: raw\r\n\r\n")
        out, _ = proxy_request(local_port, req)
        origin.requests.get(timeout=3.0)
        check("CONNECT regression",
              out.startswith(b"HTTP/1.1 200 Connection Established\r\n\r\n") and
              b"hello-forward" in out)

        # 5. local refusals before any dial.
        req = (b"GET https://" + authority + b"/ HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n\r\n")
        out, _ = proxy_request(local_port, req)
        check("https:// absolute-form refused", out.startswith(b"HTTP/1.1 400"))
        req = (b"GET http://" + authority + b"/ HTTP/1.1\r\n"
               b"Host: other.example\r\n\r\n")
        out, _ = proxy_request(local_port, req)
        check("disagreeing Host refused", out.startswith(b"HTTP/1.1 400"))

        # 6. Documented limitation: an origin that ignores Connection: close
        # delivers the whole response but keeps the local connection open.
        req = (b"GET http://" + authority + b"/hold HTTP/1.1\r\n"
               b"Host: " + authority + b"\r\n\r\n")
        out, eof = proxy_request(local_port, req, timeout=1.0)
        origin.requests.get(timeout=3.0)
        check("uncooperative origin still delivers the response",
              b"hello-forward" in out)
        check("uncooperative origin leaves connection open (known limit)",
              not eof,
              "no FIN; local socket stays open until idle teardown")

        # 7. Real TLS over CONNECT: the T32 half that a plaintext CONNECT
        #    check cannot cover. The certificate is minted locally, so no
        #    public network is involved.
        cert_path, key_path, cert_dir = make_test_cert()
        if cert_path is None:
            print("SKIP TLS over CONNECT: neither openssl nor cryptography available")
            skipped.append("5 TLS-over-CONNECT checks (needs openssl or cryptography)")
        else:
            tls_origin = TlsOrigin(cert_path, key_path)
            try:
                tls_authority = ("127.0.0.1:%d" % tls_origin.port).encode()
                try:
                    head, version, peer, out = tls_connect_request(
                        local_port, tls_authority, cert_path)
                    tls_err = None
                except (OSError, ssl.SSLError) as exc:
                    head, version, peer, out = b"", "", None, b""
                    tls_err = repr(exc)
                try:
                    tls_req = tls_origin.requests.get(timeout=3.0)
                except queue.Empty:
                    tls_req = b""
                check("CONNECT (TLS) reply is 200 Connection Established",
                      head.startswith(b"HTTP/1.1 200 Connection Established\r\n\r\n"))
                check("TLS handshake verified CA + hostname",
                      tls_err is None and version.startswith("TLSv1"),
                      tls_err or version or "no TLS session")
                check("TLS peer certificate SAN contains localhost",
                      bool(peer) and ("DNS", "localhost") in
                      peer.get("subjectAltName", ()))
                check("HTTPS response over CONNECT tunnel intact",
                      out.startswith(b"HTTP/1.1 200 OK\r\n") and b"tls-hello" in out)
                check("TLS origin saw the decrypted GET /tls",
                      tls_req.startswith(b"GET /tls HTTP/1.1\r\n"))
            finally:
                tls_origin.close()
                cert_dir.cleanup()

        if skipped:
            print("\nSKIPPED: " + "; ".join(skipped))
        if failures:
            print("\nFAILED: %d check(s): %s" % (len(failures), ", ".join(failures)))
            for path in (server_log, client_log):
                print("--- %s ---" % path.name)
                print("\n".join(path.read_text(encoding="utf-8", errors="replace")
                                .splitlines()[-20:]))
            return 1
        print("\nPASS: HTTP forward proxy real-process e2e")
        return 0
    finally:
        origin.close()
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    p.kill()
                except OSError:
                    pass
        for f in logs:
            f.close()


if __name__ == "__main__":
    sys.exit(main())
