#!/usr/bin/env python3
"""Host-side testbed server for the VM matrix (PACKAGING-MATRIX §7).

Run on the host; VMs reach it via their default gateway (see `ip route` inside the VM — the vm scripts self-locate it).

  GET  /<name>  — serve a VM harness script (packaging/testbed/vm/) or a
                  package file from the repo root
                  (lustless_*.deb / lustless-*.rpm / lustless-*.pkg.tar.zst /
                  lustless-*.apk)
  POST /?name=<file>  — store the request body as a test report under
                  target/testbed/reports/

Usage: packaging/testbed/serve.sh [port]   (default 9996)
"""
import http.server
import os
import re
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9996
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VM_DIR = os.path.join(REPO_ROOT, "packaging", "testbed", "vm")
REPORT_DIR = os.path.join(REPO_ROOT, "target", "testbed", "reports")
PACKAGES = re.compile(r"^lustless(_|-).*(\.deb|\.rpm|\.pkg\.tar\.zst|\.apk)$")


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        name = self.path.lstrip("/")
        if not name or ".." in name:
            return self._send(400, b"bad path\n")
        for base in (VM_DIR, REPO_ROOT):
            path = os.path.join(base, name)
            if os.path.isfile(path) and (
                base == VM_DIR or PACKAGES.match(name)
            ):
                with open(path, "rb") as fh:
                    return self._send(200, fh.read(), "application/octet-stream")
        self._send(404, b"not found: %s\n" % name.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        name = self.path.split("?", 1)[1] if "?" in self.path else ""
        name = dict(
            part.split("=", 1) for part in name.split("&") if "=" in part
        ).get("name", "")
        name = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "report"
        os.makedirs(REPORT_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S")
        path = os.path.join(REPORT_DIR, f"{stamp}-{name}")
        with open(path, "wb") as fh:
            fh.write(body)
        print(f"report: {path} ({len(body)} bytes)", flush=True)
        self._send(200, b"ok\n")

    def log_message(self, fmt, *args):
        print("%s - %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)


if __name__ == "__main__":
    os.makedirs(REPORT_DIR, exist_ok=True)
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as srv:
        print(f"serve.sh: http://0.0.0.0:{PORT}  vm-dir={VM_DIR}")
        srv.serve_forever()
