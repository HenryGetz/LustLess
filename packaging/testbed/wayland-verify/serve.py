#!/usr/bin/env python3
"""Wave-5 file service for the Zorin/Ubuntu testbed VMs.

Runs INSIDE the qemu container, bound to the guest's gateway address
(172.30.16.1:9996), which is the only host-side address a testbed guest can
reach (`docker exec -i zorin-os sh -c 'nohup python3 /tmp/serve5.py ...'`).

  GET  /<file>   -> serves /tmp/serve/<file> (the .deb, the run script)
  POST /<name>   -> writes the body to /tmp/serve/<name> (the VM's report)

So the whole VM side is one short typed line:
  wget -qO- http://172.30.16.1:9996/run.sh | bash
"""
import http.server
import os
import socketserver
import sys

ROOT = "/tmp/serve"
# The guest can only reach the qemu container's own addresses: its tap gateway
# (172.30.16.1) is the one the testbed images use. Port 80 lets the guest fetch
# with a bare host (`curl 172.30.16.1/go.sh`), which keeps the one line typed
# into a VNC console free of shifted characters — vncdotool's `type` drops the
# shift modifier, so `:` / `|` / `_` cannot be typed reliably.
HOST = sys.argv[1] if len(sys.argv) > 1 else "172.30.16.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9996
os.makedirs(ROOT, exist_ok=True)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        name = os.path.basename(self.path) or "report.txt"
        with open(os.path.join(ROOT, name), "wb") as handle:
            handle.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((HOST, PORT), Handler) as server:
    print(f"serving {ROOT} on {HOST}:{PORT}", flush=True)
    server.serve_forever()
