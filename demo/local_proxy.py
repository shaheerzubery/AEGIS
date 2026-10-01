"""Minimal local stand-in for the AEGIS egress proxy (packages/proxy) — lets
you verify the Day 1 goal ("log every outbound request") without Docker/Envoy.

Not a replacement for packages/proxy/envoy.yaml — just a way to sanity-check
the demo agent's traffic locally. Logs every CONNECT (HTTPS) and plain HTTP
request that passes through it.

Usage:
    python local_proxy.py                 # listens on 127.0.0.1:10000
    HTTP_PROXY=http://127.0.0.1:10000 HTTPS_PROXY=http://127.0.0.1:10000 \
        python hello_agent.py
"""

import socket
import threading
import http.server
import urllib.request
from datetime import datetime, timezone


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}")


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # replaced by our own logging below

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        log(f"CONNECT {host}:{port}")
        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError as exc:
            log(f"  -> failed to reach {host}:{port}: {exc}")
            self.send_error(502, "Bad Gateway")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        client_sock = self.connection
        self._tunnel(client_sock, upstream)

    def _tunnel(self, client_sock, upstream_sock):
        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass

        t1 = threading.Thread(target=pipe, args=(client_sock, upstream_sock), daemon=True)
        t2 = threading.Thread(target=pipe, args=(upstream_sock, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def do_GET(self):
        log(f"GET {self.path}")
        try:
            with urllib.request.urlopen(self.path, timeout=5) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except Exception as exc:
            log(f"  -> failed: {exc}")
            self.send_error(502, "Bad Gateway")


def main(host="127.0.0.1", port=10000):
    server = http.server.ThreadingHTTPServer((host, port), ProxyHandler)
    log(f"AEGIS local proxy listening on {host}:{port} (Ctrl+C to stop)")
    server.serve_forever()


if __name__ == "__main__":
    main()
