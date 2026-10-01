"""Mock webhook receiver (gap-closing work, 2026-09-16, see PROGRESS.md).
Standing in for a real Slack Incoming Webhook / email-relay endpoint —
accepts whatever notification packages/circuit-breaker (and
circuit-breaker-rs) POST and keeps them in memory so a test can confirm
they actually arrived, same role demo/mock-siem plays for Layer 6's SIEM
forwarding.

A real Slack Incoming Webhook only reads the payload's "text" field and
ignores everything else, which is why the sender always includes one —
this receiver keeps the whole payload so tests can also assert on the
structured fields (tier, reason, tenant_id, session_id) a generic
downstream consumer (PagerDuty, an internal alerting pipeline) would want.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_lock = threading.Lock()
_received: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    # See packages/circuit-breaker/circuit_breaker.py's Handler for why —
    # HTTP/1.0 (the stdlib default) forces a connection close after every
    # response, which load testing found to be the actual concurrency
    # bottleneck across all of this repo's Python services.
    protocol_version = "HTTP/1.1"

    def _send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/notify":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        notification = json.loads(self.rfile.read(length) or b"{}")
        with _lock:
            _received.append(notification)
        self._send_json(200, {"received": True, "total_received": len(_received)})

    def do_GET(self):
        if self.path.startswith("/received"):
            with _lock:
                self._send_json(200, {"count": len(_received), "notifications": _received})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=9850):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"mock-webhook listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
