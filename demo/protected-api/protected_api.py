"""Mock protected third-party service for the credential-vaulting demo
(Layer 2). Requires 'Authorization: Bearer <token>' matching one of
PROTECTED_API_TOKENS — standing in for a real API (e.g. GitHub). The point
being demonstrated is that AEGIS's credential broker holds these tokens, not
the agent (see packages/credential-vault).

Sprint 4: accepts a *set* of tokens, not just one — the multi-tenancy demo
gives each tenant its own distinct token from Vault, and this mock upstream
stands in for "the same real API accepting credentials issued to more than
one of AEGIS's tenants."

Settings now come from /app/config.py, bind-mounted by
demo/docker-compose.yml (not baked into the image — see config.py's module
docstring for why, and how to change a value without a rebuild).
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from config import PROTECTED_API_TOKEN_DEFAULT, PROTECTED_API_TOKEN_ACME, PROTECTED_API_PORT as PORT

EXPECTED_TOKENS = {PROTECTED_API_TOKEN_DEFAULT, PROTECTED_API_TOKEN_ACME}


class Handler(BaseHTTPRequestHandler):
    # See packages/circuit-breaker/circuit_breaker.py's Handler for why —
    # HTTP/1.0 (the stdlib default) forces a connection close after every
    # response, which load testing found to be the actual concurrency
    # bottleneck across all of this repo's Python services.
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
        if token not in EXPECTED_TOKENS:
            self._send(401, {"error": "unauthorized"})
            return
        if self.path == "/profile":
            self._send(200, {"user": "aegis-demo-user", "plan": "pro"})
        else:
            self._send(404, {"error": "not found"})

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"protected-api listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
