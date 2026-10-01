"""Layer 2 — credential vaulting (Sprint 2 per PLAN.md).

The agent never holds, sees, or transmits a raw credential. It sends a
declarative request ("call protected-api's /profile action") to this broker,
which:
  1. Checks the (tenant, session, service, action) against policy — reuses
     the OPA instance from packages/policy-engine via a "credential_use"
     action type (see default.rego).
  2. Fetches the actual secret from HashiCorp Vault, from a path scoped to
     the caller's tenant.
  3. Performs the authenticated call to the real service itself.
  4. Returns only the result to the agent — never the token.

Sprint 4: each service's Vault path is a per-tenant template
(SERVICES[service]["vault_path_template"]), not a single fixed path — two
tenants get two different secrets for the "same" nominal service. If a
tenant has no secret seeded at its own path, the lookup hard-fails (502) —
there is deliberately no fallback to another tenant's (or a shared) path,
so a missing per-tenant secret can never leak a different tenant's
credential.

Gap-closing work (2026-09-16, see PROGRESS.md): the actual secret read
used to go straight through with VAULT_TOKEN — a static, unscoped
dev-mode root token capable of reading (and writing) anything in Vault.
Every read now goes through a freshly-minted, tenant-scoped, single-use,
short-TTL child token instead (_mint_scoped_token). A leaked
per-request token (a log line, a crash dump, an SSRF into this process)
can only read that ONE tenant's secrets, expires in
config.VAULT_SCOPED_TOKEN_TTL, and is rejected by Vault itself after
config.VAULT_SCOPED_TOKEN_NUM_USES uses — bounding the blast radius of any
single leak to roughly one request, rather than "root access to Vault,
indefinitely."

Same-day follow-up, closing the "root token still mints those child
tokens" half of the gap above: _get_broker_token() replaces VAULT_TOKEN
(root) as the identity that mints child tokens and manages tenant
policies, with an AppRole login instead — a renewable token whose OWN
policy (aegis-credential-broker-admin, written once by
demo/docker-compose.yml's vault-init, the same one-time-root-bootstrap
pattern any real Vault deployment already uses for AppRole/Kubernetes-auth)
grants exactly auth/token/create and managing this service's own
sys/policies/acl/aegis-tenant-* policies — nothing else, and specifically
NOT direct secret read access. VAULT_TOKEN itself is untouched by this
service from here on; its only remaining job anywhere in this repo's own
Python services is vault-init's one-time bootstrap of that AppRole
identity.

Config consolidation: SERVICES used to be a dict hardcoded in this file —
adding a real credentialed service meant editing Python source. It's now
loaded from a JSON file (services.json, path overridable via
AEGIS_CREDENTIAL_SERVICES_FILE) — plain JSON rather than YAML to avoid
adding a dependency to this service's otherwise stdlib-only container (see
Dockerfile: no pip install step). See services.json for the schema; adding
a second real service is now a config-file edit plus seeding its Vault
secret, not a code change.

VAULT_ADDR/VAULT_APPROLE_*_PATH/POLICY_ENGINE_URL/PORT come from
/app/config.py, bind-mounted by demo/docker-compose.yml — see config.py's
module docstring.
services.json's own "${VAR:-default}" templating (for base_url) still
checks a real env var first (so a genuine runtime override still works
without touching any file), then falls back to config.py's matching
constant if one exists, then finally the inline default in services.json
itself — this keeps config.py as the single source of truth even though
services.json is a separate, JSON-not-Python mechanism.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config

# Security-review finding (internal, 2026-08-22 — see PROGRESS.md):
# tenant_id used to flow straight from the request body into
# vault_path_template.format(tenant_id=...) with no validation at all.
# Confirmed empirically that Vault's own HTTP router normalizes "../"
# dot-segments, so an unvalidated tenant_id could build a path that escapes
# the intended secret/ KV mount entirely and reaches other Vault mounts
# (e.g. sys/). This was NOT reachable end-to-end in practice — OPA's
# tenant-must-be-configured check in _check_policy() already fails closed
# for any tenant_id that isn't a real operator-provisioned tenant, before
# _call_service() is ever reached — but the code had zero defense-in-depth
# of its own, relying entirely on that one gate. This allowlist is checked
# here regardless, so this file no longer depends solely on OPA's gate
# holding for every future code path.
_TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

VAULT_ADDR = config.VAULT_ADDR
VAULT_SCOPED_TOKEN_TTL = config.VAULT_SCOPED_TOKEN_TTL
VAULT_SCOPED_TOKEN_NUM_USES = config.VAULT_SCOPED_TOKEN_NUM_USES
VAULT_APPROLE_ROLE_ID_PATH = config.VAULT_APPROLE_ROLE_ID_PATH
VAULT_APPROLE_SECRET_ID_PATH = config.VAULT_APPROLE_SECRET_ID_PATH
POLICY_ENGINE_URL = config.POLICY_URL
PORT = config.CREDENTIAL_VAULT_PORT
DEFAULT_TENANT = "default"
SERVICES_FILE = os.environ.get("AEGIS_CREDENTIAL_SERVICES_FILE", os.path.join(os.path.dirname(__file__), "services.json"))

# tenant_id -> True once its scoped-read-only Vault policy has been
# created, so a repeat request doesn't re-PUT the identical policy body
# every single time — Vault itself would no-op on an identical PUT, but
# there's no reason to pay that round trip on every request either.
_tenant_policy_ensured: set[str] = set()

# This service's own operating credential — an AppRole-derived token, not
# the root token (see module docstring). Guarded by a lock since
# ThreadingHTTPServer can call _get_broker_token() from multiple threads
# at once; only one should ever perform an actual login/renewal.
_broker_token_lock = threading.Lock()
_broker_token: dict = {"value": None, "expires_at": 0.0}


def _load_services(path: str) -> dict:
    """Load the service registry from JSON. Each entry's base_url may embed
    a reference of the form "${VAR_NAME:-default}" (a small subset of
    shell-style substitution, not a general templating engine) so a real
    deployment can point a service at a real host without editing this
    file at all."""
    with open(path) as f:
        raw = json.load(f)
    return {name: {**cfg, "base_url": _expand_ref(cfg["base_url"])} for name, cfg in raw.items()}


def _expand_ref(value: str) -> str:
    if not (value.startswith("${") and value.endswith("}")):
        return value
    inner = value[2:-1]
    name, _, default = inner.partition(":-")
    if name in os.environ:
        return os.environ[name]
    if hasattr(config, name):
        return getattr(config, name)
    return default


SERVICES = _load_services(SERVICES_FILE)


def _vault_request(path: str, token: str | None, method: str = "GET", body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(f"{VAULT_ADDR}/v1/{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read()
    # Vault returns 204 No Content (empty body) for some writes, e.g. the
    # policy PUT in _ensure_tenant_policy — not every call here is a read.
    return json.loads(raw) if raw else {}


def _read_approle_credentials() -> tuple[str, str]:
    """Reads the role_id/secret_id demo/docker-compose.yml's vault-init
    wrote to the shared volume (see module docstring). Retries briefly —
    defense in depth against a slow volume mount on top of
    docker-compose.yml's own depends_on: vault-init:
    condition: service_completed_successfully, not a substitute for it."""
    last_error: Exception | None = None
    for _ in range(10):
        try:
            with open(VAULT_APPROLE_ROLE_ID_PATH) as f:
                role_id = f.read().strip()
            with open(VAULT_APPROLE_SECRET_ID_PATH) as f:
                secret_id = f.read().strip()
            if role_id and secret_id:
                return role_id, secret_id
        except FileNotFoundError as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(
        f"AppRole credentials not found at {VAULT_APPROLE_ROLE_ID_PATH}/{VAULT_APPROLE_SECRET_ID_PATH} "
        f"after retrying (vault-init may not have finished): {last_error}"
    )


def _approle_login() -> dict:
    role_id, secret_id = _read_approle_credentials()
    response = _vault_request(
        "auth/approle/login",
        None,  # logging in needs no token — it's how this service gets one
        method="POST",
        body={"role_id": role_id, "secret_id": secret_id},
    )
    return response["auth"]


def _get_broker_token(force_refresh: bool = False) -> str:
    """This service's own operating credential for privileged Vault
    calls (minting child tokens, managing its own tenant policies) — see
    module docstring for why this replaced the static root token.
    Renews via a fresh AppRole login at 50% of the granted lease
    (headroom for request latency/clock drift, not racing expiry), or
    immediately if force_refresh=True (used after a 403, in case the
    token was revoked out-of-band)."""
    with _broker_token_lock:
        now = time.time()
        if not force_refresh and _broker_token["value"] and now < _broker_token["expires_at"]:
            return _broker_token["value"]

        auth = _approle_login()
        _broker_token["value"] = auth["client_token"]
        _broker_token["expires_at"] = now + auth["lease_duration"] * 0.5
        return _broker_token["value"]


def _privileged_vault_request(path: str, method: str, body: dict) -> dict:
    """Wraps _vault_request with _get_broker_token(), retrying once with
    a forced fresh login if Vault rejects the current token (403) —
    covers the token having been revoked or expired out-of-band, not
    just the normal proactive renewal _get_broker_token() already does."""
    token = _get_broker_token()
    try:
        return _vault_request(path, token, method=method, body=body)
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
        token = _get_broker_token(force_refresh=True)
        return _vault_request(path, token, method=method, body=body)


def _ensure_tenant_policy(tenant_id: str) -> str:
    """Idempotently creates a Vault ACL policy scoped to exactly this
    tenant's own secret path — read-only, nothing else. tenant_id is
    already validated against _TENANT_ID_PATTERN by the caller (do_POST),
    so it's safe to interpolate directly into the HCL policy body below."""
    policy_name = f"aegis-tenant-{tenant_id}-readonly"
    if policy_name in _tenant_policy_ensured:
        return policy_name

    policy_hcl = f'path "secret/data/{tenant_id}/*" {{\n  capabilities = ["read"]\n}}\n'
    _privileged_vault_request(f"sys/policies/acl/{policy_name}", "PUT", {"policy": policy_hcl})
    _tenant_policy_ensured.add(policy_name)
    return policy_name


def _mint_scoped_token(tenant_id: str) -> str:
    """Mints a fresh child token, scoped to exactly this tenant's
    read-only policy, short-lived and single-use (config.py's
    VAULT_SCOPED_TOKEN_TTL/VAULT_SCOPED_TOKEN_NUM_USES) — see module
    docstring for why. This service's own AppRole-derived token
    (_get_broker_token) is the parent authority here; the returned child
    token is what actually reads the secret."""
    policy_name = _ensure_tenant_policy(tenant_id)
    response = _privileged_vault_request(
        "auth/token/create",
        "POST",
        {
            "policies": [policy_name],
            "ttl": VAULT_SCOPED_TOKEN_TTL,
            "num_uses": VAULT_SCOPED_TOKEN_NUM_USES,
        },
    )
    return response["auth"]["client_token"]


def _fetch_secret(vault_path: str, field: str, token: str) -> str:
    body = _vault_request(vault_path, token)
    return body["data"]["data"][field]


def _check_policy(tenant_id: str, service: str, action: str) -> bool:
    payload = json.dumps(
        {
            "input": {
                "tenant_id": tenant_id,
                "action": {"type": "credential_use", "target": service, "method": action},
            }
        }
    ).encode()
    req = urllib.request.Request(
        f"{POLICY_ENGINE_URL}/v1/data/aegis/authz/allow",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        result = json.loads(resp.read())
    return bool(result.get("result", False))


def _call_service(tenant_id: str, service: str, action: str) -> dict:
    service_config = SERVICES[service]
    vault_path = service_config["vault_path_template"].format(tenant_id=tenant_id)
    scoped_token = _mint_scoped_token(tenant_id)
    upstream_token = _fetch_secret(vault_path, service_config["vault_field"], scoped_token)
    req = urllib.request.Request(
        f"{service_config['base_url']}/{action.lstrip('/')}",
        headers={"Authorization": f"Bearer {upstream_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"status": resp.status, "body": json.loads(resp.read())}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": json.loads(exc.read())}


class Handler(BaseHTTPRequestHandler):
    # See packages/circuit-breaker/circuit_breaker.py's Handler for why —
    # HTTP/1.0 (the stdlib default) forces a connection close after every
    # response, which load testing found to be the actual concurrency
    # bottleneck across all of this repo's Python services.
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path != "/invoke":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        req_body = json.loads(self.rfile.read(length) or b"{}")

        tenant_id = req_body.get("tenant_id") or DEFAULT_TENANT
        session_id = req_body.get("session_id", "unknown")
        service = req_body.get("service")
        action = req_body.get("action", "")

        if not _TENANT_ID_PATTERN.match(tenant_id):
            self._send(400, {"error": "invalid tenant_id"})
            return

        if service not in SERVICES:
            self._send(400, {"error": f"unknown service: {service}"})
            return

        try:
            allowed = _check_policy(tenant_id, service, action)
        except (urllib.error.URLError, OSError) as exc:
            self._send(502, {"error": f"policy engine unreachable: {exc}"})
            return

        if not allowed:
            self._send(403, {"error": "denied by policy engine"})
            return

        try:
            result = _call_service(tenant_id, service, action)
        except (urllib.error.URLError, OSError, KeyError) as exc:
            # Deliberately no fallback to another tenant's (or a shared)
            # Vault path here — an unseeded tenant secret is a hard failure,
            # not a reason to try a different path.
            self._send(502, {"error": f"upstream call failed (tenant={tenant_id}): {exc}"})
            return

        self._send(
            200,
            {
                "tenant_id": tenant_id,
                "session_id": session_id,
                "service": service,
                "action": action,
                "result": result,
            },
        )

    def do_GET(self):
        # Added for the dashboard's status check (managed-dashboard-for-
        # security-teams work, 2026-09-28, see PROGRESS.md) — this
        # service previously had no GET route at all, so a health probe
        # against it fell through to BaseHTTPRequestHandler's default
        # 501, which the dashboard would have read as "down" even when
        # the service was healthy.
        if self.path == "/health":
            self._send(200, {"status": "ok"})
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
    print(f"AEGIS credential-broker listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
