"""Dashboard backend API (proposal §4.2: "Dashboard and API — React frontend,
REST/gRPC API"). The only service that needs CORS enabled — it aggregates
calls to every other microservice server-side, so the browser only ever
talks to this one origin.

Uses aegis_sdk (packages/sdk) for policy checks and credential invocations,
so the dashboard exercises the exact same code path as any other agent —
nothing here is a special "admin bypass."

Sprint 4: every request is scoped to a tenant, forwarded to every
downstream service. This is the tenant-facing isolation boundary —
browsers never talk to circuit-breaker/audit-logger/etc. directly, only to
this API.

Gap-closing work (2026-08-22, see PROGRESS.md): this used to trust
whatever tenant_id the client supplied (query param, path segment, or JSON
body) with no authentication at all. Every request now requires
`Authorization: Bearer <key>` (see config.py's DASHBOARD_API_KEYS); the
tenant is derived from the presented key, and no handler accepts a
client-supplied tenant_id anymore — that field simply doesn't exist in any
request shape below.

Managed-dashboard-for-security-teams work (2026-09-28, see PROGRESS.md):
each key now also carries a role ("operator" or "viewer") and an
operator name. Every state-changing endpoint (_handle_check,
_handle_credential, _handle_resume, _handle_deny) requires role ==
"operator" — a "viewer" key authenticates fine and can see status/audit/
approvals-queue, but a state-changing request is rejected with 403
before it ever reaches the downstream service, the same "deny before it
does anything" shape as every other layer in this repo. Resume/deny now
attribute the action to the actual operator name from the key, not a
generic "operator via dashboard" string — see _handle_resume/_handle_deny.
"""

import json
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))

from aegis_sdk import (  # noqa: E402
    ActionDescriptor,
    AegisClient,
    CredentialDenied,
    PolicyDenied,
    RateLimited,
    SessionSuspended,
)

# Settings now come from /app/config.py, bind-mounted by
# demo/docker-compose.yml (not baked into the image — see config.py's
# module docstring for why, and how to change a value without a rebuild).
# Note: dashboard-api is the one service AegisClient itself is constructed
# in server-side, so its URLs come from here (config.py), not from the
# SDK's own env-var fallback (that fallback exists for callers outside this
# repo's containers — see aegis_sdk's module docstring).
from config import (
    AUDIT_URL,
    CIRCUIT_BREAKER_URL as BREAKER_URL,
    ANOMALY_DETECTOR_URL as ANOMALY_URL,
    POLICY_URL,
    CREDENTIAL_BROKER_URL as CREDENTIAL_URL,
    CONTENT_GUARDRAIL_URL,
    DASHBOARD_API_PORT as PORT,
    DASHBOARD_ALLOWED_ORIGINS,
    DASHBOARD_API_KEYS,
)


def _proxy_get(url: str, timeout: float = 3.0):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read())


def _summarize_llm_events(events: list[dict]) -> dict:
    """Pure aggregation over `llm_call` audit events (newest first)."""
    calls = []
    for e in events:
        llm = e.get("llm") or {}
        content = llm.get("content") or {}
        calls.append(
            {
                "event_id": e.get("event_id"),
                "timestamp": e.get("timestamp"),
                "session_id": e.get("session_id"),
                "provider": llm.get("provider"),
                "model": llm.get("model"),
                "input_tokens": llm.get("input_tokens"),
                "output_tokens": llm.get("output_tokens"),
                "latency_ms": llm.get("latency_ms"),
                "cost_usd": llm.get("cost_usd"),
                "prompt_injection_suspected": bool(llm.get("prompt_injection_suspected")),
                "flagged": any(c.get("flagged") for c in content.values()),
                "categories": sorted({cat for c in content.values() for cat in c.get("categories", [])}),
                "types": sorted({t for c in content.values() for t in c.get("types", [])}),
                # Present only when the SDK client was created with
                # capture_text=True; otherwise None (hash-only audit events).
                "input_text": (content.get("input") or {}).get("text"),
                "output_text": (content.get("output") or {}).get("text"),
                "input_truncated": bool((content.get("input") or {}).get("truncated")),
                "output_truncated": bool((content.get("output") or {}).get("truncated")),
                # "Unscanned" means the guardrail was asked to check some text
                # and was unreachable. A call with no text at all (e.g. a
                # tool-result-only turn) had nothing to scan, so it isn't.
                "scanned": all(c.get("scanned") for c in content.values()),
            }
        )

    def num(key):
        return [c[key] for c in calls if isinstance(c.get(key), (int, float))]

    latencies = sorted(num("latency_ms"))
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else None

    by_model: dict[str, dict] = {}
    for c in calls:
        m = by_model.setdefault(
            f"{c['provider'] or '?'}/{c['model'] or '?'}",
            {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "flagged": 0},
        )
        m["calls"] += 1
        m["input_tokens"] += c["input_tokens"] or 0
        m["output_tokens"] += c["output_tokens"] or 0
        m["cost_usd"] += c["cost_usd"] or 0.0
        m["flagged"] += 1 if c["flagged"] else 0

    return {
        "totals": {
            "calls": len(calls),
            "input_tokens": sum(num("input_tokens")),
            "output_tokens": sum(num("output_tokens")),
            "cost_usd": sum(num("cost_usd")),
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else None,
            "p95_latency_ms": p95,
            "flagged_calls": sum(1 for c in calls if c["flagged"]),
            "prompt_injection_suspected": sum(1 for c in calls if c["prompt_injection_suspected"]),
            "unscanned_calls": sum(1 for c in calls if not c["scanned"]),
        },
        "by_model": by_model,
        "flagged": [c for c in calls if c["flagged"]][:50],
        "recent": calls[:50],
    }


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
        origin = self.headers.get("Origin")
        if origin in DASHBOARD_ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self.headers.get("Origin")
        if origin in DASHBOARD_ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _origin_allowed(self) -> bool:
        # Security-review finding, see config.py's DASHBOARD_ALLOWED_ORIGINS
        # comment: CORS response headers alone don't stop a blind cross-site
        # form POST (the browser sends it regardless of CORS, which only
        # gates whether the *response* is readable) — this is real
        # defense-in-depth, on top of (not instead of) the Authorization
        # check below, which is now the primary defense: browsers never
        # attach custom headers to a plain HTML form submission, so blind
        # CSRF is structurally impossible once a request needs one, and a
        # key stored in this origin's localStorage can't be read by a
        # different origin's JS at all (same-origin policy).
        return self.headers.get("Origin") in DASHBOARD_ALLOWED_ORIGINS

    def _authenticate(self) -> dict | None:
        # Gap-closing work: the ONLY source of tenant identity now. Every
        # handler below uses self.tenant_id, set here — none of them read
        # tenant_id from a query param, path segment, or JSON body anymore.
        # Managed-dashboard-for-security-teams work (2026-09-28): each key
        # now resolves to {"tenant_id", "role", "operator"}, not a bare
        # tenant_id string — do_GET/do_POST below set self.tenant_id/
        # self.role/self.operator from this.
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return DASHBOARD_API_KEYS.get(auth[len("Bearer "):])

    def _read_json_body(self) -> dict:
        # Security-review finding: this used to parse the body as JSON
        # regardless of Content-Type, which meant a plain HTML
        # <form enctype="text/plain"> could smuggle a JSON-shaped body past
        # this check with no JavaScript at all. Requiring the real
        # application/json content type closes that specific trick (on top
        # of, not instead of, the checks above — a form's Content-Type is
        # browser-controlled and not itself trustworthy as the only gate).
        content_type = self.headers.get("Content-Type", "")
        if not content_type.split(";")[0].strip() == "application/json":
            raise ValueError(f"expected application/json, got {content_type!r}")
        return json.loads(self._raw_body) if self._raw_body else {}

    # ---- status ----

    def _handle_status(self):
        tenant_id = self.tenant_id
        # Managed-dashboard-for-security-teams work (2026-09-28, see
        # PROGRESS.md): credential_vault and content_guardrail were
        # missing from this check entirely — found while adding RBAC,
        # not something the "team" framing itself required, but a real
        # gap worth fixing while in this code. Both previously had no GET
        # route at all (see each service's own new do_GET), so a probe
        # against them before that fix would have fallen through to a
        # 501 and been read as "down" regardless of real health.
        checks = {
            "opa": f"{POLICY_URL}/health",
            "audit_logger": f"{AUDIT_URL}/events?limit=1",
            "circuit_breaker": f"{BREAKER_URL}/suspended?tenant_id={tenant_id}",
            "anomaly_detector": f"{ANOMALY_URL}/score/{tenant_id}/healthcheck",
            "credential_vault": f"{CREDENTIAL_URL}/health",
            "content_guardrail": f"{CONTENT_GUARDRAIL_URL}/health",
        }
        result = {"tenant_id": tenant_id, "role": self.role, "operator": self.operator}
        for name, url in checks.items():
            try:
                status, _ = _proxy_get(url, timeout=1.5)
                result[name] = status < 500
            except (urllib.error.URLError, OSError, ValueError):
                result[name] = False
        self._send_json(200, result)

    # ---- audit log ----

    def _handle_events(self, qs: dict):
        limit = qs.get("limit", ["20"])[0]
        session_id = qs.get("session_id", [None])[0]
        url = f"{AUDIT_URL}/events?limit={limit}&tenant_id={self.tenant_id}"
        if session_id:
            url += f"&session_id={session_id}"
        try:
            status, body = _proxy_get(url)
            self._send_json(status, body)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"audit logger unreachable: {exc}"})

    def _handle_llm(self, qs: dict):
        """LLM observability: token/cost/latency totals and prompt-injection
        findings, aggregated server-side from the tenant's `llm_call` audit
        events (written by aegis_sdk's AegisClient.record_llm_call()). The
        tenant comes from the API key like every other handler here."""
        limit = qs.get("limit", ["500"])[0]
        try:
            limit = max(1, min(int(limit), 5000))
        except ValueError:
            limit = 500
        url = f"{AUDIT_URL}/events?limit={limit}&tenant_id={self.tenant_id}&event_type=llm_call"
        try:
            status, events = _proxy_get(url)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"audit logger unreachable: {exc}"})
            return
        if status != 200:
            self._send_json(status, events)
            return
        self._send_json(200, _summarize_llm_events(events))

    def _handle_verify(self):
        try:
            status, body = _proxy_get(f"{AUDIT_URL}/verify?tenant_id={self.tenant_id}")
            self._send_json(status, body)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"audit logger unreachable: {exc}"})

    # ---- circuit breaker ----

    def _handle_breaker_status(self, session_id: str):
        try:
            status, body = _proxy_get(f"{BREAKER_URL}/status/{self.tenant_id}/{session_id}")
            self._send_json(status, body)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"circuit breaker unreachable: {exc}"})

    def _handle_suspended(self):
        # Always filtered by self.tenant_id (from the API key), even though
        # circuit-breaker itself would also serve an unfiltered cross-tenant
        # view — this is the actual tenant isolation boundary for the dashboard.
        try:
            status, body = _proxy_get(f"{BREAKER_URL}/suspended?tenant_id={self.tenant_id}")
            self._send_json(status, body)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"circuit breaker unreachable: {exc}"})

    def _log_operator_action(self, action: str, session_id: str) -> None:
        # Managed-dashboard-for-security-teams work (2026-09-28, see
        # PROGRESS.md): circuit-breaker's /resume doesn't take a reason
        # at all (see circuit_breaker.py's resume()), so there's nowhere
        # downstream to attach "who resumed this" — this logs a
        # dedicated audit event instead, the real place a security
        # team's attribution trail needs to live. Best-effort, same
        # reasoning as every other audit-log call in this repo: a down
        # audit-logger shouldn't block the actual approve/deny action.
        try:
            req = urllib.request.Request(
                f"{AUDIT_URL}/events",
                data=json.dumps(
                    {
                        "tenant_id": self.tenant_id,
                        "session_id": session_id,
                        "event_type": "dashboard_operator_action",
                        "action": {"action_type": action, "target": session_id, "method": None},
                        "policy_decision": {"allowed": True, "reason": f"{action} by {self.operator}"},
                        "operator": self.operator,
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except (urllib.error.URLError, OSError):
            pass

    def _handle_resume(self, session_id: str):
        self._read_json_body()  # content-type check, same as the other POST handlers
        try:
            req = urllib.request.Request(
                f"{BREAKER_URL}/resume/{self.tenant_id}/{session_id}", data=b"{}", method="POST"
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                self._log_operator_action("resume", session_id)
                self._send_json(resp.status, json.loads(resp.read()))
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"circuit breaker unreachable: {exc}"})

    def _handle_deny(self, session_id: str):
        self._read_json_body()  # content-type check, same as the other POST handlers
        try:
            # Attributes this to the real named operator from the API
            # key, not a generic string — a security team needs to know
            # WHO denied a session, not just that a dashboard did.
            body = json.dumps({"reason": f"denied by {self.operator} via dashboard"}).encode()
            req = urllib.request.Request(
                f"{BREAKER_URL}/terminate/{self.tenant_id}/{session_id}", data=body, method="POST"
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                self._log_operator_action("deny", session_id)
                self._send_json(resp.status, json.loads(resp.read()))
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"circuit breaker unreachable: {exc}"})

    # ---- anomaly detector ----

    def _handle_anomaly_score(self, session_id: str):
        try:
            status, body = _proxy_get(f"{ANOMALY_URL}/score/{self.tenant_id}/{session_id}")
            self._send_json(status, body)
        except (urllib.error.URLError, OSError) as exc:
            self._send_json(502, {"error": f"anomaly detector unreachable: {exc}"})

    # ---- policy check / credential invoke, via the real SDK ----

    def _handle_check(self):
        payload = self._read_json_body()
        session_id = payload.get("session_id", "dashboard-session")
        client = AegisClient(
            policy_engine_url=POLICY_URL,
            audit_logger_url=AUDIT_URL,
            circuit_breaker_url=BREAKER_URL,
            session_id=session_id,
            tenant_id=self.tenant_id,
        )
        action = ActionDescriptor(
            action_type=payload.get("action_type", "http_request"),
            target=payload.get("target", ""),
            method=payload.get("method") or None,
        )
        try:
            client.check(action)
            self._send_json(200, {"outcome": "allowed"})
        except SessionSuspended as e:
            self._send_json(200, {"outcome": "suspended", "detail": str(e)})
        except RateLimited as e:
            self._send_json(200, {"outcome": "rate_limited", "detail": str(e)})
        except PolicyDenied as e:
            self._send_json(200, {"outcome": "denied", "detail": e.reason})

    def _handle_credential(self):
        payload = self._read_json_body()
        session_id = payload.get("session_id", "dashboard-session")
        client = AegisClient(
            policy_engine_url=POLICY_URL,
            audit_logger_url=AUDIT_URL,
            circuit_breaker_url=BREAKER_URL,
            credential_broker_url=CREDENTIAL_URL,
            session_id=session_id,
            tenant_id=self.tenant_id,
        )
        try:
            result = client.invoke_credentialed(payload.get("service", ""), payload.get("action", ""))
            self._send_json(200, {"outcome": "allowed", "result": result})
        except SessionSuspended as e:
            self._send_json(200, {"outcome": "suspended", "detail": str(e)})
        except RateLimited as e:
            self._send_json(200, {"outcome": "rate_limited", "detail": str(e)})
        except CredentialDenied as e:
            self._send_json(200, {"outcome": "denied", "detail": e.reason})

    # ---- routing ----

    def _apply_auth(self, key_info: dict | None) -> bool:
        """Sets self.tenant_id/role/operator from the authenticated key
        info, or sends 401 and returns False if the key was missing/
        invalid. Shared by do_GET and do_POST so both stay in sync."""
        if key_info is None:
            self._send_json(401, {"error": "missing or invalid API key"})
            return False
        self.tenant_id = key_info["tenant_id"]
        self.role = key_info["role"]
        self.operator = key_info["operator"]
        return True

    def do_GET(self):
        if not self._apply_auth(self._authenticate()):
            return

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        parts = parsed.path.strip("/").split("/")

        if parsed.path == "/api/status":
            self._handle_status()
        elif parsed.path == "/api/events":
            self._handle_events(qs)
        elif parsed.path == "/api/llm":
            self._handle_llm(qs)
        elif parsed.path == "/api/events/verify":
            self._handle_verify()
        elif len(parts) == 4 and parts[:3] == ["api", "breaker", "status"]:
            self._handle_breaker_status(parts[3])
        elif parsed.path == "/api/breaker/suspended":
            self._handle_suspended()
        elif len(parts) == 4 and parts[:3] == ["api", "anomaly", "score"]:
            self._handle_anomaly_score(parts[3])
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        # Always consume the request body up front, before any early return
        # (bad origin, bad key, viewer role) or handler that doesn't read it.
        # This server speaks HTTP/1.1 keep-alive, so an unread body is parsed
        # as the start of the NEXT request on the same connection: the
        # browser's follow-up refresh after Approve/Deny got a 501 with no
        # CORS headers, which fetch() reports as "Failed to fetch".
        length = int(self.headers.get("Content-Length", 0) or 0)
        self._raw_body = self.rfile.read(length) if length else b""

        # Every POST here is state-changing (a policy check that gets
        # audit-logged and can trip the circuit breaker, a real credential
        # invocation, or an approve/deny) — both checks below run before
        # any of them, not just for /api/check and /api/credential
        # specifically. Origin check first since it's cheaper and doesn't
        # need the request body.
        if not self._origin_allowed():
            self._send_json(403, {"error": "origin not allowed"})
            return

        if not self._apply_auth(self._authenticate()):
            return

        # Managed-dashboard-for-security-teams work (2026-09-28, see
        # PROGRESS.md): every POST here is state-changing, so a "viewer"
        # key is rejected before any of them run — the same "deny before
        # it does anything" shape as every other layer in this repo, not
        # a per-handler afterthought.
        if self.role != "operator":
            self._send_json(403, {"error": f"role '{self.role}' cannot perform this action; requires 'operator'"})
            return

        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")

        try:
            if parsed.path == "/api/check":
                self._handle_check()
            elif parsed.path == "/api/credential":
                self._handle_credential()
            elif len(parts) == 4 and parts[:3] == ["api", "breaker", "resume"]:
                self._handle_resume(parts[3])
            elif len(parts) == 4 and parts[:3] == ["api", "breaker", "deny"]:
                self._handle_deny(parts[3])
            else:
                self._send_json(404, {"error": "not found"})
        except ValueError as exc:
            # _read_json_body's Content-Type check, see its own comment.
            self._send_json(400, {"error": str(exc)})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"AEGIS dashboard API listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
