"""Layer 5 — basic circuit breaker (Day 5 MVP) + rate limiting (Sprint 2)
+ hard-suspend/emergency-kill tiers (gap-closing work, 2026-09-16).

Python for now; the proposal specs a Rust service for this in Sprint 2
(sub-ms latency at scale) — this MVP proves the behaviour, not the perf target.
circuit-breaker-rs (packages/circuit-breaker-rs) is now the DEFAULT for the
demo stack (see PROGRESS.md's "circuit-breaker-rs default cutover"), but
doesn't yet have the two new tiers below — a stated gap, not a silent drop.

Two independent sliding-window counters per (tenant, session):
  - violations: policy denials. Crossing the threshold suspends the session
    (a webhook notification fires — stdout for this MVP).
  - activity: every action attempt, allowed or denied. Crossing the rate
    limit (read from OPA's data.policy.tenants.<tenant>.rate_limits, see
    packages/policy-engine) just rejects that one action — no suspension.

Rate limiting lives here rather than in OPA because OPA evaluates each
request statelessly; "how many actions has this session taken in the last
minute" needs a counter that persists across requests.

Sprint 4: every counter is keyed by the composite (tenant_id, session_id)
tuple, not bare session_id — two tenants using the identical session_id
string are fully independent. The rate limit itself is also fetched and
cached per tenant, since tenants can have different configured limits.

Gap-closing work (2026-09-16, see PROGRESS.md): the proposal's own three
escalation levels for this layer (§3.2 Layer 5 "How it works"), literally:
  - "Soft pause: the current action is held pending human review" — this
    is exactly what suspend_directly()/record_violation() already did;
    relabeled "soft_pause" below, behavior unchanged.
  - "Hard suspend: all agent processes are frozen, network access is
    revoked, and a snapshot of the agent's state is captured for
    forensics" — new hard_suspend(): same denial-everything effect as
    soft pause (this MVP's "network access revoked" — see terminate()'s
    existing docstring for why network-level denial is the mechanism
    throughout this layer), PLUS a real forensic snapshot: the session's
    actual recent audit trail, fetched live from packages/audit-logger
    and stored, not a placeholder.
  - "Emergency kill: the agent's entire runtime environment is destroyed
    (container killed, VM terminated)" — new emergency_kill(): does
    everything hard_suspend does, plus genuinely stops the agent's Docker
    container via the Docker Engine API, if one was registered for this
    session (see register_container()). Best-effort — a missing
    registration or unreachable Docker daemon degrades to "suspended, kill
    not possible," reported honestly in the response, never silently
    treated as success.
This is deliberately layered ON the existing soft-pause mechanism, not a
rewrite of it — terminate() (the human operator's post-review "terminate
permanently" resume option) is unrelated to these three and unchanged.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Settings now come from /app/config.py, bind-mounted by
# demo/docker-compose.yml (not baked into the image — see config.py's
# module docstring for why, and how to change a value without a rebuild).
from config import (
    VIOLATION_THRESHOLD,
    VIOLATION_WINDOW_SECONDS as WINDOW_SECONDS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_PER_MINUTE as DEFAULT_RATE_LIMIT,
    POLICY_URL as POLICY_ENGINE_URL,
    RATE_LIMIT_CACHE_SECONDS,
    CIRCUIT_BREAKER_PORT as PORT,
    AUDIT_URL,
    WEBHOOK_URL,
)

_lock = threading.Lock()
# All keyed by (tenant_id, session_id) — see module docstring.
_violations: dict[tuple[str, str], list[float]] = {}
_suspended: set[tuple[str, str]] = set()
_activity: dict[tuple[str, str], list[float]] = {}
_terminated: set[tuple[str, str]] = set()
# (tenant_id, session_id) -> {"reason": str, "suspended_at": float, "tier": str} —
# human-in-the-loop review needs to know *why* a session is pending and at
# which of the three escalation levels, not just that it is suspended.
_suspension_meta: dict[tuple[str, str], dict] = {}

# tenant_id -> {"value": int, "fetched_at": float} — cached separately per
# tenant since tenants can have different configured rate limits.
_rate_limit_cache: dict[str, dict] = {}

# (tenant_id, session_id) -> container_id, populated by register_container()
# — an agent runtime opts in to being killable by reporting its own Docker
# container id (see packages/sdk/aegis_sdk's register_runtime()). Nothing
# is killable by default; emergency_kill() degrades honestly if no
# registration exists for a session.
_container_registry: dict[tuple[str, str], str] = {}

# (tenant_id, session_id) -> the forensic snapshot captured at hard_suspend/
# emergency_kill time (see _capture_snapshot).
_snapshots: dict[tuple[str, str], dict] = {}


def _send_webhook(tenant_id: str, session_id: str, tier: str, reason: str, event: str) -> None:
    """Real HTTP POST to WEBHOOK_URL (gap-closing work, 2026-09-16, see
    PROGRESS.md) — this used to be a stdout print only. Same "empty string
    = disabled" convention as audit_logger.py's SIEM_URL forwarding; a
    real Slack Incoming Webhook only ever reads the "text" field, so it's
    always included, alongside the structured fields a generic receiver
    (PagerDuty, an internal pipeline, demo/mock-webhook) can use instead.

    Called on a background thread by every caller below — same reasoning
    as audit_logger.py's _forward_to_anomaly_detector fix: a slow or
    unreachable webhook receiver must never add latency to the
    suspend/kill response path."""
    if not WEBHOOK_URL:
        return
    payload = {
        "text": f"[AEGIS circuit-breaker] {event}: tenant={tenant_id} session={session_id} tier={tier} reason={reason}",
        "event": event,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "tier": tier,
        "reason": reason,
        "timestamp": time.time(),
    }
    try:
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except (urllib.error.URLError, OSError):
        pass  # webhook receiver being down shouldn't block circuit-breaker decisions


def _current_rate_limit(tenant_id: str) -> int:
    """Read the configured limit from OPA's
    data.policy.tenants.<tenant_id>.rate_limits, caching briefly per tenant so
    every single action doesn't round-trip to OPA. Falls back to the env
    default if OPA is unreachable or the tenant has no rate_limits configured."""
    now = time.time()
    cache = _rate_limit_cache.setdefault(tenant_id, {"value": DEFAULT_RATE_LIMIT, "fetched_at": 0.0})
    if now - cache["fetched_at"] < RATE_LIMIT_CACHE_SECONDS:
        return cache["value"]

    try:
        req = urllib.request.Request(
            f"{POLICY_ENGINE_URL}/v1/data/policy/tenants/{tenant_id}/rate_limits/max_actions_per_minute"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = json.loads(resp.read())
        limit = int(body.get("result", DEFAULT_RATE_LIMIT))
        cache["value"] = limit
        cache["fetched_at"] = now
        return limit
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        return cache["value"]  # keep last known value (or the default)


def record_violation(tenant_id: str, session_id: str) -> dict:
    key = (tenant_id, session_id)
    with _lock:
        now = time.time()
        history = _violations.setdefault(key, [])
        history[:] = [t for t in history if now - t < WINDOW_SECONDS]
        history.append(now)

        newly_suspended = False
        if len(history) >= VIOLATION_THRESHOLD and key not in _suspended:
            _suspended.add(key)
            newly_suspended = True
            reason = f"{len(history)} policy violations in {WINDOW_SECONDS}s (threshold={VIOLATION_THRESHOLD})"
            _suspension_meta[key] = {"reason": reason, "suspended_at": now, "tier": "soft_pause"}

        if newly_suspended:
            print(
                f"[circuit-breaker] WEBHOOK: tenant={tenant_id} session={session_id} suspended after "
                f"{len(history)} violations in {WINDOW_SECONDS}s (threshold={VIOLATION_THRESHOLD})",
                flush=True,
            )
            threading.Thread(
                target=_send_webhook,
                args=(tenant_id, session_id, "soft_pause", reason, "suspended"),
                daemon=True,
            ).start()

        return {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "violations_in_window": len(history),
            "suspended": key in _suspended,
        }


def record_activity(tenant_id: str, session_id: str) -> dict:
    limit = _current_rate_limit(tenant_id)
    key = (tenant_id, session_id)
    with _lock:
        now = time.time()
        history = _activity.setdefault(key, [])
        history[:] = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]

        rate_limited = len(history) >= limit
        if not rate_limited:
            history.append(now)

        return {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "count_in_window": len(history),
            "limit": limit,
            "rate_limited": rate_limited,
        }


def suspend_directly(tenant_id: str, session_id: str, reason: str, tier: str = "soft_pause") -> dict:
    """Immediate suspend, bypassing the violation counter — for callers that
    have already decided a session is dangerous (Sprint 3: the anomaly
    detector) rather than counting up to a threshold. tier defaults to
    "soft_pause" (proposal §3.2 Layer 5's first level) — hard_suspend() and
    emergency_kill() below call this internally for the shared
    suspend-everything effect, then layer their own extra behavior on top."""
    key = (tenant_id, session_id)
    with _lock:
        already_suspended = key in _suspended
        _suspended.add(key)
        if not already_suspended:
            _suspension_meta[key] = {"reason": reason, "suspended_at": time.time(), "tier": tier}

        if not already_suspended:
            print(
                f"[circuit-breaker] WEBHOOK: tenant={tenant_id} session={session_id} suspended directly "
                f"(tier={tier}, reason={reason})",
                flush=True,
            )
            threading.Thread(
                target=_send_webhook,
                args=(tenant_id, session_id, tier, reason, "suspended"),
                daemon=True,
            ).start()

        return {"tenant_id": tenant_id, "session_id": session_id, "suspended": True, "reason": reason, "tier": tier}


def register_container(tenant_id: str, session_id: str, container_id: str) -> dict:
    """An agent runtime opts in to being killable by reporting its own
    Docker container id (see packages/sdk/aegis_sdk's register_runtime()).
    Nothing is registered by default — emergency_kill() degrades honestly
    if this was never called for a session."""
    key = (tenant_id, session_id)
    with _lock:
        _container_registry[key] = container_id
        return {"tenant_id": tenant_id, "session_id": session_id, "container_id": container_id, "registered": True}


def _fetch_audit_trail(tenant_id: str, session_id: str, limit: int = 100) -> list[dict]:
    """Best-effort fetch of a session's real recent audit trail from
    packages/audit-logger, for the forensic snapshot below — an
    unreachable audit-logger degrades to an empty trail rather than
    failing the suspend/kill itself."""
    try:
        req = urllib.request.Request(
            f"{AUDIT_URL}/events?tenant_id={tenant_id}&session_id={session_id}&limit={limit}"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError):
        return []


def _capture_snapshot(tenant_id: str, session_id: str, reason: str, tier: str) -> dict:
    """Real forensic snapshot (proposal §3.2 Layer 5: "a snapshot of the
    agent's state is captured for forensics") — the session's actual
    audit trail at the moment of suspension, not a placeholder. Stored
    in-memory; exposed via GET /snapshot/<tenant>/<session>."""
    key = (tenant_id, session_id)
    snapshot = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "tier": tier,
        "reason": reason,
        "captured_at": time.time(),
        "audit_trail": _fetch_audit_trail(tenant_id, session_id),
    }
    with _lock:
        _snapshots[key] = snapshot
    return snapshot


def get_snapshot(tenant_id: str, session_id: str) -> dict:
    key = (tenant_id, session_id)
    with _lock:
        snapshot = _snapshots.get(key)
    if snapshot is None:
        return {"tenant_id": tenant_id, "session_id": session_id, "error": "no snapshot captured for this session"}
    return snapshot


def hard_suspend(tenant_id: str, session_id: str, reason: str) -> dict:
    """Proposal §3.2 Layer 5, second level: "all agent processes are
    frozen, network access is revoked, and a snapshot of the agent's
    state is captured for forensics." The freeze/network-revocation effect
    is the same denial-everything mechanism soft_pause already provides
    throughout this layer (see terminate()'s docstring for why network
    denial is how this MVP models "revoked" everywhere) — what's new here
    is the real forensic snapshot."""
    result = suspend_directly(tenant_id, session_id, reason, tier="hard_suspend")
    snapshot = _capture_snapshot(tenant_id, session_id, reason, tier="hard_suspend")
    result["snapshot_captured"] = True
    result["actions_in_snapshot"] = len(snapshot["audit_trail"])
    return result


def _kill_container(container_id: str) -> dict:
    """Best-effort real Docker container kill via the Docker Engine API
    (packages/circuit-breaker's mounted /var/run/docker.sock — see
    demo/docker-compose.yml and this package's README for why that's a
    meaningful privilege grant, demo-only). Imported lazily so the rest of
    this service works even if the `docker` package or socket isn't
    available — only emergency_kill() needs either."""
    try:
        import docker

        client = docker.from_env()
        container = client.containers.get(container_id)
        container.kill()
        return {"attempted": True, "success": True}
    except Exception as exc:  # noqa: BLE001 — genuinely any failure here should degrade, not crash the request
        return {"attempted": True, "success": False, "error": str(exc)}


def emergency_kill(tenant_id: str, session_id: str, reason: str) -> dict:
    """Proposal §3.2 Layer 5, third level: "the agent's entire runtime
    environment is destroyed (container killed, VM terminated), with all
    state preserved in the audit log." Does everything hard_suspend does
    (suspend + forensic snapshot preserved before any kill attempt, so the
    audit trail survives the container regardless of kill outcome), plus
    attempts a real kill of the registered container, if any. Reports the
    kill outcome honestly — "suspended, kill not possible" is a valid,
    visible result, never silently treated as a successful kill."""
    key = (tenant_id, session_id)
    result = hard_suspend(tenant_id, session_id, reason)
    result["tier"] = "emergency_kill"

    with _lock:
        container_id = _container_registry.get(key)

    if container_id is None:
        result["kill"] = {"attempted": False, "success": False, "error": "no container registered for this session"}
    else:
        result["kill"] = _kill_container(container_id)

    print(
        f"[circuit-breaker] WEBHOOK: tenant={tenant_id} session={session_id} emergency-kill "
        f"container={container_id} result={result['kill']}",
        flush=True,
    )
    threading.Thread(
        target=_send_webhook,
        args=(tenant_id, session_id, "emergency_kill", f"{reason} (kill: {result['kill']})", "emergency-kill"),
        daemon=True,
    ).start()
    return result


def terminate(tenant_id: str, session_id: str, reason: str) -> dict:
    """Permanent denial (proposal §3.2 Layer 5, human-in-the-loop resume:
    "terminate the agent permanently"). Unlike suspend, resume() refuses to
    clear this — a terminated session stays denied until an operator
    intervenes directly (there's deliberately no /unterminate endpoint;
    this MVP doesn't model "undo a termination")."""
    key = (tenant_id, session_id)
    with _lock:
        _suspended.add(key)
        _terminated.add(key)
        _suspension_meta[key] = {"reason": reason, "suspended_at": time.time(), "tier": "terminated"}
        print(
            f"[circuit-breaker] WEBHOOK: tenant={tenant_id} session={session_id} terminated permanently ({reason})",
            flush=True,
        )
        threading.Thread(
            target=_send_webhook,
            args=(tenant_id, session_id, "terminated", reason, "terminated"),
            daemon=True,
        ).start()
        return {"tenant_id": tenant_id, "session_id": session_id, "terminated": True, "reason": reason}


def get_status(tenant_id: str, session_id: str) -> dict:
    key = (tenant_id, session_id)
    with _lock:
        return {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "violations_in_window": len(_violations.get(key, [])),
            "suspended": key in _suspended,
            "terminated": key in _terminated,
        }


def list_suspended(tenant_id: str | None = None) -> list[dict]:
    """Every currently-suspended (tenant, session) with why and when — the
    queue a human operator reviews (proposal §3.2 Layer 5: "a human operator
    reviews the flagged actions, the anomaly report, and the full audit
    trail"). With no tenant_id filter this is a cross-tenant operator view
    (circuit-breaker is trusted infra); callers that must not leak across
    tenants (e.g. packages/dashboard) always pass tenant_id."""
    with _lock:
        keys = sorted(_suspended)
        if tenant_id is not None:
            keys = [k for k in keys if k[0] == tenant_id]
        return [
            {
                "tenant_id": tid,
                "session_id": sid,
                "reason": _suspension_meta.get((tid, sid), {}).get("reason", "unknown"),
                "suspended_at": _suspension_meta.get((tid, sid), {}).get("suspended_at"),
                "tier": _suspension_meta.get((tid, sid), {}).get("tier", "unknown"),
                "terminated": (tid, sid) in _terminated,
            }
            for tid, sid in keys
        ]


def resume(tenant_id: str, session_id: str) -> dict:
    key = (tenant_id, session_id)
    with _lock:
        if key in _terminated:
            return {
                "tenant_id": tenant_id,
                "session_id": session_id,
                "suspended": True,
                "error": "session was permanently terminated and cannot be resumed",
            }
        was_suspended = key in _suspended
        _suspended.discard(key)
        _violations.pop(key, None)
        _activity.pop(key, None)
        _suspension_meta.pop(key, None)
        return {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "suspended": False,
            "was_suspended": was_suspended,
        }


class Handler(BaseHTTPRequestHandler):
    # BaseHTTPRequestHandler defaults to HTTP/1.0, which closes the TCP
    # connection after every single response regardless of what the client
    # wants — confirmed via load testing (demo/load_test.py,
    # demo/load_test_results.md) to be the actual bottleneck under
    # concurrent load, not lock contention as originally suspected (CPU
    # stayed near-idle during multi-second latencies). Every response here
    # already sends a correct Content-Length, so HTTP/1.1 keep-alive is
    # safe with no other changes.
    protocol_version = "HTTP/1.1"

    def _send_json(self, status_code, body):
        data = json.dumps(body).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "violation":
            self._send_json(200, record_violation(parts[1], parts[2]))
        elif len(parts) == 3 and parts[0] == "activity":
            self._send_json(200, record_activity(parts[1], parts[2]))
        elif len(parts) == 3 and parts[0] == "resume":
            self._send_json(200, resume(parts[1], parts[2]))
        elif len(parts) == 3 and parts[0] == "suspend":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            reason = body.get("reason", "unspecified")
            self._send_json(200, suspend_directly(parts[1], parts[2], reason))
        elif len(parts) == 3 and parts[0] == "terminate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            reason = body.get("reason", "unspecified")
            self._send_json(200, terminate(parts[1], parts[2], reason))
        elif len(parts) == 3 and parts[0] == "hard-suspend":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            reason = body.get("reason", "unspecified")
            self._send_json(200, hard_suspend(parts[1], parts[2], reason))
        elif len(parts) == 3 and parts[0] == "emergency-kill":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            reason = body.get("reason", "unspecified")
            self._send_json(200, emergency_kill(parts[1], parts[2], reason))
        elif len(parts) == 3 and parts[0] == "register":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            container_id = body.get("container_id")
            if not container_id:
                self._send_json(400, {"error": "container_id is required"})
                return
            self._send_json(200, register_container(parts[1], parts[2], container_id))
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "status":
            self._send_json(200, get_status(parts[1], parts[2]))
        elif len(parts) == 3 and parts[0] == "snapshot":
            self._send_json(200, get_snapshot(parts[1], parts[2]))
        elif len(parts) == 1 and parts[0] == "suspended":
            qs = parse_qs(parsed.query)
            tenant_id = qs.get("tenant_id", [None])[0]
            self._send_json(200, list_suspended(tenant_id))
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(
        f"AEGIS circuit-breaker listening on {host}:{port} "
        f"(violation threshold={VIOLATION_THRESHOLD}/{WINDOW_SECONDS}s, "
        f"rate limit default={DEFAULT_RATE_LIMIT}/{RATE_LIMIT_WINDOW_SECONDS}s from {POLICY_ENGINE_URL})"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
