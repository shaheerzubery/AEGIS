"""Managed-dashboard-for-security-teams check (Phase 2, proposal §7.2,
added 2026-09-28 — see PROGRESS.md). Verifies packages/dashboard/api's
new role-based access control (operator vs. viewer) and per-operator
attribution against the live stack.

Run the full stack first: `docker compose up -d` (from demo/).
"""

import json
import sys
import time
import urllib.error
import urllib.request

DASHBOARD_URL = "http://localhost:9900"
BREAKER_URL = "http://localhost:9400"  # circuit-breaker-rs, the default
ORIGIN = "http://localhost:5173"  # matches config.py's DASHBOARD_ALLOWED_ORIGINS

OPERATOR_KEY = "default-demo-dashboard-key"
VIEWER_KEY = "default-demo-viewer-key"

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _request(method: str, path: str, key: str, body: dict | None = None, with_origin: bool = True) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {key}"}
    if with_origin:
        headers["Origin"] = ORIGIN
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{DASHBOARD_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_status_reports_role_operator_and_all_services():
    status, body = _request("GET", "/api/status", OPERATOR_KEY)
    check("status endpoint returns 200 for a valid key", status == 200, str(body))
    check("status reports role=operator for the operator key", body.get("role") == "operator", str(body))
    check("status reports the real operator name", body.get("operator") == "demo-operator", str(body))
    for service in ("opa", "audit_logger", "circuit_breaker", "anomaly_detector", "credential_vault", "content_guardrail"):
        check(f"status includes {service} (previously missing: credential_vault/content_guardrail)", service in body, str(body))


def test_viewer_can_read_but_not_write():
    status, body = _request("GET", "/api/status", VIEWER_KEY)
    check("viewer key authenticates and reports role=viewer", status == 200 and body.get("role") == "viewer", str(body))

    status, _ = _request("GET", "/api/breaker/suspended", VIEWER_KEY)
    check("viewer can read the approvals queue", status == 200, str(status))

    status, body = _request(
        "POST", "/api/check", VIEWER_KEY, {"session_id": "rbac-test", "action_type": "http_request", "target": "example.com"}
    )
    check("viewer is rejected with 403 pushing a policy check", status == 403, str(body))

    status, body = _request("POST", "/api/breaker/resume/nonexistent-session", VIEWER_KEY, {})
    check("viewer is rejected with 403 trying to resume a session", status == 403, str(body))

    status, body = _request("POST", "/api/breaker/deny/nonexistent-session", VIEWER_KEY, {})
    check("viewer is rejected with 403 trying to deny a session", status == 403, str(body))


def test_operator_can_write():
    status, body = _request(
        "POST", "/api/check", OPERATOR_KEY, {"session_id": "rbac-test-operator", "action_type": "http_request", "target": "example.com"}
    )
    check("operator can push a policy check", status == 200 and body.get("outcome") == "allowed", str(body))


def test_resume_attributes_to_the_real_operator_in_the_audit_log():
    session_id = "rbac-attribution-test"
    for _ in range(5):
        _request(
            "POST", "/api/check", OPERATOR_KEY,
            {"session_id": session_id, "action_type": "http_request", "target": "httpbin.org"},
        )

    status, body = _request("GET", f"/api/breaker/status/{session_id}", OPERATOR_KEY)
    check("5 denials suspend the session (existing violation threshold)", body.get("suspended") is True, str(body))

    status, body = _request("POST", f"/api/breaker/resume/{session_id}", OPERATOR_KEY, {})
    check("operator can resume the suspended session", status == 200 and body.get("suspended") is False, str(body))

    time.sleep(0.5)
    status, events = _request("GET", f"/api/events?limit=5&session_id={session_id}", OPERATOR_KEY)
    attribution_events = [e for e in events if e.get("event_type") == "dashboard_operator_action"]
    check("a dashboard_operator_action event was logged for the resume", len(attribution_events) >= 1, str(events))
    if attribution_events:
        ev = attribution_events[0]
        check("the logged event attributes the action to the real operator name", ev.get("operator") == "demo-operator", str(ev))
        check(
            "the logged reason names the real operator, not a generic string",
            ev.get("policy_decision", {}).get("reason") == "resume by demo-operator",
            str(ev),
        )


def test_missing_origin_still_rejected_for_state_changing_calls():
    """Confirms the pre-existing CSRF defense (Origin check) still runs
    before the new RBAC check, not replaced by it."""
    status, body = _request(
        "POST", "/api/check", OPERATOR_KEY,
        {"session_id": "rbac-test", "action_type": "http_request", "target": "example.com"},
        with_origin=False,
    )
    check("a state-changing request with no allowed Origin is still rejected (403)", status == 403, str(body))


def main():
    test_status_reports_role_operator_and_all_services()
    test_viewer_can_read_but_not_write()
    test_operator_can_write()
    test_resume_attributes_to_the_real_operator_in_the_audit_log()
    test_missing_origin_still_rejected_for_state_changing_calls()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
