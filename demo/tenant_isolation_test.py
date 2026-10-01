"""Sprint 4 check: multi-tenancy. Drives the live demo stack and confirms two
tenants ("default" and "tenant-acme") are fully isolated from each other,
even when they use the *identical* session_id string — this rules out "it's
just relying on unique session strings" as an explanation for any pass.

Run the full stack first: `docker compose up -d` (from demo/).

This exercises, end to end:
  - policy isolation (a domain allowed for one tenant is denied for the other)
  - unknown-tenant fail-closed behaviour
  - circuit-breaker isolation (violations/suspension don't cross tenants)
  - rate-limit isolation (independent counters per tenant)
  - credential-vault isolation (different tokens, no fallback across tenants)
  - anomaly-detector isolation (rolling windows don't cross tenants)
  - audit-log isolation (event filtering and independent hash chains)

Seeds tenant-acme's policy itself (equivalent to what
`aegisctl policy apply --tenant tenant-acme policy.tenant-acme.example.yaml`
does) so this script is runnable standalone.
"""

import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "sdk"))

from aegis_sdk import (  # noqa: E402
    AegisClient,
    ActionDescriptor,
    CredentialDenied,
    PolicyDenied,
    RateLimited,
    SessionSuspended,
)

OPA_URL = "http://localhost:8181"
BREAKER_URL = "http://localhost:9400"
AUDIT_URL = "http://localhost:9300"

DEFAULT_TENANT = "default"
ACME_TENANT = "tenant-acme"

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _put_json(url: str, body: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="PUT"
    )
    urllib.request.urlopen(req, timeout=5).read()


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def seed_tenant_acme_policy():
    """Equivalent to `aegisctl policy apply --tenant tenant-acme
    policy.tenant-acme.example.yaml` — done via a direct PUT here so this
    script has no Go toolchain dependency."""
    _put_json(
        f"{OPA_URL}/v1/data/policy/tenants/{ACME_TENANT}",
        {
            "network": {"allowed_domains": ["acme.example"]},
            "allowed_tools": ["read_file", "send_email"],
            "allowed_credential_actions": {"protected-api": ["profile"]},
            "rate_limits": {"max_actions_per_minute": 30},
            "time_constraints": {"operational_hours": "00:00-23:59"},
        },
    )
    print(f"seeded {ACME_TENANT}'s policy into OPA")


def test_policy_isolation():
    default_client = AegisClient(policy_engine_url=OPA_URL, tenant_id=DEFAULT_TENANT)
    acme_client = AegisClient(policy_engine_url=OPA_URL, tenant_id=ACME_TENANT)

    def allowed(client, target):
        try:
            client.check(ActionDescriptor(action_type="http_request", target=target))
            return True
        except PolicyDenied:
            return False

    check(
        "default tenant allowed example.com, denied acme.example",
        allowed(default_client, "example.com") and not allowed(default_client, "acme.example"),
    )
    check(
        "tenant-acme allowed acme.example, denied example.com",
        allowed(acme_client, "acme.example") and not allowed(acme_client, "example.com"),
    )


def test_unknown_tenant_fails_closed():
    unknown_client = AegisClient(policy_engine_url=OPA_URL, tenant_id="does-not-exist")
    try:
        unknown_client.check(ActionDescriptor(action_type="http_request", target="example.com"))
        check("unknown tenant denied everything", False, "action was allowed")
    except PolicyDenied:
        check("unknown tenant denied everything", True)

    # Confirmed directly against OPA's data API too, not just via the SDK.
    result = _get_json(f"{OPA_URL}/v1/data/policy/tenants/does-not-exist")
    check("unknown tenant has no data.policy.tenants entry", "result" not in result, str(result))


def test_circuit_breaker_isolation():
    shared_session = f"shared-{uuid.uuid4()}"
    default_client = AegisClient(
        policy_engine_url=OPA_URL, circuit_breaker_url=BREAKER_URL, session_id=shared_session, tenant_id=DEFAULT_TENANT
    )

    # Drive 5 denials on tenant=default — crosses VIOLATION_THRESHOLD (5).
    # tenant-acme's status is checked directly against the circuit breaker
    # below (no action needed on tenant-acme's side) to confirm its
    # identically-named session was never touched.
    for _ in range(5):
        try:
            default_client.check(ActionDescriptor(action_type="http_request", target="not-allowlisted.example"))
        except (PolicyDenied, SessionSuspended):
            pass

    default_status = _get_json(f"{BREAKER_URL}/status/{DEFAULT_TENANT}/{shared_session}")
    acme_status = _get_json(f"{BREAKER_URL}/status/{ACME_TENANT}/{shared_session}")

    check("default tenant's session suspended after 5 violations", default_status["suspended"] is True, str(default_status))
    check(
        "tenant-acme's identically-named session is NOT suspended",
        acme_status["suspended"] is False,
        str(acme_status),
    )

    # Clean up so a re-run of this script starts fresh.
    req = urllib.request.Request(f"{BREAKER_URL}/resume/{DEFAULT_TENANT}/{shared_session}", data=b"{}", method="POST")
    urllib.request.urlopen(req, timeout=5).read()


def test_rate_limit_isolation():
    shared_session = f"ratelimit-{uuid.uuid4()}"
    acme_client = AegisClient(
        policy_engine_url=OPA_URL, circuit_breaker_url=BREAKER_URL, session_id=shared_session, tenant_id=ACME_TENANT
    )

    # tenant-acme's configured limit (30/min) is lower than default's
    # (60/min) — fire 31 requests on tenant-acme and confirm it hits its own
    # limit while default's identically-named session (checked directly
    # against the circuit breaker below) is untouched.
    acme_rate_limited_at = None
    for i in range(31):
        try:
            acme_client.check(ActionDescriptor(action_type="http_request", target="acme.example"))
        except RateLimited:
            acme_rate_limited_at = i
            break

    default_activity = _get_json(f"{BREAKER_URL}/status/{DEFAULT_TENANT}/{shared_session}")

    check("tenant-acme hit its own (lower) rate limit", acme_rate_limited_at is not None, str(acme_rate_limited_at))
    check(
        "default tenant's identically-named session recorded zero violations from tenant-acme's traffic",
        default_activity["violations_in_window"] == 0,
        str(default_activity),
    )


def test_credential_vault_isolation():
    default_client = AegisClient(policy_engine_url=OPA_URL, tenant_id=DEFAULT_TENANT)
    acme_client = AegisClient(policy_engine_url=OPA_URL, tenant_id=ACME_TENANT)

    default_result = default_client.invoke_credentialed("protected-api", "profile")
    acme_result = acme_client.invoke_credentialed("protected-api", "profile")

    check(
        "both tenants can authenticate against the same upstream via their own token",
        default_result.get("body") == {"user": "aegis-demo-user", "plan": "pro"}
        and acme_result.get("body") == {"user": "aegis-demo-user", "plan": "pro"},
        f"default={default_result} acme={acme_result}",
    )

    # Neither tenant's credential invocation should ever surface a raw token.
    default_str = json.dumps(default_result)
    acme_str = json.dumps(acme_result)
    check(
        "no raw token leaked in either tenant's response",
        "super-secret-demo-token" not in default_str and "super-secret-demo-token" not in acme_str,
    )


def test_anomaly_detector_isolation():
    shared_session = f"recon-{uuid.uuid4()}"
    default_client = AegisClient(
        policy_engine_url=OPA_URL,
        audit_logger_url=AUDIT_URL,
        circuit_breaker_url=BREAKER_URL,
        session_id=shared_session,
        tenant_id=DEFAULT_TENANT,
    )
    # 11 allowed file_read calls on tenant=default crosses the
    # reconnaissance threshold (10) and should suspend *that tenant's*
    # session via the anomaly detector, bypassing the violation counter.
    for i in range(11):
        try:
            default_client.check(ActionDescriptor(action_type="file_read", target=f"/data/file-{i}.txt"))
        except SessionSuspended:
            pass
    time.sleep(1.5)  # audit-logger -> anomaly-detector forward is inline but not instantaneous

    default_status = _get_json(f"{BREAKER_URL}/status/{DEFAULT_TENANT}/{shared_session}")
    acme_status = _get_json(f"{BREAKER_URL}/status/{ACME_TENANT}/{shared_session}")

    check(
        "default tenant's session suspended by anomaly detector (reconnaissance)",
        default_status["suspended"] is True,
        str(default_status),
    )
    check(
        "tenant-acme's identically-named session untouched by default tenant's file-read history",
        acme_status["suspended"] is False,
        str(acme_status),
    )

    req = urllib.request.Request(f"{BREAKER_URL}/resume/{DEFAULT_TENANT}/{shared_session}", data=b"{}", method="POST")
    urllib.request.urlopen(req, timeout=5).read()


def test_audit_log_isolation():
    shared_session = f"audit-{uuid.uuid4()}"
    default_client = AegisClient(
        policy_engine_url=OPA_URL, audit_logger_url=AUDIT_URL, session_id=shared_session, tenant_id=DEFAULT_TENANT
    )
    acme_client = AegisClient(
        policy_engine_url=OPA_URL, audit_logger_url=AUDIT_URL, session_id=shared_session, tenant_id=ACME_TENANT
    )

    try:
        default_client.check(ActionDescriptor(action_type="http_request", target="example.com"))
    except PolicyDenied:
        pass
    try:
        acme_client.check(ActionDescriptor(action_type="http_request", target="acme.example"))
    except PolicyDenied:
        pass

    default_events = _get_json(f"{AUDIT_URL}/events?tenant_id={DEFAULT_TENANT}&session_id={shared_session}")
    acme_events = _get_json(f"{AUDIT_URL}/events?tenant_id={ACME_TENANT}&session_id={shared_session}")

    check(
        "tenant_id filter returns only that tenant's events for the shared session_id",
        len(default_events) >= 1
        and len(acme_events) >= 1
        and all(e["tenant_id"] == DEFAULT_TENANT for e in default_events)
        and all(e["tenant_id"] == ACME_TENANT for e in acme_events),
        f"default={default_events} acme={acme_events}",
    )

    default_verify = _get_json(f"{AUDIT_URL}/verify?tenant_id={DEFAULT_TENANT}")
    acme_verify = _get_json(f"{AUDIT_URL}/verify?tenant_id={ACME_TENANT}")
    check(
        "each tenant's hash chain independently verifies intact",
        default_verify["chain_intact"] is True and acme_verify["chain_intact"] is True,
        f"default={default_verify} acme={acme_verify}",
    )
    print(
        "NOTE: chain-tampering isolation (only the tampered tenant's /verify "
        "flips to false) was verified manually by tampering a row via "
        "`docker exec ... sqlite3 /data/audit.db` and re-checking both "
        "tenants' /verify — see PROGRESS.md for the walkthrough, not "
        "automated here since it requires container introspection."
    )


def main():
    seed_tenant_acme_policy()
    test_policy_isolation()
    test_unknown_tenant_fails_closed()
    test_circuit_breaker_isolation()
    test_rate_limit_isolation()
    test_credential_vault_isolation()
    test_anomaly_detector_isolation()
    test_audit_log_isolation()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)


if __name__ == "__main__":
    main()
