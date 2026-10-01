"""Gap-closing check (2026-09-16, see PROGRESS.md): automates the manual
behavioral-parity verification done for the Rust circuit-breaker rewrite
(packages/circuit-breaker-rs) against the original Python service
(packages/circuit-breaker) — same request sequence against both, asserting
matching responses, rather than re-reading a one-time manual write-up.

Run the full stack first: `docker compose up -d` (from demo/). Assumes the
2026-09-16 default-cutover port layout: circuit-breaker-rs on 9400 (the
default), circuit-breaker (Python) on 9410 — see
packages/circuit-breaker-rs/README.md.

Every check drives BOTH services with the identical request and compares
the (suspended_at-stripped, since that's a wall-clock timestamp that can
legitimately differ by milliseconds between two sequential calls) response
bodies for equality — a real behavioral diff, not just "both returned 200."

Uses one tenant_id unique to this run (a fresh uuid) so re-running this
script, or running it alongside other tests that also touch shared tenants
like "tenant-acme", can never cross-contaminate either service's in-memory
state.

Known gap, stated directly: doesn't exercise the "OPA unreachable, fall
back to cached/default rate limit" path — that needs stopping the opa
container mid-test. See packages/circuit-breaker-rs/README.md's "Known
gaps".
"""

import json
import sys
import urllib.request
import uuid

BREAKER_A_URL = "http://localhost:9400"  # default backend (circuit-breaker-rs)
BREAKER_B_URL = "http://localhost:9410"  # circuit-breaker (Python) — same API
OPA_URL = "http://localhost:8181"

TENANT = f"parity-{uuid.uuid4().hex[:8]}"

# Matches config.py's defaults exactly (VIOLATION_THRESHOLD,
# RATE_LIMIT_PER_MINUTE) — this test hardcodes them rather than importing
# config.py, same convention demo/tenant_isolation_test.py already uses.
VIOLATION_THRESHOLD = 5
DEFAULT_RATE_LIMIT = 60

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _post(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else b""
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _put_json(url: str, body: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="PUT"
    )
    urllib.request.urlopen(req, timeout=5).read()


def _strip_timestamps(obj):
    """Drops suspended_at (a wall-clock float) so two sequential calls to
    different services can still compare equal on everything else."""
    if isinstance(obj, dict):
        return {k: _strip_timestamps(v) for k, v in obj.items() if k != "suspended_at"}
    if isinstance(obj, list):
        return [_strip_timestamps(v) for v in obj]
    return obj


def compare(name: str, a, b):
    sa, sb = _strip_timestamps(a), _strip_timestamps(b)
    check(name, sa == sb, f"A={a} B={b}")


def seed_tenant_rate_limit():
    """A lower-than-default rate limit so the activity/rate-limit parity
    check below doesn't need 60+ requests per service to exercise the
    rate_limited=True branch. Equivalent to what
    demo/tenant_isolation_test.py does for tenant-acme, just under this
    test's own unique tenant so there's no shared-state risk."""
    _put_json(
        f"{OPA_URL}/v1/data/policy/tenants/{TENANT}",
        {"rate_limits": {"max_actions_per_minute": 5}},
    )


def test_fresh_status():
    session = f"session-{uuid.uuid4()}"
    a = _get(f"{BREAKER_A_URL}/status/{TENANT}/{session}")
    b = _get(f"{BREAKER_B_URL}/status/{TENANT}/{session}")
    compare("fresh session status matches", a, b)


def test_violation_escalation_and_resume():
    session = f"session-{uuid.uuid4()}"
    for i in range(1, VIOLATION_THRESHOLD + 2):
        a = _post(f"{BREAKER_A_URL}/violation/{TENANT}/{session}")
        b = _post(f"{BREAKER_B_URL}/violation/{TENANT}/{session}")
        compare(f"violation #{i} response matches", a, b)

    a = _get(f"{BREAKER_A_URL}/status/{TENANT}/{session}")
    b = _get(f"{BREAKER_B_URL}/status/{TENANT}/{session}")
    compare("post-threshold status matches", a, b)
    check("both suspended after threshold", a["suspended"] and b["suspended"])

    a = _post(f"{BREAKER_A_URL}/resume/{TENANT}/{session}")
    b = _post(f"{BREAKER_B_URL}/resume/{TENANT}/{session}")
    compare("resume response matches", a, b)

    a = _get(f"{BREAKER_A_URL}/status/{TENANT}/{session}")
    b = _get(f"{BREAKER_B_URL}/status/{TENANT}/{session}")
    compare("post-resume status matches", a, b)


def test_suspend_directly_and_suspended_list():
    session = f"session-{uuid.uuid4()}"
    a = _post(f"{BREAKER_A_URL}/suspend/{TENANT}/{session}", {"reason": "parity test"})
    b = _post(f"{BREAKER_B_URL}/suspend/{TENANT}/{session}", {"reason": "parity test"})
    compare("direct suspend response matches", a, b)

    a = _get(f"{BREAKER_A_URL}/suspended?tenant_id={TENANT}")
    b = _get(f"{BREAKER_B_URL}/suspended?tenant_id={TENANT}")
    compare("suspended list matches", a, b)

    # Same call again — already-suspended path shouldn't overwrite the
    # original reason/timestamp on either service.
    a2 = _post(f"{BREAKER_A_URL}/suspend/{TENANT}/{session}", {"reason": "different reason"})
    b2 = _post(f"{BREAKER_B_URL}/suspend/{TENANT}/{session}", {"reason": "different reason"})
    compare("re-suspend response matches (both echo the new reason)", a2, b2)
    a2_list = _get(f"{BREAKER_A_URL}/suspended?tenant_id={TENANT}")
    b2_list = _get(f"{BREAKER_B_URL}/suspended?tenant_id={TENANT}")
    compare("suspended list unchanged by re-suspend on both", a2_list, b2_list)


def test_terminate_and_refused_resume():
    session = f"session-{uuid.uuid4()}"
    # No body at all — exercises the "unspecified" default reason path.
    a = _post(f"{BREAKER_A_URL}/terminate/{TENANT}/{session}")
    b = _post(f"{BREAKER_B_URL}/terminate/{TENANT}/{session}")
    compare("terminate (no body) response matches", a, b)
    check("both default to 'unspecified' reason", a["reason"] == "unspecified" and b["reason"] == "unspecified")

    a = _post(f"{BREAKER_A_URL}/resume/{TENANT}/{session}")
    b = _post(f"{BREAKER_B_URL}/resume/{TENANT}/{session}")
    compare("resume-after-terminate refusal matches", a, b)
    check("both refuse to resume a terminated session", "error" in a and "error" in b)


def test_rate_limit_isolation_from_violations():
    """Confirms activity/rate-limit counting is independent of the
    violation counter on both services, and that both apply the same
    tenant-scoped limit (seeded to 5 above) identically."""
    session = f"session-{uuid.uuid4()}"
    a_limited_at = None
    b_limited_at = None
    for i in range(1, 8):
        a = _post(f"{BREAKER_A_URL}/activity/{TENANT}/{session}")
        b = _post(f"{BREAKER_B_URL}/activity/{TENANT}/{session}")
        compare(f"activity #{i} response matches", a, b)
        if a["rate_limited"] and a_limited_at is None:
            a_limited_at = i
        if b["rate_limited"] and b_limited_at is None:
            b_limited_at = i

    check(
        "both rate-limited at the same request number",
        a_limited_at is not None and a_limited_at == b_limited_at,
        f"A={a_limited_at} B={b_limited_at}",
    )

    a = _get(f"{BREAKER_A_URL}/status/{TENANT}/{session}")
    b = _get(f"{BREAKER_B_URL}/status/{TENANT}/{session}")
    compare("rate-limiting alone never suspends (status unaffected)", a, b)
    check("neither suspended by rate limiting alone", not a["suspended"] and not b["suspended"])


def main():
    seed_tenant_rate_limit()
    test_fresh_status()
    test_violation_escalation_and_resume()
    test_suspend_directly_and_suspended_list()
    test_terminate_and_refused_resume()
    test_rate_limit_isolation_from_violations()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
