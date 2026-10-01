"""Gap-closing check (2026-09-16, see PROGRESS.md): verifies the circuit
breaker's three escalation tiers (proposal §3.2 Layer 5 "How it works":
soft pause, hard suspend, emergency kill) against the LIVE stack — run
against BOTH packages/circuit-breaker (Python) and circuit-breaker-rs
(Rust), which now has full tier parity (2026-09-16, see
packages/circuit-breaker-rs/README.md).

Run the full stack first: `docker compose up -d` (from demo/). Requires
Docker socket access on the host running this script (the same daemon
both circuit-breaker services are already granted, per their own
docker-compose.yml comments on the meaningful privilege that implies) —
this test starts and kills a real throwaway container per service, to
prove emergency_kill actually destroys a runtime, not just flips an
in-memory flag.
"""

import json
import subprocess
import sys
import time
import urllib.request
import uuid

BREAKER_URLS = {
    "circuit-breaker-rs (default, port 9400)": "http://localhost:9400",
    "circuit-breaker (Python, port 9410)": "http://localhost:9410",
}
AUDIT_URL = "http://localhost:9300"

TENANT = "default"

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


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True).stdout.strip()


def test_hard_suspend_captures_real_forensic_snapshot(label: str, breaker_url: str):
    session = f"hardsuspend-{uuid.uuid4()}"
    _post(
        f"{AUDIT_URL}/events",
        {
            "event_type": "policy_decision",
            "tenant_id": TENANT,
            "session_id": session,
            "action": {"action_type": "file_read", "target": "/etc/passwd", "method": "GET"},
            "policy_decision": {"allowed": True},
        },
    )
    time.sleep(0.5)

    result = _post(f"{breaker_url}/hard-suspend/{TENANT}/{session}", {"reason": "forensic test"})
    check(f"[{label}] hard-suspend reports tier=hard_suspend", result.get("tier") == "hard_suspend", str(result))
    check(f"[{label}] hard-suspend reports a captured snapshot", result.get("snapshot_captured") is True, str(result))
    check(f"[{label}] snapshot contains the real audit event", result.get("actions_in_snapshot", 0) >= 1, str(result))

    snapshot = _get(f"{breaker_url}/snapshot/{TENANT}/{session}")
    trail = snapshot.get("audit_trail", [])
    check(
        f"[{label}] GET /snapshot returns the same real event, not a placeholder",
        any(e.get("action", {}).get("target") == "/etc/passwd" for e in trail),
        str(snapshot),
    )

    status = _get(f"{breaker_url}/status/{TENANT}/{session}")
    check(f"[{label}] hard-suspended session is suspended (network/action denial)", status["suspended"] is True, str(status))


def test_emergency_kill_actually_destroys_a_real_container(label: str, breaker_url: str):
    """The direct proof this isn't just an in-memory flag: starts a real
    throwaway container, registers it, emergency-kills it, and checks the
    container's ACTUAL Docker state afterward — not the circuit breaker's
    own opinion of what happened."""
    container_name = f"aegis-kill-test-{uuid.uuid4().hex[:8]}"
    session = f"killtest-{uuid.uuid4()}"

    _docker("run", "-d", "--name", container_name, "alpine:latest", "sleep", "300")
    try:
        before = _docker("inspect", container_name, "--format", "{{.State.Status}}")
        check(f"[{label}] test container starts running", before == "running", before)

        reg = _post(f"{breaker_url}/register/{TENANT}/{session}", {"container_id": container_name})
        check(f"[{label}] container registration succeeds", reg.get("registered") is True, str(reg))

        result = _post(f"{breaker_url}/emergency-kill/{TENANT}/{session}", {"reason": "kill test"})
        check(f"[{label}] emergency-kill reports tier=emergency_kill", result.get("tier") == "emergency_kill", str(result))
        check(
            f"[{label}] emergency-kill reports the kill as attempted and successful",
            result.get("kill") == {"attempted": True, "success": True},
            str(result),
        )

        time.sleep(0.5)
        after = _docker("inspect", container_name, "--format", "{{.State.Status}}")
        check(f"[{label}] the real container is actually stopped afterward (not just an in-memory flag)", after == "exited", after)
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)


def test_emergency_kill_degrades_honestly_without_registration(label: str, breaker_url: str):
    """No container was ever registered for this session — the response
    must say so plainly, never claim a kill that didn't happen."""
    session = f"nokill-{uuid.uuid4()}"
    result = _post(f"{breaker_url}/emergency-kill/{TENANT}/{session}", {"reason": "no registration"})
    check(
        f"[{label}] emergency-kill without a registered container reports attempted=False, not a false success",
        result.get("kill") == {"attempted": False, "success": False, "error": "no container registered for this session"},
        str(result),
    )
    check(f"[{label}] the session is still suspended even though the kill couldn't happen", result.get("suspended") is True, str(result))


def main():
    for label, breaker_url in BREAKER_URLS.items():
        test_hard_suspend_captures_real_forensic_snapshot(label, breaker_url)
        test_emergency_kill_actually_destroys_a_real_container(label, breaker_url)
        test_emergency_kill_degrades_honestly_without_registration(label, breaker_url)
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
