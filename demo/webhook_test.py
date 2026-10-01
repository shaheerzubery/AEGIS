"""Gap-closing check (2026-09-16, see PROGRESS.md): confirms circuit
breaker suspend/terminate events fire a REAL HTTP webhook, against both
packages/circuit-breaker (Python) and circuit-breaker-rs (Rust) — not just
the stdout print both used to have exclusively.

Run the full stack first: `docker compose up -d` (from demo/). Checks
demo/mock-webhook's received list before and after, and asserts the new
notification's actual fields (not just that the count went up).
"""

import json
import sys
import time
import urllib.request
import uuid

BREAKER_PY_URL = "http://localhost:9410"  # packages/circuit-breaker
BREAKER_RS_URL = "http://localhost:9400"  # circuit-breaker-rs (default)
WEBHOOK_RECEIVER_URL = "http://localhost:9850"

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


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _received_count() -> int:
    with urllib.request.urlopen(f"{WEBHOOK_RECEIVER_URL}/received", timeout=5) as resp:
        return json.loads(resp.read())["count"]


def _latest_notifications(n: int) -> list[dict]:
    with urllib.request.urlopen(f"{WEBHOOK_RECEIVER_URL}/received", timeout=5) as resp:
        return json.loads(resp.read())["notifications"][-n:]


def test_python_suspend_fires_real_webhook():
    before = _received_count()
    session = f"webhook-py-{uuid.uuid4()}"
    reason = f"webhook test {uuid.uuid4()}"
    _post(f"{BREAKER_PY_URL}/suspend/{TENANT}/{session}", {"reason": reason})
    time.sleep(0.3)
    after = _received_count()
    check("python suspend increases the webhook receiver's count by exactly 1", after == before + 1, f"before={before} after={after}")

    notification = _latest_notifications(1)[0]
    check("notification has the real session_id", notification.get("session_id") == session, str(notification))
    check("notification has the real reason", notification.get("reason") == reason, str(notification))
    check("notification tier is soft_pause", notification.get("tier") == "soft_pause", str(notification))
    check("notification includes a Slack-compatible 'text' field", isinstance(notification.get("text"), str) and session in notification["text"], str(notification))


def test_rust_suspend_fires_real_webhook():
    before = _received_count()
    session = f"webhook-rs-{uuid.uuid4()}"
    reason = f"webhook test {uuid.uuid4()}"
    _post(f"{BREAKER_RS_URL}/suspend/{TENANT}/{session}", {"reason": reason})
    time.sleep(0.3)
    after = _received_count()
    check("rust suspend increases the webhook receiver's count by exactly 1", after == before + 1, f"before={before} after={after}")

    notification = _latest_notifications(1)[0]
    check("notification has the real session_id", notification.get("session_id") == session, str(notification))
    check("notification has the real reason", notification.get("reason") == reason, str(notification))
    check("notification tier is soft_pause", notification.get("tier") == "soft_pause", str(notification))


def test_terminate_fires_real_webhook_with_terminated_tier():
    before = _received_count()
    session = f"webhook-terminate-{uuid.uuid4()}"
    _post(f"{BREAKER_PY_URL}/terminate/{TENANT}/{session}", {"reason": "webhook terminate test"})
    time.sleep(0.3)
    after = _received_count()
    check("terminate fires exactly 1 webhook", after == before + 1, f"before={before} after={after}")

    notification = _latest_notifications(1)[0]
    check("notification tier is terminated", notification.get("tier") == "terminated", str(notification))
    check("notification event is 'terminated'", notification.get("event") == "terminated", str(notification))


def main():
    test_python_suspend_fires_real_webhook()
    test_rust_suspend_fires_real_webhook()
    test_terminate_fires_real_webhook_with_terminated_tier()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
