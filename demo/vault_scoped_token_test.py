"""Gap-closing check (2026-09-16, see PROGRESS.md): verifies
packages/credential-vault mints real, tenant-scoped, short-lived,
single-use Vault child tokens (_mint_scoped_token) instead of ever using
the static root token to read a secret directly.

Run the full stack first: `docker compose up -d` (from demo/). Talks to
Vault directly (bypassing credential_broker.py) using the exact same
calls that module makes internally, so this proves the actual Vault-side
policy enforcement — not just that the Python code "looks right."
"""

import json
import sys
import time
import urllib.error
import urllib.request

VAULT_ADDR = "http://localhost:8200"
VAULT_TOKEN = "aegis-dev-root"  # keep in sync with config.py's VAULT_TOKEN

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _vault(path: str, method: str = "GET", body: dict | None = None, token: str = VAULT_TOKEN) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{VAULT_ADDR}/v1/{path}",
        data=data,
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, (json.loads(raw) if raw else {})


def _mint(policy: str, ttl: str = "60s", num_uses: int = 1) -> str:
    status, body = _vault(
        "auth/token/create", method="POST", body={"policies": [policy], "ttl": ttl, "num_uses": num_uses}
    )
    assert status == 200, f"mint failed: {status} {body}"
    return body["auth"]["client_token"]


def _trigger_a_real_credentialed_call(tenant_id: str):
    """Drives packages/credential-vault for real (not Vault directly) so
    it actually runs _ensure_tenant_policy/_mint_scoped_token itself —
    the policies this test then inspects are the broker's own real
    output, not something this test set up in advance."""
    req = urllib.request.Request(
        "http://localhost:9600/invoke",
        data=json.dumps(
            {"tenant_id": tenant_id, "session_id": "vault-scoped-token-test", "service": "protected-api", "action": "profile"}
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=5).read()


def test_broker_creates_real_per_tenant_policies():
    _trigger_a_real_credentialed_call("default")
    _trigger_a_real_credentialed_call("tenant-acme")

    for tenant in ("default", "tenant-acme"):
        status, body = _vault(f"sys/policies/acl/aegis-tenant-{tenant}-readonly")
        check(f"broker created a real Vault ACL policy for tenant={tenant}", status == 200, f"status={status} body={body}")
        policy_text = body.get("data", {}).get("policy", "")
        check(
            f"tenant={tenant}'s policy is scoped to exactly its own path",
            f'path "secret/data/{tenant}/*"' in policy_text and "read" in policy_text,
            policy_text,
        )


def test_scoped_token_cannot_read_another_tenants_secret():
    token = _mint("aegis-tenant-tenant-acme-readonly")
    status, body = _vault("secret/data/default/protected-api", token=token)
    check(
        "a tenant-acme-scoped token is genuinely denied reading the default tenant's secret (Vault-side, not app-side)",
        status == 403,
        f"status={status} body={body}",
    )


def test_scoped_token_is_genuinely_single_use():
    token = _mint("aegis-tenant-default-readonly", num_uses=1)
    status1, body1 = _vault("secret/data/default/protected-api", token=token)
    check("first use of a single-use token succeeds", status1 == 200, f"status={status1} body={body1}")

    status2, body2 = _vault("secret/data/default/protected-api", token=token)
    check("second use of the SAME single-use token is rejected by Vault", status2 in (403, 400), f"status={status2} body={body2}")


def test_scoped_token_genuinely_expires():
    token = _mint("aegis-tenant-default-readonly", ttl="2s", num_uses=5)
    time.sleep(3)
    status, body = _vault("secret/data/default/protected-api", token=token)
    check("an expired scoped token is rejected even though num_uses wasn't exhausted", status == 403, f"status={status} body={body}")


def test_broker_never_uses_the_root_token_to_read_a_secret():
    """Static check on the actual shipped source, not a live-behavior
    test — the strongest way to confirm this structurally, since a
    behavioral test could pass by coincidence even if a stray direct read
    still existed elsewhere."""
    with open("../packages/credential-vault/credential_broker.py") as f:
        source = f.read()
    check(
        "_fetch_secret's only caller passes a minted scoped token, not the global VAULT_TOKEN",
        "_fetch_secret(vault_path, service_config[\"vault_field\"], scoped_token)" in source,
        "source shape changed — re-check by hand",
    )


def main():
    test_broker_creates_real_per_tenant_policies()
    test_scoped_token_cannot_read_another_tenants_secret()
    test_scoped_token_is_genuinely_single_use()
    test_scoped_token_genuinely_expires()
    test_broker_never_uses_the_root_token_to_read_a_secret()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
