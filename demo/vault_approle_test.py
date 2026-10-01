"""Gap-closing check (2026-09-16, see PROGRESS.md): verifies
packages/credential-vault mints its own OWN operating Vault token via a
real AppRole login instead of using the static VAULT_TOKEN (root) that
demo/docker-compose.yml's vault-init still bootstraps everything from.

Run the full stack first: `docker compose up -d` (from demo/). Execs into
the live credential-vault container to call its own internal functions
directly (_get_broker_token, _vault_request) — the strongest way to prove
this without adding a debug HTTP endpoint just for testing.
"""

import subprocess
import sys

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _exec_python(code: str) -> str:
    result = subprocess.run(
        ["docker", "exec", "demo-credential-vault-1", "python", "-c", code],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def test_broker_token_is_not_the_static_root_token():
    output = _exec_python(
        "import sys; sys.path.insert(0, '/app'); import credential_broker as cb; "
        "print(cb._get_broker_token())"
    )
    token = output.strip().splitlines()[-1]
    check(
        "the broker's operating token is not the literal root token string",
        token != "aegis-dev-root" and token.startswith("hvs."),
        f"got: {token!r}",
    )


def test_broker_token_cannot_read_a_secret_directly():
    """The actual security improvement over the old root token: this
    identity can mint scoped child tokens (via sudo on auth/token/create)
    but cannot read secret/data/* itself — confirmed against Vault's own
    403, not this test's opinion of what the policy says."""
    output = _exec_python(
        "import sys; sys.path.insert(0, '/app'); import credential_broker as cb\n"
        "token = cb._get_broker_token()\n"
        "try:\n"
        "    cb._vault_request('secret/data/default/protected-api', token)\n"
        "    print('READ_SUCCEEDED')\n"
        "except Exception as e:\n"
        "    print('READ_DENIED', e)\n"
    )
    check(
        "the broker's own token is genuinely denied reading a secret directly (Vault-side 403)",
        "READ_DENIED" in output and "403" in output,
        output,
    )


def test_broker_token_can_still_mint_scoped_tokens_for_its_own_purpose():
    """Confirms the narrower identity still does its actual job — this
    isn't just "everything is now denied," it's "denied exactly the
    thing it never needed.\""""
    output = _exec_python(
        "import sys; sys.path.insert(0, '/app'); import credential_broker as cb\n"
        "token = cb._mint_scoped_token('default')\n"
        "print('MINTED', token[:10])\n"
    )
    check("the broker can still mint tenant-scoped child tokens for its real job", "MINTED" in output, output)


def test_vault_init_container_exited_cleanly():
    result = subprocess.run(
        ["docker", "inspect", "demo-vault-init-1", "--format", "{{.State.ExitCode}}"],
        capture_output=True,
        text=True,
    )
    check("vault-init (the one place VAULT_TOKEN/root is still used) exited 0", result.stdout.strip() == "0", result.stdout)


def main():
    test_vault_init_container_exited_cleanly()
    test_broker_token_is_not_the_static_root_token()
    test_broker_token_cannot_read_a_secret_directly()
    test_broker_token_can_still_mint_scoped_tokens_for_its_own_purpose()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
