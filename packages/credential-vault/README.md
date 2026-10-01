# AEGIS Credential Broker — Layer 2 (Credential vaulting)

The agent never directly holds, sees, or transmits credentials. It sends a
declarative request to this broker ("call protected-api's /profile action");
the broker checks policy, fetches the real secret from HashiCorp Vault,
performs the authenticated call itself, and returns only the result
(proposal §3.2 Layer 2).

## API

- `POST /invoke` — body `{"session_id": "...", "service": "protected-api", "action": "profile"}`.
  Returns `{"session_id", "service", "action", "result": {"status", "body"}}`
  on success — the credential itself never appears anywhere in the response.
  Returns 403 if policy denies the (service, action) pair, 400/502 on bad
  input or upstream failure.

## How it enforces policy

Delegates to the same OPA instance as `packages/policy-engine`, via a new
`credential_use` action type in `default.rego`. Adding a new allowed service
means adding it to both `SERVICES` here and `allowed_services` in the Rego
policy — deliberately two places, since "the broker knows how to reach it"
and "policy allows using it" are different concerns.

## Scoped, short-lived tokens (gap-closing work, 2026-09-16)

`VAULT_TOKEN` (the static dev-mode root token) is no longer used to read
secrets directly — it now only mints a fresh child token per request,
scoped to exactly the calling tenant's own secret path:

1. `_ensure_tenant_policy(tenant_id)` — idempotently creates a Vault ACL
   policy (`aegis-tenant-<tenant_id>-readonly`) granting read-only access
   to `secret/data/<tenant_id>/*` and nothing else. Cached in-memory after
   the first call per tenant so this isn't a Vault round trip on every
   request.
2. `_mint_scoped_token(tenant_id)` — `POST auth/token/create` with that
   one policy, `VAULT_SCOPED_TOKEN_TTL` (default `60s`), and
   `VAULT_SCOPED_TOKEN_NUM_USES` (default `1`).
3. That child token — not `VAULT_TOKEN` — is what actually reads the secret.

A token that leaks (a log line, a crash dump, an SSRF into this process)
can only read the one tenant's secrets it was scoped to, expires in ~60s,
and is rejected by Vault after its first use — bounding the blast radius
of a leak to roughly one request, rather than indefinite root access to
every tenant's secrets. At the time this was written, `VAULT_TOKEN`
(root) was still what minted those child tokens — narrowed in effect,
not eliminated. **Closed the same day** — see the next section.

## Replacing the root token itself with AppRole (gap-closing work, 2026-09-16)

`_ensure_tenant_policy`/`_mint_scoped_token` above no longer use
`VAULT_TOKEN` (root) at all. Instead:

1. `demo/docker-compose.yml`'s `vault-init` bootstraps an AppRole
   identity ONE TIME, using the root token — the same
   bootstrap-once-then-never-again pattern any real Vault deployment
   already uses to set up AppRole/Kubernetes-auth/etc.: enables the
   AppRole auth method, writes a policy (`aegis-credential-broker-admin`)
   granting exactly `update`+`sudo` on `auth/token/create` (the `sudo`
   capability is what lets a non-root caller mint a child token with
   policies it doesn't itself hold — found by testing, not assumed; see
   "Found by testing" below) and `create`/`update`/`read` on
   `sys/policies/acl/aegis-tenant-*` — nothing else, and specifically NOT
   `secret/data/*` read access. Creates the AppRole role, then writes the
   generated `role_id`/`secret_id` to a shared Docker volume
   (`vault-approle-data`) this service reads at startup.
2. `_get_broker_token()` logs in via that AppRole (`POST
   auth/approle/login`) to get this service's own operating token,
   refreshed via a fresh login at 50% of the granted lease (headroom for
   request latency, not racing expiry) rather than reused forever.
   `_privileged_vault_request` retries once with a forced fresh login on
   a `403`, covering out-of-band revocation.
3. `VAULT_TOKEN` (root) is now used in exactly one place in this entire
   repo: `vault-init`'s one-time bootstrap above. This service never
   sees it.

**Found by testing, not assumed**: the first version of the
`aegis-credential-broker-admin` policy granted only `capabilities =
["update"]` on `auth/token/create` — every credentialed call failed with
`{"errors":["child policies must be subset of parent"]}`. Vault enforces
that a *non-root* caller can only mint a child token whose policies are a
subset of its own, unless it also holds `sudo` on that path. Added
`"sudo"` to the policy; re-verified end-to-end afterward, not just
assumed fixed.

## Config

- `VAULT_ADDR` (default `http://vault:8200`)
- `VAULT_TOKEN` — bootstraps the AppRole identity above; not read by this
  service at all anymore (dev-mode root token in the demo stack; see
  `vault-init`'s own docker-compose.yml comment for the real-deployment
  equivalent)
- `VAULT_APPROLE_ROLE_ID_PATH`/`VAULT_APPROLE_SECRET_ID_PATH` (default
  `/vault-approle/role_id`/`/vault-approle/secret_id`) — where this
  service reads the credentials `vault-init` wrote
- `VAULT_SCOPED_TOKEN_TTL` (default `60s`), `VAULT_SCOPED_TOKEN_NUM_USES`
  (default `1`) — how long/how-many-times a per-request child token lives
- `AEGIS_POLICY_URL` (default `http://opa:8181`)
- `PROTECTED_API_URL` (default `http://protected-api:9500`)

## Verification

`demo/vault_scoped_token_test.py` talks to Vault directly (not through
this broker) with the exact same calls `_mint_scoped_token` makes, and
proves three things Vault itself enforces, not just this code's own
opinion of what it did: a tenant-acme-scoped token gets a real `403` from
Vault reading the default tenant's secret; a single-use token's second
use is rejected; an expired token is rejected even with unused uses left.
Also confirms the broker's own live traffic creates real, correctly-scoped
ACL policies in Vault (`sys/policies/acl/aegis-tenant-<id>-readonly`).
Measured overhead of minting a fresh token per call: ~8ms/request average
against the demo stack — see `PROGRESS.md`'s dated entry.

`demo/vault_approle_test.py` execs into the live container to confirm:
the broker's own operating token is a real `hvs.*` token, not the literal
root-token string; that same token gets a genuine Vault-side `403` trying
to read a secret directly (the actual security improvement); it can still
mint tenant-scoped child tokens for its real job (narrower, not broken);
and `vault-init` exited `0`.

## Known limitations (MVP)

- Only one demo service (`protected-api`) is wired up; adding a real one
  (GitHub, AWS, etc.) means adding it to the `SERVICES` dict.
- No credential rotation for the underlying secrets themselves (the scoped
  Vault *tokens* rotate every request; the secret *values* they read
  don't).
- The AppRole `secret_id` is written to disk once by `vault-init` and
  never rotated itself — a real deployment would rotate it periodically
  (Vault supports this natively) rather than treating it as permanent
  once issued. **Explicitly deprioritized for now, by direct request
  (2026-09-27) — not an oversight.** This is separate from the AppRole
  login mechanism itself (which does replace the root token for every
  privileged Vault call, and is fully built/verified — see above); only
  rotating the one credential that bootstraps it is on hold.
