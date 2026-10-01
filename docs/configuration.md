# Configuration: going from demo to real-world

**`config.py`, at the repo root, is the settings file.** It replaces what
used to be scattered hardcoded literals across `docker-compose.yml` and
five different Python files (and, briefly, a `demo/.env` — superseded by
this). Edit `config.py` directly for real-world values; there's no
separate copy-this-template step.

## How it reaches each container

`demo/docker-compose.yml` bind-mounts `config.py` read-only into each of
the services this repo builds and runs itself (`audit-logger`,
`circuit-breaker`, `anomaly-detector`, `credential-vault`, `dashboard-api`,
`protected-api`, `packages/proxy/dns-filter`) at `/app/config.py` — the
same pattern already used for OPA's policies
(`../packages/policy-engine/policies:/policies`). Each service imports it
directly: `from config import VIOLATION_THRESHOLD`, etc.

Because it's a **bind mount, not baked into the image at build time**,
editing a value and running `docker compose restart <service>` picks up
the change immediately — no rebuild needed, the same workflow this repo
had with environment variables.

## What is *not* driven by config.py, and why

Stated plainly, not implied away — three real seams, all documented
directly in `config.py`'s own module docstring too:

1. **`vault` (HashiCorp's own image) and `audit-db` (`postgres:16`) are
   third-party binaries, not Python** — they cannot import `config.py`.
   Their credentials live as literal `environment:` values in
   `docker-compose.yml`, and must be kept in sync with `config.py`'s
   `VAULT_TOKEN` and `PROTECTED_API_TOKEN_*` constants **by hand**. This
   is an unavoidable consequence of using off-the-shelf images, not a
   design gap.
2. **Each service's *published* port** (`docker-compose.yml`'s `ports:`
   host mapping, e.g. `"9400:9400"`) is a Compose-level orchestration
   concern `config.py` can't reach into from Python either. Keep it in
   sync with the matching `*_PORT` constant by hand — every port line in
   `docker-compose.yml` has a comment pointing at which constant.
3. **`packages/sdk/aegis_sdk` (`AegisClient`) deliberately does NOT read
   `config.py`.** It's meant to be embedded in an agent process that may
   not be one of this repo's own containers at all, so it keeps its own
   environment-variable fallback instead (`AEGIS_POLICY_URL` etc., used
   only when you don't pass the URL explicitly to its constructor). This
   is an intentional asymmetry: `config.py` for services *we* build and
   run, env vars for a library meant to run *anywhere*.
4. **`packages/dashboard`'s Vite frontend has its own separate one-line
   `.env`** (`VITE_AEGIS_DASHBOARD_API`) — Vite only reads `.env`-format
   files, not Python, full stop. Copy `packages/dashboard/.env.example` to
   `packages/dashboard/.env` for this one setting.
5. ~~The unwired `audit-db` Postgres.~~ Fixed — `AUDIT_STORAGE_BACKEND`
   below switches `audit-logger` onto it; SQLite stays the default.
6. **`dns-filter`'s own listen address**, as seen by Envoy's resolver
   config in `packages/proxy/envoy.yaml`, has to be a literal IP — a DNS
   resolver config can't itself depend on DNS to find its resolver. That
   IP (`172.30.0.53`) comes from a fixed-subnet override on
   `docker-compose.yml`'s implicit `default` network, not from `config.py`.
   `config.py`'s `DNS_FILTER_*` constants only control what `dns-filter`
   itself forwards *to* (its upstream resolver), not what address it
   *listens on*.
7. **`packages/circuit-breaker-rs`** (the Rust rewrite) isn't Python
   either — same category as vault/audit-db, settings come from literal
   `environment:` values in `docker-compose.yml` instead, kept in sync
   with `config.py`'s circuit-breaker constants by hand. It runs
   *alongside* the Python `circuit-breaker`, not instead of it — see
   PROGRESS.md for how to actually point other services at it.

## The host-vs-in-network URL nuance (unrelated to config.py, still true)

`config.py`'s internal service URLs (`POLICY_URL = "http://opa:8181"`,
etc.) are for **containers talking to each other inside the Compose
network** — that's why they use service names, not `localhost`.

Anything running on the **host** instead — `aegisctl`, the `demo/*.py`
scripts, an agent embedding `aegis_sdk` outside Docker — needs
`AEGIS_POLICY_URL` etc. set to `http://localhost:<port>` equivalents in its
*own* shell/process environment (see point 3 above: the SDK reads env vars
for exactly this reason, not `config.py`).

```bash
# Running aegisctl or a demo script from your host shell:
export AEGIS_POLICY_URL=http://localhost:8181
export AEGIS_CIRCUIT_BREAKER_URL=http://localhost:9400
export AEGIS_AUDIT_URL=http://localhost:9300
export AEGIS_CREDENTIAL_BROKER_URL=http://localhost:9600
```

## What each `config.py` section controls

- **Vault** — `VAULT_ADDR`/`VAULT_TOKEN`.
- **Demo credentials** — `PROTECTED_API_TOKEN_DEFAULT`/`_ACME`; also used
  by `demo/protected-api` directly and (see seam 1 above) must be kept in
  sync with `docker-compose.yml`'s `vault-init` entrypoint by hand.
- **Audit logger storage** — `AUDIT_DB_PATH` (SQLite file path, used when
  `AUDIT_STORAGE_BACKEND = "sqlite"`, the default). Set
  `AUDIT_STORAGE_BACKEND = "postgres"` to use the already-running
  `audit-db` container instead — `AUDIT_POSTGRES_HOST`/`_PORT`/`_USER`/
  `_PASSWORD`/`_DB` mirror `docker-compose.yml`'s `audit-db` service
  exactly (see seam 1 above: that's a third-party image, so those values
  must be kept in sync by hand). No data migration between backends —
  switching starts a fresh chain on whichever backend you switch to.
- **SIEM** — `SIEM_URL`; empty string disables forwarding.
- **Circuit breaker tuning** — violation threshold/window, rate-limit
  window/default/cache TTL.
- **Anomaly detector tuning** — the rolling window and all four detection
  rule thresholds, including the self-modification regex pattern.
- **Service ports** — `*_PORT` for all six services (see seam 2 above).
- **Internal service URLs** — see the host-vs-in-network nuance above.
- **Dashboard CSRF mitigation** — `DASHBOARD_ALLOWED_ORIGINS`, the allowlist
  of `Origin` header values dashboard-api will accept for any
  state-changing request (resume/deny/check/credential). Add your real
  deployed frontend's origin here when it's not `http://localhost:5173`
  (the Vite dev server default) — a mismatched or missing Origin gets a
  403 regardless of everything else being correct.
- **Dashboard authentication** — `DASHBOARD_API_KEYS`, a map of API key ->
  `{"tenant_id", "role", "operator"}` (role is `"operator"` or
  `"viewer"` — see `packages/dashboard/README.md`'s "Authentication and
  roles" for the managed-dashboard-for-security-teams work this added,
  2026-09-28). Every dashboard-api request needs
  `Authorization: Bearer <key>`; the server derives the tenant (and now
  role/operator identity) from the key and no longer accepts a
  client-supplied `tenant_id` anywhere (query param, path segment, or
  JSON body) — this is the actual fix for the "dashboard has no auth"
  gap, not just the CSRF mitigation above. Replace all demo keys before
  any real deployment, same as every other demo credential in this file.
  The dashboard frontend has an "API Key" field
  (replacing the old free-text "Tenant ID" one) that persists the key in
  the browser's `localStorage`.
- **DNS-rebinding fix** — `DNS_FILTER_UPSTREAM`/`DNS_FILTER_UPSTREAM_PORT`,
  the real resolver `packages/proxy/dns-filter` forwards to (Docker's own
  embedded DNS, `127.0.0.11`, by default — already recurses to the
  internet, so legitimate resolution is unaffected). See seam 6 above for
  why `dns-filter`'s own listen address isn't here.

## Adding a real credentialed service

Separate from `config.py`: `packages/credential-vault/services.json` is a
small JSON registry (kept as JSON rather than folded into `config.py` to
avoid coupling an unrelated, already-working mechanism). Add an entry
(`base_url`, `vault_path_template`, `vault_field`) and seed the real secret
at that Vault path for each tenant that should have access — a config +
data change, not a Python code change. `base_url` entries can reference
`${SOME_NAME:-default}`, which resolves against a real env var first, then
a matching `config.py` constant, then the inline default.

## Going from demo to real: a short checklist

1. Edit `config.py` directly — no template/copy step.
2. Replace `PROTECTED_API_TOKEN_DEFAULT`/`_ACME` (or remove `protected-api`
   entirely if you're not using that mock service) with real credentials
   seeded in your real Vault, and update `docker-compose.yml`'s
   `vault-init` entrypoint to match (seam 1).
3. Point `VAULT_ADDR`/`VAULT_TOKEN` at real Vault; remove the `vault`/
   `vault-init` services from `docker-compose.yml` once you do.
4. Set `SIEM_URL` to your real SIEM's ingest endpoint.
5. Add real entries to `packages/credential-vault/services.json` for every
   credentialed service beyond the demo `protected-api`.
6. Review the circuit-breaker/anomaly-detector tuning sections against your
   real traffic patterns — the shipped defaults are demo-scale guesses.
7. Copy `packages/dashboard/.env.example` → `.env` and point it at your
   real `dashboard-api` URL.
8. If any service will be embedded/run outside this Compose stack (a real
   agent using `aegis_sdk` directly, `aegisctl` from an ops workstation),
   set the matching `AEGIS_*_URL` environment variables in *that*
   process's own environment — see the host-vs-in-network nuance above.
