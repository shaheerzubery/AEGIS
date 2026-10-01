"""AEGIS settings — the one file to edit to go from demo to real-world
values across the Python services this repo builds and runs itself
(circuit-breaker, audit-logger, anomaly-detector, credential-vault,
dashboard-api, demo/protected-api, packages/proxy/dns-filter,
packages/content-guardrail).

How this reaches each container: demo/docker-compose.yml bind-mounts this
file read-only into every one of those six services at /app/config.py (the
same pattern already used for OPA's policies —
../packages/policy-engine/policies:/policies). Because it's a bind mount,
not baked into the image at build time, editing a value here and running
`docker compose restart <service>` picks up the change immediately — no
image rebuild needed, same workflow this repo had with env vars.

Every default below matches this repo's own previous hardcoded/env-var
default exactly — importing this unedited reproduces prior behavior
exactly.

What this file does NOT and CAN'T configure, and why (see
docs/configuration.md for the full picture):
  - `vault` (HashiCorp's own image) and `audit-db` (postgres:16) are
    third-party binaries, not Python — they can't import this file. Their
    credentials live as literals in demo/docker-compose.yml's
    `environment:` blocks, and must be kept in sync with VAULT_TOKEN, the
    two PROTECTED_API_TOKEN_* constants, and the AUDIT_POSTGRES_* constants
    below by hand.
  - Each service's *published* port (docker-compose.yml's `ports:` host
    mapping) is a Compose-level concern this file can't reach into from
    Python either — keep those in sync with the *_PORT constants below by
    hand too.
  - packages/sdk/aegis_sdk (AegisClient) deliberately does NOT read this
    file — it's meant to be embedded in an agent process that may not be
    one of this repo's own containers at all, so it keeps its own
    environment-variable fallback instead. This is an intentional
    asymmetry, not an inconsistency.
  - packages/dashboard's Vite frontend has its own separate one-line
    `.env` (VITE_AEGIS_DASHBOARD_API) — Vite only reads `.env`-format
    files, not Python.
  - dns-filter's own *listen* address, as seen by Envoy's resolver config
    in packages/proxy/envoy.yaml, has to be a literal IP (a DNS resolver
    config can't itself depend on DNS to find its resolver — the classic
    chicken-and-egg problem) — that IP is assigned via a fixed-subnet
    Docker network in demo/docker-compose.yml, not from here.
"""

# ===================== Vault =====================
# Dev-mode Vault, bundled for the demo. Pointing at a REAL Vault instance
# is not just editing these two lines — see docs/configuration.md.
VAULT_ADDR = "http://vault:8200"
# Gap-closing work (2026-09-16, see PROGRESS.md): as of the AppRole work
# below, this is no longer used by ANY of this repo's own Python
# services at runtime at all — its only remaining job anywhere is
# demo/docker-compose.yml's vault-init bootstrapping the AppRole identity
# credential_broker.py actually uses (see VAULT_APPROLE_*_PATH below).
# That's the same one-time-root-bootstrap pattern a real Vault deployment
# already uses to set up AppRole/Kubernetes-auth/etc. Kept here (rather
# than deleted) because demo/vault_scoped_token_test.py and
# demo/docker-compose.yml's vault-init/vault-init environment still need
# it for exactly that one bootstrap step.
VAULT_TOKEN = "aegis-dev-root"  # keep in sync with demo/docker-compose.yml's vault/vault-init services

# Gap-closing work (2026-09-16, see PROGRESS.md): where credential_broker.py
# reads the AppRole role_id/secret_id vault-init generates and writes at
# every startup (Vault dev-mode is in-memory, so nothing to persist across
# restarts) — see demo/docker-compose.yml's vault-approle-data volume.
# Container paths, not demo-to-real-world values — a real deployment
# would source these from its own secrets manager, not this file.
VAULT_APPROLE_ROLE_ID_PATH = "/vault-approle/role_id"
VAULT_APPROLE_SECRET_ID_PATH = "/vault-approle/secret_id"

# How long a per-request scoped Vault token lives, and how many times it
# can be used, before credential_broker.py mints a fresh one. Short and
# single-use on purpose — a token that leaked from a log line or a crash
# dump is worthless almost immediately, and can't be replayed even once
# more than the original request used it for.
VAULT_SCOPED_TOKEN_TTL = "60s"
VAULT_SCOPED_TOKEN_NUM_USES = 1

# ===================== Demo credentials — replace before any real deployment =====================
# Seeded into Vault by vault-init, and accepted by the mock protected-api
# upstream. Two tokens because the multi-tenancy demo gives each tenant its
# own token for the "same" nominal service — see credential_broker.py.
# Kept in sync with demo/docker-compose.yml's vault-init entrypoint by hand
# (vault-init is a HashiCorp Vault image, not Python — see module docstring).
PROTECTED_API_TOKEN_DEFAULT = "super-secret-demo-token-default"
PROTECTED_API_TOKEN_ACME = "super-secret-demo-token-acme"


# ===================== Dashboard API authentication =====================
# Gap-closing work (2026-08-22, see PROGRESS.md): the dashboard API used to
# have no authentication at all — anyone reaching it could claim any
# tenant_id. Each key below authenticates as exactly the one tenant it
# maps to; dashboard_api.py derives the tenant from the presented key and
# no longer trusts any client-supplied tenant_id. Static per-tenant keys,
# not a full user/session system — same "real but simple" MVP pattern as
# Vault's static dev token. Replace both before any real deployment.
#
# Managed-dashboard-for-security-teams work (2026-09-28, see PROGRESS.md):
# each key now also carries a role and an operator name, not just a
# tenant. "operator" can do everything an operator could before (push
# policy checks, invoke credentials, approve/deny suspended sessions);
# "viewer" is read-only (status/audit/approvals-queue) — a security TEAM
# means more than one person with different privilege levels, not one
# admin key shared by everyone. "operator" is also the identity attached
# to every dashboard-initiated audit event from here on (see
# dashboard_api.py's _handle_resume/_handle_deny) — replacing the old
# generic "denied by operator via dashboard" with a real name.
DASHBOARD_API_KEYS = {
    "default-demo-dashboard-key": {"tenant_id": "default", "role": "operator", "operator": "demo-operator"},
    "default-demo-viewer-key": {"tenant_id": "default", "role": "viewer", "operator": "demo-viewer"},
    "tenant-acme-demo-dashboard-key": {"tenant_id": "tenant-acme", "role": "operator", "operator": "acme-operator"},
}

# ===================== Audit logger storage =====================
AUDIT_DB_PATH = "/data/audit.db"

# Gap-closing work (2026-08-22, see PROGRESS.md): "sqlite" (default, today's
# exact behavior, no other services need to be up) or "postgres" (uses the
# already-running-but-previously-unused audit-db container below). The
# proposal's own words for this (§8 Sprint 1): "SQLite for local dev,
# PostgreSQL for production."
AUDIT_STORAGE_BACKEND = "sqlite"

# Only used when AUDIT_STORAGE_BACKEND = "postgres". Mirrors audit-db's
# literal `environment:` values in demo/docker-compose.yml exactly —
# audit-db is postgres:16, a third-party image, can't read this file
# either, so these must be kept in sync by hand, same seam as Vault's
# VAULT_TOKEN and the PROTECTED_API_TOKEN_* constants above.
AUDIT_POSTGRES_HOST = "audit-db"
AUDIT_POSTGRES_PORT = 5432
AUDIT_POSTGRES_USER = "aegis"
AUDIT_POSTGRES_PASSWORD = "aegis"
AUDIT_POSTGRES_DB = "aegis_audit"

# ===================== SIEM =====================
# Empty string = SIEM forwarding disabled. Set to a real SIEM ingest URL to
# go to production; demo/mock-siem is demo-only either way.
SIEM_URL = "http://mock-siem:9800/ingest"

# ===================== Circuit breaker webhook notifications =====================
# Gap-closing work (2026-09-16, see PROGRESS.md): circuit-breaker used to
# only print "WEBHOOK: ..." to stdout on every suspend/terminate/kill —
# same "empty string = disabled" pattern as SIEM_URL above. Set to a real
# Slack Incoming Webhook URL to go to production (the payload always
# includes a "text" field, which is all a Slack webhook reads — see
# packages/circuit-breaker/circuit_breaker.py's _send_webhook); a generic
# JSON receiver like demo/mock-webhook also gets the full structured
# fields (tier, reason, tenant_id, session_id) if you're routing to
# PagerDuty or an internal alerting pipeline instead.
WEBHOOK_URL = "http://mock-webhook:9850/notify"

# ===================== Circuit breaker (Layer 5) backend =====================
# Gap-closing work (2026-09-16, see PROGRESS.md): circuit-breaker-rs (the
# Rust rewrite, packages/circuit-breaker-rs) is now the DEFAULT backend for
# internal callers (dashboard-api, anomaly-detector) — the proposal's own
# Sprint 2 rationale (production latency/concurrency model), now that
# behavioral parity and a real performance improvement are both verified
# (see PROGRESS.md's "Rust circuit-breaker rewrite" and "circuit-breaker-rs
# default cutover" entries). Set to "python" to point back at the original
# stdlib service instead — both are still wired up in
# demo/docker-compose.yml and kept behaviorally equivalent, so this is a
# one-line revert, not a re-architecture. Same "backend switch" philosophy
# as Gap #3's AUDIT_STORAGE_BACKEND.
CIRCUIT_BREAKER_BACKEND = "rust"  # "rust" (default) or "python"

# ===================== Circuit breaker (Layer 5) tuning =====================
VIOLATION_THRESHOLD = 5
VIOLATION_WINDOW_SECONDS = 60
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_PER_MINUTE = 60
RATE_LIMIT_CACHE_SECONDS = 30

# ===================== Anomaly detector (Layer 4) tuning =====================
# Rule-based MVP thresholds (proposal §4.7/§11) — tune per deployment's
# real traffic patterns rather than these demo defaults.
ANOMALY_WINDOW_SECONDS = 120
PRIVILEGE_ESCALATION_THRESHOLD = 3
LATERAL_MOVEMENT_THRESHOLD = 5
RECONNAISSANCE_THRESHOLD = 10
SELF_MODIFICATION_PATTERN = "opa|policy|vault|circuit-breaker|audit"

# ===================== Service ports =====================
# Each service's internal listen port. Keep these in sync with
# demo/docker-compose.yml's `ports:` mapping for the same service (Compose
# publishing a container's port is an orchestration-level concern this
# file can't reach into from Python — see module docstring).
AUDIT_LOGGER_PORT = 9300
CIRCUIT_BREAKER_PORT = 9400
ANOMALY_DETECTOR_PORT = 9700
CREDENTIAL_VAULT_PORT = 9600
DASHBOARD_API_PORT = 9900
PROTECTED_API_PORT = 9500
DNS_FILTER_PORT = 53
# Added directly, not from the proposal's own roadmap — see PLAN.md's
# "Also done, requested directly" section.
CONTENT_GUARDRAIL_PORT = 9200

# ===================== DNS-rebinding fix (Gap #2, see PROGRESS.md) =====================
# packages/proxy/dns-filter forwards egress-proxy DNS queries to this real
# upstream resolver, then rejects any answer containing a private/loopback/
# link-local address before Envoy ever gets to connect — see
# packages/proxy/dns-filter/dns_filter.py. Docker's own embedded DNS
# already recurses to the internet for public hostnames, so pointing at it
# preserves today's resolution behavior exactly for anything legitimate.
DNS_FILTER_UPSTREAM = "127.0.0.11"
DNS_FILTER_UPSTREAM_PORT = 53

# ===================== Internal service URLs =====================
# For CONTAINERS talking to each other inside the Compose network (hence
# hostnames like "opa", "circuit-breaker" rather than "localhost").
# Anything running on the HOST instead — aegisctl, demo/*.py scripts, an
# agent embedding aegis_sdk outside Docker — needs http://localhost:<port>
# equivalents in ITS OWN environment instead; see docs/configuration.md.
POLICY_URL = "http://opa:8181"
AUDIT_URL = f"http://audit-logger:{AUDIT_LOGGER_PORT}"
# Both services listen on the same internal container port
# (CIRCUIT_BREAKER_PORT) — only the hostname differs, per
# CIRCUIT_BREAKER_BACKEND above. See demo/docker-compose.yml for how each
# container's *published* (host-side) port maps to this internally.
CIRCUIT_BREAKER_URL = (
    f"http://circuit-breaker-rs:{CIRCUIT_BREAKER_PORT}"
    if CIRCUIT_BREAKER_BACKEND == "rust"
    else f"http://circuit-breaker:{CIRCUIT_BREAKER_PORT}"
)
ANOMALY_DETECTOR_URL = f"http://anomaly-detector:{ANOMALY_DETECTOR_PORT}"
CREDENTIAL_BROKER_URL = f"http://credential-vault:{CREDENTIAL_VAULT_PORT}"
PROTECTED_API_URL = f"http://protected-api:{PROTECTED_API_PORT}"
CONTENT_GUARDRAIL_URL = f"http://content-guardrail:{CONTENT_GUARDRAIL_PORT}"

# ===================== Dashboard CSRF mitigation =====================
# Security-review finding (internal, 2026-08-22 — see PROGRESS.md): the
# dashboard API had no CSRF protection at all on its state-changing
# endpoints (resume/deny/check/credential) — confirmed exploitable via a
# bare cross-origin HTML form POST, no auth or JS needed. CORS headers
# (Access-Control-Allow-Origin) don't defend against this: they only gate
# whether an attacker's JS can *read* a cross-origin response, not whether
# the browser *sends* the request in the first place — a blind form POST
# is sent regardless. The actual mitigation is a server-side check that
# the browser-supplied Origin header matches one of these, which
# dashboard_api.py now enforces on every state-changing request.
DASHBOARD_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # Vite dev server default
]
