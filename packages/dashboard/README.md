# AEGIS Dashboard

React (Vite + TypeScript) frontend + a Python REST API backend (proposal
§4.2: "Dashboard and API — React frontend, REST/gRPC API"). Extended
2026-09-28 into the proposal's Phase 2 "managed dashboard for security
teams" (§7.2) — see "Managed dashboard for security teams" below.

## Structure

- `api/dashboard_api.py` — the only service that needs CORS enabled. It
  aggregates OPA, the audit logger, circuit breaker, anomaly detector,
  credential broker, and content-guardrail server-side, using `aegis_sdk`
  for policy checks and credential invocations — the dashboard exercises
  the exact same code path as any other agent, not a special admin bypass.
- `src/` — the React app: policy check, credential vaulting, human-in-the-loop
  approval queue, and audit log tabs.

## Authentication and roles

Every request needs `Authorization: Bearer <key>` (`config.py`'s
`DASHBOARD_API_KEYS`) — the tenant is derived server-side from the key;
no request shape anywhere accepts a client-supplied `tenant_id`.

Each key also carries a **role** and an **operator name**:

- `operator` — can do everything: push policy checks, invoke credentials,
  approve/deny suspended sessions.
- `viewer` — read-only: status, audit log, and the approvals queue are
  visible, but every state-changing endpoint (`/api/check`,
  `/api/credential`, `/api/breaker/resume`, `/api/breaker/deny`) is
  rejected with `403` before it reaches any downstream service. The React
  app also disables/hides the corresponding controls for a viewer key,
  so the restriction is visible in the UI, not just discoverable by
  clicking and getting an error.

Approving/denying a session now attributes the action to the real
operator name from the key — logged as a `dashboard_operator_action`
audit event (`packages/audit-logger`), not the old generic "denied by
operator via dashboard" string. `circuit-breaker`'s own `/resume` has no
reason field at all, so this dedicated event is the actual place a
security team's attribution trail lives.

## Run

```
docker compose up -d --build   # from demo/ — brings up dashboard-api along with everything else
cd packages/dashboard
npm install
npm run dev
```

Then open `http://localhost:5173`. `VITE_AEGIS_DASHBOARD_API` (default
`http://localhost:9900`) points the frontend at the backend.

## Managed dashboard for security teams (Phase 2, §7.2, 2026-09-28)

The proposal names this as a one-line go-to-market offering with no
further technical spec. Translated into what "a security TEAM, not one
admin" actually needs from this dashboard specifically:

- **RBAC** (above) — a team has people with different privilege levels;
  before this, any valid key could do everything for its tenant.
- **Per-operator attribution** (above) — a team needs to know *which*
  analyst took an action, not just that "a dashboard" did.
- **Complete status coverage** — `credential_vault` and
  `content_guardrail` were missing from the status check entirely (found
  while adding the above, not something the "team" framing itself
  required, but a real gap fixed in the same pass). Both previously had
  no `GET` route at all, so a probe against either fell through to
  `BaseHTTPRequestHandler`'s default `501` and would have been read as
  "down" regardless of real health — both now have a real `/health` route.

## Verified

Built (`npm run build`, `tsc -b` + `vite build`, zero type errors) and
exercised end-to-end against the live Docker stack, both at the API level
and with a headless Playwright browser: all six service-status
indicators green (including the two newly-added), an operator key can
push a policy check/invoke a credential/approve or deny a session, a
viewer key is rejected with a real `403` on every one of those and the
UI itself hides/disables the corresponding controls, and resuming a
session produces a real `dashboard_operator_action` audit event
attributing it to the actual operator name — confirmed by reading it
back from the live audit log, not assumed from the code. See
`demo/dashboard_rbac_test.py` (21/21) for the permanent regression
coverage.

## Known limitations (MVP)

- Polling, not a websocket — tabs refresh on demand (a button), not automatically.
- REST only; the proposal also mentions gRPC — not implemented.
- Static per-key roles, not a full user/session system with login — same
  "real but simple" MVP pattern this repo uses elsewhere (Vault's static
  dev token, the original per-tenant-only keys before this). Replace
  before any real deployment.
- No key rotation/expiry, and no per-tenant limit on how many
  operator/viewer keys exist.
