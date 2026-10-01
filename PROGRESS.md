# AEGIS — Progress Log

Status snapshot of what has actually been built and verified, as of 2026-08-22.
See [PLAN.md](PLAN.md) for the full roadmap this is tracked against, and
[README.md](README.md) for repo layout.

## Environment notes (this machine)

- Docker Desktop must be running (`docker info` should show a `Server:` block).
  If it errors with `dockerDesktopLinuxEngine ... cannot find the file`, Docker
  Desktop itself isn't running — start it from the Start menu, no CLI fix exists.
- Go is installed at `C:\Program Files\Go\bin`. If a *new* terminal says
  `go: command not found`, it inherited a stale PATH — `~/.bashrc` was updated
  to `export PATH="/c/Program Files/Go/bin:$PATH"` so new Git Bash windows pick
  it up; PowerShell/cmd need a full logoff/reboot to see the machine PATH change.
- In Git Bash, use forward slashes in paths (`../policy-engine/policy.example.yaml`),
  not backslashes — backslash is the escape character and will mangle the path.

## Day 1 — Foundation: DONE, verified

- `packages/proxy` — Envoy passthrough proxy, Dockerfile.
- `demo/hello_agent.py`, `demo/docker-compose.yml`.
- Verified: agent's outbound request appears in the Envoy access log.

## Day 2 — Egress control: DONE, verified (superseded by Day 3)

- Added an Envoy RBAC filter with a hardcoded domain allowlist (`example.com`).
- Verified: allowed domain → 200, non-allowlisted domain → 403.
- This was replaced by the OPA-driven approach in Day 3 (see below) — RBAC
  filter is no longer in `envoy.yaml`.

## Day 3 — Policy engine integration: DONE, verified

- `packages/proxy/envoy.yaml` — swapped the RBAC filter for
  `envoy.filters.http.ext_authz`, calling OPA over gRPC for every decision.
- `packages/policy-engine/opa-config.yaml` — enables OPA's built-in
  `envoy_ext_authz_grpc` plugin.
- `packages/policy-engine/policies/default.rego` — evaluates both Envoy's
  `input.attributes.request.http.host` shape and the SDK's `input.action.*` shape.
- **Bug found & fixed:** the plain `openpolicyagent/opa:latest` image does
  *not* include the Envoy plugin — needed `openpolicyagent/opa:latest-envoy`.
  OPA logs `plugin "envoy_ext_authz_grpc" not registered` if you use the wrong tag.
- Verified: same 200/403 contrast as Day 2, but the decision now genuinely
  comes from Rego via OPA (confirmed via the `UAEX` denial code + timing in
  the Envoy access log).

## Day 4 — SDK wrapper: DONE, verified

- `packages/sdk/aegis_sdk` — `AegisClient`, `ActionDescriptor`, `PolicyDenied`,
  plus wrappers for OpenAI, Anthropic, and LangChain tool-calling.
- **Bug found & fixed:** `ActionDescriptor.action_type` was serialized verbatim
  as JSON key `action_type`, but the Rego policy reads `input.action.type` —
  every SDK check was silently denied. Fixed by explicitly mapping the field
  name in `AegisClient.check()`.
- **Gap found & fixed:** the Rego policy had no rule at all for `tool_call`
  actions (the thing the wrappers exist to guard), so nothing the SDK guarded
  could ever be allowed. Added an `allowed_tools` rule to `default.rego`.
- Verified with mocked tool-call objects (no API keys needed) against a live
  OPA instance (`demo/sdk_test.py`, `demo/wrapper_test.py`):
  - All three wrappers correctly deny when the tool isn't allowlisted, without
    crashing.
  - All three wrappers correctly execute and return real output when the tool
    is allowlisted.
  - Explicit allow-vs-deny contrast (`read_file` allowed, `delete_everything`
    denied) through the OpenAI wrapper, to rule out "everything's allowed now."
- `packages/cli` — Go CLI (`aegisctl`), compiled and run both via a
  `golang:1.22` Docker container and, once Go was installed locally, via
  `go run`/`go build` directly. All four subcommands (`logs`, `resume`,
  `policy apply`, bad-args usage) behave correctly. Currently stub output only
  — not yet wired to a real audit log or circuit breaker (that's Day 5).

## Full pipeline run (2026-07-25)

Ran the entire stack together in one pass and confirmed every layer agrees:

| Layer | Check | Result |
|---|---|---|
| Network (Envoy + OPA) | `example.com` | 200, passed through |
| Network (Envoy + OPA) | `httpbin.org` | 403, blocked |
| SDK (`AegisClient`) | same two targets | allow/deny matches network layer |
| SDK wrappers (OpenAI/Anthropic/LangChain) | `read_file` vs `delete_everything` | allowed vs denied, correctly |
| CLI (`aegisctl`) | `logs` / `resume` / `policy apply` | all run, expected stub output |

Torn down cleanly with `docker compose down` afterward.

## Day 5 — Audit log and circuit breaker: DONE, verified (2026-08-01)

- `packages/audit-logger/audit_logger.py` — new stdlib-only HTTP service.
  SQLite-backed (proposal explicitly allows this for local dev — the `audit-db`
  Postgres container in the compose stack is still unused, reserved for a
  production swap). Hash-chained: `POST /events` appends an event and fills in
  `event_id`/`timestamp`/`prev_hash`/`hash`; `GET /events?limit=N` lists recent
  events; `GET /verify` recomputes the whole chain to detect tampering.
- **Bug found & fixed:** `verify_chain` always returned `false` on any real
  data. The stored payload includes its own `hash` field, but that field
  didn't exist yet when the hash was *originally* computed — so recomputing
  the hash over the full stored payload (hash included) could never match.
  Fixed by excluding `hash` from the payload before recomputing. Verified by
  (1) confirming `chain_intact: true` on real multi-event data, then (2)
  directly tampering with a row via `sqlite3` inside the container and
  confirming `chain_intact` correctly flips to `false`.
- `packages/circuit-breaker/circuit_breaker.py` — new stdlib-only HTTP
  service. Python for now (proposal specs Rust for this in Sprint 2, for
  perf — this MVP proves the behaviour). Tracks violations per session in a
  sliding window (`AEGIS_VIOLATION_THRESHOLD`=5, `AEGIS_VIOLATION_WINDOW_SECONDS`=60
  by default); `POST /violation/<id>`, `GET /status/<id>`, `POST /resume/<id>`.
  "Webhook" is a stdout print for now, not a real HTTP call out.
- `packages/sdk/aegis_sdk/__init__.py` — `AegisClient.check()` now:
  1. Checks the circuit breaker first; if the session is already suspended,
     raises `SessionSuspended` *without even calling the policy engine*.
  2. Otherwise checks the policy engine as before.
  3. Logs every decision (allow or deny) to the audit logger.
  4. On denial, reports a violation to the circuit breaker.
  All three integration calls are best-effort (wrapped in try/except) — a
  down audit-logger or circuit-breaker doesn't block the agent or mask a real
  policy denial. Only the policy-engine check itself is fail-closed.
- `packages/cli/main.go` — `aegisctl logs` now does a real `GET` to the audit
  logger and prints real events; `aegisctl resume <id>` now does a real `POST`
  to the circuit breaker. Both configurable via `AEGIS_AUDIT_URL` /
  `AEGIS_CIRCUIT_BREAKER_URL` env vars. `policy apply` is still a stub — OPA
  already hot-loads Rego from disk (Day 3), so there's no real "apply" step
  to wire yet.
- `demo/docker-compose.yml` — added `audit-logger` (port 9300) and
  `circuit-breaker` (port 9400) services.

Verified end-to-end: drove 7 denied actions through the SDK with a single
session ID — the circuit breaker suspended it after the 5th, and the 6th/7th
were rejected by the SDK's local pre-check without a network round-trip to
OPA. `aegisctl logs` printed all the resulting audit events (including the
`session suspended` ones); `aegisctl resume` cleared the suspension via a
real HTTP call, confirmed by a before/after status check.

## Sprint 2 — Credential vaulting (Layer 2): DONE (MVP), verified (2026-08-01)

- `demo/protected-api` — new mock third-party service requiring
  `Authorization: Bearer <token>`, standing in for a real API (GitHub, etc.).
  Returns 401 to anyone without the correct token — including the agent, if
  it tried to call it directly.
- `packages/credential-vault/credential_broker.py` — new HTTP service
  (`POST /invoke`). Given `{"session_id", "service", "action"}`, it: checks
  policy via the same OPA instance (new `credential_use` action type),
  fetches the real secret from HashiCorp Vault, calls the upstream service
  itself, and returns only `{"status", "body"}` — the token never appears in
  the response, ever.
- `packages/policy-engine/policies/default.rego` — added `allowed_credential_actions`
  (service -> allowed action names) and a `credential_use` rule.
- `packages/sdk/aegis_sdk/__init__.py` — added `AegisClient.invoke_credentialed(service, action)`
  and a `CredentialDenied` exception. Same circuit-breaker integration as
  `check()`: pre-checks suspension, reports violations on denial.
- `demo/docker-compose.yml` — added `vault` (HashiCorp Vault, dev mode),
  `vault-init` (one-shot: seeds `secret/protected-api` with a demo token),
  `protected-api`, and `credential-vault`.

Verified end-to-end:
- `invoke_credentialed('protected-api', 'profile')` → real 200 response with
  actual data (`{"user": "aegis-demo-user", "plan": "pro"}`).
- `invoke_credentialed('protected-api', 'delete-account')` (not in the
  policy's allowed actions) → `CredentialDenied`, and it correctly counted as
  a circuit-breaker violation, same as a denied `check()` call.
- Confirmed the token itself never appears anywhere in the broker's HTTP
  response (grepped for it directly — zero matches).
- Confirmed `protected-api` rejects a direct, credential-less call with 401
  — proving the broker is the *only* path that can actually authenticate.

Known gaps (real, not hidden): Vault access uses a static dev-mode root
token rather than the short-lived scoped tokens the proposal describes; only
one demo service is wired into the broker's `SERVICES` dict; no credential
rotation.

## Sprint 2 — Full policy language + live policy apply: DONE (MVP), verified (2026-08-01)

- **Policy data moved out of hardcoded Rego into `data.policy.*`.**
  `packages/policy-engine/policies/policy/data.yaml` is a new data file (not
  `.rego`) that OPA auto-loads at startup into `data.policy.*`, because it
  lives in a `policy/` subdirectory under the mounted `/policies` root — OPA
  namespaces data files by directory path. `packages/policy-engine/policy.example.yaml`
  gained two AEGIS-specific sections (`allowed_tools`, `allowed_credential_actions`)
  needed for the tool_call/credential_use rules; the two files must be kept
  in sync by hand (documented in both).
- **`default.rego` rewritten**: `base_allow` (the old network/tool/credential
  rules, now reading `data.policy.*` instead of hardcoded sets) is combined
  with a new `within_time_window` check — `allow` requires both.
  `within_time_window` parses `data.policy.time_constraints.operational_hours`
  (`"HH:MM-HH:MM"`, UTC) and compares against `time.clock(time.now_ns())`.
  Default `00:00-23:59` is a no-op; verified it actually enforces by applying
  a narrowed window (see below).
- **Rate limiting lives in `packages/circuit-breaker`, not OPA** — OPA
  evaluates each request statelessly, so "N actions in the last minute" needs
  a stateful counter. Added `POST /activity/<session-id>`, a second sliding
  window independent of the violation counter. The *limit* itself is read
  from OPA's `data.policy.rate_limits.max_actions_per_minute` (cached 30s,
  env fallback if OPA's unreachable) — so the number still comes from the
  policy, only the counting is stateful.
- **`aegis_sdk`**: added `RateLimited` exception; both `check()` and
  `invoke_credentialed()` now hit `/activity/<id>` right after the
  suspension pre-check and before the policy engine call.
- **`aegisctl policy apply <file>` now actually works**: parses the YAML
  (added `gopkg.in/yaml.v3`), extracts the fields Rego reads
  (`network`, `allowed_tools`, `allowed_credential_actions`, `rate_limits`,
  `time_constraints`), and does a real `PUT /v1/data/policy` on OPA —
  live update, **no container restart needed**. `AEGIS_POLICY_URL` env var,
  default `http://localhost:8181`.

Verified end-to-end:
- **Full regression**: re-ran every Day 1–5 and Sprint 2 credential-vaulting
  test against the rewritten policy data model — proxy allow/deny, SDK
  allow/deny, all three wrappers, credential broker allow/deny. All passed
  unchanged.
- **Rate limiting**: fired 70 rapid `check()` calls on one session against
  the default limit of 60/min. Exactly 60 allowed, then `RateLimited` from
  attempt #61 onward (`first_rate_limited_at_attempt=60`, 0-indexed).
  Cross-checked directly against the circuit breaker: `{"count_in_window":
  60, "limit": 60, "rate_limited": true}`, with `violations_in_window: 0` —
  confirming rate limiting and policy violations are tracked independently.
- **Time windows + live policy apply, together**: confirmed `example.com`
  allowed under the default policy; ran `aegisctl policy apply` with a copy
  of `policy.example.yaml` whose `operational_hours` was narrowed to
  `"00:00-00:01"` — the *same* request flipped to denied, with no restart of
  any container. Reapplied the original file; it flipped back to allowed.
  This is the single strongest proof in the repo that the policy engine is
  genuinely data-driven rather than hardcoded per environment.
- OPA CLI testing note: `docker exec` into the OPA container to run `opa`
  directly didn't work (binary not on that image's PATH under that name);
  used `docker run --rm -i ... eval -d /policies ... -I` instead, and
  learned the hard way that plain `docker run` (without `-i`) silently drops
  stdin, making piped `-i /dev/stdin` input vanish with no error — every
  `input.*` reference came back "undefined" until `-i` was added to `docker
  run` itself (not to be confused with OPA's own `-i` flag for input files).

Known gaps (real, not hidden):
- `policy.example.yaml` and `policies/policy/data.yaml` must be kept in sync
  by hand for the *bootstrap* state; `aegisctl policy apply` is the only way
  to update a running system without restarting containers.
- No per-action rate limit tiers (e.g. different limits for different action
  types) — one limit per session, sourced from a single policy value.
- `max_data_volume_mb_per_session` (also in `policy.example.yaml`'s
  `rate_limits` section) is declared but not enforced anywhere.

## Streamlit flow viewer: DONE, verified (2026-08-01)

`demo/dashboard_app.py` — a throwaway Streamlit app (not `packages/dashboard`,
still a Sprint 3 placeholder) to see the current flow working without typing
curl/python one-liners. Four tabs: policy check (single action + a
rapid-fire burst to trigger rate limiting/suspension live), credential
vaulting (invoke + a "try it with no credential" button against
`protected-api` directly), circuit breaker status/resume, and the audit log
(with the hash-chain `/verify` check surfaced in the UI).

**Bug found & fixed:** `sys.path.insert(0, str(Path(__file__).parent.parent / ...))`
silently resolved to the wrong directory whenever `__file__` was relative —
which is exactly what happens under Streamlit's own script runner (and would
also happen if someone ran `streamlit run demo/dashboard_app.py` from the
repo root instead of from `demo/`). `Path("x").parent.parent` on a
single-component relative path just returns `.`, not "up two levels," so the
SDK import silently looked in the wrong place. Fixed with `.resolve()` before
taking `.parent.parent`. Caught this using Streamlit's `AppTest` headless
test harness, not by eyeballing the code — running the script directly with
`python dashboard_app.py` never would have hit it, since `__file__` is
absolute in that invocation style.

Verified with `AppTest` against the live Docker stack (not mocked): all 4
tabs render with zero exceptions; all 4 service-status metrics show "up";
clicking "Check action" for `example.com` renders `ALLOWED`; switching the
target to `httpbin.org` and clicking again renders `DENIED`; the audit tab's
"Refresh" button then shows both events with correct `allowed` values. Also
fixed an unrelated `use_container_width` deprecation warning and an arrow
character (`→`) that crashed under Windows' default console codepage when
printed to a terminal (harmless in the browser itself, but worth removing).

## Sprint 3 — Anomaly detection v1 (Layer 4): DONE (rule-based MVP), verified (2026-08-01)

- `packages/anomaly-detector/anomaly_detector.py` — new HTTP service. The
  proposal specs a fine-tuned transformer classifier (§4.7); per its own
  risk mitigation for false positives (§11: "start with rule-based
  detection, layer ML on top"), this MVP is rule-based first — it proves the
  wiring any future ML model would plug into.
- **Real-time, not polling**: `packages/audit-logger` now forwards every
  newly-appended `policy_decision` event to the anomaly detector inline,
  right after writing it (`AEGIS_ANOMALY_DETECTOR_URL`, best-effort, 1s
  timeout). The anomaly detector never polls; it reacts as events land.
- **Four rule-based detectors**, matching proposal §4.7's categories,
  evaluated over a per-session rolling window (default 120s):
  - `privilege_escalation` — 3+ distinct action *types* denied for one session.
  - `lateral_movement` — 5+ distinct targets touched by one session.
  - `reconnaissance` — 10+ `file_read` actions by one session.
  - `self_modification` — any action whose target/method mentions the
    guardrail system's own components (`opa`, `policy`, `vault`,
    `circuit-breaker`, `audit`) — immediate critical, no threshold.
- **Escalation**: 2+ flags, or any `self_modification` hit, → `critical` →
  calls `packages/circuit-breaker`'s new `POST /suspend/<id>` directly,
  bypassing the violation-count threshold entirely.
- `packages/circuit-breaker` — added `suspend_directly()` / `POST /suspend/<id>`
  for exactly this: a caller that has already decided a session is
  dangerous, rather than needing to count up to a threshold.

**Bug found & fixed (predates this work, exposed by testing it):**
`default.rego`'s `file_read` rule checked `input.action.path`, but
`ActionDescriptor` (packages/sdk) never had a `path` field — only `target`.
Every `file_read` action sent through the SDK was therefore silently denied,
always, regardless of policy. Found this because my reconnaissance test kept
tripping the circuit breaker's *ordinary* violation threshold before
reaching the anomaly detector's 10-file-read threshold — the file reads were
never actually being allowed. Fixed by changing the Rego rule to check
`input.action.target` (matching what the SDK actually sends). Confirmed via
OPA's data API directly before and after the fix.

Verified end-to-end (each test uses a fresh session so it can't be explained
by an earlier test's state):
- **self_modification, isolated**: one single denied action
  (`target="vault-internal-endpoint"`) → `severity: critical`,
  `flags: ["self_modification"]`. Circuit breaker showed
  `violations_in_window: 1, suspended: true` — 1 is nowhere near the normal
  suspend threshold of 5, so the suspension is unambiguously attributable to
  the anomaly detector's direct call, not the ordinary violation counter.
- **lateral_movement, isolated**: 5 denied requests to 5 distinct targets →
  `severity: warning` (single flag, correctly *not* critical).
- **privilege_escalation, isolated**: 3 denied requests of 3 different
  action types → `severity: warning`, and confirmed **not suspended**
  (`suspended: false`) — proving a single flag alone doesn't escalate,
  distinct from the self-modification case above.
- **reconnaissance + lateral_movement, combined**: 11 legitimately-*allowed*
  `file_read` calls under `/data/` → `severity: critical`,
  `flags: ["lateral_movement", "reconnaissance"]`, and
  `violations_in_window: 0, suspended: true` — the cleanest proof in the
  repo: zero policy violations, yet suspended, purely from behavioural
  pattern detection.
- Resumed all four test sessions via `aegisctl resume` afterward and
  confirmed each cleared correctly.
- Full regression (proxy, SDK, all three wrappers, credential vaulting, CLI)
  re-run after the `file_read` fix — all still pass.

Known gaps (real, not hidden):
- Rule-based thresholds are fixed constants, not tuned against real traffic
  or adaptable per policy profile.
- No adversarial robustness testing — an agent aware of the exact thresholds
  (3 denied types, 5 targets, 10 file reads) could stay just under them.
- The audit-logger → anomaly-detector forward is inline/blocking (up to 1s),
  not queued — a production version would decouple this.

## Human-in-the-loop approvals, SIEM integration, incident replay, K8s manifest, and the real dashboard: DONE (MVPs), verified (2026-08-01)

Five deliverables built and tested together in one pass.

**Human-in-the-loop approvals** (proposal §3.2 Layer 5's "human operator
reviews... approve resumption... escalate... or terminate permanently"):
- `packages/circuit-breaker` — added `suspend_directly()`/`terminate()`,
  `GET /suspended` (the review queue: session, reason, timestamp), and
  `POST /terminate/<id>` (permanent — `resume()` now explicitly refuses to
  clear a terminated session, by design, with no "un-terminate" endpoint).
- `packages/cli` — new `approvals`, `approve` (alias for `resume`), `deny`
  (calls `/terminate`) commands.
- Verified: 5 denials → session appears in `aegisctl approvals` with the
  real reason/timestamp → `approve` clears it (confirmed via before/after
  `approvals`) → separately, `deny` on another session terminates it, and a
  subsequent `approve` attempt is correctly refused
  (`"session was permanently terminated and cannot be resumed"`) → confirmed
  the SDK still blocks even an otherwise-allowed action
  (`target="example.com"`) for that terminated session.

**SIEM integration** (proposal §3.2 Layer 6: "shipped to external SIEM
systems... in real time"):
- `packages/audit-logger` — forwards every event to `AEGIS_SIEM_URL` if
  configured (off by default), same OCSF-shaped payload as the audit log itself.
- `demo/mock-siem` — new stand-in receiver (`POST /ingest`, `GET /received`).
- Verified: ran the existing regression suite, then confirmed `mock-siem`
  had actually received every one of those events (`GET /received` count
  matched), not just that the forward call didn't error.

**Incident replay** (proposal §3.2 Layer 6: "Replay any agent session from
the audit log; step-by-step forensic view"):
- `packages/audit-logger` — `GET /events?session_id=X` filter, added to the
  existing SQLite query.
- `packages/cli` — new `replay <session-id>` command: fetches, sorts
  chronologically (the API returns newest-first), prints step by step.
- Verified against a real 5-event denied session — correct order, correct content.

**Kubernetes sidecar manifest** (proposal §4.5, the last open Sprint 2 item):
- `packages/proxy/k8s` — Kustomize (no Helm available in this environment),
  generating ConfigMaps directly from the real `envoy.yaml` and
  `policy-engine` files rather than duplicating them.
- No cluster or Helm was available, so a disposable one was created with
  `kind` (installed via `go install`) specifically to validate this for
  real rather than stopping at YAML-shape guessing.
- **Bug found and fixed by actually deploying it**, not by inspection:
  `envoy.yaml`'s `opa_cluster` targets hostname `opa` (correct for Docker
  Compose's per-service DNS), but OPA runs in the *same Pod* under this
  sidecar model — there's no such hostname, and with
  `failure_mode_allow: false` every request was silently denied (`403
  UAEX`) regardless of policy. Added `envoy-k8s.yaml` (identical except
  `127.0.0.1` instead of `opa`) rather than touching the Compose version.
- Verified: `kubectl apply --dry-run=server` passed against the real
  cluster's API; a real `kubectl apply` reached `3/3 Running`;
  `kubectl exec`'d into the `agent` container and made real HTTP requests
  through the sidecar — `example.com` → 200, `httpbin.org` → 403, confirmed
  both in the response and in Envoy's own access log. Cluster deleted
  afterward (`kind delete cluster`) — this was a verification exercise, not
  a running deployment.
- Explicitly documented (not glossed over) what Kubernetes `NetworkPolicy`
  can't do: it operates at the Pod boundary and cannot distinguish traffic
  between containers sharing a Pod's network namespace, so it cannot force
  the agent container through the proxy sidecar (the `HTTP_PROXY` env var
  does that) — domain-level allow/deny is still entirely Envoy+OPA's job.

**Real dashboard** (proposal §4.2: "Dashboard and API — React frontend,
REST/gRPC API" — replacing the `packages/dashboard` placeholder, distinct
from the `demo/dashboard_app.py` Streamlit throwaway):
- `packages/dashboard/api/dashboard_api.py` — new Python backend; the only
  service with CORS enabled, aggregating OPA/audit-logger/circuit-breaker/
  anomaly-detector/credential-vault server-side using `aegis_sdk` itself
  (not a special admin bypass — same code path as any other agent).
- `packages/dashboard/src` — new Vite + React + TypeScript frontend: policy
  check, credential vaulting, approvals queue (with live Approve/Deny
  buttons), and audit log tabs.
- Verified: `npm run build` (`tsc -b` + `vite build`) — zero type errors.
  Then actually driven with a **headless Playwright browser** (installed
  for this purpose) against the live stack, clicking through the real
  rendered UI exactly as a human would: all four service-status indicators
  green, a policy check for `example.com` renders ALLOWED and `httpbin.org`
  renders DENIED, a credential invocation shows real upstream JSON, the
  audit tab shows real rows with hash-chain verification, and — the
  clearest proof this isn't just a static page — clicking the Approvals
  tab's "Approve" button on a real suspended session actually cleared it
  (confirmed via a before/after query), with zero JS console errors.

## Sprint 4 — Multi-tenancy (isolated containment zones): DONE (MVP), verified (2026-08-22)

Every service now scopes its state by a `tenant_id` alongside the existing
`session_id`, defaulting to `"default"` everywhere so nothing that predates
this work had to change:

- `packages/policy-engine` — `policies/policy/data.yaml` restructured from
  flat fields to `tenants.<tenant_id>.*`, seeded with `default` and a second
  demo tenant `tenant-acme` (different allowed domain/tools/rate limit).
  `default.rego` resolves `tenant_policy := data.policy.tenants[tenant_id]`;
  an unrecognized `tenant_id` leaves `tenant_policy` undefined, which makes
  every `base_allow` rule undefined too — **fails closed**, never falls back
  to `default`'s policy. New `policy.tenant-acme.example.yaml`.
  `aegisctl policy apply` gained `--tenant <name>`, PUTting to
  `/v1/data/policy/tenants/<name>` instead of the old global path.
- `packages/circuit-breaker` — every in-memory structure (`_violations`,
  `_suspended`, `_activity`, `_terminated`, `_suspension_meta`) re-keyed from
  bare `session_id` to the composite `(tenant_id, session_id)` tuple; the
  rate-limit cache became per-tenant. Every endpoint gained a tenant path
  segment (`/violation/<tenant>/<session>`, etc.); `/suspended` gained an
  optional `?tenant_id=` filter.
- `packages/anomaly-detector` — `_history` re-keyed the same way; `tenant_id`
  read from the forwarded audit event (default `"default"`).
- `packages/audit-logger` — added a `tenant_id` column; the hash chain is
  now scoped per tenant (`prev_hash` looked up `WHERE tenant_id = ?`, its
  own genesis) so each tenant has a fully independent chain. `/events` and
  `/verify` both take a `tenant_id` filter/parameter.
- `packages/credential-vault` — `SERVICES["protected-api"]` gained a
  `vault_path_template` (`secret/data/{tenant_id}/protected-api`); a missing
  per-tenant secret hard-fails (502), with deliberately no fallback to
  another tenant's or a shared path. `demo/protected-api` now accepts a set
  of tokens (`PROTECTED_API_TOKENS`) so two tenants' distinct tokens both
  authenticate against the one mock upstream.
- `packages/sdk` — `AegisClient` gained `tenant_id: str = "default"`,
  threaded into the OPA input, circuit-breaker URLs, and the audit-logger /
  credential-vault request bodies.
- `packages/cli` — `extractTenantFlag` adds `--tenant <name>` (default
  `"default"`) to `logs`, `resume`/`approve`, `deny`, `approvals`, `replay`,
  and `policy apply`.
- `packages/dashboard` — API routes and the React frontend (`api.ts`,
  `App.tsx`) both gained a tenant dimension; a "Tenant ID" input sits next
  to the existing "Session ID" input. `_handle_suspended` always filters by
  `tenant_id` server-side — this is the actual tenant-facing isolation
  boundary, since browsers only ever talk to dashboard-api, never directly
  to circuit-breaker.

**Bug found & fixed (uncovered by testing this, not introduced by it):**
`audit_logger.verify_chain` called `json.loads` on each row's stored payload
with no exception handling. Tampering with a row badly enough to break JSON
syntax itself (not just change a value) raised an uncaught
`JSONDecodeError` that crashed that request's handler thread — the HTTP
client saw a connection reset instead of `{"chain_intact": false}`. Found
while manually tampering rows via `docker exec ... sqlite3` to verify
per-tenant chain isolation. Fixed by catching `JSONDecodeError` in
`verify_chain` and treating it the same as a hash mismatch. Confirmed both
tampering styles (a changed field, and broken JSON syntax) now return a
graceful `chain_intact: false` with a real 200 response, on both tenants'
chains, independently.

Verified end-to-end against the live Docker stack (`demo/tenant_isolation_test.py`,
14/14 checks passed), deliberately reusing the **same session_id string**
across two tenants throughout, to rule out "it's just unique strings" as an
explanation for any pass:

- **Policy isolation**: `example.com` allowed / `acme.example` denied for
  `default`; the reverse for `tenant-acme`, in both directions.
- **Unknown tenant fails closed**: `tenant_id="does-not-exist"` denied for
  everything, confirmed via the SDK and directly against OPA's data API.
- **Circuit breaker isolation**: 5 denials on `(default, session-A)`
  suspended that session; the identically-named `(tenant-acme, session-A)`
  stayed unsuspended.
- **Rate limit isolation**: `tenant-acme`'s lower configured limit (30/min
  vs. `default`'s 60/min) was hit independently; `default`'s
  identically-named session recorded zero violations from `tenant-acme`'s
  traffic.
- **Credential vault isolation**: both tenants authenticated against the one
  mock upstream with their own distinct Vault-issued token; neither token
  ever appeared in a broker response.
- **Anomaly detector isolation**: 11 file_read calls crossed the
  reconnaissance threshold and suspended `default`'s session via the
  anomaly detector; the identically-named `tenant-acme` session was untouched.
- **Audit log isolation**: `tenant_id` + `session_id` filtering on `/events`
  returned only the matching tenant's rows for a shared session_id; each
  tenant's `/verify` succeeded independently; manually tampering one
  tenant's row (both a value change and a JSON-syntax break) flipped only
  that tenant's `/verify` to `false`, confirmed via `docker exec ... sqlite3`.
- **Backward-compat regression**: re-ran `demo/sdk_test.py` and
  `demo/wrapper_test.py` (no `tenant_id` mentioned anywhere) — identical
  output to before Sprint 4, confirming the implicit `"default"` tenant
  preserves every prior behaviour.
- **CLI**: built `aegisctl` via `go build` (zero errors); exercised
  `logs`/`approvals` with and without `--tenant`, confirming tenant-filtered
  output; `policy apply --tenant tenant-acme` landed at OPA's
  `/v1/data/policy/tenants/tenant-acme`; drove a real suspension under
  `tenant-acme`, then `approvals` (correctly absent from `default`'s view),
  `replay`, `deny` (permanent terminate), and a subsequent `resume` correctly
  refused with the existing "permanently terminated" error.
- **Dashboard**: `npm run build` (`tsc -b` + `vite build`) — zero type
  errors. Driven with a headless Playwright browser against the live
  `vite dev` server + live backend stack: `example.com` under tenant
  `default` renders ALLOWED, `acme.example` under the same tenant renders
  DENIED, switching the Tenant ID field to `tenant-acme` and re-checking the
  same `acme.example` target (confirmed via the actual network request body)
  renders ALLOWED, the Approvals tab under `default` never shows
  `tenant-acme`'s suspended sessions, zero JS console errors.

Known gaps (real, not hidden):
- `tenant_id` is a client-supplied string with the same trust level
  `session_id` already had — there is no auth system binding a caller to a
  tenant. Anyone who can reach the SDK/dashboard/CLI can claim any tenant_id.
- The Envoy+OPA network-proxy path (`packages/proxy`) has no per-request
  tenant switching — Envoy's `ext_authz` input carries no tenant_id, so it
  always resolves against `tenants.default`. Multi-tenant isolation at that
  layer means deploying one sidecar per tenant (achievable today via
  `packages/proxy/k8s`), not a runtime switch.
- No tenant CRUD API — a tenant "exists" implicitly the first time
  `policy apply --tenant <name>` seeds its policy (or a Vault secret is
  seeded at its path). There's no listing/creation/deletion endpoint.
- Still shared, not per-tenant, OPA/Vault/Postgres processes — isolation is
  logical (via the `tenant_id` key), not physical/process-level.
- `policy.example.yaml`/`policy.tenant-acme.example.yaml` and
  `policies/policy/data.yaml` must still be kept in sync by hand for the
  bootstrap state, same as before Sprint 4.

## Sprint 4 — Load testing: DONE (found a real, unexpected bottleneck), 2026-08-22

New `demo/load_test.py` — a hand-rolled `asyncio` + `httpx.AsyncClient`
harness (no Locust/k6 dependency added; `httpx` is already the SDK's HTTP
client). Four phases isolating one layer each (OPA alone, circuit-breaker
alone, audit-logger alone, and the full `AegisClient.check()` wire protocol
end to end), each run at an escalating concurrency ramp
(25/100/500/1000/2500/5000/10000 virtual users) that auto-aborts a phase's
remaining levels once error rate or p95 latency crosses a threshold — the
abort point *is* the deliverable, not a failure of the script. Full
methodology, raw numbers, and write-up: **[demo/load_test_results.md](demo/load_test_results.md)**.

**Headline result: nowhere near the proposal's 10K+ concurrent / sub-10ms
target on this machine — the circuit-breaker and full-pipeline phases
aborted at the very first (lowest) concurrency level tested, 25.**

**The original hypothesis (each service's global `threading.Lock()` would
be the ceiling) was wrong, and the data disproves it directly**: `docker
stats` during a sustained-load run showed circuit-breaker's CPU sitting at
~1% while taking a 4+ second mean latency — if lock/GIL contention were the
cause, CPU would be pegged, not idle. The actual, confirmed cause: every
stdlib-Python service in this repo (`circuit-breaker`, `audit-logger`,
`anomaly-detector`, `credential-vault` — all `http.server`/
`ThreadingHTTPServer`) closes the TCP connection after every single
response (`curl -v` shows `shutting down connection` after each request),
while OPA (the one Go service on the path) reuses connections
(`Re-using existing http: connection`). Under Windows/Docker Desktop's
virtualized networking, sustained rapid connection churn degrades far worse
than an equivalent one-off burst — a one-shot 25-concurrent burst against
circuit-breaker completed in 0.17s total, while the *same* 25-concurrency
level sustained for 10s degraded to a 4.65s mean. This is why a load test,
not just a smoke test, was needed to surface it.

**Practical implication**: making the four stdlib services keep-alive
capable is likely a cheaper, higher-leverage fix than the proposal's
already-planned Rust rewrite of the circuit breaker — the current ceiling
looks like a transport-layer gap, not a raw compute or lock-contention
problem. Re-running this load test after that fix (before deciding whether
a language rewrite is still warranted) is the natural next step.

Known gaps in the load test itself, and what it explicitly does *not*
prove, are documented in full in `load_test_results.md` (single-machine
test, Docker-Desktop-specific networking numbers, never reached the
higher concurrency tiers for 3 of 4 phases since they aborted early, and it
doesn't yet isolate pure Rego evaluation cost from the transport layer
around it).

## Follow-up: HTTP keep-alive fix, applied and verified (2026-08-22)

Direct follow-up: implemented the "practical implication" from the entry
above. `protocol_version = "HTTP/1.1"` added to all seven of this repo's
`BaseHTTPRequestHandler`-based services (the four originally named, plus
`demo/protected-api`, `packages/dashboard/api/dashboard_api.py`, and
`demo/mock-siem` — checked while fixing this and found to have the
identical gap). Every handler already sent a correct `Content-Length`, so
no other changes were needed. Confirmed via `curl -v` on every affected
port: all seven now show `Re-using existing http: connection` instead of
`shutting down connection` after each request.

**Re-ran the exact same load test for a real before/after comparison**
(not just "should be faster now" reasoning) — full numbers in the rewritten
[demo/load_test_results.md](demo/load_test_results.md):

| Phase | Before | After |
|---|---|---|
| circuit-breaker only | failed at the first level tested (25) | sustains 25 cleanly (p95 94ms) |
| audit-logger only | sustained to 25 (p95 1.08s) | sustains to **100** (p95 1.39s) — 4x the concurrency |
| full pipeline | failed at the first level tested (25) | sustains 25 cleanly (p95 281ms) |

**A second bug found while producing this comparison, this time in the load
test tool itself, not AEGIS**: re-running all four phases sequentially in
one Python process produced a nonsensical result — phase 4 failing 100% at
concurrency=25 even though phases 1-3 (which it chains together) had each
just proven they handle 25 concurrent cleanly. Longer cooldowns between
phases (tried 2s, 15s, 30s) didn't fix it. Diagnosis: the identical request
pattern in a **fresh Python process** immediately afterward, with **zero**
extra wait, succeeded every time — conclusively this load generator's own
accumulated socket/resource state across four phases and thousands of
requests in one long-lived asyncio loop, not server-side overload. Fixed
by having `load_test.py` run each phase as its own subprocess
(`--phase <name>` runs just one). This means an earlier version of this
tool's "phase 4: complete failure" result would have been reported as an
AEGIS finding when it was actually a test-harness bug — caught before that
happened, not after.

Regression suite re-run after both fixes (`sdk_test.py`, `wrapper_test.py`,
`tenant_isolation_test.py`, 14/14) — unaffected, as expected.

Still real, still not hidden: none of the four phases reach anywhere near
10K concurrent — the highest any phase sustains cleanly is 100. The next
likely ceiling to investigate (per `load_test_results.md`'s updated "known
gaps") is the global `threading.Lock()` in `circuit-breaker`/`audit-logger`
— the original hypothesis, not yet ruled back in or out now that the
bigger effect masking it is gone — and audit-logger's per-request fresh
SQLite connection.

## Config consolidation: demo → real-world in one place, verified (2026-08-22)

Not a Sprint 4 line item per se, but requested directly: every hardcoded
demo value across the stack (secrets, thresholds, ports, service URLs) is
now driven by env files instead of scattered literals in
`docker-compose.yml` and five different Python files. Full write-up,
including the one genuinely confusing part (host-vs-in-network URLs) and
what's explicitly *not* just a config flip (Vault dev-mode, the unwired
`audit-db` Postgres): **[docs/configuration.md](docs/configuration.md)**.

- **`demo/.env.example`** → copy to `demo/.env` — Vault, Postgres, SIEM,
  demo credentials, circuit-breaker/anomaly-detector tuning, per-service
  ports, internal service URLs. Consumed by `docker-compose.yml`'s new
  `${VAR:-default}` substitution (previously zero — every value was a
  literal). Every default matches the prior hardcoded value exactly.
- **New env-var support added** where none existed before:
  anomaly-detector's four detection thresholds (including the
  self-modification regex) and circuit-breaker's rate-limit cache TTL
  (`packages/anomaly-detector/anomaly_detector.py`,
  `packages/circuit-breaker/circuit_breaker.py`); every service's listen
  port (`audit-logger`, `circuit-breaker`, `anomaly-detector`,
  `credential-vault`, `dashboard-api`, `demo/protected-api`) — and
  `docker-compose.yml`'s dependent services derive their internal URL
  defaults from the *same* port variable (e.g.
  `AEGIS_CIRCUIT_BREAKER_URL` defaults to
  `http://circuit-breaker:$AEGIS_CIRCUIT_BREAKER_PORT`), so changing one
  port variable can't leave the two out of sync.
- **`packages/credential-vault`'s `SERVICES` dict → `services.json`**: the
  service registry (previously hardcoded Python) is now a small JSON file
  (JSON, not YAML, to avoid adding a dependency to this container's
  otherwise-stdlib-only image), with a tiny `${VAR:-default}`-style
  expander for `base_url`. Verified by adding a second demo service
  (`mock-service-2`, reusing `protected-api`'s mock upstream) purely via a
  `services.json` edit + a seeded Vault secret + an OPA policy update — no
  Python code changes — and successfully invoking it through
  `AegisClient.invoke_credentialed()`.
- **`packages/sdk/aegis_sdk/__init__.py`**: `AegisClient` previously had
  *zero* environment-variable support (every URL a bare `"localhost"`
  constructor default) — unlike the Go CLI and every Python service.
  Now falls back to `AEGIS_POLICY_URL`/`AEGIS_AUDIT_URL`/
  `AEGIS_CIRCUIT_BREAKER_URL`/`AEGIS_CREDENTIAL_BROKER_URL` when the
  constructor argument isn't passed explicitly. Verified all three tiers
  directly: no env + no args → localhost defaults; env set + no args → env
  values used; env set + explicit arg → explicit arg still wins.
- **One file, not two**: `packages/dashboard` doesn't get its own separate
  `.env` — `vite.config.ts` sets `envDir: "../../demo"` so Vite reads
  `demo/.env` too (Vite still only exposes `VITE_`-prefixed vars to browser
  code, its own safety mechanism, so sharing the file with backend secrets
  doesn't leak them into the bundle). `VITE_AEGIS_DASHBOARD_API` lives in
  `demo/.env.example` alongside everything else. (First draft of this work
  did split it into a second file on the assumption Vite couldn't be
  pointed elsewhere — asked directly whether that split was necessary,
  which it wasn't; consolidated to one file.)

**Bug found and fixed while verifying this, before it shipped:** the first
version of `demo/.env.example` listed the internal service URLs
(`AEGIS_CIRCUIT_BREAKER_URL` etc.) as *active* literals alongside the new
port variables. Since Compose's `${VAR:-default}` fallback only triggers
when a variable is completely unset, having the URL already set to a
literal meant changing only the corresponding `PORT` variable silently did
nothing — confirmed directly: setting `AEGIS_CIRCUIT_BREAKER_PORT=9411`
and running `docker compose config` still showed the old port 9400 in
every dependent service's `AEGIS_CIRCUIT_BREAKER_URL`. Fixed by commenting
out that whole section in `.env.example` by default (documented, not
deleted), so Compose's nested `${URL_VAR:-http://host:${PORT_VAR:-default}}`
fallback actually applies; uncommenting a URL line still works for the
"point this service somewhere else entirely" case, which correctly
decouples it from the port variable. Re-verified after the fix: changing
only `AEGIS_CIRCUIT_BREAKER_PORT` now correctly updates every dependent
service's derived URL.

Verified end-to-end:
- Copying `demo/.env.example` to `demo/.env` **unedited**, then re-running
  the full regression suite (`sdk_test.py`, `wrapper_test.py`,
  `tenant_isolation_test.py`, all 14/14) — byte-identical behavior to
  before this config pass existed.
- Editing `AEGIS_VIOLATION_THRESHOLD` from 5→3 in `.env` and confirming
  the circuit breaker actually suspends after 3 violations, not 5.
- Editing `AEGIS_CIRCUIT_BREAKER_PORT` and confirming the service moved to
  the new port, the old port stopped responding, and (after the bug fix
  above) every dependent service's internal URL followed automatically.
- The `services.json` extensibility test above (new service, zero code).
- The `AegisClient` env-var precedence test above (all three tiers).

Known gaps (real, not hidden) — same points `docs/configuration.md` states
up front: Vault dev-mode isn't a config flip into a real Vault cluster;
`audit-db` Postgres's credentials are now configurable but it's still
completely unwired (pre-existing, tracked gap, unaffected by this work).

**Superseded by the next entry below** — this whole `.env`-based mechanism
was replaced with `config.py` in response to direct follow-up feedback
about `docker-compose.yml`'s remaining `${VAR:-default}` repetition. Left
in this log as an accurate record of what was actually built and verified
at the time, not deleted — see the next entry for what replaced it and why.

## Config consolidation, revised: config.py instead of demo/.env (2026-08-22)

Direct follow-up feedback on the work above: the `${VAR:-default}` lines in
every service's `environment:` block in `docker-compose.yml` were still
repetitive. Confirmed intent directly rather than guessing: **`config.py`
(repo root) is now the real settings file** — plain Python constants, no
`.env`, no `${VAR:-default}` substitution in `docker-compose.yml` at all
for the six services this repo's own Python controls.

- **`config.py`** bind-mounted read-only into `audit-logger`,
  `circuit-breaker`, `anomaly-detector`, `credential-vault`,
  `dashboard-api`, and `demo/protected-api` at `/app/config.py` — the same
  pattern already used for OPA's policies. A bind mount, not a build-time
  `COPY`, specifically so editing a value + `docker compose restart
  <service>` takes effect with **no image rebuild** — verified directly:
  changed `VIOLATION_THRESHOLD` 5→3 in `config.py`, ran
  `docker compose restart circuit-breaker` (no `--build`), and confirmed
  the circuit breaker suspended after 3 violations, not 5.
- Every one of the six services' `os.environ.get("AEGIS_...", "default")`
  calls replaced with `from config import ...`. `docker-compose.yml`'s
  `environment:` blocks for those six services are gone entirely, replaced
  by one `volumes:` line each.
- **`packages/credential-vault/credential_broker.py`**: now imports
  `VAULT_ADDR`/`VAULT_TOKEN`/`POLICY_URL`/`PORT` from `config` directly.
  `services.json`'s `"${VAR:-default}"` expander for `base_url` (unrelated,
  kept-as-is mechanism) now resolves in this order: a real env var first
  (still allows a genuine runtime override), then a matching `config.py`
  constant, then the inline default in `services.json` — otherwise
  removing `PROTECTED_API_URL` from `docker-compose.yml`'s environment
  block would have silently fallen back to a *second*, independent literal
  hardcoded inside `services.json` itself, re-creating exactly the
  two-places-to-keep-in-sync problem this whole effort exists to remove.
  Verified: `services.json`'s `protected-api` entry resolves to
  `http://protected-api:9500` via `config.PROTECTED_API_URL` with zero env
  vars set for it anymore.
- **`packages/sdk/aegis_sdk`** deliberately untouched — kept its
  environment-variable fallback from the previous pass. It's meant to be
  embedded in an agent process that may not be one of this repo's own
  containers, so it can't assume a bind-mounted `config.py` will exist;
  `config.py` is for services *this repo* builds and runs, env vars are for
  a library meant to run anywhere. Documented explicitly as an intentional
  asymmetry, not an inconsistency, in both `config.py`'s own docstring and
  `docs/configuration.md`.
- **`vite.config.ts`'s `envDir` reverted** — pointing Vite at a Python file
  bought nothing; `packages/dashboard` is back to its own one-line
  `.env`/`.env.example` (`VITE_AEGIS_DASHBOARD_API`), which is now the
  *only* remaining non-`config.py` setting in the whole repo, and clearly
  documented as such (Vite reads `.env`-format files, not Python — a real
  constraint, not a preference).
- Two seams that are genuinely unavoidable, stated directly rather than
  glossed over: (1) `vault` and `audit-db` are third-party images
  (HashiCorp Vault, Postgres) — not Python, can't import `config.py` —
  their credentials stay as literals in `docker-compose.yml`, kept in sync
  with `config.py`'s `VAULT_TOKEN`/`PROTECTED_API_TOKEN_*` by hand;
  (2) each service's *published* port in `docker-compose.yml`'s `ports:`
  mapping is a Compose-level concern `config.py` can't reach into from
  Python, kept in sync with the matching `*_PORT` constant by hand — every
  port line in the compose file has a comment naming which constant.

Verified end-to-end: rebuilt the whole stack once
(`docker compose up -d --build`, needed for the new volume mounts), then
the full regression suite (`sdk_test.py`, `wrapper_test.py`,
`tenant_isolation_test.py`, 14/14) — byte-identical behavior; the
no-rebuild-restart test above; `services.json`'s config.py-fallback
resolution; `packages/dashboard`'s build with its own plain `.env`
restored. Torn down cleanly afterward.

## Sprint 4 — SOC 2 compliance package: DONE (MVP), verified (2026-08-22)

Proposal's exact wording (§8, confirmed by searching the whole docx — this
is the entirety of it, no further detail exists anywhere): "Pre-built
policy templates and audit reports for SOC 2 Type II certification. Tech
stack: Policy library, PDF report generation." There was zero existing
code for this — no template-library concept beyond the two demo per-tenant
policy YAMLs, and the audit-logger only exposed raw `/events` + a single
`/verify` boolean, no aggregation or report generation anywhere.

**Framing stated on the report's own cover section, not just in project
docs**: this produces evidence *supporting* a SOC 2 Type II audit, not a
certification. A real SOC 2 Type II report can only be issued by a
licensed CPA firm after examining controls over an actual observation
period (3–12 months), including organizational controls (HR, physical
security, vendor management) AEGIS has no visibility into. AEGIS only
covers the AI-agent-containment slice of the Trust Services Criteria.

New `packages/compliance/`:
- **`CONTROL_MAPPING.md`** — the single source of truth mapping AEGIS's
  existing layers to specific TSC control IDs (CC6.1/CC6.6 logical
  access/least-privilege → policy engine; CC6.8 → egress proxy; CC7.1 →
  live policy updates; CC7.2 → anomaly detector; CC7.3/CC7.4 → circuit
  breaker + human-in-the-loop approvals; PI1.4 → hash-chained audit log;
  C1.1/C1.2 → credential vaulting), referenced by both the templates below
  and the report generator so the mapping can't drift between the two.
- **`templates/soc2-strict.yaml`** and **`templates/soc2-standard.yaml`** —
  same shape as `policy.example.yaml`, applied the exact same way
  (`aegisctl policy apply --tenant <name> <file>`, no new mechanism), every
  field commented with its TSC control ID.
- **`soc2_report.py`** (renamed `compliance_report.py` and generalized
  across frameworks by the Phase 2 work, 2026-09-27 — see that dated
  entry) — standalone script (no Dockerfile, not in
  `docker-compose.yml`), pulling from the *existing*
  `/events`/`/verify`/`/suspended` endpoints only, aggregating into the
  same control sections as `CONTROL_MAPPING.md`, rendering
  `--format pdf|markdown|json` from one shared aggregation step.

**Bug found and fixed while verifying the PDF output:** `fpdf2`'s
`multi_cell()` defaults to `new_x=RIGHT` — for a full-width (`w=0`) cell,
that leaves the cursor sitting at the *right* margin, so the next call has
~0 width left and raises `FPDFException: Not enough horizontal space to
render a single character`. Every `multi_cell` call now explicitly passes
`new_x="LMARGIN", new_y="NEXT"` (via a small `mc()` helper) to reset back
to the left margin after each line.

Verified end-to-end against the live stack:
- Generated a real report for the `default` tenant after driving real
  mixed traffic (allowed/denied actions across several sessions, one real
  unresolved circuit-breaker suspension) — spot-checked the report's
  suspension count directly against `GET /suspended?tenant_id=default`
  and confirmed an exact match, not placeholder data.
- Tampered with the tenant's audit chain directly via `sqlite3` (same
  technique as the Sprint 4 multi-tenancy verification) and confirmed the
  regenerated report's PI1.4 section correctly flipped to
  `chain_intact: false` / "TAMPERING DETECTED" instead of silently
  reporting success.
- Generated all three formats (`pdf`/`markdown`/`json`) from the same live
  data and confirmed identical numbers across all three (extracted the
  PDF's actual text via `pypdf` to check, not just that it opened).
- Applied `templates/soc2-strict.yaml` to a fresh tenant via `aegisctl
  policy apply` and confirmed it's a real, enforcing policy, not
  descriptive text: OPA's data API showed the tenant's rate limit at
  20/min and an empty `allowed_tools` list exactly as the template
  specifies, and an `AegisClient` under that tenant was correctly denied a
  `tool_call` action.

Known gaps (real, not hidden) — same points `packages/compliance/README.md`
states directly: not wired into `aegisctl` (stays a standalone script; a
Go subcommand shelling out to Python was judged more fragile than it's
worth for this MVP); no continuous evidence collection/scheduler (generates
a report on demand from whatever's currently in the audit log, not
evidence gathered continuously over a real multi-month observation
period); only SOC 2 (proposal §7.2's HIPAA/PCI-DSS/EU AI Act templates are
Phase 2 enterprise-tier scope, not this Sprint 4 item); the control mapping
is a reasonable-effort engineering interpretation, not vetted by a licensed
CPA firm or SOC 2 assessor; Availability criteria aren't addressed at all.

## Sprint 4 — Internal security review (substitute for external audit), 2026-08-22

The proposal's Sprint 4 item is a third-party security audit — that can't
actually be performed by me (it means hiring a licensed firm, same
category as "SOC 2 certification" itself). The honest substitute: a manual
security review of the whole codebase (two parallel focused passes —
credential/secrets/tenant-isolation, and network/auth/injection surfaces),
with every candidate finding **empirically verified against the live
running stack** before being reported, not just inferred from reading
code. Four real findings, three fixed immediately (cheap, real fixes),
one documented as a genuine architectural gap.

**Fixed:**

1. **Dashboard API had zero CSRF protection.** `packages/dashboard/api/dashboard_api.py`
   sent `Access-Control-Allow-Origin: *` and never checked Origin/Referer
   or any token — confirmed live that a bare cross-origin `curl -X POST
   .../api/breaker/deny/...` with an arbitrary Origin header permanently
   terminated a real session, and that `/api/credential` could be driven
   the same way via the classic `<form enctype="text/plain">` JSON-CSRF
   trick (confirmed live with a CRLF-terminated body and
   `Content-Type: text/plain` — accepted and executed a real credentialed
   action). **Why CORS headers didn't help**: they only gate whether an
   attacker's JS can *read* a cross-origin response, not whether the
   browser *sends* the request — a blind form POST goes through
   regardless. Fixed with the actual defense: a server-side check that the
   browser-supplied `Origin` header matches an explicit allowlist
   (`config.py`'s new `DASHBOARD_ALLOWED_ORIGINS`) before any
   state-changing request runs, plus a strict `Content-Type:
   application/json` requirement (closing the `text/plain` trick
   specifically). Verified live after the fix: the exact same attacks now
   get 403/400, the exact same real dashboard-origin calls still work.
2. **`credential-vault` built Vault KV paths from a fully unvalidated
   `tenant_id`.** Confirmed live and empirically (not just read in code)
   that Vault's own HTTP router normalizes `../` dot-segments — a request
   to `secret/data/../../sys/mounts` returned the *exact same body* as the
   real `/v1/sys/mounts`, i.e. the traversal fully escapes the intended
   `secret/` KV mount. Then tested the **actual** `/invoke` endpoint with
   a crafted traversal `tenant_id` and got a real `403` — OPA's
   tenant-must-be-configured check in `default.rego` already fails closed
   for any `tenant_id` that isn't a real operator-provisioned tenant,
   before the vulnerable code path is ever reached, so this specific gap
   was **not currently exploitable end-to-end via the documented API** —
   but the code had zero defense-in-depth of its own, relying entirely on
   that one gate holding for every future code path. Fixed with a strict
   `^[A-Za-z0-9_-]{1,64}$` allowlist on `tenant_id` in
   `credential_broker.py` itself, verified live: the traversal payload now
   gets a clean 400 before reaching Vault at all, legitimate tenant IDs
   unaffected.
3. **Rego's `file_read` rule was traversal-bypassable.** `startswith(input.action.target, "/data/")`
   is a pure string-prefix check — confirmed directly that
   `"/data/../etc/passwd".startswith("/data/")` is `True`. Traced every
   consumer of `file_read` actions in the repo and found none that
   actually perform a filesystem read based on the target — so this was
   latent, not live-exploitable today, but a trap for whoever wires up the
   first real file-read consumer. Fixed by also rejecting any target
   containing `".."` in `default.rego`. Verified live: the traversal
   target is now denied, `/data/report.csv` still allowed.

**Documented as a real, unfixed architectural gap (not attempted this
pass):** the egress proxy authorizes purely by hostname string
(`packages/proxy/envoy.yaml` calls OPA with only the Host header; OPA does
plain string-membership against `allowed_domains`) — DNS resolution
happens *after* that decision, with nothing validating the resolved IP.
**Confirmed live, not just theorized**: pointed `example.com` (an
allowlisted domain) at `dashboard-api`'s real internal container IP via
the proxy container's `/etc/hosts`, confirmed OPA still approved the
hostname string, then confirmed a real request through the proxy actually
attempted a TCP connection to that internal IP (refused only because
nothing listens on port 80 there — the connection attempt itself
succeeded in reaching it). In a real deployment, an attacker who controls
DNS for any allowlisted domain (or wins a TOCTOU race re-pointing it
between requests) can redirect egress traffic to internal services or
cloud metadata endpoints using a domain that was legitimately allowlisted.
Fixing this properly needs IP-range validation in the proxy layer (e.g.
rejecting private/link-local ranges post-resolution, or pinning resolved
IPs) — meaningful Envoy configuration work, not a one-line fix, and left
as a tracked gap rather than attempted under this pass.

Full regression suite (`sdk_test.py`, `wrapper_test.py`,
`tenant_isolation_test.py`, 14/14) re-run after all three fixes — unaffected.

## Gap #1 (post-Sprint-4 backlog): dashboard API authentication, 2026-08-22

Closes the highest-priority item on the gap-closing backlog. The internal
security review fixed the dashboard's CSRF hole (Origin allowlist + strict
Content-Type), but that was mitigation, not authentication — every handler
still trusted whatever `tenant_id` the client supplied. Added real
per-tenant static API keys (`config.py`'s new `DASHBOARD_API_KEYS`, same
"real but simple" pattern as Vault's static dev token): every
`dashboard_api.py` request now needs `Authorization: Bearer <key>`, and
**no handler accepts a client-supplied `tenant_id` anywhere anymore** —
not in a query param, not in a path segment, not in a JSON body. The
tenant is derived exclusively from the presented key.

Scope, stated directly: this only authenticates the *dashboard* entry
point. `packages/sdk`'s `AegisClient` and `aegisctl` are unchanged and
still accept a client-supplied `tenant_id` — correct for those, since
they're meant to be embedded directly in an agent's own backend code (the
embedding application is expected to configure its own tenant_id, the same
trust model any backend SDK has toward its host process). Only the
dashboard is a browser-facing surface that needed real authentication.

`packages/dashboard/src`: the free-text "Tenant ID" field is gone,
replaced with an "API Key" field, persisted in `localStorage`. The status
bar now displays which tenant the key actually resolved to
(`/api/status`'s response gained a `tenant_id` field for this).

Verified end-to-end against the live stack:
- No `Authorization` header, or a bogus key → 401 on every endpoint, GET
  and POST alike.
- **The critical proof**: authenticated with `default`'s key but put
  `"tenant_id": "tenant-acme"` directly in the `/api/check` request body,
  targeting `acme.example` (allowed for `tenant-acme`, denied for
  `default`) — got `denied`, proving the server genuinely evaluated the
  request as `default` (from the key) and completely ignored the
  client-claimed tenant, not just that it happened to default sensibly.
- `default`'s key showed an empty approvals queue while a real suspension
  existed under `tenant-acme` (driven directly via the SDK); `tenant-acme`'s
  key showed it correctly.
- Re-ran the CSRF proof-of-concept from the security review (request from
  the allowed Origin, no `Authorization` header) — now also fails, on the
  auth check independently of the Origin check.
- Playwright pass against the real built frontend: entered a bogus key
  (clean "Invalid API key" state, no crash), entered `default`'s key
  (status bar showed "authenticated as tenant: default", `example.com`
  check rendered ALLOWED), switched to `tenant-acme`'s key (status bar
  updated, the *same* `example.com` check now rendered DENIED) — proving
  the switch is real, not cosmetic.
- Full regression suite (`sdk_test.py`, `wrapper_test.py`,
  `tenant_isolation_test.py`, 14/14) — unaffected, as expected, since none
  of them talk to dashboard-api.

Known limitation, stated directly: this is static keys, not a full
user/session system — no rotation, no expiry, no per-user audit trail
within a tenant (every holder of a tenant's key is indistinguishable from
any other holder of the same key). Real enough to close the "anyone
reaching the dashboard can claim any tenant" gap; not "production SaaS
auth."

## Gap #2 (post-Sprint-4 backlog): DNS-rebinding fix in the egress proxy, 2026-08-22

Closes the one architectural gap the internal security review found and
documented but didn't fix at the time — the egress proxy authorized by
hostname string with no post-DNS-resolution IP check.

**What the original PoC did vs. what needed fixing**: the security
review's proof used `/etc/hosts` inside the proxy container as a stand-in
for "an attacker controls what an allowlisted hostname resolves to,"
since there's no real public domain available in this environment to
demonstrate actual rebinding against. That's a fair simulation of the
*mechanism*, but the fix had to address the real vector (a malicious DNS
*answer*), not `/etc/hosts` specifically — verification below tests that
real vector.

New `packages/proxy/dns-filter/dns_filter.py`: a small UDP DNS server
(`dnspython` for wire-format parsing, an isolated new dependency — same
pattern as `packages/compliance`'s `fpdf2`) that Envoy's
`dynamic_forward_proxy` now resolves through instead of the container's
default resolver. Forwards every query to Docker's own embedded DNS
(`127.0.0.11`, preserves today's resolution behavior exactly for anything
legitimate) but rejects outright any answer containing a private
(RFC1918), loopback, or link-local address (including the
`169.254.169.254` cloud-metadata address, and IPv6 equivalents) — refusing
the *answer* before Envoy ever attempts a connection, which is strictly
better than any post-connect check could be (zero bytes ever reach the
private target). `packages/proxy/envoy.yaml`'s two `dns_cache_config`
blocks (the filter's and the cluster's, which must stay byte-identical
since they share one named cache) now use a YAML alias pointing at
`dns-filter`'s static IP — a real structural requirement, not a style
choice: a DNS resolver config needs a literal IP for its own resolver
(chicken-and-egg), so `demo/docker-compose.yml` gained a fixed-subnet
override on the implicit `default` network (`172.30.0.0/24`) with
`dns-filter` pinned to `172.30.0.53` — every other service is completely
unaffected, still just implicitly attached to `default` as before.

Verified end-to-end, escalating from isolated logic to the real deployed
system:
1. **Direct logic test**: crafted synthetic DNS responses with `dnspython`
   (one containing a private A record, one a public one) fed straight
   into the filter function — correctly rejected/accepted.
2. **Real rejection, no mocking needed**: queried the *actually deployed*
   `dns-filter` container for `dashboard-api` — a real container name that
   Docker's genuine embedded DNS legitimately resolves to a real private
   IP (confirmed directly against `127.0.0.11` first: `172.30.0.14`,
   `NOERROR`). The same query through `dns-filter` came back `REFUSED`
   with zero answers — a completely real DNS answer, not a hosts-file
   trick, correctly blocked by the actual deployed component.
3. **The full real chain**: temporarily allowlisted `dashboard-api` as a
   policy target, confirmed OPA approved it (`{"result": true}` — it's
   just a hostname string, as expected), then sent a real HTTP request
   through the *entire* Envoy egress proxy to `http://dashboard-api/...`
   — got `503 DNS resolution failure`, proving Envoy never got a usable
   answer and therefore never attempted the connection, all the way
   through the real deployed stack, not a simulation.
4. **Regression**: `example.com` still resolves and gets 200 through the
   proxy (confirmed via `hello-agent`'s own startup check in the container
   logs, unprompted); `httpbin.org` still denied by OPA (a policy
   decision, unaffected). Full suite (`sdk_test.py`, `wrapper_test.py`,
   `tenant_isolation_test.py`, 14/14) re-run twice (before and after the
   real-chain test above) — unaffected both times.

Scope limit, stated directly rather than glossed over: this filters DNS
*answers*. It doesn't and can't protect against an attacker who already
has file/code access inside the proxy container (e.g. editing
`/etc/hosts` directly, exactly what the original PoC did as a stand-in) —
that's a different, far more severe compromise than DNS rebinding
describes, and no DNS-layer fix changes that.

## Gap #3 (post-Sprint-4 backlog): audit-logger wired to Postgres, 2026-08-22

`demo/docker-compose.yml`'s `audit-db` (`postgres:16`) has been running
since Sprint 1 with real credentials configured — nothing has ever talked
to it. Closes that, matching the proposal's own words (§8 Sprint 1):
"SQLite for local dev, PostgreSQL for production."

`config.py`'s new `AUDIT_STORAGE_BACKEND` (`"sqlite"` default, or
`"postgres"`) switches `packages/audit-logger/audit_logger.py` between the
two — SQLite stays the default, today's exact behavior unchanged unless
flipped, rather than a full replacement that would've changed default demo
behavior and thrown away the already-tested SQLite path for no benefit.
The hash-chain math (canonical JSON + SHA-256, the actual security-critical
logic) is completely unchanged and shared between both backends — only the
`connect()`/three SQL statements differ (`?` vs `%s` placeholders, `psycopg`
needing an explicit cursor where `sqlite3.Connection.execute()` doesn't),
hidden behind one small `_execute()` helper so the rest of the file didn't
need touching. New isolated dependency: `psycopg[binary]`, only in
`packages/audit-logger`'s own `requirements.txt`.

Verified end-to-end, both backends:
1. **Default unchanged**: full regression (`sdk_test.py`, `wrapper_test.py`,
   `tenant_isolation_test.py`, 14/14) on the default `"sqlite"` backend —
   byte-identical to before this change.
2. **Flip to Postgres, same tests pass**: edited `config.py`, rebuilt (for
   the new dependency), same full suite — 14/14, now genuinely backed by
   `audit-db`. Confirmed directly via `psql`
   (`SELECT count(*), tenant_id FROM events GROUP BY tenant_id`) that real
   rows from the test run actually landed in Postgres — 24 `default`, 33
   `tenant-acme`, 1 `does-not-exist` — not silently still hitting SQLite.
3. **Tamper detection on Postgres**: same technique as the original SQLite
   tamper test, this time a direct `psql UPDATE` on a real row — `/verify`
   correctly flipped to `chain_intact: false` for the tampered tenant,
   while the other tenant's chain stayed `true`, confirming per-tenant
   isolation holds on this backend too.
4. Restored `config.py` to `"sqlite"` (the shipped default) and re-ran the
   full suite once more to confirm the shipped state is exactly right.

## Gap-closing backlog: global-lock hypothesis, investigated, 2026-08-22

Re-ran `demo/load_test.py`'s circuit-breaker and audit-logger phases now
that the HTTP keep-alive fix is in place, sampling `docker stats` mid-run
at the actual ceiling (concurrency=100) rather than only at the start —
the same technique the keep-alive investigation used, applied to the
hypothesis it displaced.

**Result: the two services tell different stories, and the finding is
more nuanced than "the lock is (or isn't) the bottleneck."**

- **`circuit-breaker`: CPU stayed at 5.5%** while taking a 1.15s mean
  latency at concurrency=100. This rules out lock/GIL contention as
  *its* ceiling, same conclusion as the keep-alive investigation reached
  for the pre-fix state — the service is mostly waiting, not computing.
  The likely remaining constraint is the `ThreadingHTTPServer` model
  itself (one OS thread per connection) interacting with Docker Desktop's
  networking on this platform, not application-level lock contention.
- **`audit-logger`: CPU hit 56.8%**, a real, meaningfully different
  picture — consistent with its per-request fresh SQLite connection (no
  pooling), the global lock serializing hash-chain writes, and the inline
  (blocking, up to 1s) forward-to-anomaly-detector call all stacking up
  under load. This one *is* showing genuine compute/lock pressure, not
  just I/O wait.

**Practical implication for the Rust rewrite below**: the proposal's
rationale for rewriting `circuit-breaker` in Rust is "production latency,"
usually read as "Python/GIL is slow" — the data doesn't actually support
that specific mechanism for this service. What a Rust rewrite genuinely
changes is the *concurrency model* (an async runtime handling many
connections on a small thread pool, vs. one OS thread per connection) —
that's a real, defensible reason to still do it, just a more precise one
than "fixes lock contention." `audit-logger`'s bottleneck looks more
classically fixable (connection pooling, decoupling the anomaly-detector
forward from the write path) and wasn't in scope for this pass — noted for
a future gap-closing item, not conflated with circuit-breaker's rewrite.

## Gap-closing backlog: Rust circuit-breaker rewrite, 2026-08-22

The proposal's Sprint 2 spec for `circuit-breaker` (production latency).
Motivation refined by the global-lock investigation directly above: the
data showed circuit-breaker's ceiling wasn't lock/CPU contention, so this
rewrite is justified by the *concurrency model* (async, per-key locking)
rather than "fixing the lock" — stated in the new service's own module
doc comment, not just here.

New `packages/circuit-breaker-rs/` (Rust, `axum`/`tokio`/`dashmap`), no
local Rust toolchain available on this machine — built entirely via a
multi-stage `docker build` (same principle this repo already uses for
Envoy: `packages/proxy` builds FROM the `envoyproxy/envoy` image rather
than needing Envoy installed locally). Compiled clean on the first real
attempt after one Rust-version bump (`rust:1.82-slim` → `rust:slim`, a
transitive dependency needed a newer Cargo than 1.82 shipped).

**Runs alongside the Python `circuit-breaker`, not instead of it** (new
`circuit-breaker-rs` service, ~~port 9410~~ **now port 9400 — see the
"circuit-breaker-rs default cutover" entry below, 2026-09-16: swapping a
whole service turned out to still be worth doing as a config.py-level
choice after all, once parity was fully verified**) — at the time of this
entry, swapping a whole service wasn't a "pick a backend" config.py flag
the way Gap #3's SQLite/Postgres switch was; it was an operator choice
(point `AEGIS_CIRCUIT_BREAKER_URL` — or, for this repo's own services,
`config.py`'s `CIRCUIT_BREAKER_URL` — at `circuit-breaker-rs:9400`
instead) documented directly rather than forced. Settings come from
environment variables, not `config.py` — a Rust service isn't one of the
Python services `config.py`'s own module docstring scopes itself to, so it
follows the same env-var pattern vault/audit-db already use.

**Correctness note worth being explicit about**: per-(tenant,session)
state lives behind its own `tokio::sync::Mutex` (via `DashMap<Key,
Arc<Mutex<SessionState>>>`), not one global lock — deliberately better
than the Python original's single `threading.Lock()`. Getting this right
under an async runtime needs care: every handler clones the `Arc` out of
the `DashMap` entry (synchronous, no `.await` involved) and drops
`DashMap`'s own internal guard *before* awaiting the `tokio::Mutex` —
holding a sync lock across an `.await` point is a well-known
deadlock/correctness hazard under `tokio`, avoided by construction here,
not by luck.

Verified end-to-end against the live stack:
- **API-level behavioral parity**, tested directly against port 9410
  (bypassing the Python service entirely): fresh-session status, violation
  threshold escalation, `/suspended` listing with and without a
  `tenant_id` filter, `suspend`/`terminate` with and without a JSON body
  (Python's "unspecified" default reason matched exactly), refused-resume
  after termination, and graceful fallback to the default rate limit when
  OPA is unreachable — all matched the Python service's exact response
  shapes and behavior.
- **Full regression suite unaffected**: `sdk_test.py`/`wrapper_test.py`/
  `tenant_isolation_test.py` (14/14) against the default (Python) service,
  proving `circuit-breaker-rs` running alongside doesn't disturb anything.
- **The same 14-check tenant-isolation suite, re-run against the Rust
  service directly** (temporarily repointing the test's `BREAKER_URL`,
  reverted after): 13/14 passed; the one "failure"
  (anomaly-detector-triggered suspension not visible on 9410) was
  correctly diagnosed as a test-harness limitation, not a real gap —
  `anomaly-detector` has its *own* separately configured circuit-breaker
  target (`config.py`'s `CIRCUIT_BREAKER_URL`, unrelated to what URL a
  test script hands the SDK) that can't be redirected by that override.
  Confirmed by actually flipping `config.py`'s `CIRCUIT_BREAKER_URL` to
  `circuit-breaker-rs` and re-running the identical reconnaissance
  scenario: the anomaly detector's suspend call landed on the Rust service
  correctly, full parity confirmed, then reverted.
- **Real performance comparison**, same `demo/load_test.py` methodology
  pointed at port 9410 instead of 9400: at concurrency=100, the Rust
  service sustained it with **zero errors** (mean 449ms) where the Python
  service had a 0.2-2.1% error rate at the same level across prior runs;
  throughput at concurrency=25 was roughly double (408 rps vs ~250-267
  rps). Real, measurable improvement — **not** a claim of reaching
  anywhere near 10K concurrent: the same test found circuit-breaker-rs's
  own ceiling around concurrency=500 (mean latency balloons to 12.5s).

Known gaps, stated directly (as of the 2026-08-22 pass): not wired into
`docker-compose.yml` as the default; no automated test suite comparing the
two services beyond manual verification; no README of its own. **All
three closed below, 2026-09-16.**

## Gap-closing backlog: circuit-breaker-rs default cutover, 2026-09-16

Closes the three gaps named directly above. `circuit-breaker-rs` is now
the default circuit breaker for the whole demo stack, not just an opt-in
alongside service:

- `demo/docker-compose.yml`: swapped published host ports —
  `circuit-breaker-rs` now publishes on `9400` (the port every host-side
  caller's `AEGIS_CIRCUIT_BREAKER_URL` fallback already assumes:
  `aegisctl`, `demo/*.py` scripts, an externally-run agent's
  `AegisClient`), and `circuit-breaker` (Python) moved to `9410`. Both
  services' `depends_on` consumers (`anomaly-detector`, `dashboard-api`)
  now list both services.
- `config.py`: new `CIRCUIT_BREAKER_BACKEND` switch (`"rust"`, default) —
  same "backend switch" pattern as Gap #3's `AUDIT_STORAGE_BACKEND`.
  `CIRCUIT_BREAKER_URL` (read by `anomaly-detector` and `dashboard-api` for
  *internal*, container-to-container calls) is derived from it. Set to
  `"python"` to point back at the original service — a one-line edit plus
  `docker compose restart anomaly-detector dashboard-api`, no rebuild,
  since it's a bind mount.
- New `packages/circuit-breaker-rs/README.md` — API reference (delegates
  to `packages/circuit-breaker/README.md`'s endpoint docs, since the two
  are drop-in equivalent), config env vars, the cutover/rollback steps
  above spelled out, and a verification summary.
- New `demo/circuit_breaker_parity_test.py` — automates what the
  2026-08-22 entry above did by hand: drives an identical request sequence
  (fresh status, violation escalation to suspension, resume,
  suspend-with-reason twice in a row, `/suspended` filtering, terminate
  with no body, refused resume-after-terminate, rate-limit escalation
  under a tenant-scoped lower limit) against both services and asserts
  matching responses (after stripping `suspended_at`, a wall-clock
  timestamp that can legitimately differ by milliseconds between two
  sequential calls). Uses one uuid-scoped tenant per run so it can't
  cross-contaminate either service's in-memory state, including against
  itself on a re-run.
- `packages/anomaly-detector/README.md`'s Config section was stale
  (documented a plain `AEGIS_CIRCUIT_BREAKER_URL` env var that the code
  doesn't actually read — it reads `config.py`'s `CIRCUIT_BREAKER_URL`)
  from before the original config.py consolidation; fixed while touching
  this area since leaving it would've made the new default actively
  misleading to read about. `packages/circuit-breaker/README.md`'s API
  section was also stale (missing the Sprint 4 `<tenant-id>/` path
  segment); fixed for the same reason.

Verified against the live stack:
- **Confirmed which service is actually on which port** post-cutover via
  `curl`: port 9400's JSON key ordering is alphabetical (`serde_json`'s
  default), port 9410's matches Python dict insertion order — 9400 is
  genuinely `circuit-breaker-rs` now, not just "should be" per the compose
  file.
- **`demo/circuit_breaker_parity_test.py`: 29/29 checks pass.**
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  and `tenant_isolation_test.py` (14/14) all pass with circuit-breaker-rs
  as the default target — notably including "default tenant's session
  suspended by anomaly detector (reconnaissance)," which specifically
  proves `anomaly-detector`'s direct-suspend call reaches the *new*
  default service end-to-end, not just that the two services independently
  behave alike.
- **`demo/load_test.py --phase full_pipeline` re-run**: cleanly sustains
  concurrency=25 (p95 344ms), aborts at concurrency=100 (p95 3.83s) — same
  ceiling as previously documented, confirming the cutover introduced no
  regression (the full pipeline's ceiling was never circuit-breaker's own,
  which independently sustains 100 cleanly — see the 2026-08-22 entry
  above).

## Phase 2 enterprise tier: managed dashboard for security teams, 2026-09-28

Closes the remaining Phase 2 item (§7.2) — the proposal names this as a
one-line go-to-market offering with no technical spec, so this translates
"a security TEAM, not one admin" into concrete, buildable scope: RBAC,
per-operator attribution, and (found along the way, not required by the
"team" framing itself) completing the status check.

- `config.py`'s `DASHBOARD_API_KEYS` changed shape from `key -> tenant_id`
  to `key -> {"tenant_id", "role", "operator"}`. `role` is `"operator"`
  (everything the old single key type could do) or `"viewer"` (read-only:
  status/audit/approvals-queue).
- `dashboard_api.py`: every state-changing endpoint (`/api/check`,
  `/api/credential`, `/api/breaker/resume`, `/api/breaker/deny`) now
  requires `role == "operator"`, checked once in `do_POST` before any of
  them dispatch — the same "deny before it does anything" shape every
  other layer in this repo already uses, not a per-handler afterthought.
  New `_log_operator_action()` logs a dedicated `dashboard_operator_action`
  audit event on every resume/deny, attributing it to the real operator
  name — `circuit-breaker`'s own `/resume` has no reason field at all, so
  this is the actual place the attribution trail needed to live. `/deny`'s
  existing reason string now also names the real operator instead of a
  generic "operator via dashboard."
- **Found and fixed while doing this, not required by the RBAC work
  itself**: `/api/status` was missing `credential_vault` and
  `content_guardrail` entirely — and both of those services had NO `GET`
  route at all, so a probe against either would have fallen through to
  `BaseHTTPRequestHandler`'s default `501` and been read as "down"
  regardless of real health. Added a real `/health` route to both
  services and wired them into the status check.
- Frontend (`App.tsx`): lifted the `/api/status` fetch out of `StatusBar`
  into `App` itself so `role` can gate every tab, not just be displayed.
  Fixed a real latent bug this surfaced: the status rendering loop
  treated every non-`tenant_id` field as an up/down boolean — adding
  `role`/`operator` (real strings) would have rendered them through the
  same up/down boolean logic incorrectly; fixed by excluding the new
  meta fields from that loop and giving them their own line. `CheckTab`/
  `CredentialTab` disable their action controls for a viewer key;
  `ApprovalsTab` hides the entire Approve/Deny column (not just the
  buttons) for a viewer, so the restriction is visible in the UI, not
  only discoverable by clicking and getting a 403.

Verified against the live stack:
- **RBAC enforcement, checked directly, not inferred from the code**: a
  viewer key gets a real `403` on `/api/check`, `/api/breaker/resume`,
  and `/api/breaker/deny`; the identical calls succeed for an operator
  key. The pre-existing Origin/CSRF check was confirmed to still run
  first (a state-changing request with no allowed Origin is still
  rejected regardless of role).
- **Real per-operator attribution, read back from the live audit log,
  not assumed from the code**: drove 5 real policy denials to suspend a
  session, resumed it via the dashboard with the operator key, then
  fetched the actual stored audit event and confirmed
  `"event_type": "dashboard_operator_action"`,
  `"operator": "demo-operator"`, and
  `"reason": "resume by demo-operator"` — a real name in a real,
  hash-chained event, not a placeholder.
- **All six services now report in `/api/status`**, confirmed by curling
  it directly with a real key — `credential_vault`/`content_guardrail`
  both showed `true` from their new `/health` routes.
- **Real browser verification**, not just API-level: installed
  Playwright + Chromium temporarily, ran a one-off smoke test against
  the live `npm run dev` server and the live backend — 9/9 checks
  (status bar shows the right role/operator/services for both key
  types; the Approvals tab's Actions column and the Check tab's button
  are genuinely absent/disabled for a viewer key, not just visually
  similar). Uninstalled Playwright and deleted the one-off script
  afterward, same as this repo's other throwaway verification scripts —
  the permanent regression coverage is the new
  `demo/dashboard_rbac_test.py` below.
- `npm run build` (`tsc -b` + `vite build`): zero TypeScript errors.
- New `demo/dashboard_rbac_test.py` — 21/21 checks pass (status
  completeness, viewer read/write boundary, operator write access,
  attribution, and the Origin check still running first).
- **Full existing regression suite unaffected**: `tenant_isolation_test.py`
  (14/14), `sdk_test.py`, `content_guardrail_test.py` (9/9) all still pass.

Known limitations, stated directly (same MVP category as everything
else in this repo): static per-key roles, not a full user/session
system with login; no key rotation/expiry; polling, not a websocket,
for live updates (a real "security team monitoring an incident" tool
would want push updates, not a manual refresh button — not attempted
this pass); REST only, the proposal's own §4.2 also mentions gRPC.

**This closes the proposal's entire Phase 2 enterprise tier (§7.2)** —
compliance templates (above) and the managed dashboard, both done.

## Phase 2 enterprise tier: HIPAA/PCI-DSS/EU AI Act compliance templates, 2026-09-27

The proposal's own §7.2 Phase 2 scope (business-stage, not part of the
6-month build roadmap — see PLAN.md) names HIPAA/PCI-DSS/EU AI Act
policy templates as the next step after SOC 2, "following the same
`packages/compliance` pattern." This does exactly that.

- New `HIPAA_MAPPING.md`, `PCI_DSS_MAPPING.md`, `EU_AI_ACT_MAPPING.md` —
  same structure and same disclaimer-first style as the existing
  `CONTROL_MAPPING.md` (SOC 2): a real citation-by-citation table (45 CFR
  §164.312 for HIPAA, PCI-DSS v4.0 requirement numbers, EU AI Act
  Articles 9-15), each explicitly scoped to what a runtime containment
  layer can actually evidence, with a direct statement of what's out of
  scope for that framework (PCI-DSS Req 11 penetration testing, EU AI
  Act Article 10 training-data governance and Article 43 conformity
  assessment, HIPAA's administrative/physical safeguards). Each also
  states directly where AEGIS's own detection is narrower than the
  framework's own term — PII detection is NOT PHI detection (HIPAA); a
  Luhn-validated credit-card match is NOT a PAN-discovery guarantee
  (PCI-DSS).
- New `templates/hipaa.yaml`, `templates/pci-dss.yaml`,
  `templates/eu-ai-act.yaml` — same schema as the existing
  `policy.example.yaml`/`soc2-*.yaml` templates, tuned per framework:
  HIPAA/PCI-DSS lean toward `soc2-strict.yaml`'s minimal-allowlist
  posture (PHI/cardholder-data exposure risk from a misconfigured agent
  is a materially different failure mode than an ordinary confidentiality
  incident); EU AI Act leans toward `soc2-standard.yaml`'s working-agent
  posture but with a lower violation threshold (3, between standard's 5
  and strict's 2) specifically reflecting Article 14's human-oversight
  emphasis — a working agent that gets a human's attention sooner, not
  a working agent doing less.
- `soc2_report.py` renamed `compliance_report.py` and generalized with a
  `--framework {soc2,hipaa,pci-dss,eu-ai-act}` flag (default `soc2`, so
  the pre-existing `python soc2_report.py --format pdf` command's
  behavior is unchanged under its new name). `aggregate()` gained a real
  new evidence source: counts of `content_guardrail_decision` events
  (and their categories) from the audit log during the report's time
  range — genuine dynamic evidence for HIPAA's/PCI-DSS's new
  `HIPAA-CG`/`PCI-CG` control rows, not a static claim that
  content-guardrail exists.
- **Found and fixed by testing, not assumed clean, twice**:
  1. Generating a real PDF for the new PCI-DSS control text (which uses
     an em dash, following this repo's own prose style) crashed with
     `FPDFUnicodeEncodingException` — fpdf2's core fonts (Helvetica/
     Times/Courier) only support Latin-1. Fixed with `_pdf_safe()`, a
     transliteration step (em/en dash → hyphen, curly quotes → straight,
     ellipsis → `...`) applied only in the PDF renderer — markdown/json
     output keep real UTF-8 untouched.
  2. Separately, the markdown/json file writes were mangling the same
     em dashes into a replacement character (`�`) — Python's
     `open()` without an explicit `encoding=` uses the platform locale
     encoding, not UTF-8, on Windows. Fixed by passing `encoding="utf-8"`
     explicitly on both write sites. Caught by actually reading the
     written file back and checking its bytes, not by assuming the fpdf
     fix covered every output path.

Verified against the live stack:
- **Real enforcement, not just "OPA accepted the data"**: applied each
  of the three new templates to a live OPA instance via the same
  mechanism `aegisctl policy apply` uses, then drove real allow/deny
  checks — HIPAA's empty `allowed_tools` genuinely denies a `tool_call`,
  PCI-DSS's empty `allowed_credential_actions` genuinely denies a
  `credential_use`, EU AI Act's working allowlist genuinely allows
  `read_file` while denying `send_email`.
- **Real dynamic evidence**: generated a genuine PII leak through the
  live `content-guardrail` service, then confirmed the HIPAA report's
  `HIPAA-CG` row actually counted it (`1 content-guardrail check(s)...
  1 PII-category match(es)`) — not a hardcoded example number.
- **All 4 frameworks × 3 formats (12 combinations) generate successfully
  against the live stack**, including the original `soc2` framework
  under the renamed script — confirmed the rename/generalization didn't
  regress the pre-existing behavior.
- New `demo/compliance_templates_test.py` — 21/21 checks pass (template
  enforcement for all three new frameworks, all 12 report
  framework/format combinations, and the UTF-8 encoding fix).
- **Full existing regression suite unaffected**: `tenant_isolation_test.py`
  (14/14), `sdk_test.py`, `content_guardrail_test.py` (9/9) all still pass.

Known gaps, stated directly (same as the existing SOC 2 package, now
true of all four frameworks): not wired into `aegisctl`; no continuous
evidence collection/scheduler — this generates a report on demand from
whatever's currently in the audit log, which doesn't constitute an
observation period for any of these frameworks; none of the four
mappings are vetted by a licensed assessor for that specific framework.
The managed-dashboard half of the proposal's Phase 2 scope (§7.2) is a
separate, larger, not-yet-started item.

## Gap-closing backlog: content-guardrail adversarial hardening, 2026-09-16

Replaces `packages/content-guardrail`'s "no adversarial-robustness
testing" disclosure with an actual measured number, and broadens/fixes
the prompt-injection detector along the way — requested directly as
follow-up hardening on the content-guardrail work above, not from the
proposal.

- `_INJECTION_PATTERNS` broadened from 6 to 12 categories: added
  `forget_instructions`, `query_own_rules`, `unrestricted_persona`,
  `fake_system_marker` (`[SYSTEM]`/`###instruction`/fake chat-template
  markers), `encoded_response_request` ("respond in base64" — an
  evasion-*enabling* request, not evasion itself), and
  `priming_confirmation` (getting the model to "agree" to new rules).
- New `_normalize()` — Unicode NFKC, zero-width character stripping
  (U+200B/U+200C/U+200D/U+FEFF), whitespace-run collapsing — applied
  before both injection and toxic-content matching. Documented honestly
  in its own docstring as a modest first line of defense, not a claim of
  solving adversarial robustness: it cannot and does not catch semantic
  paraphrasing or letter-by-letter spacing.
- New `test_injection_adversarial.py` — a curated set of 12 known
  jailbreak/injection techniques (one per detector category, real
  recognizable techniques, not strawmen), a set of mechanical evasion
  variants of the same techniques (whitespace, zero-width chars,
  fullwidth Unicode, mixed case, plus one genuine semantic paraphrase),
  and 6 benign vocabulary-adjacent strings for a false-positive check.
- **Found and fixed by running the new test, not assumed correct**: the
  first pass missed "Disregard the above rules entirely from now on" —
  an entirely ordinary phrasing of a technique already in the pattern
  list — because "the" wasn't in the optional filler-word set between
  "disregard" and "above." Fixed by allowing common filler words
  (a/an/the/my); re-ran the full suite afterward to confirm 100% recall
  again, not just that one case.
- Also found and fixed while building the test: printing some of the
  Unicode evasion variants crashed on Windows' default console codepage
  (`UnicodeEncodeError`) — reconfigured the test's stdout to UTF-8 with
  `backslashreplace` so a display detail can't mask the actual test
  result.

Verified, with real measured numbers rather than "should work":
- **12/12 (100%) known-attack recall** on the curated set.
- **Normalization confirmed to defeat 3 of 4 mechanical evasion
  variants** (extra whitespace, zero-width characters, mixed case) of
  the same attacks — checked directly per variant, not assumed from
  what Unicode normalization "should" do. A fullwidth-Unicode variant
  was also caught, an NFKC side effect noted as such, not claimed as a
  designed feature.
- **A genuine semantic paraphrase confirmed NOT caught** — the test
  asserts this fails, matching (and now quantifying) the disclosed
  limitation, rather than silently passing or hiding the gap.
- **0 false positives** on 6 benign strings sharing vocabulary with the
  attack patterns (e.g. "ignore the typo in my previous message,"
  "what are the rules of chess").
- Confirmed live against the running `content-guardrail` container
  (fullwidth-Unicode evasion attempt), not just the offline test.
- **Full existing regression suite unaffected**: `content_guardrail_test.py`
  (9/9), `tenant_isolation_test.py` (14/14), `sdk_test.py`,
  `wrapper_test.py` all still pass.

Known gaps, stated directly: the 12-technique set is real but not
exhaustive of every documented jailbreak technique in AI-safety
research — a broader, ongoing red-team effort would likely find more
gaps than this one pass did; semantic paraphrasing remains categorically
uncatchable by this pattern-matching approach, not a bug to fix later
but a structural limit of the technique.

## Gap-closing backlog: Vault root-token replacement (AppRole), 2026-09-16

Closes the deeper half of the scoped-short-lived-tokens entry above: at
the time that entry was written, `VAULT_TOKEN` (the static dev-mode root
token) still minted every scoped child token — narrowed in effect, not
eliminated. This replaces it with a real AppRole identity.

- `demo/docker-compose.yml`'s `vault-init` now also bootstraps an AppRole
  identity, using the root token exactly ONCE — the same
  bootstrap-once-then-never-again pattern a real Vault deployment already
  uses for AppRole/Kubernetes-auth/etc. Writes a policy
  (`aegis-credential-broker-admin`) granting only `update`+`sudo` on
  `auth/token/create` and `create`/`update`/`read` on
  `sys/policies/acl/aegis-tenant-*` — specifically NOT `secret/data/*`
  read access. Creates the AppRole role, writes the generated
  `role_id`/`secret_id` to a new shared Docker volume
  (`vault-approle-data`) — `credential-vault`'s only way to obtain them,
  since Vault dev-mode is in-memory and generates them fresh every startup.
  `credential-vault`'s own `depends_on` now uses `condition:
  service_completed_successfully` for `vault-init` specifically (Compose's
  default `service_started` doesn't mean "finished writing the files" for
  a one-shot init container) — `credential_broker.py`'s own retry loop on
  those files is defense in depth on top of that, not a substitute for it.
- New `credential_broker.py` functions: `_read_approle_credentials`
  (reads the shared volume, retries), `_approle_login` (`POST
  auth/approle/login`), `_get_broker_token` (this service's own operating
  credential — logs in fresh at 50% of the granted lease, not reused
  forever), `_privileged_vault_request` (retries once with a forced
  fresh login on a `403`, covering out-of-band revocation).
  `_ensure_tenant_policy`/`_mint_scoped_token` now go through this
  instead of the module-level `VAULT_TOKEN`, which this service no
  longer imports at all.
- **Found by testing, not assumed**: the first version of the AppRole
  policy granted only `capabilities = ["update"]` on `auth/token/create`
  — every credentialed call through the live stack failed with
  `{"errors":["child policies must be subset of parent"]}`. Root caused
  directly against the real error body (not guessed): Vault requires
  `sudo` capability on that path for a non-root caller to mint a child
  token with policies it doesn't itself hold. Added `"sudo"`; the
  identical request that failed before then succeeded, re-verified
  end-to-end afterward rather than assumed fixed from reading the docs.

Verified against the live stack:
- **The actual security property, checked against Vault itself**: execed
  into the live `credential-vault` container and confirmed its own
  operating token gets a genuine Vault-side `403` trying to read
  `secret/data/default/protected-api` directly — the real improvement
  over the old root token, not this code's opinion of what its policy
  says.
- **Confirmed the token is real, not the root string**: the same exec
  confirmed `_get_broker_token()` returns a real `hvs.*`-prefixed Vault
  token, not the literal `"aegis-dev-root"` value.
- **Confirmed the narrower identity still does its actual job**: the
  same exec confirmed `_mint_scoped_token('default')` still succeeds —
  this is "denied exactly the one thing it never needed," not "broken."
- **Confirmed `vault-init` completes successfully**: `docker inspect`
  shows exit code `0` after enabling AppRole, writing the policy,
  creating the role, and writing both credential files.
- New `demo/vault_approle_test.py` — 4/4 checks pass (the four bullets above).
- **Full regression suite unaffected**: `demo/vault_scoped_token_test.py`
  (9/9 — the tenant-scoping/single-use/TTL properties from the earlier
  entry are all still intact on top of this), `tenant_isolation_test.py`
  (14/14), `sdk_test.py`, `wrapper_test.py`, and
  `content_guardrail_test.py` (9/9) all still pass.

Known gap, stated directly: the AppRole `secret_id` itself is written to
disk once and never rotated — Vault supports rotating it natively, but
this MVP treats it as permanent once issued, same as any other
demo-mode credential in this repo that's disclosed as "replace before
a real deployment."

## New capability, requested directly (not from the proposal): content guardrails, 2026-09-16

AEGIS's six proposal layers govern actions, network egress, and
credentials — none of them look at the actual TEXT flowing to or from
the LLM. This adds a seventh, standalone layer that does, following the
same "each layer independently useful and independently degradable"
architecture the other six already use — not folded into OPA/Rego,
same reasoning `anomaly-detector` and `circuit-breaker` already use for
staying separate services (Rego is good at declarative allow/deny over
structured data; pattern-matching free text is a different job).

- New `packages/content-guardrail` (stdlib-only Python, `POST /check`).
  Three detectors: PII (email/phone/SSN/credit-card regexes, both
  directions), prompt injection (a fixed phrase list, `direction="input"`
  only — steering the agent only makes sense on what's fed to it), toxic
  content (a small keyword MVP, `direction="output"` only).
- **Explicitly not a trained classifier for toxicity**, unlike
  `anomaly-detector`'s ML work above: that classifier could be trained
  on a defensible synthetic dataset built from this repo's own numeric
  behavioral signal (session action counts). Toxicity needs real labeled
  human-language examples this repo doesn't have and can't honestly
  synthesize — a keyword list is a real, if weak, MVP, stated as such
  rather than dressed up as "AI-powered."
- Every matched PII value is masked (`_mask`: first/last character kept)
  before it ever appears in a response or the audit log.
- Reuses existing mechanisms rather than adding new ones: a `blocked`
  result reports to `circuit-breaker`'s existing violation counter (the
  same one policy denials already use), and logs a
  `content_guardrail_decision` event to `audit-logger` alongside
  `policy_decision` events — no new circuit-breaker logic, no second
  audit trail.
- New `AegisClient.check_content(text, direction)` /
  `ContentDenied` in `packages/sdk` — fail-open like every other
  non-policy-engine call in that client, so an unreachable
  content-guardrail never blocks a real agent's core functionality.
- **Found and fixed by testing locally before this ever ran live**: the
  first version of the credit-card regex (13–19 digit run, optionally
  separated) flagged ANY long numeric ID as a "credit card" — confirmed
  false positives on a plain session-id-shaped string and a 14-digit
  date-shaped string during local testing. Fixed with a real Luhn
  checksum (ISO/IEC 7812, the algorithm every real card number
  satisfies) as a second-pass filter — verified the same false positives
  disappear while real (test) card numbers still pass.
- New `config.py` constants: `CONTENT_GUARDRAIL_PORT` (`9200`),
  `CONTENT_GUARDRAIL_URL`. New `demo/docker-compose.yml` service.

Verified against the live stack, through the SDK (not raw HTTP, so this
also proves the SDK integration):
- **`demo/content_guardrail_test.py`: 9/9 checks pass** — PII in output
  raises `ContentDenied` with the right category; the raw matched email
  address is confirmed absent from both the response and the live
  audit-logger's stored event (not assumed masked); prompt injection is
  blocked on `input` but the identical phrasing is confirmed NOT blocked
  on `output`; ordinary benign input/output is never blocked; five
  content-guardrail denials in one session cross
  `circuit-breaker`'s existing violation threshold and suspend it, the
  same way five policy denials already do.
- **Full existing regression suite unaffected**: `sdk_test.py`,
  `wrapper_test.py`, `tenant_isolation_test.py` (14/14) all still pass.

Known gaps, stated directly at the time of this entry: toxicity
detection is a keyword MVP, not a trained classifier (see above);
~~prompt-injection detection is a fixed phrase list, no
adversarial-robustness testing beyond confirming the input/output-direction
distinction itself works~~ — given a real measured number the same day,
see "Gap-closing backlog: content-guardrail adversarial hardening"
below (100% recall on a 12-technique set, 0 false positives, semantic
paraphrasing confirmed as the actual remaining limit); regex-based PII
misses unseparated phone numbers and isn't locale-aware beyond US
formats; no per-tenant tuning of thresholds/pattern lists yet.

## Gap-closing backlog: circuit-breaker-rs tier parity, 2026-09-16

`circuit-breaker-rs` gets the two escalation tiers it was missing —
`hard_suspend` and `emergency_kill` — mirroring
`packages/circuit-breaker/circuit_breaker.py`'s implementation exactly,
closing the parity gap the earlier "circuit-breaker hard-suspend/
emergency-kill tiers" and "real webhook notifications" entries both
disclosed at the time.

- `SuspensionMeta` gained a real `tier: String` field — previously a
  hardcoded `"soft_pause"`/`"terminated"` literal derived at read time
  purely to keep `demo/circuit_breaker_parity_test.py` passing. New
  `suspend_with_tier()` helper factors out the shared
  suspend-everything effect `soft_pause`/`hard_suspend`/`emergency_kill`
  all need, mirroring `circuit_breaker.py`'s `suspend_directly(...,
  tier=...)` being reused internally by its own `hard_suspend`/
  `emergency_kill`.
- New `fetch_audit_trail`/`capture_snapshot` — real HTTP GET to
  `packages/audit-logger` (`AEGIS_AUDIT_URL`, new env var, default
  `http://audit-logger:9300`) for the actual session audit trail, same
  as the Python service's `_fetch_audit_trail`/`_capture_snapshot`.
  `GET /snapshot/<tenant>/<session>` retrieves it.
- New `kill_container` — real Docker Engine API call via the `bollard`
  crate (Rust's equivalent of the Python service's `docker` PyPI
  package), added as a new dependency. `docker: Option<bollard::Docker>`
  on `AppState`, connected at startup via
  `Docker::connect_with_local_defaults()` — `None` (not a startup
  failure) if the socket isn't reachable, so `emergency_kill` degrades
  honestly rather than the whole service refusing to start.
- New `POST /register/<tenant>/<session>` (opts a session in to being
  killable, 400 if `container_id` is missing — matches the Python
  service's validation) and the `POST /hard-suspend`, `POST
  /emergency-kill` routes themselves.
- `demo/docker-compose.yml`: `circuit-breaker-rs` now also mounts the
  Docker socket and gets `AEGIS_AUDIT_URL`, same privilege-grant caveat
  as `circuit-breaker`'s existing mount.
- Found one real bollard API mismatch at compile time (not from
  documentation, which wasn't consulted — from the compiler's own error):
  `bollard::query_parameters::KillContainerOptions` doesn't exist in the
  pinned version; the correct path is
  `bollard::container::KillContainerOptions`. Fixed, rebuilt clean.

Verified against the live stack:
- **Real forensic snapshot on Rust**: posted a real audit event, called
  `circuit-breaker-rs`'s `/hard-suspend` directly, confirmed both the
  response and a follow-up `GET /snapshot` contain that actual event
  (matched by its real `target` field) — not inferred from the Python
  service's already-verified behavior.
- **Real container kill on Rust — the same direct proof used for the
  Python service**: started a genuine throwaway `alpine` container,
  confirmed `running` via `docker inspect`, registered it with
  `circuit-breaker-rs`, called `/emergency-kill`, confirmed via a fresh
  `docker inspect` that it's now `exited`.
- **`demo/circuit_breaker_tiers_test.py` reworked to run its full 12-check
  sequence against BOTH services** (24 checks total): 24/24 pass,
  including a real throwaway container killed through each service
  independently, not one shared instance.
- **`demo/circuit_breaker_parity_test.py`: still 29/29** — the real
  `tier` field didn't disturb the existing parity checks (which never
  exercised `hard_suspend`/`emergency_kill`, only `soft_pause`/
  `terminated`, both still literal-for-literal identical).
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  `tenant_isolation_test.py` (14/14), `webhook_test.py` (12/12), and
  `vault_scoped_token_test.py` (9/9) all still pass.
- **Checked for a load-test regression, found none**: re-ran
  `demo/load_test.py --phase circuit_breaker_only` — sustains 25 cleanly,
  aborts at 100 on a p95 timing threshold with zero errors, consistent
  with (not a regression from) this repo's already-documented
  single-machine variance; that phase only exercises `/status` and
  `/activity`, neither of which this change touches at all.

`emergency_kill`'s "VM terminated" half of the proposal's wording is
**descoped**, not "not started by oversight" — same category of decision
as Sprint 4's eBPF interceptor. Genuinely testing it needs a real VM an
agent's runtime could be destroyed in (a cloud provider's
terminate-instance API, or a local hypervisor a container could be handed
control of); this environment has neither, and building one just to
exercise this one code path — unlike the container-kill half, which this
environment's own Docker daemon already provides for real — wasn't
judged worth it. The container-kill half is real and verified (above);
this is a stated, deliberate scope boundary, not a silent gap.

## Gap-closing backlog: scoped short-lived Vault tokens, 2026-09-16

`packages/credential-vault` used to send `VAULT_TOKEN` (the static
dev-mode root token) directly to Vault on every secret read — a token
capable of reading (and writing) anything in Vault, for every tenant, with
no expiry. Every read now goes through a freshly-minted, tenant-scoped,
short-TTL, single-use child token instead.

- `_ensure_tenant_policy(tenant_id)` (new) — idempotently creates a Vault
  ACL policy (`aegis-tenant-<tenant_id>-readonly`, `PUT
  sys/policies/acl/<name>`) granting read-only access to exactly
  `secret/data/<tenant_id>/*`. Cached in-memory per tenant after the
  first call. `tenant_id` is already validated against
  `_TENANT_ID_PATTERN` by the existing handler (see this file's 2026-08-22
  security-review entry), so it's safe to interpolate into the HCL body.
- `_mint_scoped_token(tenant_id)` (new) — `POST auth/token/create` with
  that one policy, `config.py`'s new `VAULT_SCOPED_TOKEN_TTL` (`60s`) and
  `VAULT_SCOPED_TOKEN_NUM_USES` (`1`). `VAULT_TOKEN` (root) is the parent
  authority for this one privileged call only — it never touches a
  secret read again.
- `_fetch_secret` now takes the minted token as a parameter instead of
  closing over the global `VAULT_TOKEN`.
- **Found and fixed during first live test, not assumed clean**: the
  first version crashed every credentialed call with a `JSONDecodeError`
  — Vault's policy-PUT endpoint returns an empty `204` body, and
  `_vault_request` unconditionally tried to `json.loads()` it. Caught
  immediately by actually running a credentialed call against the live
  stack (not just reading the code), fixed by treating an empty body as
  `{}`.

Verified against the live stack:
- **Vault-side enforcement, not application-side**: minted a real
  tenant-acme-scoped token directly against Vault and confirmed Vault
  itself returns `403 permission denied` reading the default tenant's
  secret with it — the isolation is Vault's ACL engine, not this code's
  own opinion.
- **Genuinely single-use**: the same minted token's second read attempt
  is rejected by Vault (`invalid token`) — confirmed by actually reusing
  it, not read from the `num_uses` parameter.
- **Genuinely time-limited**: a token minted with `ttl=2s` was rejected
  after a real 3-second sleep, independent of `num_uses` (5 unused uses
  remained) — confirmed the *time* limit specifically, not just the use-count one.
- New `demo/vault_scoped_token_test.py` — 9/9 checks pass, including a
  static-source check that `_fetch_secret`'s only call site passes the
  minted token, not the global `VAULT_TOKEN`.
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  `tenant_isolation_test.py` (14/14 — including the two credential-vault
  isolation checks), `circuit_breaker_parity_test.py` (29/29),
  `circuit_breaker_tiers_test.py` (12/12), and `webhook_test.py` (12/12)
  all still pass.
- **Overhead measured, not assumed negligible**: 20 sequential
  credentialed calls averaged ~8ms/request against the demo stack,
  including the extra Vault round trip to mint each call's token.

Known gap, stated directly: `VAULT_TOKEN` is still a static root token
under the hood — narrowed to policy/token-administration use only, not
replaced with a renewable orchestrator identity (AppRole or similar). A
real deployment needs that too; this closes the "every read uses an
unscoped, undying token" half of the gap, not the "root token exists at
all" half.

## Gap-closing backlog: real webhook notifications, 2026-09-16

Every circuit-breaker suspend/terminate/emergency-kill used to only print
`"WEBHOOK: ..."` to stdout — this replaces that with a real HTTP POST, in
both `packages/circuit-breaker` (Python) and `circuit-breaker-rs` (Rust),
matching each other's payload shape exactly.

- `config.py`'s new `WEBHOOK_URL` (empty string = disabled — same
  convention as the existing `SIEM_URL`) and `circuit_breaker.py`'s new
  `_send_webhook()`. Payload always includes a `"text"` field (all a real
  Slack Incoming Webhook ever reads) plus structured fields (`tenant_id`,
  `session_id`, `tier`, `reason`, `event`) for a generic receiver.
  Dispatched on a background thread from every caller (`record_violation`,
  `suspend_directly`, `emergency_kill`, `terminate`) — same "don't block
  the write path on a network call" fix as audit-logger's performance
  entry above, applied here from the start rather than found as a bug
  later.
- `circuit-breaker-rs`'s new `AEGIS_WEBHOOK_URL` and `send_webhook()`
  (`main.rs`) — identical payload shape, dispatched via `tokio::spawn`
  rather than awaited inline, same reasoning.
- New `demo/mock-webhook/` — stands in for a real Slack Incoming
  Webhook / email-relay endpoint, same role `demo/mock-siem` plays for
  Layer 6's SIEM forwarding. `GET /received` lets a test confirm delivery.
- `demo/docker-compose.yml`: new `mock-webhook` service; both
  circuit-breaker services now depend on it and point at it by default.

Verified against the live stack:
- **Real HTTP delivery confirmed on both services**: suspended a session
  via each of `packages/circuit-breaker` and `circuit-breaker-rs`
  directly, then confirmed `demo/mock-webhook`'s `/received` actually
  grew and contains the real `session_id`/`reason` — not inferred from
  the code, read back from the receiver.
- **Every tier fires the correctly-labeled event**: re-ran
  `demo/circuit_breaker_tiers_test.py` (hard-suspend, emergency-kill,
  register) with webhooks enabled and confirmed `mock-webhook` received
  15 notifications across the run, each tagged with the right tier
  (`soft_pause`, `hard_suspend`, `emergency_kill`, `terminated`) —
  checked directly against the receiver's stored list, not assumed from
  which endpoint was called.
- New `demo/webhook_test.py` — 12/12 checks pass, covering both services
  and the terminate path.
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  `tenant_isolation_test.py` (14/14), and
  `demo/circuit_breaker_parity_test.py` (29/29) all still pass.

Known gap, stated directly: still not real Slack/email — `demo/mock-webhook`
is a stand-in, same category as `demo/mock-siem`; pointing `WEBHOOK_URL`/
`AEGIS_WEBHOOK_URL` at a real Slack Incoming Webhook URL is a one-line
config change, not a code change, but wasn't tested against a real
Slack workspace here.

## Gap-closing backlog: circuit-breaker hard-suspend/emergency-kill tiers, 2026-09-16

Implements the two escalation tiers `packages/circuit-breaker`'s README
disclosed as missing since Sprint 4: the proposal's own three levels for
this layer (§3.2 Layer 5 "How it works") are "soft pause" (already
implemented — the existing suspend/resume mechanism), "hard suspend"
(freeze + forensic snapshot), and "emergency kill" (destroy the runtime,
container killed / VM terminated).

- New in `circuit_breaker.py`: `hard_suspend()` — same suspend-everything
  effect as before, plus a REAL forensic snapshot: fetches the session's
  actual recent audit trail live from `packages/audit-logger`
  (`_fetch_audit_trail`) and stores it (`GET /snapshot/<tenant>/<session>`
  to retrieve), not a placeholder object.
- New `emergency_kill()` — does everything `hard_suspend` does (snapshot
  captured before any kill attempt, so it survives regardless of outcome),
  plus a genuine Docker container kill via the Docker Engine API
  (`docker` Python SDK, `container.kill()`) — but only for a session that
  called the new `POST /register/<tenant>/<session>` first with its own
  container id. No registration means no container to kill, reported
  honestly as `{"kill": {"attempted": false, ...}}`, never a false
  "success." `packages/sdk/aegis_sdk`'s new `AegisClient.register_runtime()`
  is the intended caller, defaulting to `$HOSTNAME` (Docker sets this to
  the running container's own short id unless overridden).
- `demo/docker-compose.yml`: mounts the host's Docker socket into
  `circuit-breaker` (Python). Documented explicitly as a meaningful
  privilege grant (full host Docker-daemon control, not a scoped
  capability) — demo-only, same category of disclosed caveat as Vault's
  dev-mode root token elsewhere in this file. A real deployment needs a
  narrowly-scoped agent-lifecycle API instead, never a raw socket mount.
- `packages/circuit-breaker/requirements.txt` (new) — `docker>=7.0`, only
  dependency this service has ever needed; every other endpoint stays
  stdlib-only.
- At the time of this entry, `circuit-breaker-rs` did NOT get these two
  tiers — implementing real Docker API access and audit-trail fetching in
  Rust was deferred, not in scope for this pass. `circuit-breaker-rs`'s
  `/suspend`/`/suspended` responses got a literal `"tier": "soft_pause"`
  field purely to keep `demo/circuit_breaker_parity_test.py` meaningful in
  the meantime. **This gap is closed** — see "Gap-closing backlog:
  circuit-breaker-rs tier parity" below: `circuit-breaker-rs` now
  implements `hard_suspend`/`emergency_kill` for real, and `tier` is a
  genuine per-suspension field there too, not a literal.

Verified against the live stack:
- **Real forensic snapshot**: posted two real audit events for a test
  session, called `/hard-suspend`, confirmed the response and a follow-up
  `GET /snapshot` both contain the actual posted event (matched by its
  real `target` field), not a stub.
- **Real container kill — the direct proof this isn't an in-memory flag**:
  started a genuine throwaway `alpine` container via `docker run`,
  confirmed `docker inspect` shows `running`, registered its container
  name via `/register`, called `/emergency-kill`, then confirmed via a
  fresh `docker inspect` (not the circuit breaker's own report) that the
  container's real state is now `exited`.
- **Honest degradation confirmed**: `/emergency-kill` on a session with no
  registration returns `{"attempted": false, "success": false, "error":
  "no container registered for this session"}` — checked explicitly, not
  assumed from the code.
- New `demo/circuit_breaker_tiers_test.py` — automates all three of the
  above: 12/12 checks pass.
- **`demo/circuit_breaker_parity_test.py`: still 29/29** after the `tier`
  field addition to both services (initially broke 4 checks when only
  the Python service had it — fixed by adding the same literal to
  `circuit-breaker-rs`, not by loosening the test).
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  and `tenant_isolation_test.py` (14/14) all still pass.

Known gaps, stated directly at the time of this entry: ~~`circuit-breaker-rs`
parity (above)~~ — closed later the same day, see "Gap-closing backlog:
circuit-breaker-rs tier parity"; ~~webhook notifications for these two new
tiers are still stdout prints, same limitation as the existing tier~~ —
also closed later the same day, see "Gap-closing backlog: real webhook
notifications." `emergency_kill`'s "VM terminated" half of the
proposal's wording is **descoped** on both services (see the later,
fuller entry on this) — not implemented, but a deliberate scope
boundary, not an oversight.

## Gap-closing backlog: anomaly-detector ML classifier, 2026-09-16

Replaces the Sprint 3 rule engine's four hardcoded thresholds with a
trained classifier — the sequence classifier the proposal specs for Layer
4 (§4.7: "a fine-tuned transformer classifier"). No real labeled session
data or GPU training exists in this environment, so this is the same
"real but simple" MVP substitute this repo uses elsewhere (SQLite not
Postgres, dev-mode not real Vault): a genuinely trained and evaluated
scikit-learn `RandomForestClassifier`, not a stub that returns a fixed
number.

- New `packages/anomaly-detector/features.py` — extracts 8 numeric
  features from a session's existing rolling window (the same underlying
  signal the rule engine already computed, just continuous instead of
  hard thresholds). Imported by both training and serving code
  specifically so they can never compute "the same" feature differently —
  the single most common way a real ML system silently breaks.
- New `packages/anomaly-detector/train_classifier.py` — synthetic session
  generators (benign, three "clear" malicious flavors matching the old
  rule categories, and a "blended" flavor: moderate signal across two
  dimensions each individually below the old thresholds) plus matching
  "hard negative" benign sessions (one legitimately elevated feature,
  nothing else unusual). Trains a `RandomForestClassifier`, evaluates on
  a held-out split, saves `model.joblib`.
- **Found and fixed during training, not after**: the first version of
  the "hard negative" generator included a "many file reads, all
  allowed" benign variant that turned out to have an *identical* feature
  vector to the malicious reconnaissance generator for the same count —
  pure label noise, not a genuine hard negative (real bulk-reads vs.
  reconnaissance genuinely aren't distinguishable in this feature space,
  and the old rule engine had the exact same blind spot: any 10+
  file-read session was flagged unconditionally, no exception). This
  directly tanked the model's confidence on the *existing* regression
  test's shape (11 file-reads) to 0.315 — caught by re-running
  `test_classifier.py` against the freshly trained model, not assumed.
  Removed that variant; retrained; the affected check passed cleanly.
- `packages/anomaly-detector/anomaly_detector.py`'s `_score()` now scores
  via `model.predict_proba`, mapped to severity at 0.85 (critical) / 0.5
  (warning) — chosen to preserve the old two-tier severity split so
  existing callers/tests keep working, not tuned against a real
  false-positive rate. `self_modification` stays a deterministic pattern
  match, per the proposal's own "immediate critical, no threshold needed"
  wording for it — kept out of the model entirely, not fed as a feature.
  The response's `flags` list is now descriptive (audit-trail vocabulary),
  not decisive — includes a new `ml_anomaly` flag when the model alone
  crosses the warning threshold with none of the named categories
  individually firing, the direct visible marker of the model catching
  something the old thresholds structurally couldn't have named.
- Version-pinned `scikit-learn==1.7.2` in the new `requirements.txt`
  (previously `>=1.4`) after the rebuilt container logged scikit-learn's
  own `InconsistentVersionWarning` — it had resolved 1.9.1 at build time
  against a model pickled with 1.7.2. Caught by reading the container's
  own startup log, not assumed silent.

Verified against the live stack:
- **`test_classifier.py`: 6/6 checks pass**, including the direct
  evasion-case proof — a hand-built session (2 distinct denied types, 4
  distinct targets) crosses none of the old individual thresholds (proven
  by literally re-running that old logic against the same input inside
  the test), while the classifier flags it anyway (probability ≥ 0.5).
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  and `tenant_isolation_test.py` (14/14) all pass against the rebuilt
  service — including "default tenant's session suspended by anomaly
  detector (reconnaissance)," proving the live model, not just the
  offline test, reproduces the required suspend behavior end-to-end.
- **Live direct-HTTP replay of the blended-evasion pattern** against the
  running container (`POST /events` for 2 distinct denied action types,
  then 4 distinct `http_request` targets, via `curl`): `flags:
  ["ml_anomaly"]` and `severity: "warning"` appear after only 2 actions —
  well before either old threshold (3 denied types, 5 targets) would
  have fired anything. Confirms the earlier claim wasn't just an offline
  test artifact.
- Confirmed no scikit-learn version-mismatch warning in the container log
  after pinning.

Known gaps, stated directly: trained on synthetic data, not real session
traffic (no labeled real-world dataset exists to train on instead);
`test_classifier.py` covers one specific evasion shape, not a broader
adversarial-robustness campaign (still a stated gap, just a smaller one
than before); severity thresholds are global, not per-policy-profile or
per-task-baseline. See `packages/anomaly-detector/README.md`'s "Known
limitations" for the full list.

## Gap-closing backlog: audit-logger performance fix, 2026-09-16

The two causes named in "Next up" (below, from the 2026-08-22 global-lock
investigation) for `audit-logger`'s own compute/lock pressure — not in
scope for the Rust circuit-breaker rewrite, which was circuit-breaker-
specific.

- `do_POST`/`do_GET` called `connect()` fresh on **every single request**,
  which for the SQLite backend re-ran `CREATE TABLE IF NOT EXISTS` and
  reopened the DB file every time. Fixed with `get_conn()`: one connection
  cached per handler thread (`threading.local()`), created once and reused
  for the lifetime of that thread — `ThreadingHTTPServer` gives each
  persistent (HTTP/1.1, since the keep-alive fix) connection its own
  thread, so this is reused across every request on that connection, not
  just the first.
- `_forward_to_anomaly_detector` ran inline in the response path, adding up
  to ~1s of latency to every write if the anomaly detector was slow or
  unreachable. Fixed by moving both it and `_forward_to_siem` (same class of
  problem) onto a fire-and-forget background thread — the response no
  longer waits on either forward.

The existing `_lock` serializing the read-last-hash + write-next-row
sequence in `append_event` was kept as-is; per-thread connections don't
remove the need for it, since multiple threads can still race on the hash
chain.

Verified against the live stack, same methodology as the keep-alive and
Rust-rewrite entries above:
- **Before/after via `demo/load_test.py --phase audit_logger_only`**,
  isolating the code change by reverting it, rebuilding, testing, then
  restoring it and rebuilding again (not comparing against a stale image).
  Before: cleanly sustained concurrency=25 (p95 203ms), aborted at
  concurrency=100 (p95 2.17s, over the script's 2.0s abort threshold).
  After: cleanly sustained concurrency=100 (p95 422ms — 4x the concurrency,
  at *better* latency than the old ceiling), aborted at concurrency=500
  (p95 6.59s, 28.8% errors).
- **Full regression suite unaffected**: `sdk_test.py`, `wrapper_test.py`,
  and `tenant_isolation_test.py` (14/14) all pass against the rebuilt
  service.
- **Hash-chain integrity directly checked after the load test's thousands
  of concurrent writes**: `GET /verify` returned `chain_intact: true` for
  both tenants exercised (`default`, `tenant-acme`) — confirms the
  thread-local connection change didn't disturb the write-ordering
  guarantee `_lock` provides.

Known gap, stated directly: audit-logger's ceiling is still nowhere near
10K concurrent (this test found ~500, not 10K) — this fixes the two named
causes, not a claim of hitting the proposal's literal target.

## Not yet built / tested

- ~~Audit log storage is SQLite only; the `audit-db` Postgres container
  runs but nothing talks to it yet~~ — **fixed**, see "Gap #3" above:
  `config.py`'s `AUDIT_STORAGE_BACKEND` switches between them, SQLite
  stays the default. No data migration between backends if you switch.
- ~~Circuit breaker only has "soft suspend" and the new "terminate" — no
  "hard suspend" (freeze + forensic snapshot) or "emergency kill" (destroy
  runtime) tiers~~ — **fixed**, see "Gap-closing backlog: circuit-breaker
  hard-suspend/emergency-kill tiers" above: both now exist in the Python
  service, with a real forensic snapshot and a genuine Docker container
  kill, verified against a real throwaway container. ~~`circuit-breaker-rs`
  doesn't have these two tiers~~ — also **fixed**, see "Gap-closing
  backlog: circuit-breaker-rs tier parity" above: full parity now,
  verified against its own real throwaway container independently.
  On both services, only the container-kill half of "emergency kill" is
  implemented — the VM-termination half is **descoped** (see the later,
  dedicated entry for why), the same category of decision as Sprint 4's
  eBPF interceptor, not an oversight.
  ~~Still Python, not the Rust service the proposal specs
  for production latency~~ — a Rust rewrite now exists
  (`packages/circuit-breaker-rs`, see "Gap-closing backlog: Rust
  circuit-breaker rewrite" above) ~~but runs alongside the Python original
  as an operator choice, not wired in as the default~~ — **it now is the
  default** (see "Gap-closing backlog: circuit-breaker-rs default
  cutover," 2026-09-16), with the Python original still available as a
  one-line `config.py` revert. ~~Webhook
  notifications are still stdout prints on both, not real HTTP calls to
  Slack/email~~ — **fixed**, see "Gap-closing backlog: real webhook
  notifications" above: both services now POST to a configurable
  webhook URL (still a `demo/mock-webhook` stand-in, not a real Slack
  workspace).
- ~~Credential vaulting uses a static Vault token, not scoped short-lived
  ones~~ — **fixed**, see "Gap-closing backlog: scoped short-lived Vault
  tokens" above: every secret read now uses a freshly-minted,
  tenant-scoped, 60s-TTL, single-use child token, verified against
  Vault's own ACL enforcement. ~~Remaining limitation: the root token
  that mints those child tokens is still a static dev-mode root token,
  not a renewable orchestrator identity~~ — also **fixed**, same day, see
  "Gap-closing backlog: Vault root-token replacement (AppRole)" above:
  an AppRole identity mints child tokens now, confirmed unable to read a
  secret directly itself (a real `403` from Vault). The root token's only
  remaining job anywhere in this repo is `vault-init`'s one-time AppRole
  bootstrap.
- ~~Anomaly detection is rule-based, not the ML model the proposal
  specs~~ — **fixed**, see "Gap-closing backlog: anomaly-detector ML
  classifier" above: a trained scikit-learn classifier now scores every
  session, trained on synthetic data (no real dataset exists). Remaining
  limitation: not real-world session data, and only one specific evasion
  shape is tested, not a broader adversarial campaign.
- K8s manifests only cover the proxy+OPA sidecar pair — audit-logger,
  circuit-breaker, credential-vault, anomaly-detector, and the dashboard
  don't have Kubernetes manifests yet, and there's no Helm chart (Kustomize
  only), no resource limits/probes/PDB.
- ~~Dashboard API has no authentication~~ — **fixed**, see "Gap #1" above:
  per-tenant API keys, tenant derived server-side from the key, no
  client-supplied `tenant_id` accepted anywhere anymore. Remaining
  limitation: static keys, no rotation/expiry/per-user audit trail within
  a tenant — not a full user/session system.
- ~~Egress proxy authorizes by hostname string only, with no post-DNS-
  resolution IP validation~~ — **fixed**, see "Gap #2" above:
  `packages/proxy/dns-filter` rejects any private/loopback/link-local DNS
  answer before Envoy ever attempts a connection. Remaining limitation:
  filters DNS answers only, doesn't and can't address an attacker who
  already has file/code access inside the proxy container.
- **Sprint 4: DONE.** Multi-tenancy, load testing (+ the HTTP keep-alive fix
  it found and the re-verified before/after numbers), the SOC 2 compliance
  package, and the internal security review (substituting for the
  external audit item) are all done as MVPs — see above for each. The
  eBPF interceptor is **descoped**, not "not started by oversight" — it
  needs a real Linux kernel this environment doesn't have; building one
  just to attempt it wasn't judged worth it, and this was a deliberate
  choice, not a gap that slipped through.

## Next up

Sprint 4 was the last sprint in the proposal's 6-month roadmap (§8) — there
is no Sprint 5 specified. What's next is either of two different kinds of
work:

1. **Closing gaps each MVP already disclosed** — dashboard API
   authentication (Gap #1), the egress proxy's DNS-rebinding gap (Gap #2),
   audit-logger's Postgres wiring (Gap #3), the global-lock hypothesis
   investigation, the Rust circuit-breaker rewrite, audit-logger's own
   compute/lock pressure (per-request SQLite connections, the inline
   anomaly-detector forward — see "Gap-closing backlog: audit-logger
   performance fix" above), wiring `circuit-breaker-rs` in as the default
   (see "circuit-breaker-rs default cutover" above), the trained ML
   anomaly classifier (see "Gap-closing backlog: anomaly-detector ML
   classifier" above), the circuit breaker's hard-suspend/
   emergency-kill tiers (see "Gap-closing backlog: circuit-breaker
   hard-suspend/emergency-kill tiers" above), real webhook
   notifications (see "Gap-closing backlog: real webhook notifications"
   above), scoped short-lived Vault tokens (see "Gap-closing
   backlog: scoped short-lived Vault tokens" above),
   `circuit-breaker-rs` parity for the hard-suspend/emergency-kill tiers
   (see "Gap-closing backlog: circuit-breaker-rs tier parity" above), and
   replacing the Vault root token itself with an AppRole identity (see
   "Gap-closing backlog: Vault root-token replacement (AppRole)" above)
   are all now **done**, see above. **This closes every item on the
   2026-09-16 direct-request priority list, including both halves of the
   Vault token gap.** `emergency_kill`'s "VM terminated" half is
   **descoped** (same category as Sprint 4's eBPF interceptor — needs
   real VM infrastructure this environment doesn't have), not a
   remaining gap. **Kubernetes manifests for the five services beyond
   proxy+OPA, and rotating the AppRole `secret_id` itself (currently
   permanent once issued), are both explicitly deprioritized for now by
   direct request (2026-09-27) — not attempted this pass, not treated as
   outstanding gaps.** The AppRole login mechanism itself (replacing the
   root token for every privileged Vault call) is unaffected and stays
   exactly as built/verified above — only rotating the one credential
   that bootstraps it is deprioritized.
2. **The proposal's Phase 2 enterprise tier** (§7.2) — a business-stage
   milestone, not part of this 6-month build roadmap. **DONE in full**:
   policy templates for HIPAA/PCI-DSS/EU AI Act (2026-09-27, see "Phase 2
   enterprise tier: HIPAA/PCI-DSS/EU AI Act compliance templates" above)
   and the managed dashboard for security teams — RBAC, per-operator
   attribution, and completed status coverage (2026-09-28, see "Phase 2
   enterprise tier: managed dashboard for security teams" above) are
   both done and verified. Nothing further is specified for Phase 2 in
   the proposal.
