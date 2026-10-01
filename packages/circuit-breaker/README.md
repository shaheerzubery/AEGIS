# AEGIS Circuit Breaker — Layer 5 (Circuit breaker and kill switch)

Suspends a session after too many policy violations in a sliding window, and
exposes a resume endpoint for a human operator (proposal §3.2 Layer 5).

Python for the Day 5 MVP. The proposal specs a Rust service for this in
Sprint 2 (proposal §8) for sub-ms latency at scale — this proves the
behaviour first, not the performance target.

## API

Every route below is `<tenant-id>/<session-id>` (Sprint 4 multi-tenancy —
every counter is keyed by the composite pair, not bare `session_id`).

- `POST /violation/<tenant-id>/<session-id>` — record one policy violation;
  returns the current violation count in the window and whether the
  session is now suspended.
- `POST /activity/<tenant-id>/<session-id>` — record one action attempt
  (Sprint 2: rate limiting). Returns `{"count_in_window", "limit",
  "rate_limited"}`. The limit is read from OPA's
  `data.policy.tenants.<tenant-id>.rate_limits.max_actions_per_minute` (see
  packages/policy-engine), cached for 30s per tenant, falling back to
  `AEGIS_RATE_LIMIT_PER_MINUTE` if OPA is unreachable. This is separate from
  the violation counter — rate limiting counts every attempt, not just denials.
- `GET /status/<tenant-id>/<session-id>` — current violation count,
  suspension state, termination state.
- `GET /suspended?tenant_id=<tenant-id>` (query param optional) — every
  currently-suspended session with its reason and timestamp — the
  human-in-the-loop review queue (`aegisctl approvals`). Omitting
  `tenant_id` returns a cross-tenant operator view.
- `POST /resume/<tenant-id>/<session-id>` — clear the suspension and
  activity counters (what `aegisctl resume`/`aegisctl approve` calls).
  Refuses if the session was terminated (see below).
- `POST /suspend/<tenant-id>/<session-id>` — body `{"reason": "..."}`
  (optional). Suspend immediately, bypassing the violation counter entirely
  — for callers (Sprint 3: `packages/anomaly-detector`) that have already
  decided a session is dangerous rather than needing to count up to a
  threshold. Tier: `soft_pause` (see below).
- `POST /terminate/<tenant-id>/<session-id>` — body `{"reason": "..."}`
  (optional). Permanent denial (`aegisctl deny`) — proposal §3.2 Layer 5's
  "terminate the agent permanently" resume option. Unlike suspend, `resume`
  cannot clear this; there's deliberately no "un-terminate" endpoint. Not
  one of the three escalation tiers below — this is the human operator's
  own post-review decision, unchanged by that work.
- `POST /hard-suspend/<tenant-id>/<session-id>` — body `{"reason": "..."}`
  (optional). Tier: `hard_suspend` (see below).
- `POST /emergency-kill/<tenant-id>/<session-id>` — body `{"reason": "..."}`
  (optional). Tier: `emergency_kill` (see below).
- `POST /register/<tenant-id>/<session-id>` — body `{"container_id": "..."}`
  (required). Opts a session in to `emergency_kill`'s real container-kill
  step — see below.
- `GET /snapshot/<tenant-id>/<session-id>` — the forensic snapshot captured
  by the most recent `hard_suspend`/`emergency_kill` for this session, if any.

## Escalation tiers (proposal §3.2 Layer 5 "How it works," gap-closing work 2026-09-16)

The proposal specs three levels; all three now exist here (`circuit-breaker-rs`
below only implements the first — a stated gap, not silently dropped):

1. **`soft_pause`** — "the current action is held pending human review" —
   `record_violation` (threshold-triggered) and `/suspend` both produce
   this tier. Mechanism: network/action-level denial (every layer in this
   MVP models "revoked" this way, not literal process suspension).
2. **`hard_suspend`** — "all agent processes are frozen, network access is
   revoked, and a snapshot of the agent's state is captured for
   forensics." Same denial as `soft_pause`, plus a REAL snapshot: the
   session's actual recent audit trail, fetched live from
   `packages/audit-logger` and stored (`GET /snapshot` to retrieve it) —
   not a placeholder.
3. **`emergency_kill`** — "the agent's entire runtime environment is
   destroyed (container killed, VM terminated), with all state preserved
   in the audit log." Does everything `hard_suspend` does (snapshot
   captured before any kill attempt, so it survives regardless of
   outcome), plus a genuine Docker container kill via the Docker Engine
   API — but only for a session that called `/register` first with its
   own container id. No registration means no container, which means
   `{"kill": {"attempted": false, ...}}` — reported honestly, never a
   false "success."

`packages/sdk/aegis_sdk`'s `AegisClient.register_runtime()` is the intended
caller for `/register` — it defaults to `$HOSTNAME`, which Docker sets to
the running container's own short id unless overridden.

**Meaningful privilege note**: `emergency_kill` needs the Docker Engine
API, which needs the host's Docker socket mounted into this container
(`demo/docker-compose.yml`) — that grants this container full control of
the host's Docker daemon, equivalent to host root, not a narrowly-scoped
capability. Demo-only, same category of caveat as Vault's dev-mode root
token elsewhere in this repo. A real deployment should front this with a
narrowly-scoped agent-lifecycle API instead (e.g. a Kubernetes Role
limited to pod-delete in one namespace), never a raw socket mount.

## Rust rewrite is now the default

As of the 2026-09-16 gap-closing pass, `packages/circuit-breaker-rs` is the
default backend for internal callers (`config.py`'s
`CIRCUIT_BREAKER_BACKEND = "rust"`) and is published on the port host-side
tools assume by default (`9400`) — this service moved to `9410`. See
`packages/circuit-breaker-rs/README.md` for the full picture, including how
to switch back.

## Config

- `AEGIS_VIOLATION_THRESHOLD` (default `5`)
- `AEGIS_VIOLATION_WINDOW_SECONDS` (default `60`)
- `AEGIS_RATE_LIMIT_PER_MINUTE` (default `60`) — fallback only; OPA's policy
  data is authoritative when reachable
- `AEGIS_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- `AEGIS_POLICY_URL` (default `http://opa:8181`)

## Why rate limiting lives here, not in OPA

OPA evaluates each request statelessly — it has no way to know "how many
actions has this session taken in the last minute" without an external
counter. This service already tracks sliding windows per session for
violations, so it's the natural place for the activity counter too. The
*limit* itself still comes from the policy engine's data, not a hardcoded
value here — only the counting is stateful.

## Webhook notifications

Gap-closing work (2026-09-16, see PROGRESS.md): every suspend/terminate/
emergency-kill now fires a real HTTP POST to `config.py`'s `WEBHOOK_URL`
(`_send_webhook`), on a background thread so a slow/unreachable receiver
can't add latency to the response — same "empty string = disabled"
convention as `SIEM_URL`, same "don't block the write path" fix as
`packages/audit-logger`'s. The payload always includes a `"text"` field
(all a real Slack Incoming Webhook reads) plus structured fields
(`tenant_id`, `session_id`, `tier`, `reason`, `event`) for a generic
receiver — `demo/mock-webhook` stands in for either, same role
`demo/mock-siem` plays for Layer 6. `circuit-breaker-rs` has the identical
mechanism (`AEGIS_WEBHOOK_URL`, `send_webhook` in `main.rs`) for the tier
it does support (`soft_pause`/`terminated`).

## Not yet done

- ~~`hard_suspend`/`emergency_kill` aren't implemented in
  `circuit-breaker-rs` yet~~ — **fixed, 2026-09-16**: both tiers now exist
  there too, verified independently against a real throwaway container —
  see `packages/circuit-breaker-rs/README.md`'s "Tier parity".
- `emergency_kill`'s "VM terminated" half of the proposal's wording is
  **descoped** on both services, not "not started" — same category of
  decision as this repo's Sprint 4 eBPF interceptor (see `PROGRESS.md`).
  Genuinely testing it needs real VM infrastructure (a cloud
  terminate-instance API, or a local hypervisor) this environment
  doesn't have; the container-kill half is real and verified because
  this environment's own Docker daemon actually provides that.
