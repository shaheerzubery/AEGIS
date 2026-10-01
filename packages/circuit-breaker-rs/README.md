# AEGIS Circuit Breaker (Rust) — Layer 5, production-latency rewrite

Behaviorally identical rewrite of `packages/circuit-breaker` (the Python
MVP) in Rust (`axum`/`tokio`/`dashmap`) — the proposal's own Sprint 2
rationale (§8: production latency at scale). See `main.rs`'s module doc
comment for the concurrency-model reasoning (async + per-key locking, not
"fixing a lock" — the Python service's actual measured bottleneck under
load was the thread-per-connection model, not lock contention).

## Default backend as of 2026-09-16

This service is now the **default** circuit breaker for the whole demo
stack:

- Published on host port `9400` — the port every host-side caller already
  assumes via its `AEGIS_CIRCUIT_BREAKER_URL` fallback of
  `http://localhost:9400` (`aegisctl`, `demo/*.py` scripts, an externally-run
  agent's `AegisClient`). The Python original moved to `9410` instead — see
  `demo/docker-compose.yml`.
- `config.py`'s `CIRCUIT_BREAKER_BACKEND = "rust"` (default) is what
  internal (container-to-container) callers — `anomaly-detector`,
  `dashboard-api` — resolve to `http://circuit-breaker-rs:9400` through.

### How to switch back to the Python service

Both services stay running side by side; nothing needs to be torn down.

1. Edit `config.py`: `CIRCUIT_BREAKER_BACKEND = "python"`, then
   `docker compose restart anomaly-detector dashboard-api` (bind-mounted,
   no rebuild) — this repoints every *internal* caller.
2. For host-side tools (`aegisctl`, `demo/*.py`, an external agent), set
   `AEGIS_CIRCUIT_BREAKER_URL=http://localhost:9410` in that tool's own
   environment instead.

There's no single flag that flips both at once — internal callers go
through `config.py` (this repo's own services), host-side callers go
through each tool's own env var fallback (deliberately, so
`packages/sdk/aegis_sdk` keeps working for agents that aren't running
inside this repo's containers at all — see `config.py`'s module docstring).

## API

Identical route shape to `packages/circuit-breaker` — see that package's
README for the full endpoint reference and the escalation-tier writeup
(`/violation`, `/activity`, `/status`, `/suspended`, `/resume`,
`/suspend`, `/terminate`, `/hard-suspend`, `/emergency-kill`,
`/register`, `/snapshot`, all `<tenant-id>/<session-id>`-keyed). As of
2026-09-16 this service is a **full** drop-in replacement, including the
hard-suspend/emergency-kill tiers — not a redesign, and no longer a
partial one either (see "Tier parity" below).

## Config

Environment variables, not `config.py` — this isn't one of the Python
services `config.py`'s own module docstring scopes itself to (same reason
`vault`/`audit-db` take literals in `demo/docker-compose.yml` instead).
Names match this repo's existing convention so they read as the same
setting under a different transport:

- `AEGIS_CIRCUIT_BREAKER_PORT` (default `9400`)
- `AEGIS_VIOLATION_THRESHOLD` (default `5`)
- `AEGIS_VIOLATION_WINDOW_SECONDS` (default `60`)
- `AEGIS_RATE_LIMIT_PER_MINUTE` (default `60`) — fallback only; OPA's policy
  data is authoritative when reachable
- `AEGIS_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- `AEGIS_RATE_LIMIT_CACHE_SECONDS` (default `30`)
- `AEGIS_POLICY_URL` (default `http://opa:8181`)
- `AEGIS_WEBHOOK_URL` (default empty = disabled) — see
  `packages/circuit-breaker/README.md`'s "Webhook notifications"
- `AEGIS_AUDIT_URL` (default `http://audit-logger:9300`) — where
  `hard_suspend`/`emergency_kill` fetch a session's real forensic snapshot from

Keep these in sync with `config.py`'s matching constants by hand if you
change one — see `demo/docker-compose.yml`'s `circuit-breaker-rs` service
comment.

## Tier parity (gap-closing work, 2026-09-16)

`hard_suspend`/`emergency_kill` now exist here too, mirroring
`circuit_breaker.py`'s implementation exactly (see that module's own doc
comments in `main.rs` for line-by-line correspondence):

- `hard_suspend` — same suspend-everything effect as `soft_pause`, plus a
  real forensic snapshot fetched live from `packages/audit-logger`
  (`fetch_audit_trail`/`capture_snapshot`), retrievable via `GET /snapshot`.
- `emergency_kill` — does everything `hard_suspend` does, plus a genuine
  Docker container kill via the Docker Engine API (the `bollard` crate —
  Rust's equivalent of the Python service's `docker` PyPI package),
  for any session that called `POST /register` first with its own
  container id. No registration means no container, reported honestly
  (`{"kill": {"attempted": false, ...}}`), never a false "success" —
  same as the Python service.
- `SuspensionMeta` now carries a real `tier` field (was a hardcoded
  literal before this), so `GET /suspended` reports the actual tier a
  session was suspended at, not a heuristic derived from `terminated`.
- Requires the same Docker socket mount as `packages/circuit-breaker`
  (`demo/docker-compose.yml`) — same meaningful-privilege caveat applies
  here too (full host Docker-daemon control, demo-only).
- `demo/circuit_breaker_tiers_test.py` now runs its full 12-check sequence
  against BOTH services (24 checks total) — see `PROGRESS.md`'s dated
  entry for the verification, including a real throwaway container
  killed through each service independently.

## Verification

Full write-up in `PROGRESS.md`'s "Gap-closing backlog: Rust
circuit-breaker rewrite" and "circuit-breaker-rs default cutover" entries.
Summary:

- **API-level behavioral parity** against the Python service, both by
  manual verification (fresh-session status, violation threshold
  escalation, `/suspended` filtering, suspend/terminate with and without a
  JSON body, refused-resume after termination, rate-limit fallback when
  OPA is unreachable) and by an automated parity test,
  `demo/circuit_breaker_parity_test.py`, which drives an identical request
  sequence against both services and asserts matching responses.
- **Full regression suite unaffected**: `sdk_test.py`/`wrapper_test.py`/
  `tenant_isolation_test.py` all pass with this service as the default
  target.
- **Real performance improvement**, `demo/load_test.py`: at
  concurrency=100 this service sustains it with zero errors where the
  Python service had a 0.2–2.1% error rate; throughput at concurrency=25 is
  roughly double. Its own ceiling is around concurrency=500 — nowhere near
  the proposal's literal 10K-concurrent target, a real improvement over
  the Python service's ceiling, not a claim of hitting that number.

## Known gaps

- ~~No `hard_suspend`/`emergency_kill` tiers~~ — **fixed, 2026-09-16**,
  see "Tier parity" above.
- ~~Webhook notifications are still stdout prints, not real HTTP calls to
  Slack/email~~ — **fixed, 2026-09-16**: `AEGIS_WEBHOOK_URL` (empty =
  disabled, same convention as the Python service's `WEBHOOK_URL`) now
  gets a real HTTP POST on `/suspend` and `/terminate`, dispatched via
  `tokio::spawn` so it can't add latency to the response. See
  `packages/circuit-breaker/README.md`'s "Webhook notifications" section
  for the full picture (payload shape, `demo/mock-webhook`,
  `demo/webhook_test.py`).
- `demo/circuit_breaker_parity_test.py` doesn't exercise the "OPA
  unreachable, fall back to the cached/default rate limit" path — that
  needs stopping the `opa` container mid-test, which the manual
  verification pass covered instead (see `PROGRESS.md`); worth automating
  in a future pass.
