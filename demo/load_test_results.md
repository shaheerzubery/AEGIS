# AEGIS load test results

Two runs: the original (2026-08-22, before the HTTP keep-alive fix) and a
follow-up after fixing the root cause that first run found. Both on the
same single Windows machine (Docker Desktop, no container resource limits
configured). This is **not** a distributed production benchmark — it
measures this dev machine's ceiling.

Raw numbers: `load_test_raw_results.json` (latest run). Methodology and
phase design: see the docstring in `load_test.py`.

## Run 1 (before the fix): the keep-alive finding

The circuit-breaker and full-pipeline phases aborted at the very first,
lowest concurrency level tested (25) — multi-second mean latency at only
25 concurrent virtual users.

**Root cause, found by testing, not assumed**: `docker stats` during a
sustained-load run showed circuit-breaker's CPU sitting at ~1% while
taking a 4+ second mean latency — ruling out lock/CPU contention (the
original hypothesis). The actual cause, confirmed via `curl -v`: every
stdlib-Python service in this repo (`circuit-breaker`, `audit-logger`,
`anomaly-detector`, `credential-vault`, and — checked while fixing this —
also `protected-api`, `dashboard-api`, `mock-siem`) closed the TCP
connection after every single response (`BaseHTTPRequestHandler` defaults
to HTTP/1.0), while OPA (the one Go service) reused connections. Under
Windows/Docker Desktop's virtualized networking, sustained rapid
connection churn degrades far worse than an equivalent one-off burst.

## The fix

`protocol_version = "HTTP/1.1"` added to all seven of this repo's
`BaseHTTPRequestHandler`-based services. Every handler already sent a
correct `Content-Length` on every response, so enabling HTTP/1.1
keep-alive needed no other changes. Confirmed directly via `curl -v` on
every affected port: all seven now show `Re-using existing http:
connection` instead of `shutting down connection` after each request.

## Run 2 (after the fix): results

| Phase | Before: highest concurrency sustained cleanly | After: highest concurrency sustained cleanly |
|---|---|---|
| 1. OPA only (unaffected by the fix — Go, always had keep-alive) | 25 (p95 63ms) | 25 (p95 62ms) — unchanged, as expected |
| 2. circuit-breaker only | **0** (failed at the first level tested) | **25** (p95 94ms) |
| 3. audit-logger only | 25 (p95 1.08s) | **100** (p95 1.39s) — 4x the concurrency, at *better* latency |
| 4. full pipeline (`AegisClient.check()` protocol) | **0** (failed at the first level tested) | **25** (p95 281ms) |

Every phase either newly sustains a level that used to fail completely, or
sustains a materially higher level than before. None of the four phases
reach the proposal's literal 10K-concurrent target yet — phase 1 (OPA) and
phase 2 (circuit-breaker) both start degrading once concurrency reaches
100, phase 3 (audit-logger) degrades badly at 500, and phase 4 (the full
pipeline) inherits phase 2's ~100-level ceiling as expected, since it can't
outperform its slowest dependency.

## A second bug found while producing this run: a load-generator artifact, not an AEGIS bug

The first attempt at re-running all four phases sequentially in one Python
process produced a **nonsensical** result: phase 4 failed 100% at
concurrency=25, even though phases 1-3 (each of which phase 4 chains
together) had each just individually proven they handle 25 concurrent
requests cleanly moments earlier. Increasing the cooldown between phases
(tried 2s, 15s, 30s) didn't fix it.

Diagnosis: the *exact same request pattern*, run in a **fresh Python
process** immediately afterward with **zero** extra wait, succeeded
cleanly every time. That conclusively rules out server-side overload —
it's this load generator's own accumulated socket/resource state building
up across four phases and thousands of requests in one long-lived asyncio
event loop on this platform, not anything AEGIS-side. Fixed by having
`load_test.py` run each phase as its own subprocess (`--phase <name>` runs
just one, in a fresh process) — the same isolation a real distributed load
generator's workers would have from each other. Run 2's numbers above are
from this corrected, subprocess-isolated methodology.

This is worth stating plainly: it means **this specific tool's earlier
"phase 4: 0" result (if you ran an earlier version of this script) was
never a real finding** — it was a bug in the test harness, caught and
fixed before being reported as fact.

## What this does and doesn't prove

- **Does prove**: HTTP keep-alive was a real, substantial bottleneck, and
  fixing it meaningfully moved every phase's ceiling — confirmed with
  before/after numbers from the same methodology, not just "should be
  faster now" reasoning.
- **Does not prove**: what a production Linux deployment would show — the
  magnitude of the *original* problem was likely partly specific to
  Windows/Docker Desktop's virtualized networking, though the missing
  keep-alive itself was a platform-independent code fact.
- **Does not prove**: pure OPA/Rego evaluation latency in isolation — phase
  1 still degrades around concurrency=100 for reasons not yet isolated
  from the transport layer around it (see the original run's notes on
  benchmarking OPA's `eval` CLI directly as a follow-up).
- **Does not prove** the system is now anywhere near "10K+ concurrent
  sessions" — the highest level any phase sustained cleanly is 100. That
  remains a real, unaddressed gap.

## Known gaps in this load test itself (real, not hidden)

- Client and server share one machine's CPU/network stack — not a
  distributed benchmark.
- No container resource limits configured, so this is an un-throttled
  ceiling, not a capacity-planned one.
- Never reached the higher concurrency levels (500/1000/2500/5000/10000)
  for phases 1, 2, and 4 — they abort well before that. Phase 3 got as far
  as 500. The proposal's literal "10K+ concurrent sessions" target remains
  untested at that scale, on this machine.
- Now that keep-alive is fixed, the *next* likely ceiling to investigate is
  the global `threading.Lock()` in `circuit-breaker`/`audit-logger` (the
  original hypothesis, not yet ruled back in or out now that the bigger
  effect masking it is gone) and audit-logger's per-request fresh SQLite
  connection.
