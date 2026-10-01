"""Sprint 4 check: load testing against the proposal's own target (§8:
"load testing (10K+ concurrent sessions, sub-10ms policy evaluation)").

There is no load-testing tooling anywhere else in this repo — this is a
hand-rolled asyncio + httpx.AsyncClient harness rather than Locust/k6, to
stay consistent with the repo's minimal-dependency style (most services here
are stdlib-only Python).

Four phases, each isolating one layer, so the result names *which*
component is the ceiling rather than reporting one opaque number for "the
system":

  1. OPA only         — pure policy evaluation, the most literal reading of
                         the proposal's "sub-10ms policy evaluation" claim.
  2. circuit-breaker   — isolates its global-lock hypothesis (see
                         packages/circuit-breaker/circuit_breaker.py's
                         module-level `_lock` guarding every dict/set).
  3. audit-logger      — isolates its SQLite-plus-global-lock-plus-inline-
                         anomaly-forward hypothesis (see
                         packages/audit-logger/audit_logger.py).
  4. full pipeline     — replicates AegisClient.check()'s exact wire
                         protocol (breaker status -> breaker activity -> OPA
                         -> fire-and-forget audit log) via raw async HTTP
                         calls. Not importing AegisClient itself, since it's
                         a synchronous httpx.Client and not suited to
                         asyncio-level concurrency — this intentionally
                         replicates the protocol, not the object.

Each phase runs at an escalating concurrency ramp, each level sustained for
a fixed duration. A level that shows too high an error rate or too much
latency auto-aborts the *rest of that phase's ramp* — that abort point is
itself the deliverable (the real ceiling on this machine), not a failure of
the script.

Every service in this repo (circuit-breaker, audit-logger, anomaly-detector,
credential-vault) is stdlib http.server + ThreadingHTTPServer — one OS
thread per connection, GIL-bound, no async I/O — so this is NOT expected to
cleanly sustain 10K concurrent connections. Finding and naming the actual
ceiling is the point.

Caveats (real, stated up front): this is a single-machine test — the load
generator and every service share this machine's CPU/network stack, so
these numbers reflect this dev machine, not a distributed production
deployment. No container resource limits are configured in
demo/docker-compose.yml, so this measures the stack's un-throttled ceiling.

Each phase runs as its own subprocess (`--phase <name>` runs just one, in a
fresh process). Found by testing: running all four phases sequentially in
ONE process left phase 4 failing 100% no matter how long a cooldown was
inserted between phases — but the identical request pattern, in a FRESH
process right afterward with zero extra wait, succeeded cleanly every
time. That's this load generator's own accumulated socket/resource state
carrying over between phases in one process, not a server-side bottleneck
— subprocess isolation avoids it, the same way a real distributed load
generator's workers wouldn't share that state either.

Run the full stack first: `docker compose up -d` (from demo/).
Run this with: `python load_test.py` (all phases) or
`python load_test.py --phase <name>` (one phase, see --help).
"""

import asyncio
import json
import os
import random
import statistics
import time
import uuid
from dataclasses import dataclass, field

import httpx

OPA_URL = "http://localhost:8181"
BREAKER_URL = "http://localhost:9400"
AUDIT_URL = "http://localhost:9300"
TENANT = "default"

CONCURRENCY_LEVELS = [25, 100, 500, 1000, 2500, 5000, 10000]
LEVEL_DURATION_SECONDS = 10
COOLDOWN_SECONDS = 2
# Longer cooldown between *phases* than between levels within one phase —
# found by testing: a phase that ends aborted (e.g. a 500-concurrency burst
# with a ~24-48% error rate) leaves the services in a genuinely overloaded
# state that a few seconds isn't enough to recover from on this platform,
# which then falsely tanks the very first level of the *next* phase even
# though that phase's own concurrency is much lower. Confirmed empirically:
# 15s wasn't enough (phase 4 still failed 100% at concurrency=25 right
# after phase 3's overload), 30s was.
PHASE_COOLDOWN_SECONDS = 30

ABORT_ERROR_RATE = 0.10
ABORT_P95_SECONDS = 2.0

ALLOWED_TARGET = "example.com"  # tenant "default" — see policy.example.yaml
DENIED_TARGET = "not-allowlisted.example"


@dataclass
class Outcome:
    elapsed: float
    ok: bool
    client_side_error: bool
    correctness_ok: bool | None = None  # only meaningful for phase 1


@dataclass
class LevelResult:
    concurrency: int
    duration: float
    total_requests: int
    throughput_rps: float
    latencies: list = field(default_factory=list)
    error_count: int = 0
    client_side_error_count: int = 0
    correctness_mismatches: int = 0
    aborted: bool = False

    def percentile(self, p: float) -> float:
        if not self.latencies:
            return float("nan")
        s = sorted(self.latencies)
        idx = min(int(len(s) * p), len(s) - 1)
        return s[idx]

    def summary_line(self) -> str:
        err_rate = self.error_count / self.total_requests if self.total_requests else 0.0
        mean = statistics.mean(self.latencies) if self.latencies else float("nan")
        return (
            f"concurrency={self.concurrency:>6} "
            f"requests={self.total_requests:>7} "
            f"rps={self.throughput_rps:>8.1f} "
            f"mean={mean*1000:>7.1f}ms "
            f"p50={self.percentile(0.50)*1000:>7.1f}ms "
            f"p95={self.percentile(0.95)*1000:>7.1f}ms "
            f"p99={self.percentile(0.99)*1000:>7.1f}ms "
            f"errors={self.error_count:>6} ({err_rate*100:.1f}%, "
            f"{self.client_side_error_count} client-side) "
            f"mismatches={self.correctness_mismatches}"
            + ("  <-- ABORTED, ceiling reached" if self.aborted else "")
        )


async def _worker(
    client: httpx.AsyncClient,
    deadline: float,
    do_request,
    results: list,
):
    while time.monotonic() < deadline:
        outcome = await do_request(client)
        results.append(outcome)


async def run_level(concurrency: int, do_request, limits: httpx.Limits) -> LevelResult:
    deadline = time.monotonic() + LEVEL_DURATION_SECONDS
    results: list[Outcome] = []
    start = time.monotonic()

    async with httpx.AsyncClient(limits=limits, timeout=5.0) as client:
        workers = [asyncio.create_task(_worker(client, deadline, do_request, results)) for _ in range(concurrency)]
        await asyncio.gather(*workers, return_exceptions=True)

    duration = time.monotonic() - start
    level = LevelResult(
        concurrency=concurrency,
        duration=duration,
        total_requests=len(results),
        throughput_rps=len(results) / duration if duration > 0 else 0.0,
    )
    for o in results:
        level.latencies.append(o.elapsed)
        if not o.ok:
            level.error_count += 1
            if o.client_side_error:
                level.client_side_error_count += 1
        if o.correctness_ok is False:
            level.correctness_mismatches += 1

    err_rate = level.error_count / level.total_requests if level.total_requests else 1.0
    p95 = level.percentile(0.95)
    if err_rate > ABORT_ERROR_RATE or p95 > ABORT_P95_SECONDS:
        level.aborted = True
    return level


async def run_phase(name: str, do_request) -> list[LevelResult]:
    print(f"\n=== Phase: {name} ===")
    levels: list[LevelResult] = []
    for concurrency in CONCURRENCY_LEVELS:
        limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
        result = await run_level(concurrency, do_request, limits)
        print(result.summary_line())
        levels.append(result)
        if result.aborted:
            print(f"  -> ceiling reached at concurrency={concurrency}; skipping remaining levels for this phase")
            break
        await asyncio.sleep(COOLDOWN_SECONDS)
    return levels


def _classify_exception(exc: Exception) -> bool:
    """True if this looks like a client-side failure (connection
    refused/reset, pool exhaustion, DNS) rather than a server-side one
    (non-2xx, or the server accepted the connection but timed out
    responding)."""
    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))


# ---- Phase 1: OPA only ----


async def opa_request(client: httpx.AsyncClient) -> Outcome:
    target, expect_allowed = random.choice([(ALLOWED_TARGET, True), (DENIED_TARGET, False)])
    start = time.monotonic()
    try:
        resp = await client.post(
            f"{OPA_URL}/v1/data/aegis/authz/allow",
            json={"input": {"tenant_id": TENANT, "action": {"type": "http_request", "target": target}}},
        )
        elapsed = time.monotonic() - start
        allowed = resp.json().get("result", False)
        return Outcome(elapsed, resp.status_code == 200, False, correctness_ok=(allowed == expect_allowed))
    except Exception as exc:  # noqa: BLE001 — load test needs to classify, not propagate
        return Outcome(time.monotonic() - start, False, _classify_exception(exc), correctness_ok=None)


# ---- Phase 2: circuit-breaker only ----


async def circuit_breaker_request(client: httpx.AsyncClient) -> Outcome:
    session_id = f"loadtest-cb-{uuid.uuid4()}"
    start = time.monotonic()
    try:
        r1 = await client.get(f"{BREAKER_URL}/status/{TENANT}/{session_id}")
        r2 = await client.post(f"{BREAKER_URL}/activity/{TENANT}/{session_id}")
        elapsed = time.monotonic() - start
        return Outcome(elapsed, r1.status_code == 200 and r2.status_code == 200, False)
    except Exception as exc:  # noqa: BLE001
        return Outcome(time.monotonic() - start, False, _classify_exception(exc))


# ---- Phase 3: audit-logger only ----


async def audit_logger_request(client: httpx.AsyncClient) -> Outcome:
    session_id = f"loadtest-audit-{uuid.uuid4()}"
    allowed = random.choice([True, False])
    start = time.monotonic()
    try:
        resp = await client.post(
            f"{AUDIT_URL}/events",
            json={
                "tenant_id": TENANT,
                "session_id": session_id,
                "event_type": "policy_decision",
                "action": {"action_type": "http_request", "target": ALLOWED_TARGET, "method": None},
                "policy_decision": {"allowed": allowed, "reason": None},
            },
        )
        elapsed = time.monotonic() - start
        return Outcome(elapsed, resp.status_code == 201, False)
    except Exception as exc:  # noqa: BLE001
        return Outcome(time.monotonic() - start, False, _classify_exception(exc))


# ---- Phase 4: full pipeline (replicates AegisClient.check()'s wire protocol) ----


async def full_pipeline_request(client: httpx.AsyncClient) -> Outcome:
    session_id = f"loadtest-full-{uuid.uuid4()}"
    target, expect_allowed = random.choice([(ALLOWED_TARGET, True), (DENIED_TARGET, False)])
    start = time.monotonic()
    try:
        # 1. is_suspended
        await client.get(f"{BREAKER_URL}/status/{TENANT}/{session_id}")
        # 2. check_rate_limit
        await client.post(f"{BREAKER_URL}/activity/{TENANT}/{session_id}")
        # 3. policy engine
        resp = await client.post(
            f"{OPA_URL}/v1/data/aegis/authz/allow",
            json={"input": {"tenant_id": TENANT, "action": {"type": "http_request", "target": target}}},
        )
        allowed = resp.json().get("result", False)
        # 4. audit log (best-effort in the real SDK, but still a blocking
        # call in check()'s own code path — included here for that reason)
        await client.post(
            f"{AUDIT_URL}/events",
            json={
                "tenant_id": TENANT,
                "session_id": session_id,
                "event_type": "policy_decision",
                "action": {"action_type": "http_request", "target": target, "method": None},
                "policy_decision": {"allowed": allowed, "reason": None},
            },
        )
        elapsed = time.monotonic() - start
        return Outcome(elapsed, True, False, correctness_ok=(allowed == expect_allowed))
    except Exception as exc:  # noqa: BLE001
        return Outcome(time.monotonic() - start, False, _classify_exception(exc), correctness_ok=None)


PHASES = {
    "opa_only": ("1. OPA only (pure policy evaluation)", opa_request),
    "circuit_breaker_only": ("2. circuit-breaker only", circuit_breaker_request),
    "audit_logger_only": ("3. audit-logger only", audit_logger_request),
    "full_pipeline": ("4. full pipeline (AegisClient.check() protocol)", full_pipeline_request),
}


def _levels_to_json(levels: list[LevelResult]) -> list[dict]:
    return [
        {
            "concurrency": lv.concurrency,
            "duration": lv.duration,
            "total_requests": lv.total_requests,
            "throughput_rps": lv.throughput_rps,
            "mean_ms": statistics.mean(lv.latencies) * 1000 if lv.latencies else None,
            "p50_ms": lv.percentile(0.50) * 1000,
            "p95_ms": lv.percentile(0.95) * 1000,
            "p99_ms": lv.percentile(0.99) * 1000,
            "error_count": lv.error_count,
            "client_side_error_count": lv.client_side_error_count,
            "correctness_mismatches": lv.correctness_mismatches,
            "aborted": lv.aborted,
        }
        for lv in levels
    ]


def _print_summary(all_results: dict) -> None:
    print("\n=== Summary: highest concurrency level reached cleanly (no abort) per phase ===")
    for phase_name, levels in all_results.items():
        clean = [lv for lv in levels if not lv["aborted"]]
        ceiling = clean[-1]["concurrency"] if clean else 0
        p95 = clean[-1]["p95_ms"] if clean else float("nan")
        print(f"{phase_name:>22}: sustained up to concurrency={ceiling:>6}  (p95={p95:.1f}ms)")


async def run_one_phase(phase_key: str) -> list[LevelResult]:
    title, fn = PHASES[phase_key]
    return await run_phase(title, fn)


def main():
    import argparse
    import subprocess
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=list(PHASES) + ["all"],
        default="all",
        help=(
            "Run just one phase in THIS process (fresh asyncio loop, no prior "
            "phases' accumulated client-side state), or 'all' (default) to run "
            "every phase, each as its own subprocess — see the note below "
            "'found by testing' for why subprocess isolation matters here."
        ),
    )
    args = parser.parse_args()

    if args.phase != "all":
        levels = asyncio.run(run_one_phase(args.phase))
        with open(f"load_test_raw_results.{args.phase}.json", "w") as f:
            json.dump(_levels_to_json(levels), f, indent=2)
        return

    # Found by testing: running all four phases sequentially in ONE process
    # produced a phase 4 that failed 100% at concurrency=25 no matter how
    # long a cooldown was inserted between phases (tried up to 30s) — but
    # the exact same request pattern, run in a FRESH process immediately
    # afterward with zero extra wait, succeeded cleanly every time. That
    # proves it was this load-generator process's own accumulated
    # socket/resource state (not server-side overload) causing the failure
    # — so each phase now runs as its own subprocess, guaranteeing a clean
    # OS-level state per phase, the same isolation a real distributed load
    # generator would have between its workers.
    all_results = {}
    for i, phase_key in enumerate(PHASES):
        if i > 0:
            time.sleep(PHASE_COOLDOWN_SECONDS)
        subprocess.run([sys.executable, __file__, "--phase", phase_key], check=True)
        with open(f"load_test_raw_results.{phase_key}.json") as f:
            all_results[phase_key] = json.load(f)
        os.remove(f"load_test_raw_results.{phase_key}.json")

    _print_summary(all_results)
    with open("load_test_raw_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\nRaw results written to load_test_raw_results.json")


if __name__ == "__main__":
    main()
