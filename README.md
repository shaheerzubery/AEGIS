# AEGIS — AI Agent Containment & Guardrail Platform

Model-agnostic containment sidecar that sits between any AI agent and the outside
world: egress control, credential vaulting, action-level policy, behavioural
anomaly detection, a circuit breaker / kill switch, and an immutable audit log.

## Repo layout

- `packages/proxy` — Layer 1: transparent egress proxy (Envoy), OPA-driven allow/deny, with a filtering DNS resolver (`dns-filter/`) blocking rebinding to private/internal addresses
- `packages/policy-engine` — Layer 3: OPA/Rego action-level policy evaluation, live-updatable, multi-tenant
- `packages/credential-vault` — Layer 2: HashiCorp Vault-backed credential broker
- `packages/sdk` — Python SDK wrapping OpenAI / Anthropic / LangChain tool-calling
- `packages/cli` — `aegisctl`: audit log, approvals, replay, live policy updates
- `packages/audit-logger` — Layer 6: append-only, hash-chained event log (SQLite by default, switchable to Postgres)
- `packages/circuit-breaker` — Layer 5: violation suspend/resume + rate limiting (Python MVP)
- `packages/circuit-breaker-rs` — Layer 5, Rust rewrite of the above for production latency (proposal §8's original spec); runs alongside the Python original as an operator choice, not a replacement
- `packages/anomaly-detector` — Layer 4: rule-based behavioural anomaly detection
- `packages/dashboard` — React monitoring UI + REST API backend
- `packages/compliance` — SOC 2 policy templates + audit report generator (evidence, not certification)
- `packages/content-guardrail` — text-content checks (PII, prompt injection, toxic output) — added directly, not from the proposal's own roadmap
- `demo/` — docker-compose stack + test scripts + a Streamlit flow viewer

## Status

Sprints 1-3 are done as MVPs and verified end-to-end (proxy, policy engine,
SDK + all three framework wrappers, audit log with tamper detection, circuit
breaker with rate limiting, credential vaulting, live policy updates,
anomaly detection, the dashboard, human-in-the-loop approvals, SIEM
integration, incident replay). Sprint 4 is in progress (multi-tenancy and
load testing are done; the load test turned up a real, unexpected finding,
see `demo/load_test_results.md`).

## Configuration

**[config.py](config.py)**, at the repo root, is the settings file — every
demo/dev-mode value (secrets, thresholds, ports, service URLs) lives there
as plain Python constants, bind-mounted into every container, instead of
scattered `docker-compose.yml` `environment:` blocks. Edit it directly;
`docker compose restart <service>` picks up the change, no rebuild needed.
See [docs/configuration.md](docs/configuration.md) for the handful of
things that genuinely can't come from `config.py` (third-party Vault/
Postgres images, the dashboard's own tiny Vite `.env`) and what going to a
real deployment involves.

## Quickstart

```
cd demo
docker compose up -d --build
```

Then either run the test scripts directly (`python sdk_test.py`,
`python wrapper_test.py`), or see the whole flow in a browser:

```
pip install streamlit
streamlit run demo/dashboard_app.py
```

This opens a small dashboard (not `packages/dashboard`, which is still a
placeholder) that drives the real running services — send actions through
the policy engine, invoke credentialed calls, watch the circuit breaker and
audit log live.
