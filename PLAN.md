# AEGIS Implementation Plan

Source: `AEGIS_Business_Proposal.docx` (v1.0, July 2026). This document translates
sections 4, 8, and 12 of the proposal into a concrete build order for this repo.

## Repo layout

```
AEGIS/
├── packages/
│   ├── proxy/             # Layer 1 — Egress control (Envoy sidecar, ext_authz -> OPA)
│   │   └── k8s/           # Kustomize manifest: proxy+OPA sidecar Pod, verified on kind
│   ├── policy-engine/     # Layer 3 — OPA/Rego action-level policy evaluation
│   ├── credential-vault/  # Layer 2 — HashiCorp Vault-backed credential broker
│   ├── sdk/               # Python SDK wrapping OpenAI/Anthropic/LangChain tool-calling
│   ├── cli/               # aegisctl — audit log, approvals, replay, live policy updates
│   ├── audit-logger/      # Layer 6 — hash-chained event log + SIEM forwarding (SQLite MVP)
│   ├── circuit-breaker/   # Layer 5 — suspend/resume/terminate + rate limits (Python MVP)
│   ├── anomaly-detector/  # Layer 4 — rule-based behavioural anomaly detection (Python MVP)
│   └── dashboard/         # React frontend + Python REST API backend (api/dashboard_api.py)
├── demo/                  # docker-compose demo: hello-world agent + full stack
│   ├── mock-siem/         # stand-in SIEM receiver
│   └── dashboard_app.py   # Streamlit flow viewer (separate from packages/dashboard)
└── docs/                  # architecture notes, policy language spec
```

All six containment layers from the proposal now have a package. Layers
scaffolded but with known gaps vs. the proposal's target design:
- Layer 2 (Credential vaulting) — real HashiCorp Vault integration, but uses a
  static dev-mode root token rather than short-lived scoped tokens; only one
  demo service wired up.
- Layer 5 (Circuit breaker) — Python MVP proves the behaviour; the proposal
  specs Rust for production latency, not yet built.
- Layer 4 (Anomaly detection) — rule-based, not the trained sequence
  classifier the proposal specs (§4.7); no adversarial-robustness testing.

## Build order (matches proposal §12, "Immediate next steps")

**Day 1 — Skeleton**
- [x] Monorepo scaffold (npm workspaces here; swap for Turborepo/Nx later if needed)
- [ ] Minimal Envoy passthrough proxy that logs all outbound requests (`packages/proxy`)
- [ ] "Hello world" agent using OpenAI/Anthropic SDK, run in Docker next to the proxy (`demo/`)
- [ ] Verify all agent traffic flows through the proxy and is logged

**Day 2 — Egress control**
- [ ] DNS-level allowlisting in the proxy
- [ ] `policy.example.yaml`: `allowed_domains`, `denied_domains`, `default_action: deny`
- [ ] Test: request to a non-allowlisted domain is blocked and logged

**Day 3 — Policy engine integration**
- [ ] Deploy OPA as a sidecar next to the proxy
- [ ] Rego policies evaluating action type, target URL, rate limits (`packages/policy-engine`)
- [ ] Proxy consults OPA before forwarding; deny on `deny` response

**Day 4 — SDK wrapper**
- [ ] `aegis-sdk` Python package wrapping OpenAI + Anthropic tool-calling (`packages/sdk`)
- [ ] Every tool call → structured action descriptor → policy engine → block if denied
- [ ] Publish to private index / installable from Git for early testers

**Day 5 — Audit log and circuit breaker**
- [ ] Append-only OCSF-formatted JSON audit log in Postgres (`packages/audit-logger`)
- [ ] Basic circuit breaker: >N policy violations in 60s → suspend agent + webhook
- [ ] CLI (`packages/cli`) to query the audit log and manually resume a suspended agent

**Days 6–7 — Demo and docs**
- [ ] `docker-compose.yml`: agent + proxy + OPA + audit log + dashboard
- [ ] README with architecture diagram, quickstart, policy config reference
- [ ] Demo video: agent blocked from an unauthorized destination
- [ ] Outreach one-pager for Tier 1 targets (Hugging Face, Replicate, Together AI)

## Sprint roadmap (proposal §8, 6 months)

| Sprint | Weeks | Focus | New packages |
|---|---|---|---|
| 1 | 1–4 | Foundation: egress proxy MVP, policy engine MVP, audit logger MVP, CLI, demo | `proxy`, `policy-engine`, `audit-logger`, `cli` |
| 2 | 5–8 | Core security: Vault integration, full policy language, Python SDK, basic circuit breaker, k8s sidecar | `circuit-breaker` |
| 3 | 9–14 | Intelligence: anomaly detection v1, dashboard UI, human-in-the-loop approvals, SIEM integration, incident replay | `anomaly-detector`, `dashboard` |
| 4 | 15–24 | Hardening: ~~eBPF interceptor~~ (descoped), multi-tenancy, SOC 2 package, load testing, external security audit | — |

Sprint 2 status: DONE. Vault integration (`credential-vault`), full policy
language (rate limits enforced via `circuit-breaker`, time windows enforced
in Rego), `aegisctl policy apply` (live OPA data updates, no restart), and
the Kubernetes sidecar manifest (`packages/proxy/k8s`, Kustomize, verified
on a real `kind` cluster) are all done as MVPs — see [PROGRESS.md](PROGRESS.md).

Sprint 3 status: DONE. Anomaly detection v1 (`anomaly-detector`, rule-based,
real-time event stream, four detection rules, direct circuit-breaker
escalation), the dashboard (React frontend + Python REST API backend,
`packages/dashboard`), human-in-the-loop approvals (`aegisctl
approvals`/`approve`/`deny`, circuit-breaker's `/suspended`/`/terminate`),
SIEM integration (`packages/audit-logger`'s forwarder + `demo/mock-siem`),
and incident replay (`aegisctl replay`) are all done as MVPs — see
[PROGRESS.md](PROGRESS.md) for what's verified and what gaps remain.

Sprint 4 status: IN PROGRESS. Multi-tenancy (isolated containment zones per
team/project) is done as an MVP — every service now scopes its state by a
`tenant_id` alongside `session_id` (policy, circuit breaker, rate limiting,
anomaly detection, audit log hash chains, credential vaulting, CLI,
dashboard) — see [PROGRESS.md](PROGRESS.md) for what's verified and the
known gaps (client-supplied tenant identity, no proxy-layer runtime tenant
switching, no tenant CRUD API).

Load testing is also done — nowhere near the 10K+ concurrent / sub-10ms
target yet, but it found the actual reason why: none of this repo's seven
stdlib-Python services had HTTP keep-alive, not the global locks
originally suspected (confirmed via `docker stats` showing near-zero CPU
during multi-second latencies). **That fix has since been applied and
verified with a real before/after re-run** — circuit-breaker went from
failing at the first concurrency level tested to sustaining it cleanly,
audit-logger's ceiling quadrupled. Still nowhere near 10K concurrent (the
highest any phase now sustains cleanly is 100) — the global-lock hypothesis
is back on the table as the next thing to investigate, now that the bigger
effect masking it is gone. See
[demo/load_test_results.md](demo/load_test_results.md) and
[PROGRESS.md](PROGRESS.md).

The SOC 2 compliance package is also done as an MVP — pre-built policy
templates (`packages/compliance/templates/`) mapped to specific Trust
Services Criteria, and an audit report generator
(`packages/compliance/soc2_report.py`, PDF/markdown/JSON — renamed
`compliance_report.py` and generalized across frameworks by the Phase 2
work below) built entirely on
existing audit-logger/circuit-breaker endpoints, no new ones. Explicitly
evidence *supporting* a SOC 2 Type II audit, not a certification — see
[packages/compliance/CONTROL_MAPPING.md](packages/compliance/CONTROL_MAPPING.md)
and [PROGRESS.md](PROGRESS.md).

The external security audit item can't actually be performed (it means
hiring a licensed third-party firm) — done instead as an internal security
review, findings empirically verified against the live stack rather than
just inferred from code. Found and fixed three real issues (dashboard API
had zero CSRF protection, credential-vault built Vault paths from an
unvalidated tenant_id, a Rego policy rule was traversal-bypassable), and
documented one real unfixed architectural gap: the egress proxy authorizes
by hostname string with no post-DNS-resolution IP check, confirmed
exploitable via a DNS-rebinding-style attack — see [PROGRESS.md](PROGRESS.md)
for the full write-up.

**The eBPF interceptor is descoped**, not just "not started" — it needs a
real Linux kernel with eBPF support, which this environment doesn't have,
and building it would mean standing up a Linux VM/container first purely
to attempt it. Decided not to pursue it here.

**Sprint 4 status: DONE** (four of its five items shipped as MVPs, the
fifth explicitly descoped for environment reasons, not skipped by
oversight). This closes out the proposal's entire 6-month Sprint 1–4
roadmap (§8) as MVPs. Nothing further is specified in §8 beyond Sprint 4 —
anything past this point is either the known-gaps backlog below (closing
each MVP's disclosed simplifications) or the proposal's separate Phase 2
enterprise-tier scope (§7.2: HIPAA/PCI-DSS/EU AI Act policy templates,
managed dashboard for security teams — a business-stage milestone, not
part of the 6-month build roadmap this file tracks).

**Phase 2 enterprise tier (§7.2): DONE in full**, both named items —
HIPAA/PCI-DSS/EU AI Act policy templates (2026-09-27) and the managed
dashboard for security teams (2026-09-28: role-based access control,
per-operator audit attribution, and completed service-status coverage,
verified with a real headless-browser check against the live stack, not
just an API-level one). See [PROGRESS.md](PROGRESS.md)'s two dated
entries for the full verification of each.

**Post-Sprint-4 gap-closing work, through the Vault root-token
replacement: DONE — closes every item on the 2026-09-16 direct-request
priority list, including both halves of the Vault token gap.** Real
authentication on the dashboard API (per-tenant
static API keys, `config.py`'s `DASHBOARD_API_KEYS`, tenant derived
server-side from the key), the DNS-rebinding fix in the egress proxy (new
`packages/proxy/dns-filter`, rejects any private/loopback/link-local DNS
answer before Envoy ever attempts a connection — verified through the
real deployed chain, not simulated), audit-logger wired to the
previously-unused `audit-db` Postgres container (`config.py`'s
`AUDIT_STORAGE_BACKEND` switch, SQLite stays the default), the Rust
rewrite of `circuit-breaker` the proposal specs for production latency
(new `packages/circuit-breaker-rs` — verified with real behavioral-parity
tests and a genuine load-test comparison, not just "should be faster"),
audit-logger's own compute/lock pressure (thread-local DB connections,
background-thread forwards instead of blocking the write path),
`circuit-breaker-rs` promoted from an opt-in alongside service to the
actual default (`config.py`'s `CIRCUIT_BREAKER_BACKEND` switch, the
Python original still one config edit away), the trained sequence
classifier the proposal specs for anomaly detection (new
`packages/anomaly-detector/train_classifier.py`/`model.joblib`, a
scikit-learn classifier trained on synthetic data replacing the Sprint 3
rule engine's hardcoded thresholds — verified to catch a session shape
the old rule engine structurally couldn't, both offline and live against
the deployed service), the circuit breaker's hard-suspend (real forensic
snapshot from the live audit trail) and emergency-kill (a genuine Docker
container kill via the Docker Engine API, verified against a real
throwaway container) tiers, real webhook notifications on both circuit
breaker services (replacing a stdout-only print, verified via a real HTTP
receiver), and credential-vault minting a fresh tenant-scoped, 60-second,
single-use Vault child token per request instead of ever using the static
root token to read a secret directly (verified against Vault's own ACL
enforcement, not just the application code's opinion of what it did), and
`circuit-breaker-rs` gaining the same hard-suspend/emergency-kill tiers
the Python service got (real forensic snapshot, a genuine Docker
container kill via the `bollard` crate — verified against its own
independent throwaway container, not the Python service's already-passing
result), and the Vault root token itself being replaced by a real
AppRole identity for credential-vault's own privileged operations
(bootstrapped once by `vault-init`, the same one-time-root-bootstrap
pattern a real Vault deployment already uses — verified with a genuine
`403` from Vault when that identity's own token tries to read a secret
directly, not just narrower-looking code). Found a real Vault mechanic
by testing along the way: minting a child token with policies the
caller doesn't itself hold needs `sudo` capability on
`auth/token/create`, not just `update` — the first policy attempt
failed with Vault's own error until this was added. See
[PROGRESS.md](PROGRESS.md)'s dated entries for the full verification of
each. Remaining backlog items (Kubernetes manifests,
`emergency_kill`'s VM-termination half, rotating the AppRole secret_id
itself) are listed there too.

Also done, requested directly rather than from the proposal's own roadmap:
every demo/dev-mode hardcoded value across the stack (secrets, thresholds,
ports, service URLs) is now driven by one file, [config.py](config.py) —
plain Python, bind-mounted into every container, editable without a
rebuild — instead of scattered literals or `docker-compose.yml` env-var
blocks. See [docs/configuration.md](docs/configuration.md) and
[PROGRESS.md](PROGRESS.md).

Also done, requested directly (2026-09-16): **content guardrails** — a
new layer checking the actual TEXT flowing to/from the LLM (PII, prompt
injection on input, toxic keyword matches on output), which none of the
proposal's six layers do (they govern actions/network/credentials, not
content). New `packages/content-guardrail` (stdlib-only Python), a new
`AegisClient.check_content()` in the SDK, reusing the existing
circuit-breaker violation counter and audit log rather than adding new
machinery for either. Verified live through the SDK, including that
matched PII is masked before it ever reaches a response or the audit
log, and that a bug found by testing (an unqualified digit-run regex
flagging ordinary numeric IDs as credit cards) was fixed with a real
Luhn checksum before this ever ran against real traffic. See
[PROGRESS.md](PROGRESS.md) and
[packages/content-guardrail/README.md](packages/content-guardrail/README.md).

## Target market wedge (for context, §5)

Tier 1 (AI hosting platforms: Hugging Face, Replicate, Together AI, Modal) is the
entry customer segment — build the **network proxy deployment model** first since
it requires no code changes on the customer side and directly demonstrates the
scenario in the OpenAI–Hugging Face incident.
