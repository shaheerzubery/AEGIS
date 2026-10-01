# AEGIS → SOC 2 Trust Services Criteria control mapping

**This is not an audit opinion.** SOC 2 Type II reports are issued only by
a licensed CPA firm, after examining an organization's controls over an
actual observation period (typically 3–12 months) — including many
organizational controls (HR background checks, physical security, vendor
management, change-management ticketing outside this system, etc.) that
AEGIS has no visibility into at all. This document maps AEGIS's own
containment behavior to the slice of the Trust Services Criteria (TSC)
relevant to *AI agent containment* specifically. It's a reasonable-effort
interpretation for engineering/product purposes, not vetted by a SOC 2
assessor. Treat it as a starting point for your own auditor conversation,
not a substitute for one.

This single file is the source of truth for the mapping — both
`templates/*.yaml`'s inline comments and `soc2_report.py`'s report sections
reference these same control IDs, so the mapping can't drift between the
policy templates and the generated report.

## Security (Common Criteria — mandatory for every SOC 2 report)

| Control | AICPA description (paraphrased) | AEGIS evidence |
|---|---|---|
| **CC6.1** | Logical access to systems/data is restricted to authorized users | `packages/policy-engine`'s OPA policy evaluation — every action is allow/deny'd against `data.policy.tenants.<id>.*` before it executes (Layer 3) |
| **CC6.6** | Least-privilege access is enforced | `allowed_tools`/`allowed_credential_actions` allowlists — nothing is reachable unless explicitly listed |
| **CC6.8** | The system prevents/detects unauthorized or malicious software/destinations | `packages/proxy` (Envoy) + OPA `network.allowed_domains` — egress to non-allowlisted destinations is blocked at the network layer (Layer 1), not just at the application layer |
| **CC7.1** | Configuration/change baselines are established and monitored for drift | `aegisctl policy apply` live-updates OPA's policy data — every policy change is itself observable (see CC7.2's audit trail) |
| **CC7.2** | The system monitors for anomalies/security events | `packages/anomaly-detector` (Layer 4) — real-time rule-based detection (privilege escalation, lateral movement, reconnaissance, self-modification attempts) |
| **CC7.3** | Security incidents are evaluated and responded to | `packages/circuit-breaker` (Layer 5) — automatic suspension on threshold violations or anomaly-detector escalation, plus human-in-the-loop approve/deny |
| **CC7.4** | Incident response includes recovery/remediation steps | `aegisctl approvals`/`approve`/`deny` — human review queue with an explicit permanent-termination path that cannot be silently undone |
| **CC5.2** | Control activities are deployed through policies and procedures | `packages/policy-engine/policy.example.yaml`-shaped profiles — declarative, versioned, tenant-scoped policy as the actual enforcement mechanism, not just documentation |

## Confidentiality

| Control | AICPA description (paraphrased) | AEGIS evidence |
|---|---|---|
| **C1.1** | Confidential information is identified and access is restricted | `packages/credential-vault` (Layer 2) — agents never hold, see, or transmit raw credentials; the broker holds them and returns only results |
| **C1.2** | Confidential information is protected from unauthorized disclosure | Per-tenant Vault path templates with no cross-tenant fallback — a missing tenant secret hard-fails rather than ever resolving to a different tenant's credential |

## Processing Integrity

| Control | AICPA description (paraphrased) | AEGIS evidence |
|---|---|---|
| **PI1.4** | System processing is complete, accurate, and can be verified | `packages/audit-logger`'s hash-chained event log (Layer 6) — every decision is recorded, and `/verify` recomputes the chain to detect any tampering after the fact |

## Availability

Not directly addressed by AEGIS's current containment layers — AEGIS
constrains what an agent can do, it doesn't manage the availability of the
underlying infrastructure. Out of scope for this mapping; a real SOC 2
report's Availability criteria would need evidence from elsewhere in the
deploying organization's stack.

## Multi-tenancy as a cross-cutting control

Every control above is evaluated *per tenant*: policy, rate limits, circuit
breaker state, anomaly detection windows, audit log hash chains, and
credential Vault paths are all isolated by `tenant_id`, verified directly
(same session_id reused across two tenants, confirmed fully independent —
see PROGRESS.md's Sprint 4 multi-tenancy verification). This is what makes
C1.1/C1.2 (confidentiality) and CC6.1 (logical access) meaningful in a
multi-tenant deployment specifically, rather than only in a single-tenant one.
