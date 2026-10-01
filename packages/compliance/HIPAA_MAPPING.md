# AEGIS → HIPAA Security Rule control mapping

**This is not a HIPAA compliance certification, and AEGIS alone cannot
make a covered entity or business associate HIPAA-compliant.** The
HIPAA Security Rule (45 CFR Part 164, Subpart C) requires administrative
safeguards (workforce training, sanction policies, business associate
agreements) and physical safeguards (facility access controls, device
disposal) that AEGIS has no visibility into at all — it's a runtime
containment layer for AI agents, not a covered entity's full compliance
program. This document maps AEGIS's own containment behavior to the
*technical safeguards* (§164.312) and the handful of administrative
safeguards (§164.308) a containment layer can actually produce evidence
for. Same "reasonable-effort engineering interpretation, not vetted by a
compliance attorney or HIPAA auditor" caveat as
[CONTROL_MAPPING.md](CONTROL_MAPPING.md) (SOC 2) — read that file's
disclaimer too, since the same limitation applies here.

**PHI vs. what AEGIS actually detects**: HIPAA's Protected Health
Information (PHI) is a broad legal category — names, dates, medical
record numbers, health plan beneficiary numbers, and more, per 45 CFR
§160.103 — not just the four PII categories
`packages/content-guardrail` currently detects (email, phone, US SSN,
credit-card-shaped numbers). SSN detection has real HIPAA relevance
(SSNs frequently appear alongside PHI); email/phone are contact
information, not clinical PHI themselves. Do not treat
content-guardrail's PII detection as "PHI detection" — it isn't one, and
is disclosed as such directly.

## Technical Safeguards (45 CFR §164.312)

| Control | HIPAA citation (paraphrased) | AEGIS evidence |
|---|---|---|
| **Access Control** | §164.312(a)(1) — technical policies and procedures restrict access to authorized persons/software | `packages/policy-engine`'s OPA evaluation — every action allow/deny'd against tenant-scoped policy before it executes (Layer 3) |
| **Unique User Identification** | §164.312(a)(2)(i) — assign a unique name/number for identifying and tracking user identity | Every action carries `tenant_id`/`session_id`, verified fully isolated per tenant even when `session_id` strings collide across tenants (see PROGRESS.md's multi-tenancy verification) |
| **Audit Controls** | §164.312(b) — hardware/software/procedural mechanisms to record and examine activity in systems containing PHI-adjacent data | `packages/audit-logger`'s hash-chained, append-only event log (Layer 6) — every action, allow/deny decision, and content-guardrail check is recorded |
| **Integrity** | §164.312(c)(1) — protect data from improper alteration/destruction | Hash-chained audit log; `GET /verify` recomputes the chain and detects tampering after the fact, confirmed directly (deliberately corrupting a stored row flips `chain_intact` to `false` — see PROGRESS.md) |
| **Person or Entity Authentication** | §164.312(d) — verify a person/entity seeking access is the one claimed | Dashboard API's static keys (`config.py`'s `DASHBOARD_API_KEYS`) resolve to a tenant AND a named operator identity (added 2026-09-28) — both are derived server-side from the key, never trusted from a client-supplied field |
| **Transmission Security** | §164.312(e)(1) — guard against unauthorized access to data transmitted over a network | `packages/proxy`'s egress control (Layer 1) plus the DNS-rebinding fix (`packages/proxy/dns-filter`) — rejects private/loopback/link-local DNS answers before Envoy ever attempts a connection, closing a real bypass of a hostname-only allowlist |

## Administrative Safeguards (45 CFR §164.308) — the slice a runtime layer can evidence

| Control | HIPAA citation (paraphrased) | AEGIS evidence |
|---|---|---|
| **Information System Activity Review** | §164.308(a)(1)(ii)(D) — regularly review records of system activity | `aegisctl logs` / the dashboard's audit view surface the same hash-chained log `soc2`/HIPAA/PCI-DSS reports all draw from — one source of truth, not a separate review mechanism |
| **Response and Reporting** | §164.308(a)(6)(ii) — identify and respond to suspected/known security incidents | `packages/circuit-breaker` (Layer 5): automatic suspension on threshold violations or anomaly-detector escalation, plus `aegisctl approvals`/`approve`/`deny` for human-in-the-loop response |
| **Protection from Malicious Software** | §164.308(a)(5)(ii)(B) — procedures for guarding against/detecting/reporting malicious software | `packages/anomaly-detector` (Layer 4) — real-time behavioral detection (privilege escalation, lateral movement, reconnaissance, self-modification attempts), now a trained classifier, not just hardcoded thresholds (see PROGRESS.md's ML classifier entry) |

## Content-adjacent evidence: `packages/content-guardrail`

Added directly to this repo (not from the original SOC 2 proposal
language), and genuinely relevant here: PII detected in an agent's own
output (email, phone, SSN, credit-card-shaped sequences) is masked
before it ever reaches a response or the audit log, and every detection
is itself an audit-logged `content_guardrail_decision` event — evidence
that outbound PHI-adjacent leakage is actively screened for, not just
that the containment layers around it exist. See
[packages/content-guardrail/README.md](../content-guardrail/README.md)
for exactly what is and isn't detected — stated limitations apply here
too (regex-based, not exhaustive of every PHI category).

## Multi-tenancy as a cross-cutting control

Same as [CONTROL_MAPPING.md](CONTROL_MAPPING.md)'s note: every control
above is evaluated per tenant (`tenant_id`) — policy, audit log hash
chains, and credential vaulting are all isolated, verified directly with
a shared `session_id` string reused across two tenants to rule out
"isolation by unique ID alone."
