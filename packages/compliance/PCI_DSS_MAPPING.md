# AEGIS → PCI-DSS v4.0 control mapping

**This is not a PCI-DSS certification, and AEGIS alone cannot make an
organization PCI-DSS compliant.** PCI-DSS certification requires a formal
assessment (a Report on Compliance from a Qualified Security Assessor, or
a Self-Assessment Questionnaire) covering the *entire* cardholder data
environment — network segmentation, physical security, vulnerability
scanning, penetration testing, and organizational policies AEGIS has no
visibility into. This document maps AEGIS's own containment behavior to
the slice of PCI-DSS v4.0 requirements relevant to *an AI agent that
might touch cardholder data* specifically. Same "reasonable-effort
engineering interpretation, not vetted by a QSA" caveat as
[CONTROL_MAPPING.md](CONTROL_MAPPING.md) (SOC 2) — read that file's
disclaimer too.

**PAN detection, precisely scoped**: PCI-DSS's core concern is the
Primary Account Number (PAN) and other cardholder data.
`packages/content-guardrail`'s credit-card detector is a real,
Luhn-checksum-validated (ISO/IEC 7812) match for PAN-shaped number
sequences — genuinely relevant evidence, not decoration. It is NOT a
PCI-DSS-certified data-discovery tool, has no visibility into cardholder
data at rest outside of what passes through an AEGIS-fronted agent's
input/output text, and (like any regex+checksum approach) can miss
non-standard PAN formats or false-negative on a PAN split across
multiple messages. Stated directly, not hidden.

## Requirement-by-requirement evidence

| PCI-DSS v4.0 Requirement | Paraphrased intent | AEGIS evidence |
|---|---|---|
| **Req 1** — Install and maintain network security controls | Restrict connections between untrusted networks and the cardholder data environment | `packages/proxy`'s egress control (Layer 1, Envoy + OPA) — network egress is deny-by-default; the DNS-rebinding fix (`packages/proxy/dns-filter`) closes a real bypass where an allowlisted hostname resolves to a private/internal address |
| **Req 3** — Protect stored account data | Render PAN unreadable wherever stored; restrict access to cardholder data | Two independent mechanisms: `packages/credential-vault` (Layer 2) never lets the agent hold, see, or transmit a raw credential in the first place; `packages/content-guardrail`'s credit-card detector masks any PAN-shaped sequence that appears in agent input/output text before it ever reaches a response or the audit log (first/last character kept, everything between replaced) |
| **Req 7** — Restrict access to system components and cardholder data by business need to know | Least-privilege access control | `allowed_tools`/`allowed_credential_actions` allowlists (Layer 3, OPA) — nothing is reachable unless explicitly listed; credential-vault's per-tenant Vault paths with no cross-tenant fallback |
| **Req 8** — Identify users and authenticate access to system components | Unique IDs, strong authentication | Dashboard API's static keys (`config.py`'s `DASHBOARD_API_KEYS`) resolve to a tenant, a role (operator/viewer), AND a named operator identity (added 2026-09-28) — all derived server-side from the key; `tenant_id`/`session_id` scoping on every action, verified isolated even under a shared session_id string across tenants |
| **Req 10** — Log and monitor all access to system components and cardholder data | Audit trails covering all access, protected from tampering | `packages/audit-logger`'s hash-chained, append-only log (Layer 6) — every action, decision, and content-guardrail PAN detection is recorded; `GET /verify` recomputes the chain, confirmed to flip to `chain_intact: false` on deliberate row tampering |
| **Req 10.5 / 10.3** — Audit logs are protected from unauthorized modification, retained appropriately | Log integrity | Same hash-chaining as above — tampering with any past entry breaks the chain for everything after it, detectable via `/verify` without needing a separate integrity mechanism |
| **Req 6.2 / Secure development** (partial) | Vulnerabilities are identified and addressed | This repo's own internal security review (see PROGRESS.md, 2026-08-22) found and fixed three real issues (dashboard CSRF, an unvalidated tenant_id in credential-vault, a traversal-bypassable Rego rule) empirically verified against the live stack — evidence of a review process having run, not a substitute for PCI-DSS's own required penetration testing (Req 11) |

## Known gaps for this framework specifically

- Req 11 (regular security testing — vulnerability scans, penetration
  tests, segmentation testing) is not something a containment layer can
  self-certify; this mapping doesn't claim coverage there.
- Req 4 (protect cardholder data with strong cryptography during
  transmission) — AEGIS's egress proxy controls *destination*, not
  transport encryption itself; TLS termination/cipher configuration is
  the deploying organization's own responsibility.
- The credit-card detector is a fraud-adjacent safety net for text
  flowing through an AEGIS-fronted agent, not a replacement for
  proper tokenization/encryption of cardholder data at rest — Req 3's
  stronger controls (tokenization, format-preserving encryption) are
  out of scope for what a text-pattern detector can provide.

## Multi-tenancy as a cross-cutting control

Same as [CONTROL_MAPPING.md](CONTROL_MAPPING.md)'s note — every control
above is evaluated per tenant, verified directly with a shared
`session_id` string reused across two tenants to rule out "isolation by
unique ID alone."
