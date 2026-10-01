# packages/compliance — compliance evidence package

Sprint 4 per [PLAN.md](../../PLAN.md): "SOC 2 compliance package — pre-built
policy templates and audit reports for SOC 2 Type II certification" (the
proposal's own wording, §8). Extended 2026-09-27 to the proposal's Phase 2
enterprise tier (§7.2): HIPAA, PCI-DSS, and EU AI Act templates + mappings,
following the exact same pattern. See the relevant `*_MAPPING.md` for each
framework's mapping — **including its disclaimer, read that before
treating anything here as a certification.** None of these are one.

## What's here

- **`templates/soc2-strict.yaml`**, **`templates/soc2-standard.yaml`**,
  **`templates/hipaa.yaml`**, **`templates/pci-dss.yaml`**,
  **`templates/eu-ai-act.yaml`** — ready-to-apply policy profiles, same
  shape as `packages/policy-engine/policy.example.yaml`. Apply exactly
  the way any other policy file is applied — no new mechanism:
  ```
  aegisctl policy apply --tenant <name> packages/compliance/templates/hipaa.yaml
  ```
- **`CONTROL_MAPPING.md`** (SOC 2 Trust Services Criteria),
  **`HIPAA_MAPPING.md`**, **`PCI_DSS_MAPPING.md`**,
  **`EU_AI_ACT_MAPPING.md`** — the source of truth each framework's
  template comments and `compliance_report.py`'s control sections both
  reference, so the mapping can't drift between the policy templates and
  the generated report.
- **`compliance_report.py`** — pulls from the already-running
  audit-logger, circuit-breaker, and (as of the Phase 2 work)
  content-guardrail (no new endpoints anywhere), aggregates evidence per
  the controls in the relevant mapping file, and renders a report in your
  choice of format:
  ```
  pip install -r requirements.txt   # only needed for --format pdf
  python compliance_report.py --framework soc2 --tenant default --format pdf
  python compliance_report.py --framework hipaa --tenant default --format markdown
  python compliance_report.py --framework pci-dss --tenant default --format json
  python compliance_report.py --framework eu-ai-act --tenant default --format pdf
  ```
  `--framework` defaults to `soc2` — `python compliance_report.py --format
  pdf` behaves exactly as the pre-rename `soc2_report.py` always did.
  Reads `AEGIS_AUDIT_URL`/`AEGIS_CIRCUIT_BREAKER_URL` from the environment,
  same names and same `http://localhost:<port>` host-side defaults as
  `aegisctl` and every `demo/*.py` script — see
  [docs/configuration.md](../../docs/configuration.md).

## Content-guardrail evidence (new in the Phase 2 work)

HIPAA's and PCI-DSS's reports include a real, dynamically-aggregated
control row (`HIPAA-CG`/`PCI-CG`) counting `content_guardrail_decision`
events from the audit log during the report's time range — genuine
evidence that outbound PII/PAN-shaped text is actively screened, not a
static claim. See `packages/content-guardrail/README.md` for exactly
what is and isn't detected; both mapping files repeat the relevant
scoping caveat (PII detection is not PHI detection; credit-card detection
is not a PAN-discovery guarantee).

## Verification

`demo/compliance_templates_test.py` — applies each of the three new
templates directly to a live OPA instance and drives real allow/deny
checks against each (not just confirming OPA stored the data), then runs
`compliance_report.py` for all four frameworks across all three output
formats against the live stack and confirms each produces a real,
non-empty file. Also confirms a real Unicode encoding bug found during
development (fpdf2's core fonts can't encode em dashes; Python's
`open()` without an explicit encoding mangled them on Windows) stays
fixed — see PROGRESS.md's dated entry for the full story.

## Known gaps (real, not hidden)

- Not wired into `aegisctl` — runs as a standalone script. A Go CLI
  subcommand shelling out to Python was judged more fragile than it's
  worth for this MVP.
- No continuous evidence collection/scheduler. A real observation period
  (SOC 2 Type II, or an ongoing HIPAA/PCI-DSS program) is months long;
  this generates a report on demand from whatever's currently in the
  audit log — running it once doesn't constitute ongoing evidence
  collection.
- Each mapping is a reasonable-effort engineering interpretation, not
  vetted by a licensed assessor for that specific framework (a CPA firm
  for SOC 2, a QSA for PCI-DSS, a compliance/legal specialist for
  HIPAA/EU AI Act) — see each mapping file's own disclaimer, repeated on
  every generated report's cover section.
- SOC 2's Availability criteria aren't addressed at all — AEGIS
  constrains agent behavior, it doesn't manage underlying infrastructure
  availability. Similar out-of-scope notes exist in each of the newer
  mapping files for that framework's non-runtime-evidenceable
  requirements (PCI-DSS Req 11 penetration testing, EU AI Act Article 10
  training-data governance, etc.).
