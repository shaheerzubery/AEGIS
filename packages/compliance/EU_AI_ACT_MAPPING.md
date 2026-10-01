# AEGIS → EU AI Act control mapping (high-risk AI system obligations)

**This is not a legal conformity assessment, and AEGIS alone cannot make
an AI system "EU AI Act compliant."** The Act (Regulation (EU) 2024/1689)
applies obligations based on an AI system's risk classification, and
conformity assessment for high-risk systems involves considerably more
than runtime containment — a risk management system spanning the
system's whole lifecycle (Article 9), technical documentation (Article
11), data governance for training data (Article 10, which AEGIS has no
visibility into at all — it doesn't train models), and in many cases
third-party conformity assessment. This document maps AEGIS's own
containment behavior to the slice of Chapter III, Section 2 (Articles
9–15, "Requirements for high-risk AI systems") that a runtime
containment layer can actually produce evidence for. Same
"reasonable-effort engineering interpretation, not vetted by an AI Act
compliance specialist" caveat as
[CONTROL_MAPPING.md](CONTROL_MAPPING.md) (SOC 2) — read that file's
disclaimer too.

## Requirement-by-requirement evidence

| EU AI Act Article | Paraphrased obligation | AEGIS evidence |
|---|---|---|
| **Article 9** — Risk management system | Identify, evaluate, and mitigate risks throughout the system's lifecycle, including risks from foreseeable misuse | The full layered containment model, not one control: egress control (Layer 1), credential vaulting (Layer 2), action-level policy (Layer 3), behavioral anomaly detection (Layer 4), circuit-breaker escalation (Layer 5), and content guardrails together address distinct risk categories (unauthorized network access, credential exposure, policy violation, behavioral drift, PII/prompt-injection/toxic-content risk) rather than one mechanism trying to cover all of them |
| **Article 12** — Record-keeping | Automatic logging of events ("logs") over the system's lifetime, enabling traceability | `packages/audit-logger`'s hash-chained, append-only event log (Layer 6) — every action, policy decision, anomaly score, circuit-breaker event, and content-guardrail check is recorded automatically, not opt-in; `aegisctl replay` reconstructs a session's full history from it |
| **Article 14** — Human oversight | High-risk AI systems are designed to allow effective human oversight, including the ability to intervene or halt operation ("stop button") | `packages/circuit-breaker` (Layer 5) is a direct implementation of this: soft-pause → hard-suspend (freeze + forensic snapshot) → emergency-kill (genuine container termination, verified against a real throwaway container — see PROGRESS.md), all human-resumable via `aegisctl approvals`/`approve`/`deny` except the explicit permanent-termination path |
| **Article 15** — Accuracy, robustness, and cybersecurity | High-risk systems achieve an appropriate level of accuracy/robustness and are resilient against attempts to alter their use through adversarial inputs | `packages/anomaly-detector`'s trained classifier (a real scikit-learn model, evaluated on a held-out split, verified to catch a session pattern the old rule-based thresholds structurally couldn't — see PROGRESS.md) plus `packages/content-guardrail`'s prompt-injection detection, itself measured against a curated adversarial set (12/12 known-technique recall, 3/4 mechanical-evasion techniques defeated, one genuine semantic paraphrase honestly confirmed as NOT caught — see `packages/content-guardrail/README.md`'s "Adversarial testing" section) |
| **Article 13** — Transparency and provision of information to deployers | Deployers can understand and correctly use the system's outputs | Every action's allow/deny decision is logged with its `reason`; the dashboard and `aegisctl logs` surface this directly rather than requiring deployers to infer behavior from outputs alone |
| **Article 10** (partial) — Data governance | Training/validation data quality — largely out of scope | Not addressed — AEGIS doesn't train or select the underlying agent's model. The one adjacent point: `packages/anomaly-detector`'s own classifier is trained on explicitly-synthetic data, honestly disclosed as such (no real-world labeled dataset exists or was claimed) — see PROGRESS.md's ML classifier entry |

## What this mapping does NOT cover

- Conformity assessment procedures (Article 43) and CE marking — a legal/regulatory process, not something a runtime layer can self-certify.
- Article 10's training-data governance requirements for the underlying LLM itself — AEGIS sits downstream of model training entirely.
- Fundamental rights impact assessments (Article 27) — an organizational/legal process using AEGIS's evidence as one input, not something AEGIS performs itself.
- Article 15's "appropriate level of accuracy" is evidenced here by measured test results (classifier evaluation, adversarial recall numbers), not by an accuracy claim about the underlying LLM's own outputs, which AEGIS does not generate or evaluate.

## Multi-tenancy as a cross-cutting control

Same as [CONTROL_MAPPING.md](CONTROL_MAPPING.md)'s note — every control
above is evaluated per tenant, verified directly with a shared
`session_id` string reused across two tenants to rule out "isolation by
unique ID alone."
