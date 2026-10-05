# AEGIS Content Guardrail — text-content checks (added directly, not from the proposal)

AEGIS's six proposal layers govern actions, network egress, and
credentials — none of them look at the actual TEXT flowing to or from the
LLM itself. This service does exactly that. Added directly per request,
not derived from the business proposal's own roadmap (same category as
`config.py`'s consolidation).

## What it checks

Called by `packages/sdk/aegis_sdk`'s `AegisClient.check_content(text,
direction)` before a prompt is sent (`direction="input"`) or after a
response is received (`direction="output"`):

- **PII** (both directions) — email addresses, phone numbers, US SSNs,
  credit-card-shaped number sequences. The credit-card check runs a real
  Luhn checksum (ISO/IEC 7812) on top of the regex — found by testing,
  not assumed: a bare 13–19-digit regex alone flags *any* long numeric ID
  (a session id, a date, an order number) as a false positive. Luhn
  narrows that down to numbers actually shaped like a real card.
- **Prompt injection** (`direction="input"` only) — 12 known
  injection/jailbreak techniques ("ignore previous instructions",
  "reveal your system prompt", "developer mode", persona hijacking, fake
  `[SYSTEM]` markers, encoded-response requests, priming/confirmation
  tricks, etc. — see `_INJECTION_PATTERNS`). Input-only on purpose: these
  are about steering the agent, which only makes sense on what's being
  fed to it. Text is run through `_normalize()` first (Unicode NFKC,
  zero-width character stripping, whitespace collapsing) — a real, if
  modest, defense against basic evasion; see "Adversarial testing" below
  for what this does and doesn't catch, measured, not assumed.
- **Toxic/harmful content** (`direction="output"` only) — a small,
  explicitly-labeled keyword/pattern MVP. **Stated directly: this is NOT
  a trained classifier.** Unlike `packages/anomaly-detector`, where a
  defensible synthetic training set could be built from this repo's own
  numeric behavioral signal, toxicity detection needs real labeled
  human-language examples this repo doesn't have and can't honestly
  synthesize. A keyword list is a real, if weak, MVP — not dressed up as
  "AI-powered."

Every matched PII value is masked (first/last character kept, everything
between replaced with `*`) before it ever appears in a response or the
audit log — this service exists to catch leaks, not become one itself.

## API

- `POST /check` — body `{"tenant_id", "session_id", "direction": "input"|"output", "text"}`.
  Returns `{"tenant_id", "session_id", "direction", "blocked", "categories", "matches"}`
  — `matches` never contains the raw matched text, only `masked_sample`.

## How it wires into the rest of AEGIS

Deliberately reuses existing mechanisms rather than adding new ones:

- A `blocked` result reports to `packages/circuit-breaker`'s existing
  violation counter (`POST /violation/<tenant>/<session>`) — the same
  one policy denials already use. Enough content-guardrail denials
  suspend a session through a threshold that already exists.
- Every denial is logged to `packages/audit-logger` as a
  `content_guardrail_decision` event, alongside `policy_decision` events
  — same audit trail, not a separate one. The logged event never
  includes the raw text, only masked matches.
- No new OPA policy — Rego is good at declarative allow/deny over
  structured data; pattern-matching and scoring free text is a different
  job (same reasoning `packages/anomaly-detector` and
  `packages/circuit-breaker` already use for staying separate services).

## SDK usage

```python
from aegis_sdk import AegisClient, ContentDenied

client = AegisClient(session_id="...", tenant_id="...")
try:
    client.check_content(user_prompt, direction="input")
except ContentDenied as exc:
    ...  # exc.categories, e.g. ["prompt_injection"]
```

Fail-open, like every other non-policy-engine call in `AegisClient`: an
unreachable content-guardrail returns rather than raising, so a real
agent's core functionality never depends on this optional layer being up.

## Config

Read from `config.py` (bind-mounted, not env vars):

- `CONTENT_GUARDRAIL_PORT` (default `9200`)

Host-side callers (an externally-run agent's `AegisClient`) use
`AEGIS_CONTENT_GUARDRAIL_URL` instead (default `http://localhost:9200`),
same asymmetry `config.py`'s module docstring already documents for
every other URL.

## Verification

`demo/content_guardrail_test.py` drives the live service through the SDK
(not raw HTTP), proving: real PII detection with real masking (the raw
matched value is asserted absent from both the response and the audit
log, not just "should be"); prompt injection blocked on `input` but the
identical phrasing NOT blocked on `output`; ordinary benign content never
blocked; and five content-guardrail denials crossing
`packages/circuit-breaker`'s existing violation threshold and suspending
the session, the same way five policy denials already do.

## Adversarial testing (gap-closing work, 2026-09-16)

`test_injection_adversarial.py` replaces "no adversarial-robustness
testing" with an actual measured number, run against a curated set of 12
known jailbreak/injection techniques, a set of evasion variants of those
same techniques, and a benign-vocabulary-adjacent set for false
positives. Run it: `PYTHONPATH=<repo root> python
test_injection_adversarial.py` (needs `config.py` importable, same as
the service itself).

Current measured results:
- **12/12 (100%) known-attack recall** on the curated set.
- Normalization defeats extra-whitespace, zero-width-character, and
  mixed-case evasion of the same attacks, and happens to defeat a
  fullwidth-Unicode variant too (an NFKC side effect, not specifically
  designed for) — confirmed by testing each variant, not assumed from
  what NFKC "should" do.
- **A genuine semantic paraphrase is NOT caught**, confirmed directly —
  this is pattern matching's actual, disclosed limit, not a hidden gap.
- **0 false positives** on 6 benign strings sharing vocabulary with the
  attack patterns (e.g. "ignore the typo in my previous message").

**Found and fixed by running this test, not assumed correct**: the first
version of `disregard_instructions` missed "Disregard the above rules
entirely" — an entirely ordinary phrasing — because "the" wasn't in the
optional filler-word set between "disregard" and "above." Fixed by
allowing common filler words (a/an/the/my); re-ran the suite to confirm
100% recall, not just this one case.

## Known limitations (MVP)

- Toxic-content detection is a small keyword list, not a trained
  classifier — see "What it checks" above for why.
- Regex-based PII detection has real blind spots (phone numbers written
  with no separators at all, for instance) and isn't locale-aware beyond
  US phone/SSN formats.
- Prompt-injection detection is a fixed pattern list — genuine semantic
  paraphrasing defeats it, measured directly above, not just assumed.
  Normalization raises the bar against mechanical obfuscation
  (whitespace/case/zero-width/some Unicode tricks) but categorically
  cannot catch a rephrasing with no shared vocabulary — no regex-based
  approach can.
- The 12-technique adversarial set is real but not exhaustive of every
  documented jailbreak technique in AI-safety research; it's a
  meaningful sample; a broader, ongoing red-team effort would find more
  gaps than this one pass did.
- No per-tenant tuning of thresholds or pattern lists yet — every tenant
  gets the same detectors.
