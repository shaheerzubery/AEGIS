"""Content guardrails (added directly, not from the proposal's own
roadmap — see PLAN.md's "Also done, requested directly" section, same
category as config.py's consolidation).

AEGIS's six proposal layers govern actions, network egress, and
credentials — none of them look at the actual TEXT flowing to or from the
LLM itself. This service does exactly that, checked by
packages/sdk/aegis_sdk's AegisClient.check_content() before a prompt is
sent (direction="input") or after a response is received
(direction="output"):

  - PII: email addresses, phone numbers, US SSNs, credit-card-shaped
    number sequences — regex-based, checked on both directions.
  - Prompt injection: known injection phrasings ("ignore previous
    instructions", "reveal your system prompt", etc.) — checked on
    direction="input" only; these are about *steering the agent*, which
    only makes sense on what's being fed to it.
  - Toxic/harmful content: a small, explicitly-labeled keyword/pattern
    MVP — checked on direction="output" only. Stated directly: this is
    NOT a trained classifier. Unlike packages/anomaly-detector, where a
    defensible synthetic training set could be built from the existing
    rule-based signal (session action counts, denial ratios — all
    numeric, all this repo's own data), toxicity detection needs real
    labeled human-language examples this repo doesn't have and can't
    honestly synthesize. A keyword list is a real, if weak, MVP — not
    faked as "AI-powered."

Matched PII values are masked before ever appearing in a response or the
audit log (see _mask) — this service exists to catch leaks, not become
one itself.

A denial reports to packages/circuit-breaker's existing violation counter
(the same one policy denials already use) — repeated bad content
contributes to suspension through a mechanism that already exists,
without needing new circuit-breaker logic.
"""

import json
import re
import threading
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Settings now come from /app/config.py, bind-mounted by
# demo/docker-compose.yml (not baked into the image — see config.py's
# module docstring for why, and how to change a value without a rebuild).
from config import (
    AUDIT_URL,
    CIRCUIT_BREAKER_URL,
    CONTENT_GUARDRAIL_PORT as PORT,
)

# ===================== PII (both directions) =====================
_PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<!\d)(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    # 13-19 digits, optionally grouped with spaces or dashes. Found by
    # testing, not assumed: a bare digit-length check here flags ANY long
    # numeric ID (a session id, a date, an order number) as a "credit
    # card" — confirmed false positives on '20260916123456' and
    # '12345678901234' during local testing before this ever ran live.
    # _luhn_valid below is the real fix (the standard checksum every real
    # card number satisfies), not a cosmetic narrowing of the regex.
    "credit_card": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
}


def _luhn_valid(digits: str) -> bool:
    """The checksum every real credit card number satisfies (ISO/IEC
    7812) — filters the credit_card regex's necessarily-broad digit-run
    match down to numbers that are actually shaped like a real card,
    cutting the false-positive rate on ordinary long numeric IDs from
    "constant" to "matches this specific checksum by chance.\""""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

# ===================== Prompt injection (direction="input" only) =====================
# Gap-closing work (2026-09-16, see PROGRESS.md): broadened from 6 to 12
# categories after building a real adversarial test set
# (test_injection_adversarial.py) against a curated list of known
# jailbreak/injection techniques and measuring recall honestly, rather
# than assuming the original 6 were enough. \s* (not a literal space)
# between words throughout, so _normalize's whitespace collapsing below
# doesn't create false negatives against multi-space evasion.
_INJECTION_PATTERNS = {
    "ignore_instructions": re.compile(r"ignore\s*(all|any)?\s*(previous|prior|above|earlier)\s*instructions", re.IGNORECASE),
    # Found by testing (test_injection_adversarial.py), not assumed: "the"
    # before "above" ("disregard THE above rules") wasn't in the optional
    # filler-word set, so a completely ordinary phrasing of this attack
    # went undetected. Filler words (a/an/the/my) allowed between
    # "disregard" and the temporal-scope word for exactly this reason.
    "disregard_instructions": re.compile(r"disregard\s*(all|any|the|my)?\s*(previous|prior|above|earlier)?\s*(instructions|rules|guidelines)", re.IGNORECASE),
    "forget_instructions": re.compile(r"forget\s*(everything|all)\s*(you\s*(were|have\s*been)\s*told|above|before)", re.IGNORECASE),
    "reveal_system_prompt": re.compile(r"(reveal|show|print|repeat|leak)\s*(your|the|me\s*your)?\s*(system\s*prompt|instructions|initial\s*prompt|configuration)", re.IGNORECASE),
    "query_own_rules": re.compile(r"what\s*(are|is)\s*your\s*(instructions|rules|guidelines|system\s*prompt)", re.IGNORECASE),
    "developer_mode": re.compile(r"(developer\s*mode|jailbreak|dan\s*mode|do\s*anything\s*now)", re.IGNORECASE),
    "pretend_no_restrictions": re.compile(r"pretend\s*(you|that\s*you)\s*(have\s*no|don'?t\s*have\s*any|has\s*no)\s*(restrictions|guardrails|rules|limits)", re.IGNORECASE),
    "unrestricted_persona": re.compile(r"act\s*as\s*(an?\s*)?(unfiltered|unrestricted|uncensored|unaligned)", re.IGNORECASE),
    "override_role": re.compile(r"you\s*are\s*now\s*(a|an|no\s*longer)", re.IGNORECASE),
    "fake_system_marker": re.compile(r"(\[\s*system\s*\]|###\s*instruction|<\|?\s*im_start\s*\|?>\s*system)", re.IGNORECASE),
    "encoded_response_request": re.compile(r"(respond|reply|answer)\s*(only\s*)?in\s*(base64|rot13|hex)", re.IGNORECASE),
    "priming_confirmation": re.compile(r"(say|type|respond with)\s*['\"]?(yes|understood|ok(ay)?|i\s*will\s*comply)['\"]?\s*(if|to\s*confirm)\s*you\s*(understand|agree|accept)", re.IGNORECASE),
}


def _normalize(text: str) -> str:
    """A real, modest first line of defense against basic evasion — not
    a claim of solving adversarial robustness (see the "Known
    limitations" section this module's README states directly). Unicode
    NFKC folds many visually-similar/decomposed characters (fullwidth
    Latin letters, certain accented forms) to a canonical form so a
    pattern written for plain ASCII still matches; stripping zero-width
    characters (U+200B/U+200C/U+200D/U+FEFF) defeats the specific trick
    of hiding one mid-word to split a token a substring match would
    otherwise catch whole; collapsing whitespace runs (tabs, newlines,
    repeated spaces) into single spaces is general hygiene the patterns'
    own \\s*/\\s+ already tolerate, not a distinct evasion defense on its
    own. Does NOT defeat semantic paraphrasing, letter-by-letter spacing
    ("i g n o r e"), or true homoglyphs from other scripts — no
    regex-based approach can catch those, which is exactly why this is
    labeled a "first line of defense," not a solution. See
    test_injection_adversarial.py for the measured, honest recall against
    both known phrasings and evasion attempts, including the ones this
    still misses."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[​‌‍﻿]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text

# ===================== Toxic/harmful content (direction="output" only) =====================
# Explicitly a keyword MVP, not a trained classifier — see module
# docstring for why. Deliberately small and unambiguous to keep the false
# positive rate low for an MVP with no ML backing.
_TOXIC_KEYWORDS = [
    "kill yourself",
    "i hate all",
    "should be exterminated",
    "subhuman",
]


def _mask(value: str) -> str:
    """First and last character kept, everything between replaced — a
    reviewer can confirm a real hit exists without this service (or its
    audit trail) ever storing the actual leaked value."""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _check_pii(text: str) -> list[dict]:
    hits = []
    for category, pattern in _PII_PATTERNS.items():
        for match in pattern.finditer(text):
            if category == "credit_card":
                digits = re.sub(r"[ -]", "", match.group())
                if not _luhn_valid(digits):
                    continue
            hits.append({"category": "pii", "type": category, "masked_sample": _mask(match.group())})
    return hits


def _check_injection(text: str) -> list[dict]:
    normalized = _normalize(text)
    hits = []
    for name, pattern in _INJECTION_PATTERNS.items():
        if pattern.search(normalized):
            hits.append({"category": "prompt_injection", "type": name})
    return hits


def _check_toxic(text: str) -> list[dict]:
    lowered = _normalize(text).lower()
    return [{"category": "toxic_content", "type": "keyword_match", "masked_sample": _mask(kw)} for kw in _TOXIC_KEYWORDS if kw in lowered]


def check_content(tenant_id: str, session_id: str, direction: str, text: str) -> dict:
    matches = _check_pii(text)
    if direction == "input":
        matches += _check_injection(text)
    elif direction == "output":
        matches += _check_toxic(text)

    categories = sorted({m["category"] for m in matches})
    blocked = bool(matches)

    if blocked:
        _report_violation(tenant_id, session_id)
        _log_event(tenant_id, session_id, direction, categories, matches)

    return {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "direction": direction,
        "blocked": blocked,
        "categories": categories,
        "matches": matches,
    }


def _report_violation(tenant_id: str, session_id: str) -> None:
    """Best-effort — reuses packages/circuit-breaker's existing violation
    counter, the same one policy denials already report to. A missing/
    down circuit-breaker shouldn't block a content check from returning."""
    try:
        req = urllib.request.Request(
            f"{CIRCUIT_BREAKER_URL}/violation/{tenant_id}/{session_id}",
            data=b"",
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except (urllib.error.URLError, OSError):
        pass


def _log_event(tenant_id: str, session_id: str, direction: str, categories: list[str], matches: list[dict]) -> None:
    """Best-effort — logs to the same audit trail every other layer uses.
    Never includes the raw text or unmasked matches (see _mask)."""
    try:
        req = urllib.request.Request(
            f"{AUDIT_URL}/events",
            data=json.dumps(
                {
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "event_type": "content_guardrail_decision",
                    "action": {"action_type": "content_check", "target": direction, "method": None},
                    "policy_decision": {"allowed": False, "reason": f"categories={categories}"},
                    "matches": matches,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except (urllib.error.URLError, OSError):
        pass


class Handler(BaseHTTPRequestHandler):
    # See packages/circuit-breaker/circuit_breaker.py's Handler for why —
    # HTTP/1.0 (the stdlib default) forces a connection close after every
    # response, which load testing found to be the actual concurrency
    # bottleneck across all of this repo's Python services.
    protocol_version = "HTTP/1.1"

    def _send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/check":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        tenant_id = body.get("tenant_id") or "default"
        session_id = body.get("session_id", "unknown")
        direction = body.get("direction")
        text = body.get("text", "")

        if direction not in ("input", "output"):
            self._send_json(400, {"error": "direction must be 'input' or 'output'"})
            return

        self._send_json(200, check_content(tenant_id, session_id, direction, text))

    def do_GET(self):
        # Added for the dashboard's status check (managed-dashboard-for-
        # security-teams work, 2026-09-28, see PROGRESS.md) — this
        # service previously had no GET route at all, so a health probe
        # against it fell through to BaseHTTPRequestHandler's default
        # 501, which the dashboard would have read as "down" even when
        # the service was healthy.
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"AEGIS content-guardrail listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
