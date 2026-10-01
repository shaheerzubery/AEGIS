"""Layer 4 — behavioural anomaly detection.

Sprint 3 shipped this rule-based (four hardcoded thresholds). Gap-closing
work (2026-09-16, see PROGRESS.md) replaces the threshold-crossing logic
with a trained classifier (train_classifier.py, a scikit-learn
RandomForest over the same underlying signal — see features.py) — the
sequence classifier the proposal specs for this (§4.7: "a fine-tuned
transformer classifier"). A transformer needs real labeled session data
and GPU training this environment doesn't have; the classifier here is
genuinely trained and evaluated on synthetic data, not a stub, following
this repo's "real but simple" MVP pattern elsewhere (SQLite not Postgres,
dev-mode not real Vault).

self_modification is the one exception, kept as a hardcoded pattern match
rather than a model feature — the proposal's own wording for it is
"immediate critical, no threshold needed" (§4.7), which is a deterministic
security invariant, not a statistical pattern worth a model's judgment call.

Per the proposal's own risk mitigation for false positives (§11: "start
with rule-based detection, layer ML on top"), the classifier is trained to
catch what the old OR-of-thresholds engine structurally couldn't: sessions
with moderate signal across TWO dimensions simultaneously, each individually
below the old thresholds (see train_classifier.py's make_blended_session,
and test_classifier.py's direct proof of this). It's also trained on
matching "hard negative" benign sessions with exactly ONE elevated feature,
to avoid just recreating a single-feature threshold with extra steps.

Consumes the audit log's event stream in real time: packages/audit-logger
forwards every newly-appended policy_decision event here as it's written
(see audit_logger.py's _forward_to_anomaly_detector), rather than this
service polling. Maintains a rolling window of recent actions per
(tenant, session) (proposal §3.2 Layer 4) and scores it on every new event.

Any self_modification hit, or a model probability >= CRITICAL_THRESHOLD,
escalates to "critical" and directly suspends the session via
packages/circuit-breaker's POST /suspend/<tenant>/<session> — bypassing
its violation-count threshold, because the anomaly detector has already
made the call that this session is dangerous.

Sprint 4: the rolling window is keyed by (tenant_id, session_id), not bare
session_id — two tenants sharing the same session_id string build up
completely independent histories, so an anomaly in one tenant never flags
the other. tenant_id is read from the forwarded audit event and defaults
to "default" for events that predate multi-tenancy.
"""

import json
import re
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import urllib.error
import urllib.request

import joblib

from features import extract_features

# Settings now come from /app/config.py, bind-mounted by
# demo/docker-compose.yml (not baked into the image — see config.py's
# module docstring for why, and how to change a value without a rebuild).
from config import (
    ANOMALY_WINDOW_SECONDS as WINDOW_SECONDS,
    CIRCUIT_BREAKER_URL,
    ANOMALY_DETECTOR_PORT as PORT,
    PRIVILEGE_ESCALATION_THRESHOLD,  # descriptive flag only now, see _score
    LATERAL_MOVEMENT_THRESHOLD,  # descriptive flag only now, see _score
    RECONNAISSANCE_THRESHOLD,  # descriptive flag only now, see _score
    SELF_MODIFICATION_PATTERN as SELF_MODIFICATION_PATTERN_STR,
)

SELF_MODIFICATION_PATTERN = re.compile(SELF_MODIFICATION_PATTERN_STR, re.IGNORECASE)

# Probability thresholds for the trained classifier — not tuned against a
# real-world dataset (there isn't one), chosen to match the old rule
# engine's two-tier severity split (one signal = warning, enough combined
# signal = critical) so existing callers/tests that assert on "critical"
# vs "warning" keep working. See train_classifier.py.
CRITICAL_THRESHOLD = 0.85
WARNING_THRESHOLD = 0.5

_MODEL_BUNDLE = joblib.load("model.joblib")
_MODEL = _MODEL_BUNDLE["model"]
_FEATURE_NAMES = _MODEL_BUNDLE["feature_names"]

_lock = threading.Lock()
# (tenant_id, session_id) -> deque of (timestamp, action_type, target, method, allowed)
_history: dict[tuple[str, str], deque] = {}


def _prune(history: deque, now: float) -> None:
    while history and now - history[0][0] > WINDOW_SECONDS:
        history.popleft()


def ingest_event(event: dict) -> dict:
    """Process one audit event (already known to be event_type ==
    "policy_decision" — the caller filters). Updates the (tenant, session)'s
    rolling window and re-scores it."""
    tenant_id = event.get("tenant_id") or "default"
    session_id = event.get("session_id", "unknown")
    action = event.get("action") or {}
    decision = event.get("policy_decision") or {}

    action_type = action.get("action_type", "")
    target = action.get("target", "")
    method = action.get("method") or ""
    allowed = bool(decision.get("allowed"))

    with _lock:
        now = time.time()
        key = (tenant_id, session_id)
        history = _history.setdefault(key, deque())
        _prune(history, now)
        history.append((now, action_type, target, method, allowed))
        return _score(tenant_id, session_id, history)


def _score(tenant_id: str, session_id: str, history: deque) -> dict:
    self_mod_hits = [
        h for h in history if SELF_MODIFICATION_PATTERN.search(f"{h[2]} {h[3]}")
    ]

    features = extract_features(history)
    probability = float(_MODEL.predict_proba([features])[0][1]) if history else 0.0

    # Descriptive signals for the audit trail / human review, not the
    # decision itself anymore — kept so an operator reading /suspended's
    # reason (or this endpoint) still sees *why* in the same vocabulary as
    # before, even though the severity call below comes from the model's
    # combined probability rather than any one of these crossing a
    # threshold alone.
    flags = []
    if self_mod_hits:
        flags.append("self_modification")
    feature_map = dict(zip(_FEATURE_NAMES, features))
    if feature_map["distinct_denied_types"] >= PRIVILEGE_ESCALATION_THRESHOLD:
        flags.append("privilege_escalation")
    if feature_map["distinct_targets"] >= LATERAL_MOVEMENT_THRESHOLD:
        flags.append("lateral_movement")
    if feature_map["file_read_count"] >= RECONNAISSANCE_THRESHOLD:
        flags.append("reconnaissance")
    if probability >= WARNING_THRESHOLD and len(flags) == 0:
        # The model caught something none of the individual descriptive
        # thresholds above would have named on their own — the direct
        # "layer ML on top" case (see module docstring, test_classifier.py).
        flags.append("ml_anomaly")

    if self_mod_hits or probability >= CRITICAL_THRESHOLD:
        severity = "critical"
    elif probability >= WARNING_THRESHOLD:
        severity = "warning"
    else:
        severity = "informational"
    score = 1.0 if self_mod_hits else probability

    result = {
        "tenant_id": tenant_id,
        "session_id": session_id,
        "score": score,
        "severity": severity,
        "flags": flags,
        "actions_in_window": len(history),
    }

    if severity == "critical":
        _trigger_suspend(tenant_id, session_id, flags)

    return result


def _trigger_suspend(tenant_id: str, session_id: str, flags: list[str]) -> None:
    reason = f"anomaly detector: {', '.join(flags)}"
    try:
        req = urllib.request.Request(
            f"{CIRCUIT_BREAKER_URL}/suspend/{tenant_id}/{session_id}",
            data=json.dumps({"reason": reason}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
        print(f"[anomaly-detector] suspended tenant={tenant_id} session={session_id}: {reason}", flush=True)
    except (urllib.error.URLError, OSError) as exc:
        print(f"[anomaly-detector] failed to suspend tenant={tenant_id} session={session_id}: {exc}", flush=True)


def get_score(tenant_id: str, session_id: str) -> dict:
    with _lock:
        history = _history.get((tenant_id, session_id), deque())
        _prune(history, time.time())
        return _score(tenant_id, session_id, history)


class Handler(BaseHTTPRequestHandler):
    # See packages/circuit-breaker/circuit_breaker.py's Handler for why —
    # HTTP/1.0 (the stdlib default) forces a connection close after every
    # response, which load testing found to be the actual concurrency
    # bottleneck across all of this repo's Python services.
    protocol_version = "HTTP/1.1"

    def _send_json(self, status_code, body):
        data = json.dumps(body).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/events":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        event = json.loads(self.rfile.read(length) or b"{}")

        if event.get("event_type") != "policy_decision":
            self._send_json(200, {"ignored": True})
            return

        self._send_json(200, ingest_event(event))

    def do_GET(self):
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "score":
            self._send_json(200, get_score(parts[1], parts[2]))
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(
        f"AEGIS anomaly-detector listening on {host}:{port} "
        f"(window={WINDOW_SECONDS}s, circuit-breaker={CIRCUIT_BREAKER_URL})"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
