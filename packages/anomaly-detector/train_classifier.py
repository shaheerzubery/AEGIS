"""Gap-closing work (2026-09-16, see PROGRESS.md): trains the sequence
classifier the proposal specs for Layer 4 (§4.7: "a fine-tuned transformer
classifier"). A transformer needs real labeled session data this repo
doesn't have and a GPU training run this environment can't do — the
"real but simple" MVP substitute already used elsewhere in this repo
(SQLite-not-Postgres, dev-mode-not-real Vault) is a small scikit-learn
classifier (RandomForest) trained on synthetic session data, over the
exact same rolling-window signal the rule-based MVP already computed
(see features.py) — genuinely trained and evaluated, not a stub that
always returns a fixed score.

Per the proposal's own risk mitigation for false positives (§11: "start
with rule-based detection, layer ML on top"), this is built as a literal
reading of "layer ON TOP": self_modification stays a deterministic
override (anomaly_detector.py), and the synthetic training data
deliberately includes "blended" malicious sessions — moderate signal
across two dimensions, each BELOW the old rule engine's individual
threshold — and matching "hard negative" benign sessions with ONE
elevated feature and nothing else. A pure OR-of-thresholds rule engine
can't tell either of those apart; a trained classifier weighing combined
evidence can. test_classifier.py's adversarial-evasion check is the
direct test of this claim, not just a training-accuracy number.

Run this to regenerate model.joblib: `python train_classifier.py`
(needs scikit-learn — see requirements.txt). The committed model.joblib
in this directory is this script's exact output; re-run it after editing
any generator function below.
"""

import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, extract_features

MODEL_PATH = "model.joblib"
RANDOM_SEED = 42
SAMPLES_PER_CLASS = 700


def _row(t, action_type, target, method, allowed):
    return (t, action_type, target, method, allowed)


def make_benign_session(rng) -> list:
    """A normal agent session: a handful of actions, one dominant action
    type, mostly the same target, almost everything allowed."""
    n = int(rng.integers(1, 9))
    action_pool = ["file_read", "http_request", "tool_call", "send_email"]
    primary = rng.choice(action_pool)
    n_targets = max(1, int(n * rng.uniform(0.1, 0.4)))
    targets = [f"target-{i}" for i in range(n_targets)]
    methods = ["GET", "POST"]
    rows = []
    for i in range(n):
        action_type = primary if rng.random() < 0.85 else rng.choice(action_pool)
        allowed = rng.random() > 0.05
        rows.append(_row(float(i), action_type, rng.choice(targets), rng.choice(methods), bool(allowed)))
    return rows


def make_benign_hard_negative(rng) -> list:
    """A normal session with exactly ONE feature elevated into the range
    the OLD rule engine would have flagged alone — a user legitimately
    hitting a few denied domains, or browsing several hosts, but nothing
    else about the session is unusual (denied_ratio stays low, or the
    session mixes in ordinary allowed activity around the denials).
    Labeled benign on purpose: teaches the model that one elevated
    dimension alone isn't sufficient, directly counteracting the
    false-positive brittleness of a single hard threshold.

    Deliberately does NOT have a "many file reads, all allowed, all
    distinct targets" variant: that shape is indistinguishable in this
    feature space from make_reconnaissance_session's malicious pattern
    (same features, by construction) — there's no signal here to tell
    "legitimate bulk read" from "reconnaissance probing" apart, so trying
    to teach both as different labels is pure label noise, not a genuine
    hard negative. The old rule engine had the same blind spot (any 10+
    file-read session was flagged unconditionally); this MVP keeps that
    behavior rather than manufacturing a false sense of nuance."""
    which = rng.choice(["targets", "denied"])
    rows = []
    if which == "targets":
        n_targets = int(rng.integers(5, 8))  # >= old LATERAL_MOVEMENT_THRESHOLD (5)
        for i in range(n_targets):
            rows.append(_row(float(i), "http_request", f"site-{i}.example.com", "GET", True))
    else:
        n_denied_types = int(rng.integers(3, 5))  # >= old PRIVILEGE_ESCALATION_THRESHOLD (3)
        for i in range(n_denied_types):
            rows.append(_row(float(i), f"action_{i}", "shared-target", "POST", False))
        for i in range(3):  # plus some ordinary allowed activity around it
            rows.append(_row(float(n_denied_types + i), "tool_call", "shared-target", "POST", True))
    return rows


def make_privilege_escalation_session(rng) -> list:
    n_types = int(rng.integers(3, 8))
    types = [f"action_{i}" for i in range(n_types)]
    n = int(rng.integers(n_types, n_types + 6))
    rows = []
    for i in range(n):
        allowed = rng.random() > 0.85
        rows.append(_row(float(i), rng.choice(types), "shared-target", "POST", bool(allowed)))
    return rows


def make_lateral_movement_session(rng) -> list:
    n_targets = int(rng.integers(5, 12))
    targets = [f"host-{i}.example.com" for i in range(n_targets)]
    n = int(rng.integers(n_targets, n_targets + 6))
    rows = []
    for i in range(n):
        allowed = rng.random() > 0.3
        rows.append(_row(float(i), "http_request", rng.choice(targets), "GET", bool(allowed)))
    return rows


def make_reconnaissance_session(rng) -> list:
    n = int(rng.integers(10, 25))
    return [_row(float(i), "file_read", f"/data/file-{i}.txt", "GET", True) for i in range(n)]


def make_blended_session(rng) -> list:
    """Moderate signal across TWO dimensions, each below the old rule
    engine's individual threshold — e.g. 2 distinct denied types (below
    privilege_escalation's 3) AND 4 distinct targets (below
    lateral_movement's 5) in the same session. No single old rule would
    have fired; combined, it's a real anomaly. This is the direct test
    of "layer ML on top" rather than "replace the rules with a bigger
    OR.\""""
    n_denied_types = int(rng.integers(2, 3))
    n_targets = int(rng.integers(3, 5))
    n_file_reads = int(rng.integers(4, 9))
    types = [f"action_{i}" for i in range(n_denied_types)]
    targets = [f"host-{i}.example.com" for i in range(n_targets)]
    rows = []
    t = 0.0
    for i in range(n_denied_types + 2):
        rows.append(_row(t, rng.choice(types), "shared-target", "POST", False))
        t += 1
    for i in range(n_targets):
        rows.append(_row(t, "http_request", targets[i], "GET", True))
        t += 1
    for i in range(n_file_reads):
        rows.append(_row(t, "file_read", f"/data/probe-{i}.txt", "GET", True))
        t += 1
    return rows


def build_dataset(rng, n_per_class: int):
    sessions, labels = [], []
    benign_generators = [make_benign_session, make_benign_session, make_benign_hard_negative]
    malicious_generators = [
        make_privilege_escalation_session,
        make_lateral_movement_session,
        make_reconnaissance_session,
        make_blended_session,
    ]
    for _ in range(n_per_class):
        gen = benign_generators[rng.integers(0, len(benign_generators))]
        sessions.append(gen(rng))
        labels.append(0)
    for _ in range(n_per_class):
        gen = malicious_generators[rng.integers(0, len(malicious_generators))]
        sessions.append(gen(rng))
        labels.append(1)
    return sessions, labels


def main():
    rng = np.random.default_rng(RANDOM_SEED)
    sessions, labels = build_dataset(rng, SAMPLES_PER_CLASS)
    X = np.array([extract_features(s) for s in sessions])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=RANDOM_SEED)
    start = time.time()
    model.fit(X_train, y_train)
    train_seconds = time.time() - start

    y_pred = model.predict(X_test)
    print(f"trained on {len(X_train)} samples, {len(FEATURE_NAMES)} features, {train_seconds:.2f}s")
    print(f"feature importances: {dict(zip(FEATURE_NAMES, model.feature_importances_.round(3)))}")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    print(f"saved {MODEL_PATH}")


if __name__ == "__main__":
    main()
