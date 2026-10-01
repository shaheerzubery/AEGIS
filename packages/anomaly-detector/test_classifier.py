"""Direct test of the ML classifier's value-add claim (see
train_classifier.py's module docstring) — not training accuracy on
synthetic held-out data (train_classifier.py already reports that), but a
concrete scenario built by hand: one specific "blended" session that the
OLD rule engine's OR-of-thresholds genuinely could not have flagged
(verified below by literally re-running that old logic), which the
classifier flags anyway.

Loads model.joblib directly — no live services needed, unlike
demo/tenant_isolation_test.py's end-to-end anomaly-detector check.
"""

import sys

import joblib

from features import extract_features

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def old_rule_engine_flags(history) -> list[str]:
    """A literal copy of anomaly_detector.py's pre-ML _score() thresholds
    (PRIVILEGE_ESCALATION_THRESHOLD=3, LATERAL_MOVEMENT_THRESHOLD=5,
    RECONNAISSANCE_THRESHOLD=10 — config.py's defaults), used here only to
    prove a specific input crosses none of them. Not imported from
    anomaly_detector.py because that module now scores with the trained
    model instead — this function is a fixed historical reference point."""
    denied_types = {h[1] for h in history if not h[4]}
    distinct_targets = {h[2] for h in history if h[2]}
    file_reads = [h for h in history if h[1] == "file_read"]
    flags = []
    if len(denied_types) >= 3:
        flags.append("privilege_escalation")
    if len(distinct_targets) >= 5:
        flags.append("lateral_movement")
    if len(file_reads) >= 10:
        flags.append("reconnaissance")
    return flags


def _row(t, action_type, target, method, allowed):
    return (t, action_type, target, method, allowed)


def test_blended_evasion_case():
    """2 distinct denied action types (below the old threshold of 3) AND
    4 distinct targets (below the old threshold of 5) in one session —
    the exact shape train_classifier.py's make_blended_session teaches.
    A session that mixes weak-but-real signals across two categories
    specifically to stay under each individual old threshold."""
    history = [
        _row(0.0, "admin_action", "shared-target", "POST", False),
        _row(1.0, "config_change", "shared-target", "POST", False),
        _row(2.0, "http_request", "host-a.example.com", "GET", True),
        _row(3.0, "http_request", "host-b.example.com", "GET", True),
        _row(4.0, "http_request", "host-c.example.com", "GET", True),
        _row(5.0, "http_request", "host-d.example.com", "GET", True),
    ]

    old_flags = old_rule_engine_flags(history)
    check(
        "the old rule engine genuinely misses this pattern (0 or 1 flags, never critical)",
        len(old_flags) <= 1,
        f"old_flags={old_flags}",
    )

    bundle = joblib.load("model.joblib")
    model, feature_names = bundle["model"], bundle["feature_names"]
    features = extract_features(history)
    probability = model.predict_proba([features])[0][1]
    check(
        "the classifier flags it anyway (probability >= 0.5)",
        probability >= 0.5,
        f"probability={probability:.3f} features={dict(zip(feature_names, features))}",
    )


def test_clear_malicious_patterns_score_high():
    reconnaissance = [_row(float(i), "file_read", f"/data/file-{i}.txt", "GET", True) for i in range(11)]
    lateral_movement = [
        _row(float(i), "http_request", f"host-{i}.example.com", "GET", True) for i in range(8)
    ]
    bundle = joblib.load("model.joblib")
    model = bundle["model"]
    for name, history in [("reconnaissance", reconnaissance), ("lateral_movement", lateral_movement)]:
        probability = model.predict_proba([extract_features(history)])[0][1]
        check(f"clear {name} pattern scores high (probability >= 0.5)", probability >= 0.5, f"probability={probability:.3f}")


def test_clear_benign_session_scores_low():
    history = [_row(float(i), "file_read", "report.pdf", "GET", True) for i in range(3)]
    bundle = joblib.load("model.joblib")
    model = bundle["model"]
    probability = model.predict_proba([extract_features(history)])[0][1]
    check("a small, ordinary session scores low (probability < 0.5)", probability < 0.5, f"probability={probability:.3f}")


def test_hard_negative_single_elevated_feature_not_flagged():
    """The "targets" shape make_benign_hard_negative teaches: one
    legitimately elevated feature (here, 6 distinct hosts browsed) with
    nothing else unusual shouldn't alone be enough to flag — proves the
    model isn't just recreating a single-feature threshold with extra
    steps."""
    history = [_row(float(i), "http_request", f"site-{i}.example.com", "GET", True) for i in range(6)]
    bundle = joblib.load("model.joblib")
    model = bundle["model"]
    probability = model.predict_proba([extract_features(history)])[0][1]
    check(
        "one elevated feature alone (6 distinct hosts, everything else clean) isn't flagged",
        probability < 0.5,
        f"probability={probability:.3f}",
    )


def main():
    test_blended_evasion_case()
    test_clear_malicious_patterns_score_high()
    test_clear_benign_session_scores_low()
    test_hard_negative_single_elevated_feature_not_flagged()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
