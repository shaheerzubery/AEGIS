"""Feature extraction shared between train_classifier.py (offline training)
and anomaly_detector.py (online scoring) — the single most common way a
real ML system silently breaks is training and serving computing "the same"
feature slightly differently. Importing one function from one file makes
that class of bug structurally impossible here instead of a code-review
convention.

Every feature is derived from the same rolling window of
(timestamp, action_type, target, method, allowed) tuples the rule-based
MVP already maintained (see anomaly_detector.py's `_history`) — this
doesn't require any new signal, just combines the existing ones
statistically instead of with hard OR'd thresholds. self_modification is
deliberately NOT a feature here: the proposal's own wording for it is
"immediate critical, no threshold needed" — it stays a deterministic
override in anomaly_detector.py, not something for the model to weigh.

FEATURE_NAMES fixes both the identity and the order of the vector
train_classifier.py fits on and anomaly_detector.py calls predict_proba
with — order must match or the model silently scores nonsense.
"""

FEATURE_NAMES = [
    "n_actions",
    "denied_ratio",
    "distinct_denied_types",
    "distinct_targets",
    "distinct_action_types",
    "file_read_count",
    "file_read_ratio",
    "distinct_methods",
]


def extract_features(history) -> list[float]:
    """history: an iterable of (timestamp, action_type, target, method,
    allowed) tuples — anomaly_detector.py's deque, or a plain list of the
    same shape from train_classifier.py's synthetic generator. Returns a
    vector in FEATURE_NAMES order."""
    rows = list(history)
    n_actions = len(rows)
    if n_actions == 0:
        return [0.0] * len(FEATURE_NAMES)

    denied = [r for r in rows if not r[4]]
    action_types = {r[1] for r in rows}
    denied_types = {r[1] for r in denied}
    targets = {r[2] for r in rows if r[2]}
    methods = {r[3] for r in rows if r[3]}
    file_reads = [r for r in rows if r[1] == "file_read"]

    return [
        float(n_actions),
        len(denied) / n_actions,
        float(len(denied_types)),
        float(len(targets)),
        float(len(action_types)),
        float(len(file_reads)),
        len(file_reads) / n_actions,
        float(len(methods)),
    ]
