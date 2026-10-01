# AEGIS Anomaly Detector — Layer 4 (Behavioural anomaly detection)

Sprint 3 shipped this rule-based. Gap-closing work (2026-09-16, see
PROGRESS.md) replaced the threshold-crossing decision with a trained
classifier (`train_classifier.py`, a scikit-learn `RandomForestClassifier`,
committed as `model.joblib`) — the sequence classifier the proposal specs
for this (§4.7: "a fine-tuned transformer classifier"). A transformer
needs real labeled session data and GPU training this environment doesn't
have; this is the "real but simple" MVP substitute this repo uses
elsewhere (SQLite not Postgres, dev-mode not real Vault) — a genuinely
trained and evaluated model, not a stub.

Per the proposal's own risk mitigation for false positives (§11: "start
with rule-based detection, layer ML on top"), the model is trained to
catch what the old OR-of-thresholds rule engine structurally couldn't:
moderate signal across two dimensions at once, each individually below
the old thresholds — see `train_classifier.py`'s `make_blended_session`
and `test_classifier.py`'s direct proof this actually works, including
against the old logic literally re-run on the same input for comparison.
It's also trained on matching "hard negative" benign sessions (one
elevated feature, nothing else unusual) so it isn't just recreating a
single-feature threshold with extra steps.

`self_modification` is the one exception, kept as a deterministic pattern
match rather than a model feature — the proposal's own wording for it is
"immediate critical, no threshold needed" (§4.7), a security invariant,
not a statistical judgment call.

## How events reach it

`packages/audit-logger` forwards every newly-appended `policy_decision`
event here in real time (`POST /events`), rather than this service polling.
See `audit_logger.py`'s `_forward_to_anomaly_detector`.

## Features and scoring (proposal §4.7 "Detection categories")

`features.py` extracts 8 numeric features from a session's rolling window
(`n_actions`, `denied_ratio`, `distinct_denied_types`, `distinct_targets`,
`distinct_action_types`, `file_read_count`, `file_read_ratio`,
`distinct_methods`) — the exact same underlying signal the old rule engine
used, just continuous instead of hard thresholds. `model.joblib`'s
`predict_proba` turns that into one probability; `anomaly_detector.py`'s
`_score()` maps it to severity:

- **critical** — `self_modification` pattern match, OR probability ≥ 0.85.
- **warning** — probability ≥ 0.5.
- **informational** — otherwise.

`critical` calls `packages/circuit-breaker`'s `POST /suspend/<tenant>/<session>`
directly — bypassing its violation-count threshold, since the anomaly
detector has already decided the session is dangerous.

The response's `flags` list is descriptive now, not decisive — it still
names `privilege_escalation`/`lateral_movement`/`reconnaissance` when
their old individual thresholds are crossed (so an operator reading
`/suspended`'s reason sees familiar vocabulary), plus a new `ml_anomaly`
flag when the model alone crosses the warning probability with none of
those individually firing — the direct, visible case of the model
catching something the old thresholds structurally couldn't have named.

## API

- `POST /events` — called by the audit logger with one event. Non-
  `policy_decision` events are acknowledged and ignored.
- `GET /score/<tenant-id>/<session-id>` — current score/severity/flags for
  a session.

## Config

Read from `config.py` (bind-mounted, not env vars — see its module docstring):

- `ANOMALY_WINDOW_SECONDS` (default `120`)
- `PRIVILEGE_ESCALATION_THRESHOLD` / `LATERAL_MOVEMENT_THRESHOLD` /
  `RECONNAISSANCE_THRESHOLD` — descriptive-flag thresholds only now (see
  above), no longer decide severity.
- `CIRCUIT_BREAKER_URL` — derived from `CIRCUIT_BREAKER_BACKEND` (default
  `"rust"`, i.e. `http://circuit-breaker-rs:9400`; set to `"python"` for
  `http://circuit-breaker:9400` instead — see `config.py` and
  `packages/circuit-breaker-rs/README.md`).

`CRITICAL_THRESHOLD`/`WARNING_THRESHOLD` (0.85/0.5) are constants in
`anomaly_detector.py` itself, not `config.py` — they're properties of the
model's probability calibration, not a demo-to-real-world deployment
value the way the rest of `config.py` is.

## Retraining

`python train_classifier.py` regenerates `model.joblib` from the synthetic
generators in that file — re-run it (and re-run `test_classifier.py`
after) if you change any generator, the feature set, or want to retrain
against real session data once it exists. Needs `scikit-learn` (see
`requirements.txt`, pinned to the exact version `model.joblib` was trained
with — scikit-learn's own docs warn that unpickling an estimator with a
different version than it was trained with "might lead to breaking code
or invalid results").

## Verification

- `test_classifier.py` — offline, no live services needed. Proves (1) a
  hand-built "blended" session crosses none of the old individual
  thresholds (by literally re-running that old logic), yet the classifier
  flags it anyway; (2) clear reconnaissance/lateral-movement patterns
  score high; (3) an ordinary small session scores low; (4) one elevated
  feature alone, nothing else unusual, isn't flagged.
- Live, end-to-end via `demo/tenant_isolation_test.py`'s
  `test_anomaly_detector_isolation` — 11 real `file_read` calls through
  the full stack (SDK → policy engine → audit logger → this service)
  still suspend the session via the live model, same as the old rule
  engine did, and tenant isolation is unaffected.
- Live, direct HTTP replay of the blended-evasion pattern against a
  running `anomaly-detector` (`POST /events` twice for 2 distinct denied
  types, then 4 distinct `http_request` targets) — `flags: ["ml_anomaly"]`
  appears after only 2 actions, well before either old threshold (3 denied
  types, 5 targets) would have fired anything at all. See PROGRESS.md's
  dated entry for the full transcript.

## Known limitations (MVP)

- Trained on synthetic data, not real session traffic — there isn't a
  labeled real-world dataset for this. `CRITICAL_THRESHOLD`/
  `WARNING_THRESHOLD` are chosen to match the old rule engine's two-tier
  split, not tuned against real false-positive/false-negative rates.
- Still no adversarial robustness *testing suite* (proposal §4.7's stated
  requirement) beyond `test_classifier.py`'s specific blended-evasion
  case — a broader campaign (many evasion strategies, not one) is future
  work.
- Thresholds/probabilities are global, not per-policy-profile or
  per-task-baseline.
- A trained model can't explain itself as legibly as a named rule could —
  `flags` covers the common case (the named categories, plus
  `ml_anomaly` when none apply) but doesn't expose full feature
  attribution per decision.
