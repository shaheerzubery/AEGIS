# AEGIS Audit Logger — Layer 6 (Immutable audit log)

Append-only, OCSF-formatted event log. Every action, policy decision, anomaly
score, and circuit-breaker event is recorded with a hash of the previous entry
(cryptographic chaining, proposal §3.2 Layer 6).

## Day 5: done

`audit_logger.py` is a small stdlib-only HTTP service, SQLite-backed for now
(swap to Postgres for production — the `audit-db` container in the demo stack
is reserved for that, not yet wired up).

## API

- `POST /events` — append one event. Body is any JSON object; the server
  fills in `event_id`, `timestamp`, `prev_hash`, and `hash` and returns the
  stored record.
- `GET /events?limit=N` — most recent N events, newest first.
- `GET /events?session_id=X&limit=N` — same, filtered to one session — used
  by `aegisctl replay` for incident reconstruction (proposal §3.2 Layer 6).
- `GET /verify` — recompute the whole hash chain and confirm nothing's been
  tampered with (`{"chain_intact": true|false}`).

## Storage
- Local dev (current): SQLite, path via `AEGIS_AUDIT_DB` (default `/data/audit.db`)
- Production (future): PostgreSQL

## Real-time forwarding (Sprint 3)

Every `policy_decision` event is forwarded to `packages/anomaly-detector`
right after it's written (`AEGIS_ANOMALY_DETECTOR_URL`, default
`http://anomaly-detector:9700`), best-effort with a 1s timeout — a down
anomaly detector adds up to ~1s of write latency but never blocks logging.
Runs inline, not via a queue, so this isn't fully decoupled; acceptable for
the MVP, worth revisiting before this needs to survive real load.

## SIEM forwarding (Sprint 3)

Every event is also forwarded to `AEGIS_SIEM_URL` if set (empty by default —
forwarding is off unless configured). Same OCSF-shaped payload as the audit
log itself (`schema/ocsf_event.json`). `demo/mock-siem` is a stand-in
receiver for local testing — a real deployment would point this at Splunk,
Datadog, or Elastic (proposal §3.2 Layer 6).
