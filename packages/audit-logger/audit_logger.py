"""Layer 6 — append-only, cryptographically chained audit log (Day 5 MVP).

SQLite- or Postgres-backed per the proposal ("SQLite for local dev,
PostgreSQL for production" — §8 Sprint 1; wired up as a config.py switch,
2026-08-22, see PROGRESS.md's "Gap #3"). Each event's hash covers its own
canonical form plus the previous event's hash, so tampering with any past
entry breaks the chain for everything after it. Schema: schema/ocsf_event.json.

Sprint 3: also forwards every newly-appended event to the anomaly detector
(packages/anomaly-detector) in real time, so it can consume the action
stream as it happens rather than polling. Also forwards every event to a
configurable SIEM endpoint (proposal §3.2 Layer 6: "Logs can be shipped to
external SIEM systems... in real time"), and supports filtering by
session_id for incident replay (proposal §3.2 Layer 6: "Replay any agent
session from the audit log").

Sprint 4: events carry a tenant_id (default "default" for callers that
predate multi-tenancy), and the hash chain is scoped per tenant — each
tenant has its own independent chain with its own genesis, computed by
looking up the most recent row *for that tenant* rather than the most
recent row overall. This means tampering with one tenant's chain can never
be masked or falsely flagged by another tenant's data, and /verify always
checks one tenant's chain at a time.

Gap #3: AUDIT_STORAGE_BACKEND (see config.py) selects "sqlite" (default,
today's exact behavior, no other services need to be up) or "postgres"
(uses audit-db, which has been running since Sprint 1 with nothing talking
to it). The hash-chain math below (canonical JSON + SHA-256) is identical
either way — only connect()/the three SQL statements differ, behind the
_execute() helper and the PARAM placeholder chosen at import time.
"""

import hashlib
import json
import os
import sqlite3
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Settings now come from /app/config.py, bind-mounted by
# demo/docker-compose.yml (not baked into the image — see config.py's
# module docstring for why, and how to change a value without a rebuild).
from config import (
    AUDIT_DB_PATH as DB_PATH,
    AUDIT_STORAGE_BACKEND,
    AUDIT_POSTGRES_HOST,
    AUDIT_POSTGRES_PORT,
    AUDIT_POSTGRES_USER,
    AUDIT_POSTGRES_PASSWORD,
    AUDIT_POSTGRES_DB,
    ANOMALY_DETECTOR_URL,
    SIEM_URL,
    AUDIT_LOGGER_PORT as PORT,
)

GENESIS_HASH = "0" * 64
DEFAULT_TENANT = "default"

_lock = threading.Lock()
_thread_local = threading.local()

_SCHEMA_SQLITE = """CREATE TABLE IF NOT EXISTS events (
    rowid_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    timestamp TEXT,
    tenant_id TEXT,
    session_id TEXT,
    event_type TEXT,
    payload TEXT,
    prev_hash TEXT,
    hash TEXT
)"""

_SCHEMA_POSTGRES = """CREATE TABLE IF NOT EXISTS events (
    rowid_seq SERIAL PRIMARY KEY,
    event_id TEXT UNIQUE,
    timestamp TEXT,
    tenant_id TEXT,
    session_id TEXT,
    event_type TEXT,
    payload TEXT,
    prev_hash TEXT,
    hash TEXT
)"""

if AUDIT_STORAGE_BACKEND == "postgres":
    import psycopg  # deferred import — only needed for this backend, see requirements.txt

    PARAM = "%s"

    def connect():
        conn = psycopg.connect(
            host=AUDIT_POSTGRES_HOST,
            port=AUDIT_POSTGRES_PORT,
            user=AUDIT_POSTGRES_USER,
            password=AUDIT_POSTGRES_PASSWORD,
            dbname=AUDIT_POSTGRES_DB,
        )
        _execute(conn, _SCHEMA_POSTGRES)
        conn.commit()
        return conn

elif AUDIT_STORAGE_BACKEND == "sqlite":
    PARAM = "?"

    def connect():
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _execute(conn, _SCHEMA_SQLITE)
        conn.commit()
        return conn

else:
    raise ValueError(f"unknown AUDIT_STORAGE_BACKEND: {AUDIT_STORAGE_BACKEND!r} (expected 'sqlite' or 'postgres')")


def get_conn():
    """One connection per handler thread, cached for the thread's lifetime
    instead of opening a fresh one (and re-running CREATE TABLE IF NOT
    EXISTS) on every request — the per-request connect() was one of the two
    causes found behind audit-logger's load-test ceiling (see PROGRESS.md's
    global-lock investigation). ThreadingHTTPServer gives each persistent
    (HTTP/1.1) connection its own thread, so this is reused across every
    request on that connection, not just the first."""
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = connect()
        _thread_local.conn = conn
    return conn


def _execute(conn, sql: str, params=()):
    """Runs sql on either backend, returns something with .fetchone()/
    .fetchall() either way. sqlite3.Connection has .execute() as a
    convenience shortcut that returns a fetchable cursor directly; a
    psycopg connection needs an explicit cursor first — this hides that
    one difference so every caller below is backend-agnostic."""
    if isinstance(conn, sqlite3.Connection):
        return conn.execute(sql, params)
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def append_event(conn, event: dict) -> dict:
    """Append one event to its tenant's chain. Thread-safe; returns the
    stored event (with event_id/timestamp/tenant_id/prev_hash/hash filled in)."""
    with _lock:
        tenant_id = event.get("tenant_id") or DEFAULT_TENANT
        row = _execute(
            conn,
            f"SELECT hash FROM events WHERE tenant_id = {PARAM} ORDER BY rowid_seq DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev_hash = row[0] if row else GENESIS_HASH

        stored = dict(event)
        stored["tenant_id"] = tenant_id
        stored["event_id"] = stored.get("event_id") or str(uuid.uuid4())
        stored["timestamp"] = stored.get("timestamp") or datetime.now(timezone.utc).isoformat()
        stored["prev_hash"] = prev_hash

        canonical = json.dumps(stored, sort_keys=True)
        stored["hash"] = hashlib.sha256((canonical + prev_hash).encode()).hexdigest()

        placeholders = ", ".join([PARAM] * 8)
        _execute(
            conn,
            f"INSERT INTO events (event_id, timestamp, tenant_id, session_id, event_type, payload, prev_hash, hash) "
            f"VALUES ({placeholders})",
            (
                stored["event_id"],
                stored["timestamp"],
                tenant_id,
                stored.get("session_id", ""),
                stored.get("event_type", ""),
                json.dumps(stored),
                prev_hash,
                stored["hash"],
            ),
        )
        conn.commit()
        return stored


def _forward_to_anomaly_detector(event: dict) -> None:
    """Best-effort, short-timeout forward of one stored event. Called on a
    background thread (see do_POST) rather than inline — a slow/unreachable
    anomaly detector used to add up to ~1s of latency to every write; this
    was one of the two causes found behind audit-logger's load-test ceiling
    (see PROGRESS.md's global-lock investigation)."""
    try:
        req = urllib.request.Request(
            f"{ANOMALY_DETECTOR_URL}/events",
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1)
    except (urllib.error.URLError, OSError):
        pass  # anomaly detector being down shouldn't block audit logging


def _forward_to_siem(event: dict) -> None:
    """Best-effort forward to a SIEM receiver (Splunk/Datadog/Elastic in
    production; demo/mock-siem for this repo). Same OCSF-shaped event as the
    audit log itself — see schema/ocsf_event.json. No-op if AEGIS_SIEM_URL
    isn't configured. Called on a background thread (see do_POST), same
    reasoning as _forward_to_anomaly_detector above."""
    if not SIEM_URL:
        return
    try:
        req = urllib.request.Request(
            SIEM_URL,
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1)
    except (urllib.error.URLError, OSError):
        pass  # SIEM being down shouldn't block audit logging


def list_events(
    conn,
    limit: int = 20,
    session_id: str | None = None,
    tenant_id: str | None = None,
    event_type: str | None = None,
) -> list:
    clauses = []
    params: list = []
    if tenant_id:
        clauses.append(f"tenant_id = {PARAM}")
        params.append(tenant_id)
    if session_id:
        clauses.append(f"session_id = {PARAM}")
        params.append(session_id)
    if event_type:
        clauses.append(f"event_type = {PARAM}")
        params.append(event_type)

    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    params.append(limit)
    rows = _execute(
        conn, f"SELECT payload FROM events {where}ORDER BY rowid_seq DESC LIMIT {PARAM}", params
    ).fetchall()
    return [json.loads(r[0]) for r in rows]


def verify_chain(conn, tenant_id: str = DEFAULT_TENANT) -> bool:
    """Recompute every hash in one tenant's chain, in order, and confirm it's
    intact. Scoped to a single tenant_id — tampering with another tenant's
    rows never affects this result, and vice versa."""
    rows = _execute(
        conn,
        f"SELECT payload, prev_hash, hash FROM events WHERE tenant_id = {PARAM} ORDER BY rowid_seq ASC",
        (tenant_id,),
    ).fetchall()
    expected_prev = GENESIS_HASH
    for payload_json, prev_hash, stored_hash in rows:
        if prev_hash != expected_prev:
            return False
        try:
            event = json.loads(payload_json)
        except json.JSONDecodeError:
            # A row tampered with badly enough to break JSON syntax itself
            # (not just change a value) is still tampering — report it the
            # same way as a hash mismatch instead of letting the exception
            # propagate and crash the request handler.
            return False
        # The stored payload includes "hash" itself, but that field didn't
        # exist yet when the hash was originally computed (see append_event)
        # — exclude it here or every recomputation would be self-referential
        # and never match.
        event_without_hash = {k: v for k, v in event.items() if k != "hash"}
        canonical = json.dumps(event_without_hash, sort_keys=True)
        recomputed = hashlib.sha256((canonical + prev_hash).encode()).hexdigest()
        if recomputed != stored_hash:
            return False
        expected_prev = stored_hash
    return True


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
        if self.path == "/events":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            conn = get_conn()
            stored = append_event(conn, body)
            if stored.get("event_type") == "policy_decision":
                threading.Thread(target=_forward_to_anomaly_detector, args=(stored,), daemon=True).start()
            threading.Thread(target=_forward_to_siem, args=(stored,), daemon=True).start()
            self._send_json(201, stored)
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/events":
            qs = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["20"])[0])
            session_id = qs.get("session_id", [None])[0]
            tenant_id = qs.get("tenant_id", [None])[0]
            event_type = qs.get("event_type", [None])[0]
            conn = get_conn()
            self._send_json(200, list_events(conn, limit, session_id, tenant_id, event_type))
        elif parsed.path == "/verify":
            qs = parse_qs(parsed.query)
            tenant_id = qs.get("tenant_id", [DEFAULT_TENANT])[0]
            conn = get_conn()
            self._send_json(200, {"tenant_id": tenant_id, "chain_intact": verify_chain(conn, tenant_id)})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def main(host="0.0.0.0", port=PORT):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"AEGIS audit-logger listening on {host}:{port} (backend: {AUDIT_STORAGE_BACKEND})")
    server.serve_forever()


if __name__ == "__main__":
    main()
