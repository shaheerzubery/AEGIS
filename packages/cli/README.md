# aegisctl

Command-line interface for the AEGIS containment platform: audit log,
human-in-the-loop approval queue, incident replay, and live policy updates.

## Commands

- `aegisctl logs` — show recent audit log events.
- `aegisctl approvals` — list sessions currently suspended, pending human
  review (proposal §3.2 Layer 5).
- `aegisctl resume <session-id>` (alias `approve`) — resume a suspended session.
- `aegisctl deny <session-id>` — permanently terminate a session; unlike
  resume, this cannot be undone via the CLI.
- `aegisctl replay <session-id>` — reconstruct a session's full audit trail
  in chronological order, one step at a time (proposal §3.2 Layer 6).
- `aegisctl policy apply <file>` — push a policy.example.yaml-shaped file
  into OPA's live policy data (no restart needed).

## Env

- `AEGIS_AUDIT_URL` (default `http://localhost:9300`)
- `AEGIS_CIRCUIT_BREAKER_URL` (default `http://localhost:9400`)
- `AEGIS_POLICY_URL` (default `http://localhost:8181`)

## Build

```
go build -o aegisctl .
```
