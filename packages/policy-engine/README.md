# AEGIS Policy Engine — Layer 3 (Action-level policy)

OPA/Rego evaluation of every discrete agent action (API call, file write, shell
command, DB query) against a declarative policy profile. Proxy and SDK both
consult this service before allowing an action through.

- `policy.example.yaml` — human-authored policy profile (allow/deny, network
  allowlist, rate limits, time windows, escalation rules — see proposal §4.6)
- `policies/default.rego` — compiled evaluation logic OPA runs against actions

## Day 2 goal
Read `policy.example.yaml` on proxy startup; enforce `allowed_domains` /
`denied_domains` / `default_action: deny` for network destinations only.

## Day 3 goal
Full OPA sidecar; Rego policies evaluate action type, target URL, rate limits.
