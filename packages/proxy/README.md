# AEGIS Proxy — Layer 1 (Egress control)

Transparent proxy that all agent outbound traffic is routed through. Default-deny:
no destination is reachable unless allowlisted in the active policy profile.

- `envoy.yaml` — Envoy config: passthrough filter (Day 1) → DNS allowlist filter (Day 2)
- Consults `packages/policy-engine` (OPA) before forwarding each request (Day 3)

## Day 1 goal
Log every outbound request from the containerized agent. No blocking yet.

## Day 2 goal
Resolve DNS only for domains in `allowed_domains`; default_action: deny.
