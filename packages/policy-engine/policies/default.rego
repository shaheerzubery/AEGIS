package aegis.authz

import rego.v1

# This file is consulted from three directions:
#   1. Envoy's ext_authz gRPC filter (packages/proxy/envoy.yaml) — OPA's
#      built-in envoy_ext_authz_grpc plugin evaluates data.aegis.authz.allow
#      against input.attributes.request.http.{host,method,path} (the
#      Envoy CheckRequest shape). Envoy has no concept of a tenant, so this
#      path always resolves against the "default" tenant's policy — per-tenant
#      isolation at the network-proxy layer means deploying one sidecar per
#      tenant (see packages/proxy/k8s), not switching tenants per request.
#   2. The AEGIS SDK (packages/sdk) — sends its own action descriptor plus a
#      tenant_id: {"tenant_id": "...", "action": {"type": "http_request", ...}}.
#   3. The credential broker (packages/credential-vault) — same shape, with
#      action.type == "credential_use".
#
# Sprint 4: policy data is namespaced per tenant under data.policy.tenants.*
# (bootstrapped from policies/policy/data.yaml at container startup, and
# overwritable live via `aegisctl policy apply --tenant <name>` — PUT
# /v1/data/policy/tenants/<name> on OPA). See policy.example.yaml and
# policy.tenant-acme.example.yaml for the human-edited sources of truth.
#
# An unrecognized tenant_id resolves tenant_policy to undefined below, which
# makes every base_allow rule undefined too — allow stays false. This is a
# deliberate fail-closed choice: an unknown tenant is denied everything, it
# never falls back to "default"'s policy.
#
# Rate limiting is NOT enforced here — OPA is stateless per-request and has
# no notion of "how many actions has this session taken in the last minute."
# That's handled by packages/circuit-breaker, which the SDK consults before
# ever reaching this policy engine (see packages/sdk).

default allow := false

allow if {
    base_allow
    within_time_window
}

# tenant_id defaults to "default" so callers that predate Sprint 4's
# multi-tenancy (no tenant_id in their input) keep resolving exactly as
# before. Envoy's CheckRequest shape never carries a tenant_id at all, so it
# always takes this default too.
tenant_id := object.get(input, "tenant_id", "default")

# Deliberately NOT `default tenant_policy := {}` — an unknown tenant_id must
# leave tenant_policy undefined so every base_allow rule below is undefined
# too, rather than resolving against an empty-but-defined policy that could
# be confused with "default"'s.
tenant_policy := data.policy.tenants[tenant_id]

base_allow if {
    input.attributes.request.http.host in tenant_policy.network.allowed_domains
}

base_allow if {
    input.action.type == "http_request"
    input.action.target in tenant_policy.network.allowed_domains
}

base_allow if {
    # ActionDescriptor (packages/sdk) only ever sends "target", never "path" —
    # this used to check input.action.path, which the SDK can never populate,
    # so no file_read action could ever be legitimately allowed. Fixed to
    # match the actual SDK contract.
    #
    # This rule doesn't otherwise read anything tenant-specific, but still
    # requires tenant_policy to reference a real tenant — a bare reference to
    # an undefined value makes the whole rule body undefined, so an unknown
    # tenant_id is denied file_read too, not just the tenant-scoped rules.
    tenant_policy
    input.action.type == "file_read"
    startswith(input.action.target, "/data/")
    # Security-review finding (internal, 2026-08-22 — see PROGRESS.md):
    # startswith is a pure string-prefix check, so "/data/../etc/passwd"
    # satisfies it too — confirmed directly ('/data/../etc/passwd' really
    # does start with '/data/'). No code in this repo currently performs
    # an actual filesystem read based on this target (traced every
    # consumer), so this was latent, not live-exploitable — but it's a
    # trap for whoever wires up the first real file_read consumer if left
    # as-is. Reject any target containing a ".." segment outright, on top
    # of the prefix check, rather than trying to canonicalize it (Rego has
    # no built-in path-canonicalization primitive to lean on).
    not contains(input.action.target, "..")
}

base_allow if {
    input.action.type == "tool_call"
    input.action.target in tenant_policy.allowed_tools
}

base_allow if {
    input.action.type == "credential_use"
    input.action.method in tenant_policy.allowed_credential_actions[input.action.target]
}

# data.policy.tenants.<tenant_id>.time_constraints.operational_hours is
# "HH:MM-HH:MM" (UTC). Default "00:00-23:59" spans the whole day, so this is
# a no-op unless a narrower window is applied.
within_time_window if {
    bounds := split(tenant_policy.time_constraints.operational_hours, "-")
    minutes_of_day(bounds[0]) <= current_minute_of_day
    current_minute_of_day <= minutes_of_day(bounds[1])
}

minutes_of_day(hhmm) := minutes if {
    parts := split(hhmm, ":")
    minutes := (to_number(parts[0]) * 60) + to_number(parts[1])
}

current_minute_of_day := minutes if {
    clock := time.clock(time.now_ns())
    minutes := (clock[0] * 60) + clock[1]
}
