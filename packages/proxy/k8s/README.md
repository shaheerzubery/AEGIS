# AEGIS Kubernetes sidecar manifest

Deploys the AEGIS proxy (Envoy) + OPA sidecar alongside an agent container in
one Pod (proposal §4.5: "AEGIS deploys as a sidecar container in the same
pod as the agent"). Plain Kustomize, not a Helm chart — no Helm was
available in the environment this was built in, and Kustomize (bundled with
`kubectl`) does the one thing that actually mattered here: generating
ConfigMaps directly from the real `packages/proxy/envoy.yaml` and
`packages/policy-engine` files, so this can never silently drift from what
`demo/docker-compose.yml` actually runs.

## Files

- `kustomization.yaml` — ties it together; generates 3 ConfigMaps from the
  real proxy/policy-engine files.
- `deployment.yaml` — the Pod: `agent` (placeholder), `aegis-proxy` (Envoy),
  `opa`. The agent's `HTTP_PROXY`/`HTTPS_PROXY` point at `localhost:10000` —
  same mechanism as the Docker Compose demo.
- `networkpolicy.yaml` — pod-level egress segmentation. **Read the comments
  in this file** — it's explicit about what NetworkPolicy can and can't do
  here (see below).
- `service.yaml` — exposes Envoy admin and OPA's data API in-cluster.
- `envoy-k8s.yaml` — **not** a copy of `../envoy.yaml`. See below.

## Render / validate / deploy

```
# Render (pulls files from outside this directory, so needs this flag):
kubectl kustomize --load-restrictor LoadRestrictionsNone .

# Structural validation against a real API server (dry-run=client alone
# doesn't work offline — kubectl queries live API discovery even for
# client-side dry-run):
kubectl kustomize --load-restrictor LoadRestrictionsNone . | kubectl apply --dry-run=server -f -

# Actually deploy:
kubectl kustomize --load-restrictor LoadRestrictionsNone . | kubectl apply -f -
```

## Why `envoy-k8s.yaml` exists instead of reusing `../envoy.yaml`

Found by actually deploying this to a real cluster (`kind create cluster`),
not by inspection: `../envoy.yaml`'s `opa_cluster` points at hostname `opa`,
which resolves in Docker Compose (separate container, compose-network DNS)
but does **not** resolve inside a Kubernetes Pod's network namespace, where
OPA is a sidecar *in the same Pod* and must be reached via `localhost`. With
the wrong address, every ext_authz call failed and — because
`failure_mode_allow: false` — every single request was denied (`403 UAEX`),
including ones that should have been allowed. `envoy-k8s.yaml` is identical
except `opa_cluster`'s endpoint is `127.0.0.1` instead of `opa`.

## What NetworkPolicy does and doesn't do here

NetworkPolicy operates at the **Pod** boundary. It cannot see or distinguish
traffic between containers sharing a Pod's network namespace, so it
**cannot** force the `agent` container specifically through the
`aegis-proxy` container — that's the `HTTP_PROXY` env var's job, unchanged
from Docker Compose. Domain-level allow/deny (`example.com` yes,
`httpbin.org` no) is still entirely Envoy+OPA's job.

What `networkpolicy.yaml` *does* add: this Pod, as a whole, can only reach
DNS, the AEGIS control-plane services, and the open internet on 80/443 —
not arbitrary other pods/namespaces in the cluster. That's a real additional
containment boundary (defense-in-depth, proposal §3.1), just not the
domain-filtering mechanism itself. Don't read this manifest as "NetworkPolicy
replicates what Envoy+OPA do" — it doesn't, and can't.

## Verified (2026-08-01)

Actually deployed to a real (if disposable) cluster — `kind create cluster`,
since neither a pre-existing cluster nor Helm was available in this
environment:

1. `kubectl kustomize | kubectl apply --dry-run=server -f -` — passed;
   real API server accepted all 6 objects' schemas.
2. `kubectl apply -f -` — actually deployed. Pod reached `3/3 Running`.
3. Found and fixed the `envoy-k8s.yaml` bug above by `kubectl exec`-ing into
   the `agent` container and making real HTTP requests through the sidecar.
4. After the fix: `example.com` → 200, `httpbin.org` → 403 — confirmed both
   in the response and in the Envoy access log (`kubectl logs -c aegis-proxy`).
5. Cluster deleted afterward (`kind delete cluster`) — this was a
   verification exercise, not a persistent deployment.

## Known limitations (MVP)

- Kustomize, not the Helm chart the proposal/PLAN.md call for.
- `agent` is a placeholder (`sleep infinity`) — swap the image/command for
  a real workload.
- `audit-logger`/`circuit-breaker`/`credential-vault`/`anomaly-detector`
  aren't included as Kubernetes manifests yet — only the proxy+OPA sidecar
  pair, matching PLAN.md's own scope for this deliverable.
- No resource requests/limits, liveness/readiness probes, or PodDisruptionBudget.
