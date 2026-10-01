"""Basic Streamlit dashboard to see the current AEGIS flow working, live.

Not packages/dashboard (the React placeholder from Sprint 3) — this is a
throwaway visualization tool for the demo stack, using aegis_sdk directly.

Run:
    docker compose up -d          # from demo/, brings up proxy/OPA/audit-logger/
                                   # circuit-breaker/vault/credential-vault
    streamlit run dashboard_app.py

Requires the demo stack's ports (8181, 9300, 9400, 9600) reachable at
localhost, same as every other test script in this directory.
"""

import sys
import time
from pathlib import Path

import httpx
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packages" / "sdk"))

from aegis_sdk import (  # noqa: E402
    ActionDescriptor,
    AegisClient,
    CredentialDenied,
    PolicyDenied,
    RateLimited,
    SessionSuspended,
)

AUDIT_URL = "http://localhost:9300"
BREAKER_URL = "http://localhost:9400"

st.set_page_config(page_title="AEGIS flow viewer", layout="wide")
st.title("AEGIS — containment flow viewer")
st.caption(
    "Every action below goes through the same real services as the CLI/test scripts: "
    "OPA (policy), the circuit breaker (violations + rate limits), the audit logger, "
    "and the credential broker. Nothing here is simulated."
)

if "session_id" not in st.session_state:
    st.session_state.session_id = f"streamlit-{int(time.time())}"
if "tenant_id" not in st.session_state:
    # Sprint 4: every request now carries a tenant_id; "default" matches
    # AegisClient's own default so this demo behaves exactly as before
    # unless you deliberately type a different tenant.
    st.session_state.tenant_id = "default"


def get_client() -> AegisClient:
    return AegisClient(session_id=st.session_state.session_id, tenant_id=st.session_state.tenant_id)


def service_status():
    checks = {
        "OPA (policy engine)": "http://localhost:8181/health",
        "Audit logger": f"{AUDIT_URL}/events?limit=1",
        "Circuit breaker": f"{BREAKER_URL}/status/{st.session_state.tenant_id}/healthcheck",
        "Credential broker": "http://localhost:9600/invoke",
    }
    cols = st.columns(len(checks))
    for col, (name, url) in zip(cols, checks.items()):
        try:
            resp = httpx.get(url, timeout=1.5) if "invoke" not in url else httpx.post(url, timeout=1.5)
            up = resp.status_code < 500
        except httpx.HTTPError:
            up = False
        col.metric(name, "up" if up else "down", delta=None)


service_status()
st.divider()

col_tenant, col_session, col_reset = st.columns([2, 3, 1])
with col_tenant:
    st.text_input("Tenant ID", key="tenant_id")
with col_session:
    st.text_input("Session ID (all actions below use this)", key="session_id")
with col_reset:
    st.write("")
    if st.button("New session"):
        st.session_state.session_id = f"streamlit-{int(time.time())}"
        st.rerun()

tab_policy, tab_credential, tab_breaker, tab_audit = st.tabs(
    ["Policy check", "Credential vaulting", "Circuit breaker", "Audit log"]
)

with tab_policy:
    st.subheader("Send an action through the policy engine")
    st.caption("Try target=`example.com` (allowed) vs. `httpbin.org` (denied). "
               "Try action_type=`tool_call` with target=`read_file` (allowed) vs. anything else.")
    c1, c2, c3 = st.columns(3)
    action_type = c1.selectbox("action_type", ["http_request", "tool_call", "file_read", "credential_use"])
    target = c2.text_input("target", value="example.com")
    method = c3.text_input("method (optional)", value="")

    if st.button("Check action", type="primary"):
        client = get_client()
        action = ActionDescriptor(action_type=action_type, target=target, method=method or None)
        try:
            client.check(action)
            st.success(f"ALLOWED - {action_type} -> {target}")
        except SessionSuspended as e:
            st.error(f"SUSPENDED — {e}")
        except RateLimited as e:
            st.warning(f"RATE LIMITED — {e}")
        except PolicyDenied as e:
            st.error(f"DENIED — {e.reason}")

    st.divider()
    st.caption("Fire N requests quickly to see rate limiting / circuit-breaker suspension kick in.")
    burst_target = st.text_input("burst target", value="httpbin.org", key="burst_target")
    burst_count = st.slider("number of requests", 1, 80, 10)
    if st.button("Fire burst"):
        client = get_client()
        results = {"allowed": 0, "denied": 0, "rate_limited": 0, "suspended": 0}
        progress = st.progress(0)
        for i in range(burst_count):
            action = ActionDescriptor(action_type="http_request", target=burst_target)
            try:
                client.check(action)
                results["allowed"] += 1
            except SessionSuspended:
                results["suspended"] += 1
            except RateLimited:
                results["rate_limited"] += 1
            except PolicyDenied:
                results["denied"] += 1
            progress.progress((i + 1) / burst_count)
        st.json(results)

with tab_credential:
    st.subheader("Credential vaulting — the agent never sees the token")
    st.caption("Try action=`profile` (allowed) vs. `delete-account` (denied).")
    cred_action = st.text_input("action", value="profile")
    if st.button("Invoke via credential broker", type="primary"):
        client = get_client()
        try:
            result = client.invoke_credentialed("protected-api", cred_action)
            st.success("ALLOWED — result from the real upstream service:")
            st.json(result)
        except SessionSuspended as e:
            st.error(f"SUSPENDED — {e}")
        except RateLimited as e:
            st.warning(f"RATE LIMITED — {e}")
        except CredentialDenied as e:
            st.error(f"DENIED — {e.reason}")

    st.caption(
        "Proof the token never leaves the broker: try hitting the upstream service "
        "directly, with no credential."
    )
    if st.button("Try calling protected-api directly (no credential)"):
        try:
            resp = httpx.get("http://localhost:9500/profile", timeout=2)
            st.code(f"HTTP {resp.status_code}: {resp.text}")
        except httpx.HTTPError as e:
            st.error(str(e))

with tab_breaker:
    st.subheader("Circuit breaker status for this session")
    if st.button("Refresh status"):
        st.rerun()
    try:
        status = httpx.get(
            f"{BREAKER_URL}/status/{st.session_state.tenant_id}/{st.session_state.session_id}", timeout=2
        ).json()
        st.json(status)
    except httpx.HTTPError as e:
        st.error(f"circuit breaker unreachable: {e}")

    if st.button("Resume this session (clear suspension)"):
        try:
            resp = httpx.post(
                f"{BREAKER_URL}/resume/{st.session_state.tenant_id}/{st.session_state.session_id}", timeout=2
            )
            st.success(resp.json())
        except httpx.HTTPError as e:
            st.error(str(e))

with tab_audit:
    st.subheader("Recent audit events (all sessions, current tenant)")
    limit = st.slider("how many", 5, 100, 20)
    if st.button("Refresh audit log"):
        st.rerun()
    try:
        events = httpx.get(
            f"{AUDIT_URL}/events?limit={limit}&tenant_id={st.session_state.tenant_id}", timeout=2
        ).json()
        if not events:
            st.info("No audit events yet — try an action in another tab first.")
        else:
            rows = [
                {
                    "timestamp": e.get("timestamp"),
                    "session_id": e.get("session_id"),
                    "event_type": e.get("event_type"),
                    "action_type": (e.get("action") or {}).get("action_type"),
                    "target": (e.get("action") or {}).get("target"),
                    "allowed": (e.get("policy_decision") or {}).get("allowed"),
                    "reason": (e.get("policy_decision") or {}).get("reason"),
                }
                for e in events
            ]
            st.dataframe(rows, width="stretch")

        verify = httpx.get(f"{AUDIT_URL}/verify?tenant_id={st.session_state.tenant_id}", timeout=2).json()
        if verify.get("chain_intact"):
            st.success("Hash chain intact — no tampering detected.")
        else:
            st.error("Hash chain broken — tampering detected!")
    except httpx.HTTPError as e:
        st.error(f"audit logger unreachable: {e}")
