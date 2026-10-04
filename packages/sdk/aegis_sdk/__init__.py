"""AEGIS containment SDK.

Wraps an agent framework's tool-calling layer so every tool invocation is
checked against the AEGIS policy engine before it executes. Also reports
every decision to the audit logger (Layer 6) and every denial to the circuit
breaker (Layer 5) — see packages/audit-logger and packages/circuit-breaker.

Config consolidation: unlike packages/cli (Go, envOr()) and every Python
service in this repo, AegisClient used to have zero environment-variable
support — every URL was a bare "localhost" default in the constructor
signature. AegisClient now falls back to AEGIS_POLICY_URL/AEGIS_AUDIT_URL/
AEGIS_CIRCUIT_BREAKER_URL/AEGIS_CREDENTIAL_BROKER_URL when the corresponding
constructor argument isn't passed explicitly, so embedding this SDK in a
real agent can be pointed at production infra via environment alone. An
explicit constructor argument always wins over the environment variable,
which in turn wins over the "localhost" default — see _url_default().
"""

import hashlib
import os
import time
import uuid
from dataclasses import dataclass

import httpx


def _url_default(env_var: str, localhost_default: str) -> str:
    return os.environ.get(env_var, localhost_default)


@dataclass
class ActionDescriptor:
    """Structured description of a single agent action (proposal §4.3, step 2)."""

    action_type: str
    target: str
    method: str | None = None
    parameters: dict | None = None


class PolicyDenied(Exception):
    def __init__(self, action: ActionDescriptor, reason: str):
        self.action = action
        self.reason = reason
        super().__init__(f"Action denied: {action.action_type} -> {action.target}: {reason}")


class SessionSuspended(Exception):
    """Raised when the circuit breaker has already suspended this session —
    the action is rejected without even consulting the policy engine."""

    def __init__(self, tenant_id: str, session_id: str):
        self.tenant_id = tenant_id
        self.session_id = session_id
        super().__init__(f"Session {session_id} (tenant {tenant_id}) is suspended by the circuit breaker")


class RateLimited(Exception):
    """Raised when the circuit breaker's rate limiter (Sprint 2) rejects this
    action — the session has exceeded
    data.policy.tenants.<tenant_id>.rate_limits.max_actions_per_minute (see
    packages/policy-engine and packages/circuit-breaker)."""

    def __init__(self, tenant_id: str, session_id: str, count_in_window: int, limit: int):
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.count_in_window = count_in_window
        self.limit = limit
        super().__init__(
            f"Session {session_id} (tenant {tenant_id}) rate-limited: "
            f"{count_in_window} actions in window (limit {limit})"
        )


class CredentialDenied(Exception):
    """Raised when the credential broker (Layer 2) refuses to make a
    credentialed call on the agent's behalf — either policy denied it, or the
    upstream call itself failed. The agent never sees a credential either way."""

    def __init__(self, service: str, action: str, reason: str):
        self.service = service
        self.action = action
        self.reason = reason
        super().__init__(f"Credential use denied: {service}.{action}: {reason}")


class ContentDenied(Exception):
    """Raised by AegisClient.check_content() (added directly, not from the
    proposal's own roadmap — see packages/content-guardrail) when the
    text being checked matches a PII, prompt-injection, or toxic-content
    pattern. The matched categories are available, but never the raw
    matched text — packages/content-guardrail masks that before it ever
    leaves that service, and this exception doesn't carry the original
    text either."""

    def __init__(self, direction: str, categories: list[str]):
        self.direction = direction
        self.categories = categories
        super().__init__(f"Content check denied ({direction}): categories={categories}")


class AegisClient:
    """Talks to the AEGIS policy engine, audit logger, and circuit breaker.

    Sprint 4: every call carries a tenant_id (default "default") alongside
    the existing session_id — two clients with the same session_id but
    different tenant_id are fully isolated from each other at every layer
    (policy, rate limiting, circuit breaker, audit log, credential vaulting).
    """

    def __init__(
        self,
        policy_engine_url: str | None = None,
        audit_logger_url: str | None = None,
        circuit_breaker_url: str | None = None,
        credential_broker_url: str | None = None,
        content_guardrail_url: str | None = None,
        session_id: str | None = None,
        tenant_id: str = "default",
        pricing: dict[str, tuple[float, float]] | None = None,
        capture_text: bool = False,
        capture_max_chars: int = 2000,
    ):
        # capture_text: OFF by default. When True, record_llm_call() also
        # stores the prompt and response text (truncated to
        # capture_max_chars) in the audit event so the dashboard can show
        # them. The audit log is hash-chained and append-only, so stored text
        # cannot be deleted later and may contain PII or secrets; leave this
        # off unless that is acceptable for your data.
        self.capture_text = capture_text
        self.capture_max_chars = capture_max_chars
        # pricing: optional {model_id: (usd_per_1M_input_tokens,
        # usd_per_1M_output_tokens)} used by record_llm_call() to compute
        # cost. Deliberately caller-supplied: prices change and differ by
        # contract, so none are hardcoded. Omit it and cost_usd is simply
        # not reported.
        self.pricing = pricing or {}
        # None (the default) falls back to the environment, which in turn
        # falls back to "localhost" — resolved here, not as a function
        # default, so each construction picks up whatever's in the
        # environment *at call time*, not at import time.
        policy_engine_url = policy_engine_url or _url_default("AEGIS_POLICY_URL", "http://localhost:8181")
        audit_logger_url = audit_logger_url or _url_default("AEGIS_AUDIT_URL", "http://localhost:9300")
        circuit_breaker_url = circuit_breaker_url or _url_default("AEGIS_CIRCUIT_BREAKER_URL", "http://localhost:9400")
        credential_broker_url = credential_broker_url or _url_default(
            "AEGIS_CREDENTIAL_BROKER_URL", "http://localhost:9600"
        )
        content_guardrail_url = content_guardrail_url or _url_default(
            "AEGIS_CONTENT_GUARDRAIL_URL", "http://localhost:9200"
        )

        self.session_id = session_id or str(uuid.uuid4())
        self.tenant_id = tenant_id
        self._policy = httpx.Client(base_url=policy_engine_url, timeout=2.0)
        self._audit = httpx.Client(base_url=audit_logger_url, timeout=2.0)
        self._breaker = httpx.Client(base_url=circuit_breaker_url, timeout=2.0)
        self._credentials = httpx.Client(base_url=credential_broker_url, timeout=5.0)
        self._content_guardrail = httpx.Client(base_url=content_guardrail_url, timeout=2.0)

    def check(self, action: ActionDescriptor) -> None:
        """Raise SessionSuspended, RateLimited, or PolicyDenied if the action
        is not permitted. Otherwise return. Every decision is audit-logged."""
        if self._is_suspended():
            self._log_event(action, allowed=False, reason="session suspended")
            raise SessionSuspended(self.tenant_id, self.session_id)

        self._check_rate_limit()  # raises RateLimited, or returns

        # Rego (packages/policy-engine/policies/default.rego) expects
        # input.action.type, not action_type — translate the field name here.
        response = self._policy.post(
            "/v1/data/aegis/authz/allow",
            json={
                "input": {
                    "tenant_id": self.tenant_id,
                    "action": {
                        "type": action.action_type,
                        "target": action.target,
                        "method": action.method,
                        "parameters": action.parameters,
                    },
                }
            },
        )
        response.raise_for_status()
        allowed = response.json().get("result", False)

        self._log_event(action, allowed=allowed)

        if not allowed:
            self._report_violation()
            raise PolicyDenied(action, "denied by policy engine")

    def check_content(self, text: str, direction: str) -> None:
        """Added directly, not from the proposal's own roadmap — see
        packages/content-guardrail. Checks the actual TEXT going to
        (direction="input") or coming from (direction="output") the LLM
        for PII, prompt injection, or toxic content — none of which
        check()'s action-level policy check looks at.

        Fail-open like every other non-policy-engine call in this
        client: an unreachable content-guardrail returns rather than
        raising, so a real agent's core functionality never depends on
        this optional layer being up. Only PolicyDenied's underlying
        check (the actual policy engine) is fail-closed in this SDK."""
        try:
            response = self._content_guardrail.post(
                "/check",
                json={
                    "tenant_id": self.tenant_id,
                    "session_id": self.session_id,
                    "direction": direction,
                    "text": text,
                },
            )
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError:
            return  # content-guardrail unreachable — don't block the agent on it

        if body.get("blocked"):
            raise ContentDenied(direction, body.get("categories", []))

    def timed(self) -> "Stopwatch":
        """`with client.timed() as t: resp = llm(...)`, then pass
        latency_ms=t.ms to record_llm_call()."""
        return Stopwatch()

    def record_llm_call(
        self,
        model: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        latency_ms: float | None = None,
        prompt: str | None = None,
        response: str | None = None,
        provider: str | None = None,
        cost_usd: float | None = None,
        enforce: bool = False,
    ) -> dict:
        """Record one LLM round trip in the audit log as an `llm_call` event:
        token counts, latency, cost, and (if prompt/response text is given)
        a content-guardrail verdict for each (PII, prompt injection, toxic).

        The verdict is recorded for EVERY scanned call, clean or not
        (content-guardrail itself only logs the blocked ones), so the audit
        trail answers both "was this session ever injected?" and "how many
        calls were checked at all?". By default raw text is not stored: only its
        SHA-256, length, and the guardrail's category/type verdicts, so a
        flagged call can be matched back to the original text by whoever
        holds it without the audit log becoming a prompt archive. The
        exception is the client's opt-in capture_text=True, which also
        stores a truncated copy of each text.

        Returns the recorded summary. With enforce=True, raises ContentDenied
        when the prompt or response is flagged (after recording it). Like the
        other non-policy calls here, an unreachable guardrail or audit logger
        never raises."""
        content = {}
        flagged_by = None
        for direction, text in (("input", prompt), ("output", response)):
            if text is None:
                continue
            verdict = self._scan(text, direction)
            entry = {
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "chars": len(text),
                "scanned": verdict is not None,
                "flagged": bool(verdict and verdict.get("blocked")),
                "categories": (verdict or {}).get("categories", []),
                "types": sorted({m["type"] for m in (verdict or {}).get("matches", []) if m.get("type")}),
            }
            if self.capture_text:
                entry["text"] = text[: self.capture_max_chars]
                entry["truncated"] = len(text) > self.capture_max_chars
            content[direction] = entry
            if entry["flagged"] and flagged_by is None:
                flagged_by = (direction, entry["categories"])

        if cost_usd is None and model in self.pricing and input_tokens is not None and output_tokens is not None:
            price_in, price_out = self.pricing[model]
            cost_usd = (input_tokens * price_in + output_tokens * price_out) / 1_000_000

        total = None
        if input_tokens is not None or output_tokens is not None:
            total = (input_tokens or 0) + (output_tokens or 0)

        summary = {
            "provider": provider,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total,
            "latency_ms": latency_ms,
            "cost_usd": cost_usd,
            "content": content,
            "prompt_injection_suspected": "prompt_injection" in content.get("input", {}).get("categories", []),
        }
        try:
            self._audit.post(
                "/events",
                json={
                    "tenant_id": self.tenant_id,
                    "session_id": self.session_id,
                    "event_type": "llm_call",
                    "severity": "warning" if flagged_by else "informational",
                    "llm": summary,
                },
            )
        except httpx.HTTPError:
            pass  # best-effort, same as _log_event

        if enforce and flagged_by:
            raise ContentDenied(*flagged_by)
        return summary

    def _scan(self, text: str, direction: str) -> dict | None:
        try:
            response = self._content_guardrail.post(
                "/check",
                json={
                    "tenant_id": self.tenant_id,
                    "session_id": self.session_id,
                    "direction": direction,
                    "text": text,
                },
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            return None  # guardrail unreachable: recorded as scanned=False

    def register_runtime(self, container_id: str | None = None) -> bool:
        """Gap-closing work (2026-09-16, see PROGRESS.md): opts this
        session in to the circuit breaker's emergency_kill tier by
        reporting the agent's own Docker container id. Without this call,
        emergency_kill degrades honestly to "suspended, kill not
        possible" — nothing is killable by default.

        container_id defaults to $HOSTNAME, which Docker sets to the
        container's own short id unless overridden — true for the
        container this code is actually running in, not a guess. Returns
        whether registration succeeded; best-effort like every other
        circuit-breaker call here, since a real agent shouldn't crash
        just because this opt-in step failed."""
        container_id = container_id or os.environ.get("HOSTNAME")
        if not container_id:
            return False
        try:
            response = self._breaker.post(
                f"/register/{self.tenant_id}/{self.session_id}",
                json={"container_id": container_id},
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    def invoke_credentialed(self, service: str, action: str) -> dict:
        """Ask the credential broker (packages/credential-vault) to make a
        credentialed call on the agent's behalf. The agent never sees the
        credential — only the result. Raises SessionSuspended or
        CredentialDenied if it's not permitted."""
        if self._is_suspended():
            raise SessionSuspended(self.tenant_id, self.session_id)

        self._check_rate_limit()  # raises RateLimited, or returns

        response = self._credentials.post(
            "/invoke",
            json={
                "tenant_id": self.tenant_id,
                "session_id": self.session_id,
                "service": service,
                "action": action,
            },
        )

        if response.status_code == 403:
            self._report_violation()
            raise CredentialDenied(service, action, "denied by policy engine")
        if response.status_code != 200:
            raise CredentialDenied(service, action, response.text)

        return response.json()["result"]

    def _is_suspended(self) -> bool:
        try:
            response = self._breaker.get(f"/status/{self.tenant_id}/{self.session_id}")
            response.raise_for_status()
            return response.json().get("suspended", False)
        except httpx.HTTPError:
            return False  # circuit breaker unreachable — don't block the agent on it

    def _check_rate_limit(self) -> None:
        try:
            response = self._breaker.post(f"/activity/{self.tenant_id}/{self.session_id}")
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError:
            return  # circuit breaker unreachable — don't block the agent on it

        if body.get("rate_limited", False):
            raise RateLimited(self.tenant_id, self.session_id, body["count_in_window"], body["limit"])

    def _report_violation(self) -> None:
        try:
            self._breaker.post(f"/violation/{self.tenant_id}/{self.session_id}")
        except httpx.HTTPError:
            pass  # best-effort; a missing circuit breaker shouldn't mask the real denial

    def _log_event(self, action: ActionDescriptor, allowed: bool, reason: str | None = None) -> None:
        try:
            self._audit.post(
                "/events",
                json={
                    "tenant_id": self.tenant_id,
                    "session_id": self.session_id,
                    "event_type": "policy_decision",
                    "action": {
                        "action_type": action.action_type,
                        "target": action.target,
                        "method": action.method,
                    },
                    "policy_decision": {"allowed": allowed, "reason": reason},
                },
            )
        except httpx.HTTPError:
            pass  # best-effort; audit-logger being down shouldn't block the agent


class Stopwatch:
    """Context manager measuring wall-clock milliseconds in `.ms`."""

    ms: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.ms = (time.perf_counter() - self._start) * 1000
        return False


def guard(client: AegisClient, action: ActionDescriptor):
    """Decorator-friendly helper: raises PolicyDenied before the wrapped call runs."""

    def _decorator(fn):
        def _wrapped(*args, **kwargs):
            client.check(action)
            return fn(*args, **kwargs)

        return _wrapped

    return _decorator
