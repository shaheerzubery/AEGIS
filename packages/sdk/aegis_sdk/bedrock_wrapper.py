"""Wraps AWS Bedrock tool use with AEGIS policy checks.

Targets the Bedrock Runtime Converse API (`bedrock-runtime` client's
`converse()`), where the model's tool requests come back as content blocks
of the form `{"toolUse": {"toolUseId": ..., "name": ..., "input": {...}}}`.
Also accepts the Anthropic-style `{"type": "tool_use", ...}` block returned
by `invoke_model` for Anthropic models hosted on Bedrock.
"""

from . import ActionDescriptor, AegisClient, PolicyDenied


def _parse_tool_use(block: dict) -> tuple[str | None, str, dict]:
    """Return (tool_use_id, name, input) from either block shape."""
    if "toolUse" in block:
        tu = block["toolUse"]
        return tu.get("toolUseId"), tu["name"], tu.get("input") or {}
    if block.get("type") == "tool_use":
        return block.get("id"), block["name"], block.get("input") or {}
    raise ValueError(f"not a Bedrock tool-use block: {block!r}")


class GuardedToolExecutor:
    def __init__(self, client: AegisClient, tools_by_name: dict):
        self._client = client
        self._tools = tools_by_name

    def execute(self, tool_use_block: dict):
        """Check one tool-use block against policy, then run the tool.
        Raises PolicyDenied (or SessionSuspended/RateLimited) if blocked."""
        _, name, args = _parse_tool_use(tool_use_block)
        self._client.check(
            ActionDescriptor(action_type="tool_call", target=name, parameters=args)
        )
        return self._tools[name](**args)

    def run_converse_tools(self, response: dict) -> dict | None:
        """Handle every toolUse block in a `converse()` response. Returns the
        user message (with toolResult blocks) to append to `messages` for the
        next `converse()` call, or None if the model requested no tools.
        Denied calls are reported back to the model as error results rather
        than raised, so the agent loop can continue."""
        content = response.get("output", {}).get("message", {}).get("content", [])
        results = []
        for block in content:
            if "toolUse" not in block:
                continue
            tool_use_id, _, _ = _parse_tool_use(block)
            try:
                value = self.execute(block)
                results.append({"toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"json": value} if isinstance(value, (dict, list)) else {"text": str(value)}],
                }})
            except PolicyDenied as exc:
                results.append({"toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"text": f"blocked by AEGIS policy: {exc.reason}"}],
                    "status": "error",
                }})
        return {"role": "user", "content": results} if results else None


def record_call(client: AegisClient, response: dict, model_id: str, prompt: str | None = None,
                latency_ms: float | None = None, enforce: bool = False) -> dict:
    """Record a Bedrock `converse()` response via AegisClient.record_llm_call().
    Tokens come from `response["usage"]`; latency defaults to Bedrock's own
    `response["metrics"]["latencyMs"]` when the caller didn't measure it."""
    usage = response.get("usage", {})
    blocks = response.get("output", {}).get("message", {}).get("content", [])
    text = "".join(b.get("text", "") for b in blocks) or None
    return client.record_llm_call(
        model=model_id,
        provider="bedrock",
        input_tokens=usage.get("inputTokens"),
        output_tokens=usage.get("outputTokens"),
        latency_ms=latency_ms if latency_ms is not None else response.get("metrics", {}).get("latencyMs"),
        prompt=prompt,
        response=text,
        enforce=enforce,
    )
