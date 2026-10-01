"""Wraps Anthropic tool use with AEGIS policy checks. Day 4 skeleton (proposal §4.4)."""

from . import ActionDescriptor, AegisClient


class GuardedToolExecutor:
    def __init__(self, client: AegisClient, tools_by_name: dict):
        self._client = client
        self._tools = tools_by_name

    def execute(self, tool_use_block):
        action = ActionDescriptor(
            action_type="tool_call",
            target=tool_use_block.name,
            parameters=tool_use_block.input,
        )
        self._client.check(action)
        tool_fn = self._tools[tool_use_block.name]
        return tool_fn(**tool_use_block.input)


def record_call(client: AegisClient, response, prompt: str | None = None,
                latency_ms: float | None = None, enforce: bool = False) -> dict:
    """Record an Anthropic Messages response (tokens from `.usage`, reply text
    from its text blocks) via AegisClient.record_llm_call()."""
    usage = getattr(response, "usage", None)
    text = "".join(getattr(b, "text", "") for b in getattr(response, "content", []) or []) or None
    return client.record_llm_call(
        model=getattr(response, "model", "unknown"),
        provider="anthropic",
        input_tokens=getattr(usage, "input_tokens", None),
        output_tokens=getattr(usage, "output_tokens", None),
        latency_ms=latency_ms,
        prompt=prompt,
        response=text,
        enforce=enforce,
    )
