"""LangChain/LangGraph callback handler enforcing AEGIS policy on every tool
call. Day 4 skeleton (proposal §4.4)."""

from . import ActionDescriptor, AegisClient


class AegisCallbackHandler:
    """Pass an instance of this to LangChain's `callbacks=[...]`.

    `on_tool_start` checks the action before the tool body runs; raising here
    aborts the tool call.
    """

    def __init__(self, client: AegisClient):
        self._client = client

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        action = ActionDescriptor(
            action_type="tool_call",
            target=serialized.get("name", "unknown"),
            parameters={"input": input_str},
        )
        self._client.check(action)
