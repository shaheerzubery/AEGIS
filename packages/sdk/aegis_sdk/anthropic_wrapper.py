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
