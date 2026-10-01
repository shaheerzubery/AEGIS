"""Wraps the OpenAI Agents SDK tool-calling layer with AEGIS policy checks.

Day 4 skeleton (proposal §4.4, P0 launch framework).
"""

from . import ActionDescriptor, AegisClient, PolicyDenied


class GuardedToolExecutor:
    """Drop-in wrapper: call `.execute(tool_call)` instead of running the tool
    call directly. Denied calls raise PolicyDenied instead of executing."""

    def __init__(self, client: AegisClient, tools_by_name: dict):
        self._client = client
        self._tools = tools_by_name

    def execute(self, tool_call):
        action = ActionDescriptor(
            action_type="tool_call",
            target=tool_call.function.name,
            parameters=tool_call.function.arguments,
        )
        self._client.check(action)  # raises PolicyDenied if not allowed
        tool_fn = self._tools[tool_call.function.name]
        return tool_fn(**tool_call.function.arguments)
