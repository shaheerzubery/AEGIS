"""Day 4 check: exercise the three tool-call wrappers with mocked framework
objects (no API keys needed) against a live OPA instance. Run OPA first:
`docker compose up -d opa`.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "sdk"))

from aegis_sdk import AegisClient, PolicyDenied  # noqa: E402
from aegis_sdk.openai_wrapper import GuardedToolExecutor as OpenAIExecutor  # noqa: E402
from aegis_sdk.anthropic_wrapper import GuardedToolExecutor as AnthropicExecutor  # noqa: E402
from aegis_sdk.bedrock_wrapper import GuardedToolExecutor as BedrockExecutor  # noqa: E402
from aegis_sdk.langchain_wrapper import AegisCallbackHandler  # noqa: E402


def read_file(path: str) -> str:
    return f"contents of {path}"


TOOLS = {"read_file": read_file}


def test_openai(client):
    tool_call = SimpleNamespace(
        function=SimpleNamespace(name="read_file", arguments={"path": "/etc/hosts"})
    )
    executor = OpenAIExecutor(client, TOOLS)
    try:
        result = executor.execute(tool_call)
        print(f"OpenAI wrapper: ALLOWED -> {result}")
    except PolicyDenied as exc:
        print(f"OpenAI wrapper: DENIED -> {exc.reason}")


def test_anthropic(client):
    tool_use_block = SimpleNamespace(name="read_file", input={"path": "/etc/hosts"})
    executor = AnthropicExecutor(client, TOOLS)
    try:
        result = executor.execute(tool_use_block)
        print(f"Anthropic wrapper: ALLOWED -> {result}")
    except PolicyDenied as exc:
        print(f"Anthropic wrapper: DENIED -> {exc.reason}")


def test_bedrock(client):
    response = {"output": {"message": {"role": "assistant", "content": [
        {"toolUse": {"toolUseId": "t1", "name": "read_file", "input": {"path": "/etc/hosts"}}}]}}}
    executor = BedrockExecutor(client, TOOLS)
    reply = executor.run_converse_tools(response)
    result = reply["content"][0]["toolResult"]
    print(f"Bedrock wrapper: {'DENIED' if result.get('status') == 'error' else 'ALLOWED'} -> {result['content']}")


def test_langchain(client):
    handler = AegisCallbackHandler(client)
    try:
        handler.on_tool_start({"name": "read_file"}, "/etc/hosts")
        print("LangChain wrapper: ALLOWED (on_tool_start did not raise)")
    except PolicyDenied as exc:
        print(f"LangChain wrapper: DENIED -> {exc.reason}")


def main():
    client = AegisClient(policy_engine_url="http://localhost:8181")
    test_openai(client)
    test_anthropic(client)
    test_bedrock(client)
    test_langchain(client)


if __name__ == "__main__":
    main()
