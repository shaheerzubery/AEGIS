# aegis-sdk

Python SDK that wraps an agent framework's tool-calling layer. Every tool
invocation is intercepted, sent to the AEGIS policy engine as a structured
action descriptor, and blocked if denied — before it executes (proposal §4.3, §4.4).

Day 4 target frameworks: OpenAI Agents SDK, Anthropic tool use, LangChain/LangGraph.

## Layout
- `aegis_sdk/__init__.py` — public API (`guard()`, `AegisClient`)
- `aegis_sdk/openai_wrapper.py` — wraps OpenAI tool-calling
- `aegis_sdk/anthropic_wrapper.py` — wraps Anthropic tool use
- `aegis_sdk/bedrock_wrapper.py` — wraps AWS Bedrock Converse tool use
- `aegis_sdk/langchain_wrapper.py` — LangChain callback handler / tool wrapper

## Install

Early testers install straight from Git (no package index yet):
```
pip install "git+https://github.com/shaheerzubery/AEGIS.git#subdirectory=packages/sdk"
# with a framework extra:
pip install "git+https://github.com/shaheerzubery/AEGIS.git#subdirectory=packages/sdk[openai]"   # or [anthropic], [langchain]
```
Pin a release with `@<tag>` before `#subdirectory`. From a local checkout:
`pip install ./packages/sdk`.

## LLM metrics and prompt-injection recording

`AegisClient.record_llm_call()` writes an `llm_call` audit event per LLM round
trip: token counts, latency, cost, and a content-guardrail verdict (PII /
prompt injection / toxic) for the prompt and the response. Each provider
wrapper has a `record_call()` helper that reads tokens and reply text from the
provider's response object.

```python
from aegis_sdk import AegisClient
from aegis_sdk.openai_wrapper import record_call

aegis = AegisClient(pricing={"gpt-4o": (2.50, 10.00)})  # USD per 1M tokens (in, out); optional
with aegis.timed() as t:
    resp = openai_client.chat.completions.create(...)
record_call(aegis, resp, prompt=user_prompt, latency_ms=t.ms)  # enforce=True raises ContentDenied
```

Verdicts are recorded for every scanned call, clean or flagged. Raw prompt and
response text is never stored: only its SHA-256, length, and the guardrail's
categories/types. Flagged events have `severity: warning` and
`llm.prompt_injection_suspected: true`. Requires `content-guardrail` and
`audit-logger` to be running; if either is down the call is not blocked.
