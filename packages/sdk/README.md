# aegis-sdk

Python SDK that wraps an agent framework's tool-calling layer. Every tool
invocation is intercepted, sent to the AEGIS policy engine as a structured
action descriptor, and blocked if denied — before it executes (proposal §4.3, §4.4).

Day 4 target frameworks: OpenAI Agents SDK, Anthropic tool use, LangChain/LangGraph.

## Layout
- `aegis_sdk/__init__.py` — public API (`guard()`, `AegisClient`)
- `aegis_sdk/openai_wrapper.py` — wraps OpenAI tool-calling
- `aegis_sdk/anthropic_wrapper.py` — wraps Anthropic tool use
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
