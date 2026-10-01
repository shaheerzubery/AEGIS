"""Day 1-2 'hello world' agent: makes tool calls to an allowlisted and a
non-allowlisted domain, to show the AEGIS proxy logging both and blocking the
latter (see ../PLAN.md, Day 1-2).

Uses plain HTTP: the proxy's RBAC allowlist matches on the :authority header
before TLS would even come into play. TLS interception (CONNECT tunneling) is
a later Layer 1 feature, not yet implemented in packages/proxy/envoy.yaml.

Run standalone: `python hello_agent.py` (hits both domains directly, no
blocking — there's no proxy in the loop).
Run through the proxy: `docker compose up --build` from this directory, or
set HTTP_PROXY to the aegis-proxy address before running locally.
"""

import httpx


def call_tool(url: str) -> str:
    """A trivial 'tool' the agent can invoke — just an outbound HTTP call so
    we can watch it pass through (or get blocked by) the AEGIS proxy."""
    try:
        response = httpx.get(url, timeout=5.0)
        return f"{url} -> {response.status_code}"
    except httpx.HTTPError as exc:
        return f"{url} -> failed: {exc}"


def main():
    print("hello-agent: calling an allowlisted domain (example.com)...")
    print(call_tool("http://example.com/"))

    print("hello-agent: calling a non-allowlisted domain (httpbin.org)...")
    print(call_tool("http://httpbin.org/get"))


if __name__ == "__main__":
    main()
