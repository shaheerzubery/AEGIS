"""Day 4 check: drive aegis_sdk against the running OPA instance and confirm
a disallowed tool call is blocked at the SDK layer (not just the network
layer, see envoy.yaml's ext_authz). Run OPA first: `docker compose up -d opa`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "sdk"))

from aegis_sdk import AegisClient, ActionDescriptor, PolicyDenied  # noqa: E402


def try_action(client: AegisClient, target: str):
    action = ActionDescriptor(action_type="http_request", target=target)
    try:
        client.check(action)
        print(f"ALLOWED: http_request -> {target}")
    except PolicyDenied as exc:
        print(f"DENIED:  http_request -> {target} ({exc.reason})")


def main():
    client = AegisClient(policy_engine_url="http://localhost:8181")
    try_action(client, "example.com")
    try_action(client, "httpbin.org")


if __name__ == "__main__":
    main()
