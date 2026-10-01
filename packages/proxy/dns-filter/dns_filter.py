"""DNS-rebinding fix for the egress proxy (Gap #2 per PROGRESS.md).

packages/proxy/envoy.yaml's dynamic_forward_proxy resolves DNS and connects
*after* OPA has already approved a request based on the hostname string
alone — nothing validated the resolved IP. Confirmed live (see
PROGRESS.md's security review) that pointing an allowlisted domain at an
internal address let Envoy genuinely attempt a connection there.

This is the fix: Envoy's DNS cache config (see envoy.yaml's
typed_dns_resolver_config) points at this service instead of the default
resolver. Every query is forwarded to a real upstream resolver — Docker's
own embedded DNS (127.0.0.11) by default, which already recurses to the
internet, so legitimate public hostnames resolve exactly as before — but
any answer containing a private, loopback, or link-local address (RFC1918,
127.0.0.0/8, 169.254.0.0/16 including the 169.254.169.254 cloud metadata
address specifically, and their IPv6 equivalents) is rejected outright
*before* Envoy ever gets the answer, so no connection to that address is
ever attempted. This is strictly better than any post-connect check (e.g.
a Lua filter inspecting the upstream host after the fact) could be — zero
bytes ever reach the private target.

These ranges are fixed networking standards, not something that varies
demo-to-real, so they're hardcoded constants here rather than config.py
settings (see config.py's own module docstring for the rest of what it
does and doesn't cover).

Scope limit, stated directly: this filters DNS *answers*. It cannot and
does not protect against an attacker who already has file/code access
inside this container (e.g. editing /etc/hosts directly) — that's a
different, far more severe compromise than DNS rebinding describes, and no
DNS-layer fix changes that.

Only used by the egress proxy's own DNS cache — no other container's name
resolution changes.
"""

import argparse
import ipaddress
import socketserver
import sys

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

try:
    from config import DNS_FILTER_PORT, DNS_FILTER_UPSTREAM, DNS_FILTER_UPSTREAM_PORT
except ImportError:
    # Standalone/test usage (see --upstream/--port below) without
    # /app/config.py bind-mounted — same fallback values as config.py's.
    DNS_FILTER_PORT = 53
    DNS_FILTER_UPSTREAM = "127.0.0.11"
    DNS_FILTER_UPSTREAM_PORT = 53

# RFC1918 private ranges, loopback, link-local (v4 and v6, including the
# 169.254.169.254 cloud-metadata address, which falls inside 169.254.0.0/16
# so it doesn't need its own separate entry), IPv6 unique-local, and
# "this network" (0.0.0.0/8) — the standard set of addresses a public
# hostname should never legitimately resolve to.
BLOCKED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    )
]


def is_blocked_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # malformed address — refuse defensively, don't guess
    return any(ip in net for net in BLOCKED_NETWORKS)


def response_is_blocked(response: dns.message.Message) -> bool:
    """True if any A/AAAA answer in this response resolves to a blocked
    range. Rejects the whole response rather than stripping individual
    records — simpler, and avoids a partial answer being misread as a
    clean one by whatever queried it."""
    for rrset in response.answer:
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            continue
        for rr in rrset:
            if is_blocked_address(rr.address):
                return True
    return False


def resolve_filtered(query: dns.message.Message, upstream_host: str, upstream_port: int) -> dns.message.Message:
    """Forward query to the real upstream resolver, then either return its
    response unchanged or a REFUSED response if it contained a blocked
    address. Raises on upstream failure — caller decides what to do."""
    response = dns.query.udp(query, upstream_host, port=upstream_port, timeout=3)
    if response_is_blocked(response):
        question = query.question[0] if query.question else "?"
        print(f"[dns-filter] BLOCKED a private/loopback/link-local answer for {question}", flush=True)
        refused = dns.message.make_response(query)
        refused.set_rcode(dns.rcode.REFUSED)
        return refused
    return response


def make_handler(upstream_host: str, upstream_port: int):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            try:
                query = dns.message.from_wire(data)
            except Exception:
                return
            try:
                response = resolve_filtered(query, upstream_host, upstream_port)
            except Exception as exc:
                print(f"[dns-filter] upstream lookup failed: {exc}", flush=True)
                return
            sock.sendto(response.to_wire(), self.client_address)

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DNS_FILTER_PORT)
    parser.add_argument("--upstream", default=DNS_FILTER_UPSTREAM)
    parser.add_argument("--upstream-port", type=int, default=DNS_FILTER_UPSTREAM_PORT)
    args = parser.parse_args()

    server = socketserver.ThreadingUDPServer(
        ("0.0.0.0", args.port), make_handler(args.upstream, args.upstream_port)
    )
    print(
        f"AEGIS dns-filter listening on 0.0.0.0:{args.port}, "
        f"forwarding to {args.upstream}:{args.upstream_port}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
