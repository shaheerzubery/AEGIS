"""Phase 2 enterprise-tier check (proposal §7.2, added 2026-09-27 — see
PROGRESS.md): verifies the HIPAA/PCI-DSS/EU AI Act policy templates
(packages/compliance/templates/) actually apply and enforce, the same
way packages/compliance's existing SOC 2 templates already do, and that
compliance_report.py generates a real report per framework/format
against the live stack.

Run the full stack first: `docker compose up -d` (from demo/). Applies
each template's policy fields directly via PUT to OPA (the same subset
aegisctl policy apply sends — see packages/cli/main.go's policyFields —
avoiding a Go build dependency in this test), then drives real
allow/deny checks against the live policy engine, not just confirms OPA
stored the data.
"""

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

OPA_URL = "http://localhost:8181"
COMPLIANCE_DIR = Path(__file__).parent.parent / "packages" / "compliance"

# Same subset packages/cli/main.go's policyFields sends — see that file's
# own comment that it must be kept in sync with default.rego.
POLICY_FIELDS = ["network", "allowed_tools", "allowed_credential_actions", "rate_limits", "time_constraints"]

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def _put_json(url: str, body: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="PUT"
    )
    urllib.request.urlopen(req, timeout=5).read()


def _post_json(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def apply_template(tenant: str, template_path: Path) -> None:
    with open(template_path, encoding="utf-8") as f:
        parsed = yaml.safe_load(f)
    policy_data = {k: parsed[k] for k in POLICY_FIELDS if k in parsed}
    _put_json(f"{OPA_URL}/v1/data/policy/tenants/{tenant}", policy_data)


def allowed(tenant: str, action: dict) -> bool:
    result = _post_json(f"{OPA_URL}/v1/data/aegis/authz/allow", {"input": {"tenant_id": tenant, "action": action}})
    return bool(result.get("result", False))


def test_hipaa_template_enforces():
    tenant = "compliance-test-hipaa"
    apply_template(tenant, COMPLIANCE_DIR / "templates" / "hipaa.yaml")
    check(
        "hipaa: allowed domain (example.com) is allowed",
        allowed(tenant, {"type": "http_request", "target": "example.com"}),
    )
    check(
        "hipaa: non-allowlisted domain is denied",
        not allowed(tenant, {"type": "http_request", "target": "evil.example"}),
    )
    check(
        "hipaa: allowed_tools is empty, any tool_call is denied",
        not allowed(tenant, {"type": "tool_call", "target": "read_file"}),
    )


def test_pci_dss_template_enforces():
    tenant = "compliance-test-pci-dss"
    apply_template(tenant, COMPLIANCE_DIR / "templates" / "pci-dss.yaml")
    check(
        "pci-dss: allowed_credential_actions is empty, any credential_use is denied",
        not allowed(tenant, {"type": "credential_use", "target": "protected-api", "method": "profile"}),
    )
    check(
        "pci-dss: non-allowlisted domain is denied",
        not allowed(tenant, {"type": "http_request", "target": "evil.example"}),
    )


def test_eu_ai_act_template_enforces():
    tenant = "compliance-test-eu-ai-act"
    apply_template(tenant, COMPLIANCE_DIR / "templates" / "eu-ai-act.yaml")
    check(
        "eu-ai-act: allowlisted tool (read_file) is allowed",
        allowed(tenant, {"type": "tool_call", "target": "read_file"}),
    )
    check(
        "eu-ai-act: a tool NOT on the allowlist is denied",
        not allowed(tenant, {"type": "tool_call", "target": "send_email"}),
    )
    check(
        "eu-ai-act: allowlisted credential action (protected-api/profile) is allowed",
        allowed(tenant, {"type": "credential_use", "target": "protected-api", "method": "profile"}),
    )


def test_report_generates_for_every_framework_and_format():
    """Drives compliance_report.py directly (the actual CLI entrypoint),
    for every framework this Phase 2 work added plus the pre-existing
    soc2 one, across all three output formats — confirms nothing about
    generalizing the script broke the original SOC 2 behavior."""
    for framework in ("soc2", "hipaa", "pci-dss", "eu-ai-act"):
        for fmt, ext in (("markdown", "md"), ("json", "json"), ("pdf", "pdf")):
            output_name = f"compliance_test_{framework}.{ext}"
            output_path = COMPLIANCE_DIR / output_name
            result = subprocess.run(
                [
                    sys.executable,
                    "compliance_report.py",
                    "--framework", framework,
                    "--tenant", "default",
                    "--format", fmt,
                    "--output", output_name,
                ],
                cwd=COMPLIANCE_DIR,
                capture_output=True,
                text=True,
            )
            ok = result.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0
            check(f"compliance_report.py --framework {framework} --format {fmt} produces a real, non-empty file", ok, result.stderr)
            if output_path.exists():
                output_path.unlink()


def test_generated_reports_use_real_utf8_not_mangled_bytes():
    """Found by testing during development, not assumed: fpdf2's core
    fonts can't encode em dashes (crashes PDF generation), and Python's
    open() without an explicit encoding mangled them on Windows for
    markdown/json. Both are fixed; this confirms markdown output contains
    a real em dash, not a mangled replacement character."""
    output_name = "compliance_test_encoding.md"
    output_path = COMPLIANCE_DIR / output_name
    subprocess.run(
        [sys.executable, "compliance_report.py", "--framework", "eu-ai-act", "--tenant", "default",
         "--format", "markdown", "--output", output_name],
        cwd=COMPLIANCE_DIR, capture_output=True, text=True,
    )
    try:
        content = output_path.read_text(encoding="utf-8")
        check("generated markdown contains a real em dash, not a mangled replacement character", "—" in content and "�" not in content)
    finally:
        if output_path.exists():
            output_path.unlink()


def main():
    test_hipaa_template_enforces()
    test_pci_dss_template_enforces()
    test_eu_ai_act_template_enforces()
    test_report_generates_for_every_framework_and_format()
    test_generated_reports_use_real_utf8_not_mangled_bytes()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
