// aegisctl — deploy the AEGIS sidecar, manage policies, query the audit log.
// Day 5: logs/resume call the real audit-logger/circuit-breaker services.
// Sprint 2: policy apply pushes a policy.example.yaml-shaped file straight
// into OPA's data.policy document via its data API — no restart needed
// (see ../../PLAN.md and packages/policy-engine/policies/default.rego).
// Sprint 3: approvals/approve/deny — a human-in-the-loop review queue over
// the circuit breaker's suspended sessions (proposal §3.2 Layer 5); replay —
// incident reconstruction from the audit log (proposal §3.2 Layer 6).
// Sprint 4: every command that touches tenant-scoped state accepts a
// --tenant <name> flag (default "default"), matching every other service's
// default tenant so pre-Sprint-4 usage keeps working unchanged.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

const defaultTenant = "default"

// extractTenantFlag pulls a "--tenant <name>" (or "--tenant=<name>") pair out
// of args, wherever it appears, and returns the tenant (defaultTenant if the
// flag wasn't given) plus the remaining positional args in order.
func extractTenantFlag(args []string) (string, []string) {
	tenant := defaultTenant
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--tenant":
			if i+1 < len(args) {
				tenant = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--tenant="):
			tenant = strings.TrimPrefix(arg, "--tenant=")
		default:
			rest = append(rest, arg)
		}
	}
	return tenant, rest
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "logs":
		cmdLogs(os.Args[2:])
	case "resume", "approve":
		cmdResume(os.Args[2:])
	case "deny":
		cmdDeny(os.Args[2:])
	case "approvals":
		cmdApprovals(os.Args[2:])
	case "replay":
		cmdReplay(os.Args[2:])
	case "policy":
		cmdPolicy(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`aegisctl — AEGIS containment CLI

Usage:
  aegisctl logs                       Show recent audit log events
  aegisctl approvals                  List sessions suspended, pending human review
  aegisctl resume <session-id>        Resume a suspended session (alias: approve)
  aegisctl approve <session-id>       Alias for resume
  aegisctl deny <session-id>          Permanently terminate a session (cannot be resumed)
  aegisctl replay <session-id>        Reconstruct a session's audit trail, in order
  aegisctl policy apply <file>        Apply a policy profile

All of the above accept --tenant <name> (default "default") anywhere after
the subcommand, e.g. "aegisctl resume --tenant tenant-acme session-123" or
"aegisctl resume session-123 --tenant tenant-acme".

Env:
  AEGIS_AUDIT_URL           default http://localhost:9300
  AEGIS_CIRCUIT_BREAKER_URL default http://localhost:9400
  AEGIS_POLICY_URL          default http://localhost:8181`)
}

func cmdLogs(args []string) {
	tenant, _ := extractTenantFlag(args)
	baseURL := envOr("AEGIS_AUDIT_URL", "http://localhost:9300")
	resp, err := http.Get(baseURL + "/events?limit=20&tenant_id=" + tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach audit logger at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "audit logger returned %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var events []map[string]any
	if err := json.Unmarshal(body, &events); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse response: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Println("no audit events yet")
		return
	}

	for _, ev := range events {
		fmt.Printf("[%v] tenant=%v session=%v type=%v allowed=%v\n",
			ev["timestamp"], ev["tenant_id"], ev["session_id"], ev["event_type"], eventAllowed(ev))
	}
}

func eventAllowed(ev map[string]any) any {
	decision, ok := ev["policy_decision"].(map[string]any)
	if !ok {
		return "-"
	}
	return decision["allowed"]
}

func cmdResume(args []string) {
	tenant, rest := extractTenantFlag(args)
	if len(rest) < 1 {
		fmt.Println("usage: aegisctl resume [--tenant <name>] <session-id>")
		os.Exit(1)
	}
	sessionID := rest[0]
	baseURL := envOr("AEGIS_CIRCUIT_BREAKER_URL", "http://localhost:9400")

	resp, err := http.Post(baseURL+"/resume/"+tenant+"/"+sessionID, "application/json", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach circuit breaker at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "circuit breaker returned %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	fmt.Printf("resumed session %s (tenant %s): %s\n", sessionID, tenant, body)
}

func cmdDeny(args []string) {
	tenant, rest := extractTenantFlag(args)
	if len(rest) < 1 {
		fmt.Println("usage: aegisctl deny [--tenant <name>] <session-id>")
		os.Exit(1)
	}
	sessionID := rest[0]
	baseURL := envOr("AEGIS_CIRCUIT_BREAKER_URL", "http://localhost:9400")

	reqBody, _ := json.Marshal(map[string]string{"reason": "denied by operator via aegisctl"})
	resp, err := http.Post(baseURL+"/terminate/"+tenant+"/"+sessionID, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach circuit breaker at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "circuit breaker returned %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	fmt.Printf("session %s (tenant %s) permanently terminated: %s\n", sessionID, tenant, body)
}

func cmdApprovals(args []string) {
	tenant, _ := extractTenantFlag(args)
	baseURL := envOr("AEGIS_CIRCUIT_BREAKER_URL", "http://localhost:9400")
	resp, err := http.Get(baseURL + "/suspended?tenant_id=" + tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach circuit breaker at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "circuit breaker returned %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var suspended []map[string]any
	if err := json.Unmarshal(body, &suspended); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse response: %v\n", err)
		os.Exit(1)
	}

	if len(suspended) == 0 {
		fmt.Println("no sessions pending review")
		return
	}

	for _, s := range suspended {
		status := "SUSPENDED"
		if t, _ := s["terminated"].(bool); t {
			status = "TERMINATED"
		}
		fmt.Printf("[%s] tenant=%v session=%v reason=%v suspended_at=%v\n",
			status, s["tenant_id"], s["session_id"], s["reason"], s["suspended_at"])
	}
}

func cmdReplay(args []string) {
	tenant, rest := extractTenantFlag(args)
	if len(rest) < 1 {
		fmt.Println("usage: aegisctl replay [--tenant <name>] <session-id>")
		os.Exit(1)
	}
	sessionID := rest[0]
	baseURL := envOr("AEGIS_AUDIT_URL", "http://localhost:9300")

	resp, err := http.Get(baseURL + "/events?session_id=" + sessionID + "&tenant_id=" + tenant + "&limit=1000")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach audit logger at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "audit logger returned %d: %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var events []map[string]any
	if err := json.Unmarshal(body, &events); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse response: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Printf("no audit events for session %s\n", sessionID)
		return
	}

	// audit-logger returns newest-first; a replay reads chronologically.
	sort.Slice(events, func(i, j int) bool {
		ti, _ := events[i]["timestamp"].(string)
		tj, _ := events[j]["timestamp"].(string)
		return ti < tj
	})

	fmt.Printf("Replaying session %s (tenant %s, %d events):\n\n", sessionID, tenant, len(events))
	for i, ev := range events {
		action, _ := ev["action"].(map[string]any)
		fmt.Printf("Step %d [%v]\n", i+1, ev["timestamp"])
		if action != nil {
			fmt.Printf("  action:   %v -> %v\n", action["action_type"], action["target"])
		}
		fmt.Printf("  decision: allowed=%v\n", eventAllowed(ev))
		fmt.Println()
	}
}

// policyFields is what default.rego actually reads from data.policy.* —
// keep this in sync with packages/policy-engine/policies/default.rego.
var policyFields = []string{
	"network",
	"allowed_tools",
	"allowed_credential_actions",
	"rate_limits",
	"time_constraints",
}

func cmdPolicy(args []string) {
	tenant, rest := extractTenantFlag(args)
	if len(rest) < 2 || rest[0] != "apply" {
		fmt.Println("usage: aegisctl policy apply [--tenant <name>] <file>")
		os.Exit(1)
	}
	path := rest[1]

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", path, err)
		os.Exit(1)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse %s as YAML: %v\n", path, err)
		os.Exit(1)
	}

	policyData := map[string]any{}
	for _, field := range policyFields {
		if v, ok := parsed[field]; ok {
			policyData[field] = v
		}
	}

	body, err := json.Marshal(policyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode policy data: %v\n", err)
		os.Exit(1)
	}

	opaURL := envOr("AEGIS_POLICY_URL", "http://localhost:8181")
	req, err := http.NewRequest(http.MethodPut, opaURL+"/v1/data/policy/tenants/"+tenant, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to reach OPA at %s: %v\n", opaURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "OPA returned %d applying policy: %s\n", resp.StatusCode, respBody)
		os.Exit(1)
	}

	fmt.Printf("applied %s to tenant %q at %s/v1/data/policy/tenants/%s (status %d)\n",
		path, tenant, opaURL, tenant, resp.StatusCode)
}
