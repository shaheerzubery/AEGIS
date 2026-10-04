import type { AuditEvent } from "./api";

// "Oct 4, 17:28:54": readable local time instead of a raw ISO string.
export function fmtTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export type Decision = "ALLOWED" | "BLOCKED" | "INFO";

export interface Described {
  label: string;
  decision: Decision;
  what: string;
  why: string;
}

// Turns each audit event shape into one uniform row. Event types come from
// different services (SDK policy checks, content-guardrail, SDK LLM
// recording, dashboard operator actions), so there is no single "allowed"
// field to read: content-guardrail only ever logs blocked content, and
// llm_call / operator events carry no allow-or-deny decision at all.
export function describeEvent(e: AuditEvent): Described {
  const action = [e.action?.action_type, e.action?.target].filter(Boolean).join(" -> ");
  switch (e.event_type) {
    case "policy_decision": {
      const allowed = e.policy_decision?.allowed === true;
      return {
        label: "Policy check",
        decision: allowed ? "ALLOWED" : "BLOCKED",
        what: action || "-",
        why: e.policy_decision?.reason || (allowed ? "permitted by policy" : "denied by policy engine"),
      };
    }
    case "content_guardrail_decision": {
      const types = (e.matches || []).map((m) => m.type).filter(Boolean);
      return {
        label: "Content guardrail",
        decision: "BLOCKED",
        what: `${e.action?.target ?? "?"} text`,
        why: [e.policy_decision?.reason, types.length ? `matched: ${types.join(", ")}` : ""].filter(Boolean).join(" | "),
      };
    }
    case "llm_call": {
      const l = e.llm || {};
      const cats = Object.values(l.content || {}).flatMap((c) => c.categories || []);
      return {
        label: "LLM call",
        decision: "INFO",
        what: `${l.provider ?? "?"}/${l.model ?? "?"} - ${l.input_tokens ?? "-"} in / ${l.output_tokens ?? "-"} out tokens, ${
          l.latency_ms == null ? "-" : Math.round(l.latency_ms)
        } ms`,
        why: cats.length ? `FLAGGED: ${[...new Set(cats)].join(", ")}` : "content clean",
      };
    }
    case "dashboard_operator_action":
      return {
        label: "Operator action",
        decision: "INFO",
        what: action || "-",
        why: e.policy_decision?.reason || e.operator || "",
      };
    default:
      return { label: e.event_type, decision: "INFO", what: action || "-", why: e.policy_decision?.reason || "" };
  }
}

const BADGE: Record<Decision, { cls: string; icon: string; text: string }> = {
  ALLOWED: { cls: "allowed", icon: "✓", text: "Allowed" },
  BLOCKED: { cls: "blocked", icon: "✕", text: "Blocked" },
  INFO: { cls: "info", icon: "•", text: "Info" },
};

// Status color + icon + label together, so state never rides on color alone.
export function Badge({ decision }: { decision: Decision }) {
  const b = BADGE[decision];
  return (
    <span className={`badge ${b.cls}`}>
      <span className="ic" aria-hidden="true">
        {b.icon}
      </span>
      {b.text}
    </span>
  );
}
