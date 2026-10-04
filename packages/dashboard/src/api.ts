// Thin fetch wrapper over packages/dashboard/api/dashboard_api.py.
// Configurable so a built/deployed dashboard isn't hardcoded to localhost.
const API_BASE = (import.meta.env.VITE_AEGIS_DASHBOARD_API as string) || "http://localhost:9900";

// Gap-closing work (2026-08-22, see PROGRESS.md): every call now needs an
// API key (see config.py's DASHBOARD_API_KEYS) instead of a free-text
// tenant_id — the server derives the tenant from the key, tenant_id is no
// longer a client-supplied value anywhere in this file.
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function authHeader(apiKey: string): Record<string, string> {
  return { Authorization: `Bearer ${apiKey}` };
}

async function checkOk(res: Response): Promise<Response> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, body.error || res.statusText);
  }
  return res;
}

async function getJSON<T>(apiKey: string, path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeader(apiKey) });
  await checkOk(res);
  return res.json() as Promise<T>;
}

async function postJSON<T>(apiKey: string, path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeader(apiKey) },
    body: JSON.stringify(body),
  });
  await checkOk(res);
  return res.json() as Promise<T>;
}

export type ServiceStatus = Record<string, boolean | string>;

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  tenant_id: string;
  session_id: string;
  event_type: string;
  severity?: string;
  action?: { action_type?: string; target?: string; method?: string | null };
  policy_decision?: { allowed?: boolean; reason?: string | null };
  // content_guardrail_decision events
  matches?: { category?: string; type?: string; masked_sample?: string }[];
  // dashboard_operator_action events
  operator?: string;
  // llm_call events (see packages/sdk record_llm_call)
  llm?: {
    provider?: string | null;
    model?: string | null;
    input_tokens?: number | null;
    output_tokens?: number | null;
    latency_ms?: number | null;
    prompt_injection_suspected?: boolean;
    content?: Record<string, { flagged?: boolean; categories?: string[]; types?: string[] }>;
  };
}

export interface CheckOutcome {
  outcome: "allowed" | "denied" | "suspended" | "rate_limited";
  detail?: string;
}

export interface CredentialOutcome {
  outcome: "allowed" | "denied" | "suspended" | "rate_limited";
  detail?: string;
  result?: { status: number; body: unknown };
}

export interface BreakerStatus {
  tenant_id: string;
  session_id: string;
  violations_in_window: number;
  suspended: boolean;
  terminated: boolean;
}

export interface AnomalyScore {
  tenant_id: string;
  session_id: string;
  score: number;
  severity: string;
  flags: string[];
  actions_in_window: number;
}

export interface SuspendedSession {
  tenant_id: string;
  session_id: string;
  reason: string;
  suspended_at: number;
  terminated: boolean;
}

export interface LlmCall {
  event_id: string;
  timestamp: string;
  session_id: string;
  provider: string | null;
  model: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  latency_ms: number | null;
  cost_usd: number | null;
  prompt_injection_suspected: boolean;
  flagged: boolean;
  categories: string[];
  types: string[];
  scanned: boolean;
  input_text: string | null;
  output_text: string | null;
  input_truncated: boolean;
  output_truncated: boolean;
}

export interface LlmSummary {
  totals: {
    calls: number;
    input_tokens: number;
    output_tokens: number;
    cost_usd: number;
    avg_latency_ms: number | null;
    p95_latency_ms: number | null;
    flagged_calls: number;
    prompt_injection_suspected: number;
    unscanned_calls: number;
  };
  by_model: Record<
    string,
    { calls: number; input_tokens: number; output_tokens: number; cost_usd: number; flagged: number }
  >;
  flagged: LlmCall[];
  recent: LlmCall[];
}

export const api = {
  llm: (apiKey: string) => getJSON<LlmSummary>(apiKey, "/api/llm"),
  status: (apiKey: string) => getJSON<ServiceStatus>(apiKey, "/api/status"),
  events: (apiKey: string, limit: number, sessionId?: string) =>
    getJSON<AuditEvent[]>(apiKey, `/api/events?limit=${limit}${sessionId ? `&session_id=${sessionId}` : ""}`),
  verify: (apiKey: string) => getJSON<{ tenant_id: string; chain_intact: boolean }>(apiKey, "/api/events/verify"),
  check: (apiKey: string, sessionId: string, actionType: string, target: string, method: string) =>
    postJSON<CheckOutcome>(apiKey, "/api/check", {
      session_id: sessionId,
      action_type: actionType,
      target,
      method,
    }),
  credential: (apiKey: string, sessionId: string, service: string, action: string) =>
    postJSON<CredentialOutcome>(apiKey, "/api/credential", { session_id: sessionId, service, action }),
  breakerStatus: (apiKey: string, sessionId: string) =>
    getJSON<BreakerStatus>(apiKey, `/api/breaker/status/${sessionId}`),
  anomalyScore: (apiKey: string, sessionId: string) =>
    getJSON<AnomalyScore>(apiKey, `/api/anomaly/score/${sessionId}`),
  suspended: (apiKey: string) => getJSON<SuspendedSession[]>(apiKey, "/api/breaker/suspended"),
  resume: (apiKey: string, sessionId: string) => postJSON<unknown>(apiKey, `/api/breaker/resume/${sessionId}`, {}),
  deny: (apiKey: string, sessionId: string) => postJSON<unknown>(apiKey, `/api/breaker/deny/${sessionId}`, {}),
};
