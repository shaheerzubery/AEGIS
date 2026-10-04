import { Fragment, useEffect, useState } from "react";
import { Badge, describeEvent, fmtTime } from "./events";
import { LlmCharts, OverviewTab } from "./overview";
import { api, ApiError, type AnomalyScore, type AuditEvent, type LlmCall, type LlmSummary, type ServiceStatus, type SuspendedSession } from "./api";
import "./app.css";

type Tab = "overview" | "check" | "credential" | "approvals" | "audit" | "llm";

const API_KEY_STORAGE_KEY = "aegis-dashboard-api-key";

function useSessionId(): [string, (v: string) => void] {
  const [sessionId, setSessionId] = useState(`dashboard-${Date.now()}`);
  return [sessionId, setSessionId];
}

// Gap-closing work (2026-08-22, see PROGRESS.md): the dashboard used to
// have a free-text "Tenant ID" field trusted as-is by the backend — no
// authentication bound a caller to a tenant at all. It's now an API key
// (see config.py's DASHBOARD_API_KEYS) that the server resolves to a
// tenant server-side; persisted in localStorage so it survives reloads
// (same-origin only — a different origin's JS can't read it).
function useApiKey(): [string, (v: string) => void] {
  const [apiKey, setApiKeyState] = useState(() => localStorage.getItem(API_KEY_STORAGE_KEY) || "");
  const setApiKey = (v: string) => {
    setApiKeyState(v);
    localStorage.setItem(API_KEY_STORAGE_KEY, v);
  };
  return [apiKey, setApiKey];
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return `${err.status === 401 ? "Invalid API key" : err.message}`;
  return String(err);
}

// Managed-dashboard-for-security-teams work (2026-09-28, see
// PROGRESS.md): /api/status now also returns "role" and "operator" —
// both real strings (not up/down booleans like every other field), so
// they need their own display, not the generic up/down rendering below.
const STATUS_META_FIELDS = ["tenant_id", "role", "operator"];

function useDashboardStatus(apiKey: string): { status: ServiceStatus | null; error: string | null } {
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!apiKey) {
      setStatus(null);
      setError("Enter an API key below to connect.");
      return;
    }
    api
      .status(apiKey)
      .then((s) => {
        setStatus(s);
        setError(null);
      })
      .catch((err) => {
        setStatus(null);
        setError(errorMessage(err));
      });
  }, [apiKey]);

  return { status, error };
}

function StatusBar({ status, error }: { status: ServiceStatus | null; error: string | null }) {
  if (error) return <div className="pills"><span className="pill warn"><span className="dot down" />{error}</span></div>;
  if (!status) return <div className="pills"><span className="pill">service status unavailable</span></div>;

  return (
    <div className="pills">
      <span className="pill">tenant: {String(status.tenant_id)}</span>
      <span className="pill">
        {String(status.operator)} · {String(status.role)}
      </span>
      {Object.entries(status)
        .filter(([name]) => !STATUS_META_FIELDS.includes(name))
        .map(([name, up]) => (
          <span key={name} className="pill" title={`${name}: ${up ? "up" : "down"}`}>
            <span className={`dot ${up ? "up" : "down"}`} />
            {name.replace(/_/g, " ")}
          </span>
        ))}
    </div>
  );
}

// Managed-dashboard-for-security-teams work (2026-09-28, see
// PROGRESS.md): a "viewer" key can see everything below but can't submit
// any of these actions — the backend rejects them with 403 regardless
// (see dashboard_api.py's do_POST), this just avoids offering a control
// that would fail, and makes the read-only role visible in the UI
// itself rather than only discoverable by clicking and getting an error.
function CheckTab({ apiKey, sessionId, isOperator }: { apiKey: string; sessionId: string; isOperator: boolean }) {
  const [actionType, setActionType] = useState("http_request");
  const [target, setTarget] = useState("example.com");
  const [method, setMethod] = useState("");
  const [result, setResult] = useState<string | null>(null);

  const run = async () => {
    try {
      const res = await api.check(apiKey, sessionId, actionType, target, method);
      setResult(`${res.outcome.toUpperCase()}${res.detail ? ` — ${res.detail}` : ""}`);
    } catch (err) {
      setResult(`ERROR — ${errorMessage(err)}`);
    }
  };

  return (
    <div className="panel">
      <h3>Send an action through the policy engine</h3>
      <p className="hint">
        Try target=<code>example.com</code> (allowed for tenant "default") vs. <code>acme.example</code>{" "}
        (allowed for tenant "tenant-acme" instead) to see tenant isolation.
      </p>
      {!isOperator && <p className="hint">Viewer role: read-only, this action is disabled.</p>}
      <div className="row">
        <select value={actionType} onChange={(e) => setActionType(e.target.value)} disabled={!isOperator}>
          <option value="http_request">http_request</option>
          <option value="tool_call">tool_call</option>
          <option value="file_read">file_read</option>
          <option value="credential_use">credential_use</option>
        </select>
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="target" disabled={!isOperator} />
        <input
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          placeholder="method (optional)"
          disabled={!isOperator}
        />
        <button onClick={run} disabled={!isOperator}>
          Check action
        </button>
      </div>
      {result && <div className={`result ${result.startsWith("ALLOWED") ? "ok" : "bad"}`}>{result}</div>}
    </div>
  );
}

function CredentialTab({ apiKey, sessionId, isOperator }: { apiKey: string; sessionId: string; isOperator: boolean }) {
  const [action, setAction] = useState("profile");
  const [result, setResult] = useState<string | null>(null);

  const run = async () => {
    try {
      const res = await api.credential(apiKey, sessionId, "protected-api", action);
      setResult(
        res.outcome === "allowed"
          ? `ALLOWED — ${JSON.stringify(res.result)}`
          : `${res.outcome.toUpperCase()}${res.detail ? ` — ${res.detail}` : ""}`
      );
    } catch (err) {
      setResult(`ERROR — ${errorMessage(err)}`);
    }
  };

  return (
    <div className="panel">
      <h3>Credential vaulting — the agent never sees the token</h3>
      <p className="hint">
        Try action=<code>profile</code> (allowed) vs. <code>delete-account</code> (denied). Each tenant gets a
        different token from Vault for the same nominal service.
      </p>
      {!isOperator && <p className="hint">Viewer role: read-only, this action is disabled.</p>}
      <div className="row">
        <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="action" disabled={!isOperator} />
        <button onClick={run} disabled={!isOperator}>
          Invoke via credential broker
        </button>
      </div>
      {result && <div className={`result ${result.startsWith("ALLOWED") ? "ok" : "bad"}`}>{result}</div>}
    </div>
  );
}

// Plain-language meaning of each flag the anomaly detector can raise (see
// packages/anomaly-detector and config.py's *_THRESHOLD values).
const FLAG_MEANING: Record<string, string> = {
  self_modification: "the session touched its own code, config or policy (always critical)",
  privilege_escalation: "several different kinds of action were denied, probing for something that works",
  lateral_movement: "the session reached for many different targets in a short time",
  reconnaissance: "many file reads in a short time, mapping what is available",
  ml_anomaly: "the trained classifier rated the overall pattern as risky, though no single rule threshold was crossed",
};

// Evidence for a reviewer before approving/denying: the detector's current
// score and flags, and the session's own audit trail (the permanent record).
// The score only covers the detector's recent window (config.py's
// ANOMALY_WINDOW_SECONDS), so for an older suspension it can read low or
// empty while the timeline below still shows exactly what happened.
function SessionEvidence({ apiKey, sessionId }: { apiKey: string; sessionId: string }) {
  const [score, setScore] = useState<AnomalyScore | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.anomalyScore(apiKey, sessionId).then(setScore).catch(() => setScore(null));
    api
      .events(apiKey, 100, sessionId)
      .then(setEvents)
      .catch((err) => setError(errorMessage(err)));
  }, [apiKey, sessionId]);

  const rows = events.map((e) => ({ e, d: describeEvent(e) }));
  const blocked = rows.filter((r) => r.d.decision === "BLOCKED").length;
  const allowed = rows.filter((r) => r.d.decision === "ALLOWED").length;
  const distinctBlocked = new Set(rows.filter((r) => r.d.decision === "BLOCKED").map((r) => r.d.what)).size;

  return (
    <div>
      <strong>Why it was suspended</strong>
      {score ? (
        <div>
          <div className="statusbar">
            <span className={score.severity === "critical" ? "status-down" : ""}>
              anomaly score: {score.score.toFixed(2)} ({score.severity})
            </span>
            <span>actions in window: {score.actions_in_window}</span>
            <span>
              history: {allowed} allowed, {blocked} blocked ({distinctBlocked} distinct blocked actions)
            </span>
          </div>
          {score.flags.length === 0 ? (
            <p className="hint">
              No flags in the detector's current window (it only looks at the last couple of minutes). Use the
              timeline below.
            </p>
          ) : (
            <ul>
              {score.flags.map((f) => (
                <li key={f}>
                  <code>{f}</code>: {FLAG_MEANING[f] ?? "see detector documentation"}
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
        <p className="hint">Anomaly detector unavailable; showing the audit trail only.</p>
      )}
      {error && <div className="result bad">{error}</div>}
      <strong>What the session did (newest first)</strong>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Decision</th>
            <th>What</th>
            <th>Why / details</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={5}>No audit events for this session.</td>
            </tr>
          )}
          {rows.map(({ e, d }) => (
            <tr key={e.event_id}>
              <td>{fmtTime(e.timestamp)}</td>
              <td>{d.label}</td>
              <td>
                <Badge decision={d.decision} />
              </td>
              <td>{d.what}</td>
              <td>{d.why}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ApprovalsTab({ apiKey, isOperator }: { apiKey: string; isOperator: boolean }) {
  const [suspended, setSuspended] = useState<SuspendedSession[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = () =>
    api
      .suspended(apiKey)
      .then((s) => {
        setSuspended(s);
        setError(null);
      })
      .catch((err) => setError(errorMessage(err)));
  // Approve/Deny: surface a failure instead of silently dropping it, and
  // refresh the queue either way so the table never shows stale state.
  const decide = (action: "resume" | "deny", sessionId: string) =>
    api[action](apiKey, sessionId)
      .then(() => setError(null))
      .catch((err) => setError(`${action} failed: ${errorMessage(err)}`))
      .then(refresh);
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey]);

  return (
    <div className="panel">
      <h3>Human-in-the-loop approval queue (current tenant only)</h3>
      <p className="hint">
        Sessions suspended by the circuit breaker or anomaly detector, pending review. Scoped to the tenant your
        API key authenticates as — a different tenant's suspended sessions never appear here.
      </p>
      {!isOperator && <p className="hint">Viewer role: can see the queue, cannot approve/deny.</p>}
      <button onClick={refresh}>Refresh</button>
      {error && <div className="result bad">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>Session</th>
            <th>Reason</th>
            <th>Status</th>
            {isOperator && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {suspended.length === 0 && (
            <tr>
              <td colSpan={isOperator ? 4 : 3}>No sessions pending review.</td>
            </tr>
          )}
          {suspended.map((s) => (
            <Fragment key={s.session_id}>
              <tr>
                <td>{s.session_id}</td>
                <td>{s.reason}</td>
                <td>{s.terminated ? "TERMINATED" : "SUSPENDED"}</td>
                {isOperator && (
                  <td>
                    {!s.terminated && (
                      <>
                        <button className="btn-approve" onClick={() => decide("resume", s.session_id)}>
                          Approve
                        </button>
                        <button className="btn-deny" onClick={() => decide("deny", s.session_id)}>
                          Deny
                        </button>
                      </>
                    )}
                  </td>
                )}
              </tr>
              <tr>
                <td colSpan={isOperator ? 4 : 3}>
                  <SessionEvidence apiKey={apiKey} sessionId={s.session_id} />
                </td>
              </tr>
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditTab({ apiKey }: { apiKey: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [chainIntact, setChainIntact] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<"all" | "ALLOWED" | "BLOCKED" | "INFO">("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sessionFilter, setSessionFilter] = useState("");

  const refresh = () => {
    api.events(apiKey, 200).then(setEvents).catch((err) => setError(errorMessage(err)));
    api
      .verify(apiKey)
      .then((v) => setChainIntact(v.chain_intact))
      .catch((err) => setError(errorMessage(err)));
  };
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey]);

  const rows = events.map((e) => ({ e, d: describeEvent(e) }));
  const count = (dec: "ALLOWED" | "BLOCKED" | "INFO") => rows.filter((r) => r.d.decision === dec).length;
  const types = [...new Set(rows.map((r) => r.d.label))];
  const shown = rows.filter(
    (r) =>
      (decisionFilter === "all" || r.d.decision === decisionFilter) &&
      (typeFilter === "all" || r.d.label === typeFilter) &&
      (!sessionFilter || r.e.session_id.includes(sessionFilter))
  );

  return (
    <div className="panel">
      <h3>Audit log (latest 200 events, current tenant)</h3>
      <p className="hint">
        Every row is one recorded event. ALLOWED / BLOCKED are decisions by the policy engine or content guardrail;
        INFO rows (LLM calls, operator actions) record what happened and carry no allow-or-deny decision. The
        guardrail only logs content it blocked.
      </p>
      <button onClick={refresh}>Refresh</button>
      {error && <div className="result bad">{error}</div>}
      {chainIntact !== null && (
        <div className={`result ${chainIntact ? "ok" : "bad"}`}>
          {chainIntact ? "Hash chain intact - no tampering detected." : "Hash chain broken - tampering detected!"}
        </div>
      )}
      <div className="statusbar">
        <span className="status-up">allowed: {count("ALLOWED")}</span>
        <span className="status-down">blocked: {count("BLOCKED")}</span>
        <span>info: {count("INFO")}</span>
        <span>total: {rows.length}</span>
      </div>
      <div className="row">
        <select value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value as "all" | "ALLOWED" | "BLOCKED" | "INFO")}>
          <option value="all">all decisions</option>
          <option value="ALLOWED">allowed</option>
          <option value="BLOCKED">blocked</option>
          <option value="INFO">info</option>
        </select>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="all">all event types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input value={sessionFilter} onChange={(e) => setSessionFilter(e.target.value)} placeholder="filter by session id" />
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Session</th>
            <th>Type</th>
            <th>Decision</th>
            <th>What</th>
            <th>Why / details</th>
            <th>Raw</th>
          </tr>
        </thead>
        <tbody>
          {shown.length === 0 && (
            <tr>
              <td colSpan={7}>No events match.</td>
            </tr>
          )}
          {shown.map(({ e, d }) => (
            <tr key={e.event_id}>
              <td>{fmtTime(e.timestamp)}</td>
              <td>{e.session_id}</td>
              <td>{d.label}</td>
              <td>
                <Badge decision={d.decision} />
              </td>
              <td>{d.what}</td>
              <td>{d.why}</td>
              <td>
                <details>
                  <summary>json</summary>
                  <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>{JSON.stringify(e, null, 2)}</pre>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const fmt = (n: number | null | undefined, digits = 0) => (n == null ? "-" : n.toFixed(digits));

// Prompt/response text is only present when the SDK client was created
// with capture_text=True (off by default, audit events are otherwise
// hash-only), so a missing value is the normal case, not an error.
function TextCell({ call }: { call: LlmCall }) {
  if (call.input_text == null && call.output_text == null) {
    return <span className="hint">not captured (hash only)</span>;
  }
  return (
    <details>
      <summary>view</summary>
      <div>
        <strong>Input{call.input_truncated ? " (truncated)" : ""}:</strong>
        <pre style={{ whiteSpace: "pre-wrap", margin: "4px 0" }}>{call.input_text ?? "(none)"}</pre>
        <strong>Output{call.output_truncated ? " (truncated)" : ""}:</strong>
        <pre style={{ whiteSpace: "pre-wrap", margin: "4px 0" }}>{call.output_text ?? "(none)"}</pre>
      </div>
    </details>
  );
}

function LlmTab({ apiKey }: { apiKey: string }) {
  const [data, setData] = useState<LlmSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () =>
    api
      .llm(apiKey)
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((err) => setError(errorMessage(err)));
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey]);

  const t = data?.totals;
  return (
    <div className="panel">
      <h3>LLM usage and prompt-injection findings (current tenant)</h3>
      <p className="hint">
        From <code>llm_call</code> audit events recorded by <code>AegisClient.record_llm_call()</code> (last 500
        calls). Prompt and response text appears only if the SDK client was created with capture_text=True; otherwise only hashes and guardrail verdicts are stored.
      </p>
      <button onClick={refresh}>Refresh</button>
      {error && <div className="result bad">{error}</div>}
      {t && (
        <>
          <div className="statusbar">
            <span>calls: {t.calls}</span>
            <span>
              tokens: {t.input_tokens} in / {t.output_tokens} out
            </span>
            <span>cost: ${t.cost_usd.toFixed(4)}</span>
            <span>
              latency: avg {fmt(t.avg_latency_ms)} ms, p95 {fmt(t.p95_latency_ms)} ms
            </span>
            <span className={t.prompt_injection_suspected ? "status-down" : "status-up"}>
              suspected injections: {t.prompt_injection_suspected}
            </span>
            <span className={t.flagged_calls ? "status-down" : "status-up"}>flagged calls: {t.flagged_calls}</span>
            {t.unscanned_calls > 0 && <span className="status-down">unscanned: {t.unscanned_calls}</span>}
          </div>

          <div className="grid-charts" style={{ marginTop: 14 }}>
            <LlmCharts recent={data.recent} />
          </div>

          <h4>By model</h4>
          <table>
            <thead>
              <tr>
                <th>Model</th>
                <th>Calls</th>
                <th>Input tokens</th>
                <th>Output tokens</th>
                <th>Cost (USD)</th>
                <th>Flagged</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.by_model).map(([model, m]) => (
                <tr key={model}>
                  <td>{model}</td>
                  <td>{m.calls}</td>
                  <td>{m.input_tokens}</td>
                  <td>{m.output_tokens}</td>
                  <td>{m.cost_usd.toFixed(4)}</td>
                  <td>{m.flagged}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>Flagged calls (PII / prompt injection / toxic)</h4>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Session</th>
                <th>Model</th>
                <th>Categories</th>
                <th>Matched patterns</th>
                <th>Input / output</th>
              </tr>
            </thead>
            <tbody>
              {data.flagged.length === 0 && (
                <tr>
                  <td colSpan={6}>No flagged calls.</td>
                </tr>
              )}
              {data.flagged.map((c) => (
                <tr key={c.event_id}>
                  <td>{fmtTime(c.timestamp)}</td>
                  <td>{c.session_id}</td>
                  <td>{c.model}</td>
                  <td>{c.categories.join(", ")}</td>
                  <td>{c.types.join(", ")}</td>
                  <td>
                    <TextCell call={c} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>Recent calls</h4>
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Session</th>
                <th>Model</th>
                <th>Tokens in/out</th>
                <th>Latency (ms)</th>
                <th>Cost</th>
                <th>Verdict</th>
                <th>Input / output</th>
              </tr>
            </thead>
            <tbody>
              {data.recent.map((c) => (
                <tr key={c.event_id}>
                  <td>{fmtTime(c.timestamp)}</td>
                  <td>{c.session_id}</td>
                  <td>{c.model}</td>
                  <td>
                    {c.input_tokens ?? "-"} / {c.output_tokens ?? "-"}
                  </td>
                  <td>{fmt(c.latency_ms)}</td>
                  <td>{c.cost_usd == null ? "-" : c.cost_usd.toFixed(4)}</td>
                  <td>{!c.scanned ? "not scanned" : c.flagged ? `FLAGGED: ${c.categories.join(", ")}` : "clean"}</td>
                  <td>
                    <TextCell call={c} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

const TAB_LABELS: Record<Tab, string> = {
  overview: "Overview",
  check: "Policy check",
  credential: "Credentials",
  approvals: "Approvals",
  audit: "Audit log",
  llm: "LLM",
};

const THEME_KEY = "aegis-dashboard-theme";

function useTheme(): ["light" | "dark", () => void] {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);
  return [theme, () => setTheme(theme === "dark" ? "light" : "dark")];
}

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [apiKey, setApiKey] = useApiKey();
  const [sessionId, setSessionId] = useSessionId();
  const [theme, toggleTheme] = useTheme();
  // Managed-dashboard-for-security-teams work (2026-09-28, see
  // PROGRESS.md): lifted up from StatusBar so role/operator (from the
  // same /api/status call) can gate the operator-only controls in every
  // tab below, not just be displayed in the status bar itself.
  const { status, error } = useDashboardStatus(apiKey);
  const isOperator = status?.role === "operator";
  const [waiting, setWaiting] = useState(0);

  // Badge on the Approvals tab: how many sessions are waiting for a person.
  useEffect(() => {
    if (!status) {
      setWaiting(0);
      return;
    }
    const load = () =>
      api
        .suspended(apiKey)
        .then((s) => setWaiting(s.filter((x) => !x.terminated).length))
        .catch(() => undefined);
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, [apiKey, status]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            A
          </div>
          <div>
            <h1>AEGIS</h1>
            <p className="hint">Containment for AI agents · live view of the real services</p>
          </div>
        </div>
        <div className="pills">
          <StatusBar status={status} error={error} />
          <button className="btn-ghost" onClick={toggleTheme} aria-label="Toggle light and dark theme">
            {theme === "dark" ? "☀ Light" : "☾ Dark"}
          </button>
        </div>
      </header>

      <div className="card connect">
        <div className="row" style={{ margin: 0 }}>
          <label>
            API key
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="paste your dashboard API key"
              style={{ minWidth: 260 }}
            />
          </label>
          <label>
            Session
            <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} style={{ minWidth: 230 }} />
          </label>
          <button className="btn-ghost" onClick={() => setSessionId(`dashboard-${Date.now()}`)}>
            New session
          </button>
        </div>
      </div>

      {!status ? (
        <div className="card empty-state">
          <h2>Connect to see your data</h2>
          <p className="hint">
            Paste a dashboard API key above. The demo keys are in <code>config.py</code> under{" "}
            <code>DASHBOARD_API_KEYS</code>; the key decides which tenant you see.
          </p>
        </div>
      ) : (
        <>
          <nav className="tabs">
            {(Object.keys(TAB_LABELS) as Tab[]).map((t) => (
              <button key={t} className={tab === t ? "tab active" : "tab"} onClick={() => setTab(t)}>
                {TAB_LABELS[t]}
                {t === "approvals" && waiting > 0 && <span className="count">{waiting}</span>}
              </button>
            ))}
          </nav>

          {tab === "overview" && <OverviewTab apiKey={apiKey} goTo={setTab} />}
          {tab === "check" && <CheckTab apiKey={apiKey} sessionId={sessionId} isOperator={isOperator} />}
          {tab === "credential" && <CredentialTab apiKey={apiKey} sessionId={sessionId} isOperator={isOperator} />}
          {tab === "approvals" && <ApprovalsTab apiKey={apiKey} isOperator={isOperator} />}
          {tab === "audit" && <AuditTab apiKey={apiKey} />}
          {tab === "llm" && <LlmTab apiKey={apiKey} />}
        </>
      )}
    </div>
  );
}
