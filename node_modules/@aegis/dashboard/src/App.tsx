import { useEffect, useState } from "react";
import { api, ApiError, type AuditEvent, type ServiceStatus, type SuspendedSession } from "./api";
import "./app.css";

type Tab = "check" | "credential" | "approvals" | "audit";

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
  if (error) return <div className="statusbar status-down">{error}</div>;
  if (!status) return <div className="statusbar">service status unavailable</div>;

  return (
    <div className="statusbar">
      <span className="status-up">authenticated as tenant: {String(status.tenant_id)}</span>
      <span className="status-up">
        operator: {String(status.operator)} (role: {String(status.role)})
      </span>
      {Object.entries(status)
        .filter(([name]) => !STATUS_META_FIELDS.includes(name))
        .map(([name, up]) => (
          <span key={name} className={up ? "status-up" : "status-down"}>
            {name}: {up ? "up" : "down"}
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

function ApprovalsTab({ apiKey, isOperator }: { apiKey: string; isOperator: boolean }) {
  const [suspended, setSuspended] = useState<SuspendedSession[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => api.suspended(apiKey).then(setSuspended).catch((err) => setError(errorMessage(err)));
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
            <tr key={s.session_id}>
              <td>{s.session_id}</td>
              <td>{s.reason}</td>
              <td>{s.terminated ? "TERMINATED" : "SUSPENDED"}</td>
              {isOperator && (
                <td>
                  {!s.terminated && (
                    <>
                      <button onClick={() => api.resume(apiKey, s.session_id).then(refresh)}>Approve</button>
                      <button onClick={() => api.deny(apiKey, s.session_id).then(refresh)}>Deny</button>
                    </>
                  )}
                </td>
              )}
            </tr>
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

  const refresh = () => {
    api.events(apiKey, 30).then(setEvents).catch((err) => setError(errorMessage(err)));
    api
      .verify(apiKey)
      .then((v) => setChainIntact(v.chain_intact))
      .catch((err) => setError(errorMessage(err)));
  };
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey]);

  return (
    <div className="panel">
      <h3>Recent audit events (all sessions, current tenant)</h3>
      <button onClick={refresh}>Refresh</button>
      {error && <div className="result bad">{error}</div>}
      {chainIntact !== null && (
        <div className={`result ${chainIntact ? "ok" : "bad"}`}>
          {chainIntact ? "Hash chain intact — no tampering detected." : "Hash chain broken — tampering detected!"}
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Session</th>
            <th>Action</th>
            <th>Target</th>
            <th>Allowed</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.event_id}>
              <td>{e.timestamp}</td>
              <td>{e.session_id}</td>
              <td>{e.action?.action_type}</td>
              <td>{e.action?.target}</td>
              <td>{String(e.policy_decision?.allowed)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("check");
  const [apiKey, setApiKey] = useApiKey();
  const [sessionId, setSessionId] = useSessionId();
  // Managed-dashboard-for-security-teams work (2026-09-28, see
  // PROGRESS.md): lifted up from StatusBar so role/operator (from the
  // same /api/status call) can gate the operator-only controls in every
  // tab below, not just be displayed in the status bar itself.
  const { status, error } = useDashboardStatus(apiKey);
  const isOperator = status?.role === "operator";

  return (
    <div className="app">
      <h1>AEGIS — containment flow viewer</h1>
      <p className="hint">
        Every action here goes through the same real services as the CLI/test scripts. Nothing is simulated.
      </p>
      <StatusBar status={status} error={error} />

      <div className="row">
        <label>
          API Key:{" "}
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="paste your dashboard API key"
          />
        </label>
        <label>
          Session ID:{" "}
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
        </label>
        <button onClick={() => setSessionId(`dashboard-${Date.now()}`)}>New session</button>
      </div>

      <div className="tabs">
        {(["check", "credential", "approvals", "audit"] as Tab[]).map((t) => (
          <button key={t} className={tab === t ? "tab active" : "tab"} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>

      {tab === "check" && <CheckTab apiKey={apiKey} sessionId={sessionId} isOperator={isOperator} />}
      {tab === "credential" && <CredentialTab apiKey={apiKey} sessionId={sessionId} isOperator={isOperator} />}
      {tab === "approvals" && <ApprovalsTab apiKey={apiKey} isOperator={isOperator} />}
      {tab === "audit" && <AuditTab apiKey={apiKey} />}
    </div>
  );
}
