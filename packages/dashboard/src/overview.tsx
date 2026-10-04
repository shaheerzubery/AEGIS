import { useCallback, useEffect, useState } from "react";
import { api, type AuditEvent, type LlmCall, type LlmSummary, type SuspendedSession } from "./api";
import { ChartCard, HBars, LineChart, Meter, StackedColumns, StatTile, compact } from "./charts";
import { describeEvent } from "./events";

const S1 = "var(--series-1)";
const S2 = "var(--series-2)";

const clock = (ms: number, withSeconds: boolean) =>
  new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false, ...(withSeconds ? { second: "2-digit" } : {}) });

// ---- LLM charts, shared by the Overview and the LLM tab ----

export function LlmCharts({ recent }: { recent: LlmCall[] }) {
  // API returns newest first; charts read left -> right in time.
  const calls = [...recent].reverse();
  const latency = calls
    .filter((c) => typeof c.latency_ms === "number")
    .map((c) => ({ label: clock(Date.parse(c.timestamp), true), value: c.latency_ms as number }));
  const tokens = calls.map((c) => ({
    label: clock(Date.parse(c.timestamp), true),
    values: [c.input_tokens ?? 0, c.output_tokens ?? 0],
  }));

  return (
    <>
      <ChartCard
        title="LLM latency per call"
        subtitle="Round-trip time of each recorded model call (ms)"
        empty={latency.length === 0 ? "No LLM calls recorded yet. Run an agent through record_llm_call()." : undefined}
        table={{ columns: ["Time", "Latency (ms)"], rows: latency.map((p) => [p.label, Math.round(p.value)]) }}
      >
        <LineChart points={latency} color={S1} unit="ms" />
      </ChartCard>
      <ChartCard
        title="Tokens per call"
        subtitle="Input and output tokens for each recorded model call"
        legend={[
          { label: "Input tokens", color: S1 },
          { label: "Output tokens", color: S2 },
        ]}
        empty={tokens.length === 0 ? "No LLM calls recorded yet." : undefined}
        table={{ columns: ["Time", "Input", "Output"], rows: tokens.map((t) => [t.label, t.values[0], t.values[1]]) }}
      >
        <StackedColumns
          data={tokens}
          series={[
            { name: "Input tokens", color: S1 },
            { name: "Output tokens", color: S2 },
          ]}
        />
      </ChartCard>
    </>
  );
}

// ---- Overview tab ----

export function OverviewTab({ apiKey, goTo }: { apiKey: string; goTo: (tab: "approvals" | "audit" | "llm") => void }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [llm, setLlm] = useState<LlmSummary | null>(null);
  const [suspended, setSuspended] = useState<SuspendedSession[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([api.events(apiKey, 500), api.llm(apiKey), api.suspended(apiKey)])
      .then(([e, l, s]) => {
        setEvents(e);
        setLlm(l);
        setSuspended(s);
        setError(null);
      })
      .catch((err) => setError(String(err instanceof Error ? err.message : err)))
      .finally(() => setLoading(false));
  }, [apiKey]);

  // Live: refetch every 10s. The previous render stays on screen (dimmed)
  // while reloading, so the layout never jumps.
  useEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, [load]);

  if (!events || !llm) {
    return <div className="panel">{error ? <div className="result bad">{error}</div> : <p className="hint">Loading…</p>}</div>;
  }

  const rows = events.map((e) => ({ e, d: describeEvent(e), t: Date.parse(e.timestamp) })).filter((r) => !Number.isNaN(r.t));
  const decided = rows.filter((r) => r.d.decision !== "INFO");
  const allowed = decided.filter((r) => r.d.decision === "ALLOWED").length;
  const blocked = decided.filter((r) => r.d.decision === "BLOCKED").length;
  const blockRate = decided.length ? (blocked / decided.length) * 100 : 0;

  // Bucket decisions across the observed time span (12 buckets).
  const BUCKETS = 12;
  const times = decided.map((r) => r.t);
  const min = Math.min(...times);
  const max = Math.max(...times);
  const size = Math.max(Math.ceil((max - min) / BUCKETS), 1000);
  const withSeconds = max - min < 10 * 60_000;
  const buckets = Array.from({ length: BUCKETS }, (_, i) => ({ label: clock(min + i * size, withSeconds), values: [0, 0] }));
  for (const r of decided) {
    const i = Math.min(Math.floor((r.t - min) / size), BUCKETS - 1);
    buckets[i].values[r.d.decision === "ALLOWED" ? 0 : 1] += 1;
  }
  const trimmed = decided.length ? buckets : [];

  // Top blocked actions.
  const counts = new Map<string, number>();
  for (const r of decided) if (r.d.decision === "BLOCKED") counts.set(r.d.what, (counts.get(r.d.what) ?? 0) + 1);
  const topBlocked = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value }));

  const t = llm.totals;
  const tokensSpark = [...llm.recent].reverse().map((c) => (c.input_tokens ?? 0) + (c.output_tokens ?? 0));
  const waiting = suspended.filter((s) => !s.terminated);

  return (
    <div className={loading ? "loading" : ""}>
      {error && <div className="result bad">{error}</div>}

      <div className={`card attention ${waiting.length ? "" : "clear"}`}>
        <div>
          <strong>
            {waiting.length ? `${waiting.length} session${waiting.length > 1 ? "s" : ""} waiting for review` : "Nothing waiting for review"}
          </strong>
          <div className="hint">
            {waiting.length
              ? "Suspended by the circuit breaker or anomaly detector. A person must approve or deny."
              : "No suspended sessions for this tenant."}
          </div>
        </div>
        {waiting.length > 0 && <button onClick={() => goTo("approvals")}>Review</button>}
      </div>

      <div className="grid-stats">
        <StatTile
          label="Decisions"
          value={compact(decided.length)}
          sub={`${allowed} allowed · ${blocked} blocked`}
          spark={trimmed.map((b) => b.values[0] + b.values[1])}
        />
        <StatTile label="Blocked" value={compact(blocked)} sub={`${blockRate.toFixed(0)}% of decisions`} tone={blocked ? "bad" : "good"} />
        <StatTile label="LLM calls" value={compact(t.calls)} sub={`${t.flagged_calls} flagged`} tone={t.flagged_calls ? "bad" : undefined} />
        <StatTile
          label="Tokens"
          value={compact(t.input_tokens + t.output_tokens)}
          sub={`${compact(t.input_tokens)} in · ${compact(t.output_tokens)} out`}
          spark={tokensSpark}
        />
        <StatTile
          label="Avg latency"
          value={t.avg_latency_ms == null ? "-" : `${Math.round(t.avg_latency_ms)} ms`}
          sub={t.p95_latency_ms == null ? "" : `p95 ${Math.round(t.p95_latency_ms)} ms`}
        />
        <StatTile
          label="Suspected injections"
          value={String(t.prompt_injection_suspected)}
          sub={t.prompt_injection_suspected ? "see LLM tab" : "none detected"}
          tone={t.prompt_injection_suspected ? "bad" : "good"}
        />
      </div>

      <div className="grid-charts">
        <ChartCard
          title="Decisions over time"
          subtitle="Allowed vs blocked, policy checks and content guardrail"
          legend={[
            { label: "Allowed", color: S1 },
            { label: "Blocked", color: S2 },
          ]}
          empty={decided.length === 0 ? "No policy or guardrail decisions recorded yet." : undefined}
          table={{ columns: ["From", "Allowed", "Blocked"], rows: trimmed.map((b) => [b.label, b.values[0], b.values[1]]) }}
        >
          <StackedColumns
            data={trimmed}
            series={[
              { name: "Allowed", color: S1 },
              { name: "Blocked", color: S2 },
            ]}
          />
        </ChartCard>

        <ChartCard
          title="Top blocked actions"
          subtitle="What the policy engine and guardrail refused most"
          empty={topBlocked.length === 0 ? "Nothing has been blocked." : undefined}
          table={{ columns: ["Action", "Blocked"], rows: topBlocked.map((r) => [r.label, r.value]) }}
        >
          <HBars rows={topBlocked} color={S2} unit="blocked" />
        </ChartCard>

        <section className="card chart-card">
          <header className="chart-head">
            <div>
              <h3>Enforcement</h3>
              <p className="hint">How much of the traffic AEGIS stopped</p>
            </div>
          </header>
          <Meter
            value={blocked}
            max={decided.length}
            label="Block rate"
            detail={`${blocked} of ${decided.length} decisions were blocked`}
          />
          <div className="row">
            <button className="btn-ghost" onClick={() => goTo("audit")}>
              Open audit log
            </button>
            <button className="btn-ghost" onClick={() => goTo("llm")}>
              Open LLM details
            </button>
          </div>
        </section>

        <LlmCharts recent={llm.recent} />
      </div>
    </div>
  );
}
