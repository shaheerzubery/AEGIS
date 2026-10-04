// Small dependency-free SVG chart kit for the dashboard.
//
// Follows the dataviz skill's method: thin marks (bars <= 24px with a 4px
// rounded data end, 2px lines, >= 8px end dots with a 2px surface ring),
// a 2px surface gap between stacked segments, recessive hairline grid, text
// in ink tokens (never the series color), a legend for every multi-series
// chart, a hover tooltip on every chart, and a table view for each card.
// All colors come from CSS variables defined in app.css (validated palette,
// light and dark), so nothing here hardcodes a hex value.

import { useRef, useState, type ReactNode } from "react";

// ---------- shared helpers ----------

export function niceMax(max: number): number {
  if (max <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(max)));
  const n = max / pow;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return step * pow;
}

export function compact(n: number): string {
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(Math.round(n * 100) / 100);
}

interface Tip {
  x: number; // px, relative to the chart container
  y: number;
  title?: string;
  rows: { color?: string; label: string; value: string }[];
}

function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div className="chart-tip" style={{ left: tip.x, top: tip.y }} role="status">
      {tip.title && <div className="chart-tip-title">{tip.title}</div>}
      {tip.rows.map((r, i) => (
        <div key={i} className="chart-tip-row">
          {r.color && <span className="chart-tip-key" style={{ background: r.color }} />}
          <span className="chart-tip-value">{r.value}</span>
          <span className="chart-tip-label">{r.label}</span>
        </div>
      ))}
    </div>
  );
}

function usePointer() {
  const box = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  // Position relative to the container so the tooltip tracks the pointer.
  const place = (e: { clientX: number; clientY: number }) => {
    const r = box.current?.getBoundingClientRect();
    return { x: e.clientX - (r?.left ?? 0) + 12, y: e.clientY - (r?.top ?? 0) + 12 };
  };
  return { box, tip, setTip, place };
}

// ---------- card + legend + table view ----------

export interface TableView {
  columns: string[];
  rows: (string | number)[][];
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="legend">
      {items.map((i) => (
        <span key={i.label} className="legend-item">
          <span className="legend-swatch" style={{ background: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

export function ChartCard({
  title,
  subtitle,
  legend,
  table,
  children,
  empty,
}: {
  title: string;
  subtitle?: string;
  legend?: { label: string; color: string }[];
  table?: TableView;
  children: ReactNode;
  empty?: string; // shown instead of the chart when set
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className="card chart-card">
      <header className="chart-head">
        <div>
          <h3>{title}</h3>
          {subtitle && <p className="hint">{subtitle}</p>}
        </div>
        {table && !empty && (
          <button className="btn-ghost" onClick={() => setAsTable(!asTable)}>
            {asTable ? "Chart" : "Table"}
          </button>
        )}
      </header>
      {legend && legend.length > 1 && !empty && <Legend items={legend} />}
      {empty ? (
        <div className="chart-empty">{empty}</div>
      ) : asTable && table ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                {table.columns.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r, i) => (
                <tr key={i}>
                  {r.map((v, j) => (
                    <td key={j}>{v}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        children
      )}
    </section>
  );
}

// ---------- stat tile (+ optional sparkline) ----------

export function StatTile({
  label,
  value,
  sub,
  tone,
  spark,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "good" | "bad";
  spark?: number[];
}) {
  return (
    <div className="card stat-tile">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className={`stat-sub ${tone ?? ""}`}>{sub}</div>}
      {spark && spark.length > 1 && <Sparkline values={spark} />}
    </div>
  );
}

function Sparkline({ values }: { values: number[] }) {
  const W = 120;
  const H = 28;
  const max = Math.max(...values, 1);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * (W - 8) + 4, H - 4 - (v / max) * (H - 8)]);
  const last = pts[pts.length - 1];
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="trend">
      <polyline
        points={pts.map((p) => p.join(",")).join(" ")}
        fill="none"
        stroke="var(--muted)"
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle cx={last[0]} cy={last[1]} r="4" fill="var(--series-1)" stroke="var(--surface)" strokeWidth="2" />
    </svg>
  );
}

// ---------- meter ----------

export function Meter({ value, max, label, detail }: { value: number; max: number; label: string; detail?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="meter" role="meter" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <div className="meter-head">
        <span>{label}</span>
        <strong>{pct.toFixed(0)}%</strong>
      </div>
      <div className="meter-track">
        <div className="meter-fill" style={{ width: `${pct}%` }} />
      </div>
      {detail && <div className="hint">{detail}</div>}
    </div>
  );
}

// ---------- stacked columns (two or more series per bucket) ----------

export interface ColumnDatum {
  label: string;
  values: number[]; // one per series, stacked bottom -> top
}

export function StackedColumns({
  data,
  series,
  height = 220,
}: {
  data: ColumnDatum[];
  series: { name: string; color: string }[];
  height?: number;
}) {
  const { box, tip, setTip, place } = usePointer();
  const [hover, setHover] = useState<number | null>(null);
  const W = 640;
  const pad = { l: 40, r: 8, t: 10, b: 26 };
  const innerW = W - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const totals = data.map((d) => d.values.reduce((a, b) => a + b, 0));
  const top = niceMax(Math.max(...totals, 1));
  const band = innerW / Math.max(data.length, 1);
  const barW = Math.min(24, band * 0.7);
  const y = (v: number) => pad.t + innerH - (v / top) * innerH;
  const ticks = [0, top / 2, top];
  const labelEvery = Math.ceil(data.length / 6);

  return (
    <div className="chart-box" ref={box} onPointerLeave={() => (setTip(null), setHover(null))}>
      <svg viewBox={`0 0 ${W} ${height}`} className="chart-svg" role="img" aria-label="stacked column chart">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} className={t === 0 ? "axis" : "grid"} />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" className="tick">
              {compact(t)}
            </text>
          </g>
        ))}
        {data.map((d, i) => {
          const cx = pad.l + band * i + band / 2;
          let acc = 0;
          const segs = d.values.map((v, s) => {
            const y0 = y(acc);
            acc += v;
            const y1 = y(acc);
            return { v, s, y0, y1 };
          });
          const lastNonZero = [...segs].reverse().find((g) => g.v > 0)?.s;
          return (
            <g key={i}>
              {segs.map(({ v, s, y0, y1 }) => {
                if (v <= 0) return null;
                // 2px surface gap between segments: shave the lower edge.
                const h = Math.max(y0 - y1 - (s > 0 ? 2 : 0), 1);
                const yTop = y1;
                const r = s === lastNonZero ? Math.min(4, h) : 0;
                const x = cx - barW / 2;
                // square at the baseline/inner edge, 4px rounded data end on the top segment
                const d2 = `M${x},${yTop + h} V${yTop + r} Q${x},${yTop} ${x + r},${yTop} H${x + barW - r} Q${x + barW},${yTop} ${x + barW},${yTop + r} V${yTop + h} Z`;
                return (
                  <path
                    key={s}
                    d={d2}
                    fill={series[s].color}
                    opacity={hover === null || hover === i ? 1 : 0.55}
                  />
                );
              })}
              {(i % labelEvery === 0 || i === data.length - 1) && (
                <text x={cx} y={height - 8} textAnchor="middle" className="tick">
                  {d.label}
                </text>
              )}
              {/* hit target: the whole band, taller and wider than the painted bar */}
              <rect
                x={pad.l + band * i}
                y={pad.t}
                width={band}
                height={innerH + pad.b}
                fill="transparent"
                tabIndex={0}
                onPointerMove={(e) => {
                  setHover(i);
                  setTip({
                    ...place(e),
                    title: d.label,
                    rows: series.map((sr, s) => ({ color: sr.color, label: sr.name, value: String(d.values[s]) })),
                  });
                }}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
              />
            </g>
          );
        })}
      </svg>
      <Tooltip tip={tip} />
    </div>
  );
}

// ---------- horizontal bars (ranked categories) ----------

export function HBars({
  rows,
  color,
  unit = "",
}: {
  rows: { label: string; value: number }[];
  color: string;
  unit?: string;
}) {
  const { box, tip, setTip, place } = usePointer();
  const max = niceMax(Math.max(...rows.map((r) => r.value), 1));
  return (
    <div className="chart-box hbars" ref={box} onPointerLeave={() => setTip(null)}>
      {rows.map((r) => (
        <div
          key={r.label}
          className="hbar-row"
          tabIndex={0}
          onPointerMove={(e) => setTip({ ...place(e), title: r.label, rows: [{ color, label: unit || "count", value: String(r.value) }] })}
        >
          <span className="hbar-label" title={r.label}>
            {r.label}
          </span>
          <span className="hbar-track">
            <span className="hbar-fill" style={{ width: `${(r.value / max) * 100}%`, background: color }} />
          </span>
          <span className="hbar-value">{r.value}</span>
        </div>
      ))}
      <Tooltip tip={tip} />
    </div>
  );
}

// ---------- line chart (single series, crosshair tooltip) ----------

export function LineChart({
  points,
  color,
  unit,
  height = 200,
}: {
  points: { label: string; value: number }[];
  color: string;
  unit: string;
  height?: number;
}) {
  const { box, tip, setTip, place } = usePointer();
  const [hover, setHover] = useState<number | null>(null);
  const W = 640;
  const pad = { l: 44, r: 14, t: 10, b: 26 };
  const innerW = W - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const top = niceMax(Math.max(...points.map((p) => p.value), 1));
  const x = (i: number) => pad.l + (points.length === 1 ? innerW / 2 : (i / (points.length - 1)) * innerW);
  const y = (v: number) => pad.t + innerH - (v / top) * innerH;
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(p.value)}`).join(" ");
  const area = points.length > 1 ? `${path} L${x(points.length - 1)},${y(0)} L${x(0)},${y(0)} Z` : "";
  const ticks = [0, top / 2, top];
  const labelEvery = Math.ceil(points.length / 6);
  const last = points.length - 1;

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const rect = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
    const frac = (e.clientX - rect.left) / rect.width;
    const px = frac * W;
    let best = 0;
    points.forEach((_, i) => {
      if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
    });
    setHover(best);
    setTip({ ...place(e), title: points[best].label, rows: [{ color, label: unit, value: compact(points[best].value) }] });
  };

  return (
    <div className="chart-box" ref={box} onPointerLeave={() => (setTip(null), setHover(null))}>
      <svg viewBox={`0 0 ${W} ${height}`} className="chart-svg" role="img" aria-label="line chart">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} className={t === 0 ? "axis" : "grid"} />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" className="tick">
              {compact(t)}
            </text>
          </g>
        ))}
        {area && <path d={area} fill={color} opacity="0.1" />}
        <path d={path} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {points.map((p, i) =>
          i % labelEvery === 0 || i === last ? (
            <text key={i} x={x(i)} y={height - 8} textAnchor="middle" className="tick">
              {p.label}
            </text>
          ) : null
        )}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + innerH} className="crosshair" />}
        {/* end dot, always shown; hovered dot too. 2px surface ring so it stays legible */}
        {[last, ...(hover !== null && hover !== last ? [hover] : [])].map((i) => (
          <circle key={i} cx={x(i)} cy={y(points[i].value)} r="4" fill={color} stroke="var(--surface)" strokeWidth="2" />
        ))}
        <rect x={pad.l} y={pad.t} width={innerW} height={innerH + pad.b} fill="transparent" onPointerMove={onMove} />
      </svg>
      <Tooltip tip={tip} />
    </div>
  );
}
