import { useId, useState, type ReactNode } from 'react';

export interface Series {
  key: string;
  label: string;
  color: string;
}

interface ChartProps {
  data: Record<string, number>[]; // each row has `ts` plus series keys
  series: Series[];
  format: (v: number) => string;
  max?: number; // fixed y max (e.g. 100 for percentages)
  height?: number;
  axisFormat?: (v: number) => string;
}

const W = 600;
const timeLabel = (ts: number, span: number) =>
  span > 36 * 3600_000
    ? new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    : new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

/** Smooth path through points (monotone-ish Catmull-Rom to Bezier) */
function smooth(pts: [number, number][]): string {
  if (pts.length < 3) return pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('');
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] ?? pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] ?? p2;
    const t = 0.18;
    const c1: [number, number] = [p1[0] + (p2[0] - p0[0]) * t, p1[1] + (p2[1] - p0[1]) * t];
    const c2: [number, number] = [p2[0] - (p3[0] - p1[0]) * t, p2[1] - (p3[1] - p1[1]) * t];
    d += `C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

/** Responsive SVG area chart with gradient fills, axis labels and a hover crosshair. No dependencies. */
export function Chart({ data, series, format, max, height = 170, axisFormat }: ChartProps) {
  const uid = useId().replace(/:/g, '');
  const [hover, setHover] = useState<number | null>(null);
  if (data.length < 2) return <div className="chart-empty" style={{ height }} />;

  const PADT = 10;
  const top = niceMax(max ?? Math.max(1e-9, ...data.flatMap((d) => series.map((s) => d[s.key] ?? 0))) * 1.1, max != null);
  const x0 = data[0].ts;
  const x1 = data[data.length - 1].ts;
  const span = x1 - x0 || 1;
  const x = (ts: number) => ((ts - x0) / span) * W;
  const y = (v: number) => PADT + (1 - Math.min(Math.max(v, 0), top) / top) * (height - PADT);
  const hoverRow = hover != null ? data[hover] : null;
  const ticks = [0, 0.5, 1];
  const fmtAxis = axisFormat ?? format;

  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const ts = x0 + ((e.clientX - r.left) / r.width) * span;
    let lo = 0;
    let hi = data.length - 1;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      data[mid].ts < ts ? (lo = mid) : (hi = mid);
    }
    setHover(Math.abs(data[lo].ts - ts) < Math.abs(data[hi].ts - ts) ? lo : hi);
  };

  return (
    <div className="chart2">
      <div className="yaxis" style={{ height }}>
        {ticks.map((g) => (
          <span key={g} style={{ top: `${((y(top * g) ) / height) * 100}%` }}>{fmtAxis(top * g)}</span>
        ))}
      </div>
      <div className="plot" onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" style={{ height }} role="img">
          <defs>
            {series.map((s, i) => (
              <linearGradient key={s.key} id={`${uid}-${i}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={0.32} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          {ticks.map((g) => (
            <line key={g} x1={0} x2={W} y1={y(top * g)} y2={y(top * g)} className="grid" vectorEffect="non-scaling-stroke" />
          ))}
          {series.map((s, i) => {
            const pts: [number, number][] = data.map((d) => [x(d.ts), y(d[s.key] ?? 0)]);
            const line = smooth(pts);
            return (
              <g key={s.key}>
                <path d={`${line}L${W},${height}L0,${height}Z`} fill={`url(#${uid}-${i})`} />
                <path d={line} fill="none" stroke={s.color} strokeWidth={1.8} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
              </g>
            );
          })}
          {hoverRow && <line x1={x(hoverRow.ts)} x2={x(hoverRow.ts)} y1={0} y2={height} className="cross" vectorEffect="non-scaling-stroke" />}
        </svg>
        {hoverRow &&
          series.map((s) => (
            <i key={s.key} className="hover-dot" style={{ left: `${(x(hoverRow.ts) / W) * 100}%`, top: y(hoverRow[s.key] ?? 0), background: s.color }} />
          ))}
        <div className="xaxis">
          <span>{timeLabel(x0, span)}</span>
          <span>{timeLabel(x0 + span / 2, span)}</span>
          <span>{timeLabel(x1, span)}</span>
        </div>
        {hoverRow && (
          <div className="chart-tip" style={{ left: `${(x(hoverRow.ts) / W) * 100}%`, transform: hover! > data.length * 0.6 ? 'translateX(-108%)' : 'translateX(10px)' }}>
            <div className="muted">{new Date(hoverRow.ts).toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}</div>
            {series.map((s) => (
              <div key={s.key}>
                <i style={{ background: s.color }} /> {s.label} <b>{format(hoverRow[s.key] ?? 0)}</b>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function niceMax(v: number, fixed: boolean): number {
  if (fixed) return v;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

/** Tiny inline trend line for tables and cards. */
export function Spark({ values, color = 'var(--accent)', max = 100, width = 84 }: { values: number[]; color?: string; max?: number; width?: number | string }) {
  const uid = useId().replace(/:/g, '');
  if (values.length < 2) return <svg className="spark" style={{ width }} viewBox="0 0 100 28" />;
  const pts: [number, number][] = values.map((v, i) => [(i / (values.length - 1)) * 100, 25 - (Math.min(v, max) / max) * 22]);
  const d = smooth(pts);
  return (
    <svg className="spark" style={{ width }} viewBox="0 0 100 28" preserveAspectRatio="none">
      <defs>
        <linearGradient id={uid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity={0.3} />
          <stop offset="1" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={`${d}L100,28L0,28Z`} fill={`url(#${uid})`} />
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// ---------- radial gauge ----------
const polar = (cx: number, cy: number, r: number, deg: number): [number, number] => [cx + r * Math.cos((deg * Math.PI) / 180), cy + r * Math.sin((deg * Math.PI) / 180)];
function arc(cx: number, cy: number, r: number, from: number, to: number): string {
  const [x0, y0] = polar(cx, cy, r, from);
  const [x1, y1] = polar(cx, cy, r, to);
  return `M${x0.toFixed(2)},${y0.toFixed(2)}A${r},${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x1.toFixed(2)},${y1.toFixed(2)}`;
}

/** 270° radial gauge. `value` is 0-100. */
export function Gauge({ value, label, sub, size = 132, invert }: { value: number | null | undefined; label: string; sub?: ReactNode; size?: number; invert?: boolean }) {
  const v = value == null ? 0 : Math.max(0, Math.min(100, value));
  const bad = invert ? v < 40 : v >= 90;
  const warn = invert ? v < 70 : v >= 75;
  const color = value == null ? 'var(--line-strong)' : bad ? 'var(--bad)' : warn ? 'var(--warn)' : 'var(--ok)';
  const R = 44;
  const end = 135 + (270 * v) / 100;
  return (
    <div className="gauge" style={{ width: '100%', maxWidth: size }}>
      <svg viewBox="0 0 110 100" style={{ width: '100%', height: 'auto' }}>
        <path d={arc(55, 55, R, 135, 405)} fill="none" stroke="var(--line)" strokeWidth={9} strokeLinecap="round" />
        {v > 0.5 && <path d={arc(55, 55, R, 135, end)} fill="none" stroke={color} strokeWidth={9} strokeLinecap="round" />}
        <text x="55" y="58" textAnchor="middle" className="g-val">{value == null ? '–' : Math.round(v)}<tspan className="g-unit">%</tspan></text>
        <text x="55" y="74" textAnchor="middle" className="g-label">{label}</text>
      </svg>
      {sub && <div className="g-sub">{sub}</div>}
    </div>
  );
}

// ---------- donut ----------
export interface Slice {
  label: string;
  value: number;
  color: string;
}

export function Donut({ slices, center, caption, size = 150 }: { slices: Slice[]; center: ReactNode; caption?: string; size?: number }) {
  const total = slices.reduce((s, x) => s + x.value, 0);
  const R = 38;
  const C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 100 100" width={size} height={size} role="img">
        <circle cx="50" cy="50" r={R} fill="none" stroke="var(--line)" strokeWidth={11} />
        {total > 0 &&
          slices
            .filter((s) => s.value > 0)
            .map((s) => {
              const len = (s.value / total) * C;
              const gap = slices.filter((x) => x.value > 0).length > 1 ? 1.6 : 0;
              const el = (
                <circle key={s.label} cx="50" cy="50" r={R} fill="none" stroke={s.color} strokeWidth={11} strokeDasharray={`${Math.max(0, len - gap)} ${C}`} strokeDashoffset={-offset} transform="rotate(-90 50 50)" />
              );
              offset += len;
              return el;
            })}
        <text x="50" y={caption ? 51 : 56} textAnchor="middle" className="d-val">{center}</text>
        {caption && <text x="50" y="64" textAnchor="middle" className="d-cap">{caption}</text>}
      </svg>
      <ul className="legend">
        {slices.map((s) => (
          <li key={s.label}>
            <i style={{ background: s.color }} />
            <span className="grow">{s.label}</span>
            <b className="num">{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------- stacked column chart (e.g. events per hour) ----------
export interface Column {
  label: string;
  parts: { value: number; color: string; name: string }[];
}

export function Columns({ cols, height = 120 }: { cols: Column[]; height?: number }) {
  const max = Math.max(1, ...cols.map((c) => c.parts.reduce((s, p) => s + p.value, 0)));
  return (
    <div>
      <div className="columns" style={{ height }}>
        {cols.map((c, i) => {
          const total = c.parts.reduce((s, p) => s + p.value, 0);
          return (
            <div key={i} className="col" title={`${c.label}: ${c.parts.map((p) => `${p.name} ${p.value}`).join(', ')}`}>
              <div className="stack" style={{ height: `${(total / max) * 100}%` }}>
                {c.parts.filter((p) => p.value > 0).map((p) => (
                  <i key={p.name} style={{ flex: p.value, background: p.color }} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <div className="xaxis" style={{ position: 'static', marginTop: 6 }}>
        <span>{cols[0]?.label}</span>
        <span>{cols[Math.floor(cols.length / 2)]?.label}</span>
        <span>{cols[cols.length - 1]?.label}</span>
      </div>
    </div>
  );
}

// ---------- horizontal bars ----------
export function HBars({ rows, format = (v) => `${v.toFixed(0)}%`, max = 100, thresholds = true }: { rows: { label: ReactNode; value: number; sub?: string }[]; format?: (v: number) => string; max?: number; thresholds?: boolean }) {
  return (
    <div className="hbars">
      {rows.map((r, i) => {
        const tone = !thresholds ? '' : r.value >= 90 ? 'bad' : r.value >= 75 ? 'warn' : '';
        return (
          <div key={i} className="hbar">
            <div className="row spread">
              <span className="lbl">{r.label}</span>
              <span className="num">{format(r.value)}</span>
            </div>
            <div className="bar"><i className={tone} style={{ width: `${Math.min(100, (r.value / max) * 100)}%` }} /></div>
            {r.sub && <div className="muted" style={{ fontSize: 11.5 }}>{r.sub}</div>}
          </div>
        );
      })}
    </div>
  );
}

/** Stacked horizontal bar per row (severity split per host). */
export function StackedBars({ rows }: { rows: { label: ReactNode; parts: { value: number; color: string; name: string }[] }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.parts.reduce((s, p) => s + p.value, 0)));
  return (
    <div className="hbars">
      {rows.map((r, i) => {
        const total = r.parts.reduce((s, p) => s + p.value, 0);
        return (
          <div key={i} className="hbar">
            <div className="row spread">
              <span className="lbl">{r.label}</span>
              <span className="num muted">{total}</span>
            </div>
            <div className="bar stackedbar" style={{ background: 'var(--line)' }}>
              <div style={{ display: 'flex', width: `${(total / max) * 100}%`, height: '100%' }}>
                {r.parts.filter((p) => p.value > 0).map((p) => (
                  <i key={p.name} title={`${p.name}: ${p.value}`} style={{ flex: p.value, background: p.color }} />
                ))}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
