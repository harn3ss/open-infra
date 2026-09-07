import { useMemo } from "react";
import type { JobMetricSeries } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * A tiny dependency-free time-series line chart (inline SVG), used by the SageMaker-style
 * job Metrics tab. Draws one or more series on a shared axis with value/time ticks and a
 * unit-aware Y label. Purely presentational — it draws whatever points it's given and never
 * fabricates data; the caller handles the `{ available:false }` empty state.
 */

// Distinct, theme-token colors for up to a few overlaid series.
const SERIES_COLORS = [
  "hsl(var(--primary))",
  "hsl(var(--accent))",
  "hsl(var(--success))",
  "hsl(var(--muted-foreground))",
];

// Internal coordinate space; the SVG scales uniformly to its container width.
const W = 720;
const H = 220;
const PAD = { top: 14, right: 18, bottom: 26, left: 60 };

function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function formatValue(v: number, unit: string): string {
  switch (unit) {
    case "bytes":
      return formatBytes(v);
    case "percent":
      return `${Math.round(v)}%`;
    case "cores":
      return v >= 10 ? v.toFixed(0) : v.toFixed(2);
    default:
      return Number.isInteger(v) ? String(v) : v.toFixed(2);
  }
}

function formatTime(tsSeconds: number): string {
  const d = new Date(tsSeconds * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** "nice" upper bound so the top gridline lands on a round-ish number. */
function niceMax(max: number): number {
  if (max <= 0) return 1;
  const exp = Math.floor(Math.log10(max));
  const base = Math.pow(10, exp);
  const frac = max / base;
  const nice = frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10;
  return nice * base;
}

export function MetricChart({
  series,
  title,
  className,
  height = H,
}: {
  /** A single series or several to overlay on one axis (assumed to share a unit). */
  series: JobMetricSeries | JobMetricSeries[];
  /** Optional heading shown top-left (e.g. the metric name). */
  title?: string;
  className?: string;
  /** Rendered pixel height; the width is always 100% of the container. */
  height?: number;
}) {
  const list = useMemo(() => (Array.isArray(series) ? series : [series]), [series]);
  const unit = list[0]?.unit ?? "";

  const model = useMemo(() => {
    const withPoints = list.filter((s) => s.points.length > 0);
    if (withPoints.length === 0) return null;

    let xMin = Infinity;
    let xMax = -Infinity;
    let yMax = -Infinity;
    for (const s of withPoints) {
      for (const [t, v] of s.points) {
        if (t < xMin) xMin = t;
        if (t > xMax) xMax = t;
        if (v > yMax) yMax = v;
      }
    }
    if (!Number.isFinite(xMin) || !Number.isFinite(xMax)) return null;
    const topY = niceMax(yMax > 0 ? yMax : 0);
    const xSpan = xMax - xMin || 1;

    const sx = (t: number) =>
      PAD.left + ((t - xMin) / xSpan) * (W - PAD.left - PAD.right);
    const sy = (v: number) =>
      height - PAD.bottom - (v / topY) * (height - PAD.top - PAD.bottom);

    return { withPoints, xMin, xMax, topY, sx, sy };
  }, [list, height]);

  if (!model) {
    return (
      <div
        className={cn(
          "flex items-center justify-center rounded-md border border-dashed border-border text-xs text-muted-foreground",
          className,
        )}
        style={{ height }}
      >
        No data points yet.
      </div>
    );
  }

  const { withPoints, xMin, xMax, topY, sx, sy } = model;

  // Y ticks: 0, ¼, ½, ¾, top.
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * topY);
  // X ticks: start, middle, end.
  const xTicks = [xMin, (xMin + xMax) / 2, xMax];

  return (
    <figure className={cn("m-0", className)}>
      {(title || withPoints.length > 1) && (
        <figcaption className="mb-1 flex flex-wrap items-center gap-x-4 gap-y-1">
          {title ? <span className="text-sm font-medium">{title}</span> : null}
          {withPoints.length > 1 ? (
            <span className="flex flex-wrap items-center gap-3">
              {withPoints.map((s, i) => (
                <span key={s.name} className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span
                    className="inline-block size-2 rounded-full"
                    style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }}
                  />
                  {s.name}
                </span>
              ))}
            </span>
          ) : null}
        </figcaption>
      )}
      <svg
        viewBox={`0 0 ${W} ${height}`}
        className="w-full"
        style={{ height }}
        role="img"
        aria-label={title ? `${title} time series` : "metric time series"}
      >
        {/* Horizontal gridlines + Y tick labels */}
        {yTicks.map((v, i) => {
          const y = sy(v);
          return (
            <g key={`y${i}`}>
              <line
                x1={PAD.left}
                x2={W - PAD.right}
                y1={y}
                y2={y}
                stroke="hsl(var(--border))"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
              <text
                x={PAD.left - 6}
                y={y}
                textAnchor="end"
                dominantBaseline="middle"
                fontSize={11}
                fill="hsl(var(--muted-foreground))"
              >
                {formatValue(v, unit)}
              </text>
            </g>
          );
        })}

        {/* X tick labels */}
        {xTicks.map((t, i) => {
          const x = sx(t);
          const anchor = i === 0 ? "start" : i === xTicks.length - 1 ? "end" : "middle";
          return (
            <text
              key={`x${i}`}
              x={x}
              y={height - PAD.bottom + 16}
              textAnchor={anchor}
              fontSize={11}
              fill="hsl(var(--muted-foreground))"
            >
              {formatTime(t)}
            </text>
          );
        })}

        {/* Series */}
        {withPoints.map((s, i) => {
          const color = SERIES_COLORS[i % SERIES_COLORS.length];
          const p0 = s.points[0];
          if (s.points.length === 1 && p0) {
            const [t, v] = p0;
            return <circle key={s.name} cx={sx(t)} cy={sy(v)} r={2.5} fill={color} />;
          }
          const d = s.points.map(([t, v]) => `${sx(t)},${sy(v)}`).join(" ");
          return (
            <polyline
              key={s.name}
              points={d}
              fill="none"
              stroke={color}
              strokeWidth={1.75}
              strokeLinejoin="round"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          );
        })}
      </svg>
      {unit ? (
        <figcaption className="mt-0.5 text-right text-[11px] text-muted-foreground">
          {unit}
        </figcaption>
      ) : null}
    </figure>
  );
}
