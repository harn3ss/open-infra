import { Activity, CheckCircle2, CircleAlert, CircleX } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { nodeReady } from "@/features/nodes/node-utils";
import { applicationHealth } from "@/features/applications/application-status";
import type { Application, Deployment, Node, Pod } from "@/types/k8s";

interface HealthRow {
  label: string;
  healthy: number;
  total: number;
}

function tone(row: HealthRow): "success" | "warning" | "destructive" {
  if (row.total === 0) return "success";
  if (row.healthy === row.total) return "success";
  if (row.healthy >= row.total * 0.7) return "warning";
  return "destructive";
}

function HealthBar({ row }: { row: HealthRow }) {
  const pct = row.total === 0 ? 100 : Math.round((row.healthy / row.total) * 100);
  const t = tone(row);
  const barColor =
    t === "success" ? "bg-success" : t === "warning" ? "bg-warning" : "bg-destructive";
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{row.label}</span>
        <span className="text-muted-foreground tabular-nums">
          {row.healthy}/{row.total} healthy
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-secondary">
        <div
          className={cn("h-full rounded-full transition-all", barColor)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

export function HealthPanel({
  pods,
  nodes,
  deployments,
  applications,
}: {
  pods: Pod[];
  nodes: Node[];
  deployments: Deployment[];
  applications: Application[];
}) {
  const podsHealthy = pods.filter((p) => {
    const phase = p.status?.phase;
    return phase === "Running" || phase === "Succeeded";
  }).length;

  const nodesHealthy = nodes.filter((n) => nodeReady(n).ready).length;

  const deploymentsHealthy = deployments.filter((d) => {
    const ready = d.status?.readyReplicas ?? 0;
    const desired = d.spec?.replicas ?? 0;
    return desired === 0 || ready >= desired;
  }).length;

  const appsHealthy = applications.filter(
    (a) => applicationHealth(a).tone === "success",
  ).length;

  const rows: HealthRow[] = [
    { label: "Applications", healthy: appsHealthy, total: applications.length },
    { label: "Deployments", healthy: deploymentsHealthy, total: deployments.length },
    { label: "Pods", healthy: podsHealthy, total: pods.length },
    { label: "Nodes", healthy: nodesHealthy, total: nodes.length },
  ];

  // Overall posture from the worst row.
  const worst = rows.reduce<"success" | "warning" | "destructive">(
    (acc, r) => {
      const t = tone(r);
      if (acc === "destructive" || t === "destructive") return "destructive";
      if (acc === "warning" || t === "warning") return "warning";
      return "success";
    },
    "success",
  );

  const overall = {
    success: {
      label: "All systems healthy",
      icon: CheckCircle2,
      className: "bg-success/10 text-success",
    },
    warning: {
      label: "Degraded — some workloads need attention",
      icon: CircleAlert,
      className: "bg-warning/10 text-warning",
    },
    destructive: {
      label: "Unhealthy — multiple failures detected",
      icon: CircleX,
      className: "bg-destructive/10 text-destructive",
    },
  }[worst];

  const OverallIcon = overall.icon;

  return (
    <Card className="h-full">
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Cluster health</CardTitle>
        <Activity className="size-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="space-y-5">
        <div
          className={cn(
            "flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium",
            overall.className,
          )}
        >
          <OverallIcon className="size-5 shrink-0" />
          {overall.label}
        </div>
        <div className="space-y-4">
          {rows.map((row) => (
            <HealthBar key={row.label} row={row} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
