import { AlertTriangle, Info } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { SimActionResult, SimPlaneResult, SimulateResult } from "@/lib/api";

/**
 * The simulator's per-action verdict table (AWS Policy Simulator's results grid): one row per action with
 * its net decision, the plane that decided, whether a REAL enforcement path produced it, and the reason.
 * Data-plane actions expand to show BOTH planes — so a control-plane "allowed" that a data-plane Deny
 * would still block is visible here, before the click. The returned `warnings`/`limitations` are surfaced
 * verbatim underneath: this tool reports what the engine can honestly evaluate, and says what it can't.
 */

type DecisionMeta = {
  variant: "success" | "destructive" | "warning" | "muted";
  label: string;
};

function decisionMeta(decision: string): DecisionMeta {
  switch (decision) {
    case "allow":
      return { variant: "success", label: "Allowed" };
    case "deny":
      return { variant: "destructive", label: "Denied" };
    case "not-governed":
      return { variant: "muted", label: "Not governed" };
    case "indeterminate":
      return { variant: "warning", label: "Indeterminate" };
    default:
      return { variant: "muted", label: decision || "Unknown" };
  }
}

function planeLabel(plane: string): { variant: "accent" | "default" | "muted"; label: string } {
  switch (plane) {
    case "control":
      return { variant: "accent", label: "Control plane" };
    case "data":
      return { variant: "default", label: "Data plane" };
    default:
      return { variant: "muted", label: "Unknown" };
  }
}

function DecisionBadge({ decision }: { decision: string }) {
  const m = decisionMeta(decision);
  return <Badge variant={m.variant}>{m.label}</Badge>;
}

/** One plane's sub-verdict, indented under the row's reason. */
function PlaneRow({ label, plane }: { label: string; plane: SimPlaneResult }) {
  const m = decisionMeta(plane.decision);
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
      <span className="w-24 shrink-0 text-muted-foreground">{label}</span>
      <span
        className={[
          "font-medium",
          m.variant === "success"
            ? "text-success"
            : m.variant === "destructive"
              ? "text-destructive"
              : m.variant === "warning"
                ? "text-warning"
                : "text-muted-foreground",
        ].join(" ")}
      >
        {m.label}
      </span>
      {plane.governed === false ? (
        <span className="text-muted-foreground">(no policy governs this service)</span>
      ) : null}
      <span className="min-w-0 basis-full text-muted-foreground">{plane.reason}</span>
    </div>
  );
}

function ResultRow({ r }: { r: SimActionResult }) {
  const plane = planeLabel(r.plane);
  const hasBothPlanes = Boolean(r.controlPlane && r.dataPlane);
  return (
    <tr className="border-b align-top last:border-0">
      <td className="p-3">
        <code className="text-xs font-medium text-foreground">{r.action}</code>
      </td>
      <td className="p-3">
        <Badge variant={plane.variant}>{plane.label}</Badge>
      </td>
      <td className="p-3">
        <DecisionBadge decision={r.decision} />
      </td>
      <td className="p-3">
        {r.enforced ? (
          <span className="text-xs text-muted-foreground">Enforced</span>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs text-warning">
            <AlertTriangle className="size-3" /> Not enforced
          </span>
        )}
      </td>
      <td className="p-3">
        <p className="text-xs text-foreground/90">{r.reason}</p>
        {hasBothPlanes ? (
          <div className="mt-1.5 space-y-1 border-l-2 border-border pl-2">
            {r.controlPlane ? <PlaneRow label="Control plane" plane={r.controlPlane} /> : null}
            {r.dataPlane ? <PlaneRow label="Data plane" plane={r.dataPlane} /> : null}
          </div>
        ) : null}
      </td>
    </tr>
  );
}

export function ResultTable({ result }: { result: SimulateResult }) {
  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Action</th>
                  <th className="p-3 font-medium">Plane</th>
                  <th className="p-3 font-medium">Decision</th>
                  <th className="p-3 font-medium">Evaluation</th>
                  <th className="p-3 font-medium">Reason</th>
                </tr>
              </thead>
              <tbody>
                {result.results.map((r) => (
                  <ResultRow key={r.action} r={r} />
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {result.warnings.length > 0 ? (
        <div className="space-y-2 rounded-md border border-warning/40 bg-warning/10 p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-warning">
            <AlertTriangle className="size-3.5" /> Warnings
          </p>
          <ul className="list-disc space-y-1 pl-5 text-xs text-foreground/90">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {result.limitations.length > 0 ? (
        <div className="space-y-2 rounded-md border border-border bg-secondary p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
            <Info className="size-3.5 text-primary" /> Simulator limitations
          </p>
          <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
            {result.limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
