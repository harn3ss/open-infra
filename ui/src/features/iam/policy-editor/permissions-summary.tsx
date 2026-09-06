import { Badge } from "@/components/ui/badge";
import { CEDAR_SERVICES, serviceByName } from "@/lib/iam-cedar-vocab";
import type { PolicyDoc } from "./model";

/**
 * AWS's permissions-summary table, reproduced for the Policy CR. One row per service, columns
 * Access level / Resource / Request condition — the information-dense read of what a policy grants,
 * across both planes (control-plane RBAC and data-plane Cedar). Used on the policy detail page and as
 * the editor's live "what this grants" panel.
 */

const CONTROL_VERB_LEVEL: Record<string, string> = {
  Get: "Read",
  Watch: "Read",
  List: "List",
  Create: "Write",
  Update: "Write",
  Patch: "Write",
  Delete: "Delete",
  Bind: "Permissions management",
  Escalate: "Permissions management",
  Impersonate: "Permissions management",
};

const LEVEL_ORDER = ["List", "Read", "Write", "Delete", "Tagging", "Permissions management"];

function levelTone(level: string): "muted" | "warning" {
  return level === "Permissions management" ? "warning" : "muted";
}

function sortLevels(levels: Set<string>): string[] {
  return [...levels].sort((a, b) => {
    const ia = LEVEL_ORDER.indexOf(a);
    const ib = LEVEL_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
}

interface SummaryRow {
  service: string;
  plane: "Platform (control plane)" | "Data service";
  effect?: "Allow" | "Deny";
  levels: string[];
  resource: string;
  condition: string;
}

function controlLevel(verb: string): string {
  if (verb === "*") return "Full access";
  return CONTROL_VERB_LEVEL[verb] ?? "Other";
}

/** Access levels covered by a data action string (handles "<svc>:*" and "*"). */
function dataLevels(service: string, actions: string[]): Set<string> {
  const svc = serviceByName(service);
  const out = new Set<string>();
  if (!svc) return out;
  const all = actions.includes("*") || actions.includes(`${service}:*`);
  for (const a of svc.actions) {
    if (all || actions.includes(a.action)) out.add(a.level);
  }
  return out;
}

function buildRows(doc: PolicyDoc): SummaryRow[] {
  const rows: SummaryRow[] = [];

  // Control plane: group actions by resource (the openinfra.dev kind).
  const controlActions = (doc.statements ?? []).flatMap((s) => s.actions ?? []);
  const byResource = new Map<string, Set<string>>();
  for (const a of controlActions) {
    const [res, verb] = a.split(":");
    if (!res || !verb) continue;
    if (!byResource.has(res)) byResource.set(res, new Set());
    byResource.get(res)!.add(controlLevel(verb));
  }
  for (const [res, levels] of byResource) {
    rows.push({
      service: res === "*" ? "All platform resources" : res,
      plane: "Platform (control plane)",
      effect: "Allow",
      levels: sortLevels(levels),
      resource: "All (RBAC cannot scope list/watch by name)",
      condition: "—",
    });
  }

  // Data plane: one row per statement.
  for (const st of doc.dataPlane?.statements ?? []) {
    const svcName = firstService(st.actions ?? []);
    const svc = serviceByName(svcName);
    const levels = sortLevels(dataLevels(svcName, st.actions ?? []));
    const resource =
      !st.resources || st.resources.length === 0 || st.resources.includes("*")
        ? `Any ${svc?.resourceLabel ?? "resource"}`
        : st.resources.join(", ");
    const condition = st.condition
      ? Object.entries(st.condition)
          .map(([k, v]) => `${k}=${v}`)
          .join(", ") || "—"
      : "—";
    rows.push({
      service: svc?.label ?? svcName,
      plane: "Data service",
      effect: st.effect,
      levels: levels.length ? levels : ["Full access"],
      resource,
      condition,
    });
  }

  return rows;
}

function firstService(actions: string[]): string {
  for (const a of actions) {
    const i = a.indexOf(":");
    if (i > 0) {
      const svc = a.slice(0, i);
      if (serviceByName(svc)) return svc;
    }
  }
  return CEDAR_SERVICES[0]?.service ?? "s3";
}

export function PermissionsSummary({ doc }: { doc: PolicyDoc }) {
  const rows = buildRows(doc);

  if (rows.length === 0) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        This policy grants nothing — it has no platform permissions and no data-service statements.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="p-3 font-medium">Service</th>
            <th className="p-3 font-medium">Effect</th>
            <th className="p-3 font-medium">Access level</th>
            <th className="p-3 font-medium">Resource</th>
            <th className="p-3 font-medium">Request condition</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b last:border-0 align-top">
              <td className="p-3">
                <div className="font-medium">{r.service}</div>
                <div className="text-[11px] text-muted-foreground">{r.plane}</div>
              </td>
              <td className="p-3">
                {r.effect ? (
                  <Badge variant={r.effect === "Deny" ? "destructive" : "success"}>{r.effect}</Badge>
                ) : (
                  "—"
                )}
              </td>
              <td className="p-3">
                <div className="flex flex-wrap gap-1">
                  {r.levels.map((l) => (
                    <Badge key={l} variant={levelTone(l)}>
                      {l}
                    </Badge>
                  ))}
                </div>
              </td>
              <td className="p-3 text-muted-foreground">{r.resource}</td>
              <td className="p-3 text-muted-foreground">
                {r.condition === "—" ? "—" : <code className="text-xs">{r.condition}</code>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
