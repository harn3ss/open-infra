import { AlertTriangle, Ban, Plus, ShieldAlert, Trash2 } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";

// A permission row is one resource + the verbs allowed on it. It maps to a set of
// "<resource>:<verb>" actions in a single Allow statement — the shape kind: Policy takes.
export interface PermRow {
  resource: string;
  verbs: string[];
}

// The canonical control-plane verb set. rowsToActions/actionsToRows use THIS list to decide when a
// row collapses to "<resource>:*", so it must stay the source of truth even when the UI is driven by
// the BFF's /iam/config policyVerbs (which is this same set plus "*").
const VERBS = ["Get", "List", "Watch", "Create", "Update", "Patch", "Delete"];

// rowsToActions flattens the editor into policy actions. A row with all verbs collapses to
// "<resource>:*"; an empty row is skipped.
export function rowsToActions(rows: PermRow[]): string[] {
  const out: string[] = [];
  for (const r of rows) {
    if (!r.resource || r.verbs.length === 0) continue;
    if (r.verbs.includes("*") || r.verbs.length === VERBS.length) {
      out.push(`${r.resource}:*`);
    } else {
      for (const v of r.verbs) out.push(`${r.resource}:${v}`);
    }
  }
  return out;
}

// actionsToRows is the inverse, for editing an existing policy. Groups actions by resource.
export function actionsToRows(actions: string[]): PermRow[] {
  const byRes = new Map<string, Set<string>>();
  for (const a of actions) {
    const [res, verb] = a.split(":");
    if (!res || !verb) continue;
    if (!byRes.has(res)) byRes.set(res, new Set());
    byRes.get(res)!.add(verb === "*" ? "*" : verb);
  }
  return [...byRes.entries()].map(([resource, set]) => ({
    resource,
    verbs: set.has("*") ? [...VERBS] : [...set],
  }));
}

// ── Access-level grouping (mirrors user-permissions-tab.tsx levelForVerb + permissions-summary.tsx) ──
//
// The control plane is grouped by the same AWS-style access levels as the data-plane Cedar editor, so
// the two planes read as one editor. Kubernetes RBAC has no escalation verbs a Policy may name
// (bind/escalate/impersonate are excluded by the platform boundary), so "Permissions management" is
// always empty here — surfaced honestly rather than hidden.

export type ControlAccessLevel = "List" | "Read" | "Write" | "Delete" | "Permissions management";

export const CONTROL_ACCESS_LEVELS: readonly ControlAccessLevel[] = [
  "List",
  "Read",
  "Write",
  "Delete",
  "Permissions management",
] as const;

export function controlLevelForVerb(verb: string): ControlAccessLevel {
  const v = verb.toLowerCase();
  if (v === "list" || v === "watch") return "List";
  if (v === "get") return "Read";
  if (v === "create" || v === "update" || v === "patch") return "Write";
  if (v === "delete" || v === "deletecollection") return "Delete";
  if (v === "bind" || v === "escalate" || v === "impersonate") return "Permissions management";
  return "Write";
}

/**
 * The control-plane (platform) permission editor — AWS's visual policy editor grammar applied to the
 * Kubernetes RBAC vocabulary, mirroring the data-plane {@link CedarBlockEditor}. Each openinfra.dev
 * resource is ONE permission block: Select a resource → Actions grouped by access level → Resources →
 * (Deny/conditions honestly disabled). Emits into a Policy's spec.statements via {@link rowsToActions}.
 *
 * The honest deviations from AWS are preserved, not hidden: RBAC is Allow-only (no Deny), unconditional
 * (no request conditions), and unscoped (a rule always applies to every resource of the kind). Where AWS
 * offers those affordances the block shows them disabled with the reason, so the two planes stay
 * structurally identical while staying truthful about what each can enforce.
 */
export function PermissionEditor({
  resources,
  rows,
  verbs = VERBS,
  onChange,
}: {
  /** openinfra.dev resources selectable on the control plane (the permission boundary). */
  resources: string[];
  rows: PermRow[];
  /** The verb vocabulary (from /iam/config policyVerbs, minus "*"). Defaults to the canonical set. */
  verbs?: string[];
  onChange: (rows: PermRow[]) => void;
}) {
  const setRow = (i: number, patch: Partial<PermRow>) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = () => onChange([...rows, { resource: "", verbs: [] }]);
  const remove = (i: number) => onChange(rows.filter((_, j) => j !== i));

  return (
    <div className="space-y-3">
      {rows.length === 0 ? (
        <p className="rounded-md border border-dashed border-border p-3 text-xs text-muted-foreground">
          No platform permissions. Add one to grant actions over an openinfra.dev resource (compiled to
          a Kubernetes ClusterRole).
        </p>
      ) : null}

      {rows.map((row, i) => (
        <ControlBlock
          key={i}
          row={row}
          resources={resources}
          verbs={verbs}
          onChange={(r) => setRow(i, r)}
          onRemove={() => remove(i)}
        />
      ))}

      <Button variant="outline" size="sm" onClick={add}>
        <Plus className="size-3.5" /> Add more permissions
      </Button>
    </div>
  );
}

/** One AWS-style platform permission block: a single openinfra.dev resource and the verbs allowed on it. */
function ControlBlock({
  row,
  resources,
  verbs,
  onChange,
  onRemove,
}: {
  row: PermRow;
  resources: string[];
  verbs: string[];
  onChange: (r: PermRow) => void;
  onRemove: () => void;
}) {
  const options = ["*", ...resources];
  const resourceLabel = !row.resource
    ? "resource"
    : row.resource === "*"
      ? "openinfra.dev resource"
      : row.resource;

  const allActions = verbs.length > 0 && verbs.every((v) => row.verbs.includes(v));
  const selectedCount = allActions ? verbs.length : row.verbs.length;

  const toggleVerb = (v: string) => {
    const on = row.verbs.includes(v);
    onChange({ ...row, verbs: on ? row.verbs.filter((x) => x !== v) : [...row.verbs, v] });
  };
  const toggleLevel = (levelVerbs: string[]) => {
    const allOn = levelVerbs.every((v) => row.verbs.includes(v));
    onChange({
      ...row,
      verbs: allOn
        ? row.verbs.filter((v) => !levelVerbs.includes(v))
        : [...new Set([...row.verbs, ...levelVerbs])],
    });
  };
  const setAll = (on: boolean) => onChange({ ...row, verbs: on ? [...verbs] : [] });

  // Group the available verbs by access level, keeping EVERY level (incl. the empty
  // Permissions-management group, which is a deliberate boundary note).
  const groups = CONTROL_ACCESS_LEVELS.map((level) => ({
    level,
    verbs: verbs.filter((v) => controlLevelForVerb(v) === level),
  }));

  return (
    <div className="rounded-lg border border-border">
      {/* Block header: resource + effect + remove — same layout as the data-plane block. */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/30 p-3">
        <span className="text-xs font-medium text-muted-foreground">Resource</span>
        <Select value={row.resource} onValueChange={(v) => onChange({ ...row, resource: v })}>
          <SelectTrigger className="h-8 w-56 text-xs">
            <SelectValue placeholder="Select a resource" />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o} value={o}>
                {o === "*" ? "All openinfra.dev resources (*)" : o}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Allow / Deny — Deny is disabled: RBAC is additive and cannot Deny. Honest, not hidden. */}
        <div
          className="ml-2 inline-flex overflow-hidden rounded-md border border-border"
          title="Kubernetes RBAC is additive: a platform permission can only Allow. For an explicit Deny, use a data-service block."
        >
          <span className="bg-success/15 px-2.5 py-1 text-xs font-medium text-success">Allow</span>
          <span className="inline-flex cursor-not-allowed items-center gap-1 px-2.5 py-1 text-xs font-medium text-muted-foreground/50">
            <Ban className="size-3" /> Deny
          </span>
        </div>

        <span className="ml-2 text-xs text-muted-foreground">Kubernetes RBAC (control plane)</span>

        <Button variant="ghost" size="sm" className="ml-auto text-destructive" onClick={onRemove}>
          <Trash2 className="size-3.5" /> Remove
        </Button>
      </div>

      <div className="space-y-4 p-3">
        {/* 1. Actions allowed — grouped by access level, mirroring the Cedar block. */}
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold">
              Actions allowed
              <span className="ml-2 font-normal text-muted-foreground">{selectedCount} selected</span>
            </h4>
            <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                className="size-3.5 accent-[hsl(var(--primary))]"
                checked={allActions}
                onChange={(e) => setAll(e.target.checked)}
              />
              All {resourceLabel} actions ({row.resource || "resource"}:*)
            </label>
          </div>

          {allActions ? (
            <p className="rounded-md border border-warning/40 bg-warning/10 px-2.5 py-1.5 text-xs text-warning">
              <AlertTriangle className="mr-1 inline size-3.5" />
              Grants every verb on {resourceLabel}. Prefer selecting only the access levels you need.
            </p>
          ) : (
            <div className="space-y-2">
              {groups.map((g) => {
                if (g.verbs.length === 0) {
                  // The always-empty Permissions-management group is a boundary honesty note.
                  if (g.level !== "Permissions management") return null;
                  return (
                    <div
                      key={g.level}
                      className="flex items-start gap-1.5 rounded-md border border-dashed border-border/70 px-2.5 py-1.5 text-[11px] text-muted-foreground"
                    >
                      <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
                      <span>
                        <span className="font-medium">Permissions management</span> — none. RBAC
                        escalation verbs (bind, escalate, impersonate) are excluded from Policies by the
                        platform boundary, so no policy can escalate a principal.
                      </span>
                    </div>
                  );
                }
                const allOn = g.verbs.every((v) => row.verbs.includes(v));
                const onCount = g.verbs.filter((v) => row.verbs.includes(v)).length;
                return (
                  <div key={g.level} className="rounded-md border border-border/70">
                    <div className="flex items-center justify-between border-b border-border/70 bg-muted/20 px-2.5 py-1.5">
                      <label className="flex cursor-pointer items-center gap-1.5 text-xs font-medium">
                        <input
                          type="checkbox"
                          className="size-3.5 accent-[hsl(var(--primary))]"
                          checked={allOn}
                          onChange={() => toggleLevel(g.verbs)}
                        />
                        {g.level}
                      </label>
                      <span className="text-[11px] text-muted-foreground">
                        {onCount}/{g.verbs.length}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 gap-x-4 gap-y-1 p-2 sm:grid-cols-2">
                      {g.verbs.map((v) => (
                        <label key={v} className="flex cursor-pointer items-center gap-1.5 text-xs">
                          <input
                            type="checkbox"
                            className="size-3.5 accent-[hsl(var(--primary))]"
                            checked={row.verbs.includes(v)}
                            onChange={() => toggleVerb(v)}
                          />
                          <span className="font-medium">{v}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 2. Resources — honestly fixed to "all of the kind": RBAC cannot scope list/watch by name. */}
        <section className="space-y-2">
          <h4 className="text-xs font-semibold">Resources</h4>
          <label className="flex cursor-not-allowed items-center gap-1.5 text-xs text-muted-foreground">
            <input
              type="radio"
              className="size-3.5 accent-[hsl(var(--primary))]"
              checked
              readOnly
              disabled
            />
            All {resourceLabel} in the cluster
          </label>
          <p className="text-[11px] text-muted-foreground">
            Kubernetes RBAC cannot scope a control-plane rule to a named resource, so a platform
            permission always applies to every resource of the kind. Use a data-service block to scope to
            specific resources.
          </p>
        </section>

        {/* 3. Request conditions — not enforceable on the control plane. Same slot as the Cedar block. */}
        <section className="space-y-1">
          <h4 className="text-xs font-semibold text-muted-foreground">
            Request conditions <span className="font-normal">- not supported</span>
          </h4>
          <p className="text-[11px] text-muted-foreground">
            RBAC evaluates no request context, so conditions (source IP, authenticated, …) cannot apply
            here. Author a data-service block for conditional access.
          </p>
        </section>
      </div>
    </div>
  );
}
