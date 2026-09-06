import { useState } from "react";
import { AlertTriangle, Plus, X } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  actionsByLevel,
  CEDAR_SERVICES,
  serviceByName,
  type CedarAction,
} from "@/lib/iam-cedar-vocab";

/**
 * The AWS Policy Simulator / visual-editor action picker: choose a "service" — either an openinfra.dev
 * product resource (control plane, emits "<resource>:<verb>") or a governed data service (S3/DynamoDB/
 * Lambda, emits "s3:GetObject") — then tick the actions to test, grouped by AWS-style access level. The
 * selected set persists across service switches, so a single simulation can span both planes. The picker
 * owns the full `actions[]` list through `onChange`.
 */

// Control-plane k8s verbs → AWS-style access level (a superset of the data-plane ACCESS_LEVELS, adding
// "Delete" for k8s and keeping Permissions management for bind/escalate/impersonate). Unknown verbs fall
// into "Other" rather than being hidden.
const CP_LEVEL_ORDER = ["List", "Read", "Write", "Delete", "Permissions management", "Other"] as const;
const CP_VERB_LEVEL: Record<string, string> = {
  list: "List",
  watch: "List",
  get: "Read",
  create: "Write",
  update: "Write",
  patch: "Write",
  delete: "Delete",
  deletecollection: "Delete",
  bind: "Permissions management",
  escalate: "Permissions management",
  impersonate: "Permissions management",
};
function cpLevel(verb: string): string {
  return CP_VERB_LEVEL[verb.toLowerCase()] ?? "Other";
}

interface LevelGroup {
  level: string;
  /** { action: full string emitted, name: label, description?, approximate? } */
  actions: { action: string; name: string; description?: string; approximate?: boolean }[];
}

/** Build the access-level groups for the currently-viewed service. */
function groupsForService(svc: string, policyVerbs: string[]): LevelGroup[] {
  if (svc.startsWith("cp:")) {
    const resource = svc.slice(3);
    const byLevel = new Map<string, LevelGroup["actions"]>();
    for (const verb of policyVerbs) {
      const level = cpLevel(verb);
      const list = byLevel.get(level) ?? [];
      list.push({ action: `${resource}:${verb}`, name: verb });
      byLevel.set(level, list);
    }
    return CP_LEVEL_ORDER.filter((l) => byLevel.has(l)).map((level) => ({
      level,
      actions: byLevel.get(level)!,
    }));
  }
  if (svc.startsWith("dp:")) {
    const service = serviceByName(svc.slice(3));
    if (!service) return [];
    return actionsByLevel(service).map(({ level, actions }) => ({
      level,
      actions: actions.map((a: CedarAction) => ({
        action: a.action,
        name: a.name,
        description: a.description,
        approximate: a.approximate,
      })),
    }));
  }
  return [];
}

export function ActionPicker({
  policyResources,
  policyVerbs,
  selected,
  onChange,
  invalid,
}: {
  /** openinfra.dev resources a control-plane action may name (from /api/iam/config). */
  policyResources: string[];
  /** Verbs a control-plane action may use (from /api/iam/config). */
  policyVerbs: string[];
  /** The full set of selected action strings (both planes). */
  selected: string[];
  onChange: (next: string[]) => void;
  /** When true, show the "add at least one action" error (after a failed submit). */
  invalid?: boolean;
}) {
  const [svc, setSvc] = useState("");
  const [manual, setManual] = useState("");

  const selectedSet = new Set(selected);
  const groups = groupsForService(svc, policyVerbs);

  const toggle = (action: string) => {
    if (selectedSet.has(action)) onChange(selected.filter((a) => a !== action));
    else onChange([...selected, action]);
  };
  const toggleGroup = (actions: string[]) => {
    const allOn = actions.every((a) => selectedSet.has(a));
    if (allOn) onChange(selected.filter((a) => !actions.includes(a)));
    else onChange([...selected, ...actions.filter((a) => !selectedSet.has(a))]);
  };
  const addManual = () => {
    const a = manual.trim();
    if (a && !selectedSet.has(a)) onChange([...selected, a]);
    setManual("");
  };

  return (
    <div className="space-y-3">
      {/* Service / resource picker — grouped Platform (control plane) vs Data services. */}
      <Select value={svc} onValueChange={setSvc}>
        <SelectTrigger className="h-9 w-full text-sm">
          <SelectValue placeholder="Choose a service or resource…" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>Data services (data plane)</SelectLabel>
            {CEDAR_SERVICES.map((s) => (
              <SelectItem key={s.service} value={`dp:${s.service}`}>
                {s.label}
              </SelectItem>
            ))}
          </SelectGroup>
          <SelectGroup>
            <SelectLabel>Platform (control plane)</SelectLabel>
            {policyResources.map((r) => (
              <SelectItem key={r} value={`cp:${r}`}>
                {r}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>

      {/* Actions for the chosen service, grouped by access level. */}
      {svc ? (
        groups.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No enforceable actions catalogued for this service.
          </p>
        ) : (
          <div className="space-y-3 rounded-md border border-border p-3">
            {groups.map((g) => {
              const actions = g.actions.map((a) => a.action);
              const allOn = actions.every((a) => selectedSet.has(a));
              const perms = g.level === "Permissions management";
              return (
                <div key={g.level} className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={[
                        "text-xs font-semibold",
                        perms ? "text-warning" : "text-muted-foreground",
                      ].join(" ")}
                    >
                      {perms ? (
                        <AlertTriangle className="mr-1 inline size-3.5 align-[-2px]" />
                      ) : null}
                      {g.level}
                    </span>
                    <button
                      type="button"
                      onClick={() => toggleGroup(actions)}
                      className="rounded border border-dashed px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted"
                    >
                      {allOn ? "Clear" : "Select all"}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {g.actions.map((a) => {
                      const on = selectedSet.has(a.action);
                      return (
                        <button
                          key={a.action}
                          type="button"
                          title={
                            (a.description ?? "") +
                            (a.approximate ? " (recognized for authz; not fully implemented at the data layer)" : "")
                          }
                          onClick={() => toggle(a.action)}
                          className={[
                            "rounded border px-2 py-0.5 text-xs transition-colors",
                            on
                              ? "border-primary/40 bg-primary/15 text-primary"
                              : "border-border text-muted-foreground hover:bg-muted",
                          ].join(" ")}
                        >
                          {a.name}
                          {a.approximate ? <span className="ml-1 opacity-60">≈</span> : null}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )
      ) : null}

      {/* Manual action entry — the simulator accepts any action string, mirroring AWS's "Add actions". */}
      <div className="flex gap-2">
        <Input
          value={manual}
          onChange={(e) => setManual(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addManual();
            }
          }}
          placeholder="Add an action, e.g. s3:GetObject or virtualmachines:Get"
          className="h-8 text-xs"
        />
        <Button variant="outline" size="sm" onClick={addManual} disabled={!manual.trim()}>
          <Plus className="size-3.5" /> Add
        </Button>
      </div>

      {/* Selected actions — the accumulated set across every service, removable. */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground">
            Selected actions ({selected.length})
          </span>
          {selected.length > 0 ? (
            <button
              type="button"
              onClick={() => onChange([])}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              Clear all
            </button>
          ) : null}
        </div>
        {selected.length === 0 ? (
          <p className={["text-xs", invalid ? "text-destructive" : "text-muted-foreground"].join(" ")}>
            {invalid ? "Add at least one action to simulate." : "No actions selected yet."}
          </p>
        ) : (
          <div className="flex flex-wrap gap-1">
            {selected.map((a) => (
              <Badge key={a} variant="secondary" className="gap-1 font-mono">
                {a}
                <button
                  type="button"
                  onClick={() => toggle(a)}
                  aria-label={`Remove ${a}`}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="size-3" />
                </button>
              </Badge>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
