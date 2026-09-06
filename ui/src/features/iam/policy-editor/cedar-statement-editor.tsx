import { AlertTriangle, Plus, Trash2, X } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  CEDAR_SERVICES,
  CEDAR_CONDITION_KEYS,
  actionsByLevel,
  serviceByName,
} from "@/lib/iam-cedar-vocab";
import type { DataBlock } from "./model";

/**
 * One AWS-style data-plane permission block (a Cedar statement). Reproduces AWS's four collapsible
 * sub-sections — Select a service → Actions allowed (grouped by access level) → Resources → Request
 * conditions — plus the per-block Allow/Deny switch. Emits into a Policy's spec.dataPlane.statements.
 *
 * Unlike the control-plane grid, this block CAN Deny and CAN carry conditions and typed resource scopes,
 * because it is enforced by Cedar at the aws-shim, not compiled to (additive, condition-less) RBAC.
 */
export function CedarBlockEditor({
  block,
  onChange,
  onRemove,
}: {
  block: DataBlock;
  onChange: (b: DataBlock) => void;
  onRemove: () => void;
}) {
  const svc = serviceByName(block.service) ?? CEDAR_SERVICES[0]!;
  const groups = actionsByLevel(svc);
  const set = (patch: Partial<DataBlock>) => onChange({ ...block, ...patch });

  const toggleAction = (action: string) => {
    const on = block.actions.includes(action);
    set({ actions: on ? block.actions.filter((a) => a !== action) : [...block.actions, action] });
  };
  const toggleLevel = (levelActions: string[]) => {
    const allOn = levelActions.every((a) => block.actions.includes(a));
    set({
      actions: allOn
        ? block.actions.filter((a) => !levelActions.includes(a))
        : [...new Set([...block.actions, ...levelActions])],
    });
  };

  const selectedCount = block.allActions ? svc.actions.length : block.actions.length;

  return (
    <div className="rounded-lg border border-border">
      {/* Block header: service + Allow/Deny + remove */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/30 p-3">
        <span className="text-xs font-medium text-muted-foreground">Service</span>
        <Select
          value={block.service}
          onValueChange={(v) =>
            // Changing service invalidates the selected actions/resources for the old service.
            onChange({ ...block, service: v, allActions: false, actions: [], resources: [], anyResource: true })
          }
        >
          <SelectTrigger className="h-8 w-48 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {CEDAR_SERVICES.map((s) => (
              <SelectItem key={s.service} value={s.service}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Allow / Deny — data-plane only capability. */}
        <div className="ml-2 inline-flex overflow-hidden rounded-md border border-border">
          {(["Allow", "Deny"] as const).map((eff) => (
            <button
              key={eff}
              type="button"
              onClick={() => set({ effect: eff })}
              className={[
                "px-2.5 py-1 text-xs font-medium transition-colors",
                block.effect === eff
                  ? eff === "Deny"
                    ? "bg-destructive/15 text-destructive"
                    : "bg-success/15 text-success"
                  : "text-muted-foreground hover:bg-muted",
              ].join(" ")}
            >
              {eff}
            </button>
          ))}
        </div>

        <span className="ml-2 text-xs text-muted-foreground">{svc.description}</span>

        <Button variant="ghost" size="sm" className="ml-auto text-destructive" onClick={onRemove}>
          <Trash2 className="size-3.5" /> Remove
        </Button>
      </div>

      <div className="space-y-4 p-3">
        {/* 1. Actions allowed */}
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold">
              Actions {block.effect === "Deny" ? "denied" : "allowed"}
              <span className="ml-2 font-normal text-muted-foreground">
                {selectedCount} selected
              </span>
            </h4>
            <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                className="size-3.5 accent-[hsl(var(--primary))]"
                checked={block.allActions}
                onChange={(e) => set({ allActions: e.target.checked })}
              />
              All {svc.label} actions ({svc.service}:*)
            </label>
          </div>

          {block.allActions ? (
            <p className="rounded-md border border-warning/40 bg-warning/10 px-2.5 py-1.5 text-xs text-warning">
              <AlertTriangle className="mr-1 inline size-3.5" />
              Grants every {svc.label} action. Prefer selecting only the actions you need.
            </p>
          ) : (
            <div className="space-y-2">
              {groups.map((g) => {
                const allOn = g.actions.every((a) => block.actions.includes(a.action));
                return (
                  <div key={g.level} className="rounded-md border border-border/70">
                    <div className="flex items-center justify-between border-b border-border/70 bg-muted/20 px-2.5 py-1.5">
                      <label className="flex cursor-pointer items-center gap-1.5 text-xs font-medium">
                        <input
                          type="checkbox"
                          className="size-3.5 accent-[hsl(var(--primary))]"
                          checked={allOn}
                          onChange={() => toggleLevel(g.actions.map((a) => a.action))}
                        />
                        {g.level}
                        {g.level === "Permissions management" ? (
                          <Badge variant="warning" className="ml-1">sensitive</Badge>
                        ) : null}
                      </label>
                      <span className="text-[11px] text-muted-foreground">
                        {g.actions.filter((a) => block.actions.includes(a.action)).length}/{g.actions.length}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 gap-x-4 gap-y-1 p-2 sm:grid-cols-2">
                      {g.actions.map((a) => (
                        <label
                          key={a.action}
                          className="flex cursor-pointer items-start gap-1.5 text-xs"
                          title={a.description}
                        >
                          <input
                            type="checkbox"
                            className="mt-0.5 size-3.5 accent-[hsl(var(--primary))]"
                            checked={block.actions.includes(a.action)}
                            onChange={() => toggleAction(a.action)}
                          />
                          <span className="min-w-0">
                            <span className="font-medium">{a.name}</span>
                            {a.approximate ? (
                              <span className="ml-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                                unscoped
                              </span>
                            ) : null}
                            <span className="block text-[11px] text-muted-foreground">{a.description}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 2. Resources */}
        <section className="space-y-2">
          <h4 className="text-xs font-semibold">Resources</h4>
          <div className="flex flex-wrap gap-3 text-xs">
            <label className="flex cursor-pointer items-center gap-1.5">
              <input
                type="radio"
                name={`res-${block.id}`}
                className="size-3.5 accent-[hsl(var(--primary))]"
                checked={block.anyResource}
                onChange={() => set({ anyResource: true })}
              />
              Any {svc.resourceLabel}
            </label>
            <label className="flex cursor-pointer items-center gap-1.5">
              <input
                type="radio"
                name={`res-${block.id}`}
                className="size-3.5 accent-[hsl(var(--primary))]"
                checked={!block.anyResource}
                onChange={() => set({ anyResource: false })}
              />
              Specific {svc.resourceLabel}s
            </label>
          </div>
          {!block.anyResource ? (
            <ResourceList
              type={svc.resourceType}
              example={svc.resourceExample}
              resources={block.resources}
              onChange={(resources) => set({ resources })}
            />
          ) : null}
        </section>

        {/* 3. Request conditions */}
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold">
              Request conditions <span className="font-normal text-muted-foreground">- optional</span>
            </h4>
            <Button
              variant="outline"
              size="sm"
              onClick={() => set({ conditions: [...block.conditions, { key: "", value: "" }] })}
            >
              <Plus className="size-3.5" /> Add condition
            </Button>
          </div>
          {block.conditions.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No conditions. The platform can match on {CEDAR_CONDITION_KEYS.map((k) => k.key).join(", ")}.
            </p>
          ) : (
            <div className="space-y-1.5">
              {block.conditions.map((c, i) => {
                const known = CEDAR_CONDITION_KEYS.find((k) => k.key === c.key);
                return (
                  <div key={i} className="flex items-center gap-2">
                    <Select
                      value={c.key || undefined}
                      onValueChange={(v) =>
                        set({
                          conditions: block.conditions.map((x, j) => (j === i ? { ...x, key: v } : x)),
                        })
                      }
                    >
                      <SelectTrigger className="h-8 w-44 text-xs">
                        <SelectValue placeholder="Condition key" />
                      </SelectTrigger>
                      <SelectContent>
                        {CEDAR_CONDITION_KEYS.map((k) => (
                          <SelectItem key={k.key} value={k.key}>
                            {k.key}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <span className="text-xs text-muted-foreground">=</span>
                    {known?.type === "boolean" ? (
                      <Select
                        value={c.value || undefined}
                        onValueChange={(v) =>
                          set({
                            conditions: block.conditions.map((x, j) => (j === i ? { ...x, value: v } : x)),
                          })
                        }
                      >
                        <SelectTrigger className="h-8 w-28 text-xs">
                          <SelectValue placeholder="true/false" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="true">true</SelectItem>
                          <SelectItem value="false">false</SelectItem>
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        className="h-8 w-56 text-xs"
                        value={c.value}
                        placeholder={known?.type === "string" ? "10.0.0.0/8" : "value"}
                        onChange={(e) =>
                          set({
                            conditions: block.conditions.map((x, j) =>
                              j === i ? { ...x, value: e.target.value } : x,
                            ),
                          })
                        }
                      />
                    )}
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-muted-foreground"
                      onClick={() => set({ conditions: block.conditions.filter((_, j) => j !== i) })}
                    >
                      <X className="size-3.5" />
                    </Button>
                    {known ? (
                      <span className="text-[11px] text-muted-foreground">{known.description}</span>
                    ) : null}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

/** A typed-resource chip list: user types an id, it's stored as "<Type>::<id>"; a "*" is Type::* (all). */
function ResourceList({
  type,
  example,
  resources,
  onChange,
}: {
  type: string;
  example: string;
  resources: string[];
  onChange: (r: string[]) => void;
}) {
  const add = (raw: string) => {
    const id = raw.trim();
    if (!id) return;
    // Accept a full "Type::id" or a bare id (prefixed with the service's type).
    const full = id.includes("::") ? id : `${type}::${id}`;
    if (!resources.includes(full)) onChange([...resources, full]);
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {resources.map((r) => (
          <span
            key={r}
            className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 py-0.5 text-xs"
          >
            <code>{r}</code>
            <button
              type="button"
              className="text-muted-foreground hover:text-destructive"
              onClick={() => onChange(resources.filter((x) => x !== r))}
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        {resources.length === 0 ? (
          <span className="text-xs text-muted-foreground">No resources — add one below.</span>
        ) : null}
      </div>
      <ResourceAdder type={type} example={example} onAdd={add} />
    </div>
  );
}

function ResourceAdder({
  type,
  example,
  onAdd,
}: {
  type: string;
  example: string;
  onAdd: (raw: string) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="rounded-l-md border border-r-0 border-border bg-muted/40 px-2 py-1 font-mono text-xs text-muted-foreground">
        {type}::
      </span>
      <Input
        className="h-8 w-56 rounded-l-none text-xs"
        placeholder={`e.g. ${example.split("::")[1] ?? "name"} or *`}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            onAdd((e.target as HTMLInputElement).value);
            (e.target as HTMLInputElement).value = "";
          }
        }}
      />
      <span className="text-[11px] text-muted-foreground">Press Enter to add</span>
    </div>
  );
}
