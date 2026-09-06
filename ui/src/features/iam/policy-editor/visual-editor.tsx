import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PermissionEditor } from "../permission-editor";
import { CedarBlockEditor } from "./cedar-statement-editor";
import { newDataBlock, type DataBlock, type PolicyModel } from "./model";

/**
 * The Visual policy editor — AWS's visual authoring surface, adapted to open-infra's two enforcement
 * vocabularies (aws-iam-console-reference.md §8.3):
 *
 *   • Platform permissions (control plane)  → spec.statements (Kubernetes RBAC). The existing coarse
 *     resource×verb grid, reused verbatim. Allow-only, no conditions, resources are always "all" —
 *     stated honestly, because that is what RBAC can enforce.
 *   • Data-service permissions (data plane) → spec.dataPlane (Cedar at the aws-shim). AWS-style
 *     permission blocks with Allow/Deny, typed resources, and request conditions — what RBAC cannot do.
 *
 * The section (not a per-block dropdown) chooses the vocabulary, which keeps each surface honest about
 * what it can enforce.
 */
export function VisualEditor({
  model,
  onChange,
  controlResources,
}: {
  model: PolicyModel;
  onChange: (m: PolicyModel) => void;
  /** openinfra.dev resources selectable on the control plane (the boundary) — from /iam/config. */
  controlResources: string[];
}) {
  const setBlock = (id: string, b: DataBlock) =>
    onChange({ ...model, dataBlocks: model.dataBlocks.map((x) => (x.id === id ? b : x)) });
  const addBlock = () => onChange({ ...model, dataBlocks: [...model.dataBlocks, newDataBlock()] });
  const removeBlock = (id: string) =>
    onChange({ ...model, dataBlocks: model.dataBlocks.filter((x) => x.id !== id) });

  return (
    <div className="space-y-6">
      {/* ── Platform (control plane) ─────────────────────────────────────── */}
      <section className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">Platform permissions</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Actions over openinfra.dev resources (the permission boundary). These compile to a Kubernetes
            ClusterRole — so they are <span className="font-medium">Allow-only</span>, apply to{" "}
            <span className="font-medium">all resources of the kind</span> (RBAC cannot scope list/watch by
            name), and take no conditions. Use a data-service block below for Deny, scoping, or conditions.
          </p>
        </div>
        <PermissionEditor
          resources={controlResources}
          rows={model.controlRows}
          onChange={(controlRows) => onChange({ ...model, controlRows })}
        />
      </section>

      {/* ── Data services (data plane / Cedar) ───────────────────────────── */}
      <section className="space-y-3 rounded-lg border border-border p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold">Data-service permissions</h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              S3, DynamoDB and Lambda access, enforced by Cedar at the AWS-compatible gateway. These{" "}
              <span className="font-medium">can Deny</span> (Deny overrides), scope to typed resources, and
              match request conditions.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={addBlock}>
            <Plus className="size-3.5" /> Add permission
          </Button>
        </div>

        {/* Applies to (dataPlane.appliesTo) */}
        {model.dataBlocks.length > 0 ? (
          <AppliesToEditor
            appliesTo={model.appliesTo}
            onChange={(appliesTo) => onChange({ ...model, appliesTo })}
          />
        ) : null}

        {model.dataBlocks.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-3 text-xs text-muted-foreground">
            No data-service permissions. Add one to grant (or deny) S3/DynamoDB/Lambda access with typed
            resources and conditions.
          </p>
        ) : (
          <div className="space-y-3">
            {model.dataBlocks.map((b) => (
              <CedarBlockEditor
                key={b.id}
                block={b}
                onChange={(nb) => setBlock(b.id, nb)}
                onRemove={() => removeBlock(b.id)}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

/** Edits dataPlane.appliesTo — the principals the data-plane statements govern. */
function AppliesToEditor({
  appliesTo,
  onChange,
}: {
  appliesTo: string[];
  onChange: (v: string[]) => void;
}) {
  const isAll = appliesTo.includes("*");
  const add = (raw: string) => {
    const v = raw.trim();
    if (!v || appliesTo.includes(v)) return;
    // Drop the "*" catch-all once a specific principal is named.
    onChange([...appliesTo.filter((p) => p !== "*"), v]);
  };

  return (
    <div className="space-y-2 rounded-md border border-border/70 bg-muted/20 p-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium">Applies to principals</span>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
          <input
            type="checkbox"
            className="size-3.5 accent-[hsl(var(--primary))]"
            checked={isAll}
            onChange={(e) => onChange(e.target.checked ? ["*"] : [])}
          />
          Any principal (*)
        </label>
      </div>
      {!isAll ? (
        <>
          <div className="flex flex-wrap gap-1.5">
            {appliesTo.map((p) => (
              <span
                key={p}
                className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-0.5 text-xs"
              >
                <code>{p}</code>
                <button
                  type="button"
                  className="text-muted-foreground hover:text-destructive"
                  onClick={() => onChange(appliesTo.filter((x) => x !== p))}
                >
                  <X className="size-3" />
                </button>
              </span>
            ))}
            {appliesTo.length === 0 ? (
              <span className="text-xs text-muted-foreground">
                No principals — this block will apply to no one. Add User::name or Group::name.
              </span>
            ) : null}
          </div>
          <Input
            className="h-8 w-64 text-xs"
            placeholder="User::alice or Group::eng — Enter to add"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add((e.target as HTMLInputElement).value);
                (e.target as HTMLInputElement).value = "";
              }
            }}
          />
        </>
      ) : (
        <p className="text-xs text-muted-foreground">
          The data-plane statements govern every principal. Uncheck to scope to specific Users/Groups.
        </p>
      )}
    </div>
  );
}
