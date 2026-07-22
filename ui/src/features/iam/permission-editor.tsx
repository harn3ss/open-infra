import { Plus, Trash2 } from "lucide-react";
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

export function PermissionEditor({
  resources,
  rows,
  onChange,
}: {
  resources: string[];
  rows: PermRow[];
  onChange: (rows: PermRow[]) => void;
}) {
  const set = (i: number, patch: Partial<PermRow>) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = () => onChange([...rows, { resource: "", verbs: [] }]);
  const remove = (i: number) => onChange(rows.filter((_, j) => j !== i));
  const toggleVerb = (i: number, v: string) => {
    const cur = rows[i]?.verbs ?? [];
    set(i, { verbs: cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v] });
  };

  const options = ["*", ...resources];

  return (
    <div className="space-y-2">
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground">No permissions yet — add one below.</p>
      ) : null}
      {rows.map((row, i) => (
        <div key={i} className="rounded-md border p-2.5">
          <div className="flex items-center gap-2">
            <Select value={row.resource} onValueChange={(v) => set(i, { resource: v })}>
              <SelectTrigger className="h-8 w-56 text-xs">
                <SelectValue placeholder="Choose a resource" />
              </SelectTrigger>
              <SelectContent>
                {options.map((o) => (
                  <SelectItem key={o} value={o}>
                    {o === "*" ? "All openinfra.dev resources (*)" : o}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto text-destructive"
              onClick={() => remove(i)}
            >
              <Trash2 className="size-3.5" />
            </Button>
          </div>
          <div className="mt-2 flex flex-wrap gap-1">
            {VERBS.map((v) => {
              const on = row.verbs.includes(v) || row.verbs.includes("*");
              return (
                <button
                  key={v}
                  type="button"
                  onClick={() => toggleVerb(i, v)}
                  className={[
                    "rounded border px-2 py-0.5 text-xs transition-colors",
                    on
                      ? "border-primary/40 bg-primary/15 text-primary"
                      : "border-border text-muted-foreground hover:bg-muted",
                  ].join(" ")}
                >
                  {v}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() =>
                set(i, { verbs: row.verbs.length === VERBS.length ? [] : [...VERBS] })
              }
              className="rounded border border-dashed px-2 py-0.5 text-xs text-muted-foreground hover:bg-muted"
            >
              {row.verbs.length === VERBS.length ? "Clear" : "All"}
            </button>
          </div>
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={add}>
        <Plus className="size-3.5" /> Add permission
      </Button>
    </div>
  );
}
