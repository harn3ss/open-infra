import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Lock, Search } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PermissionsSummary } from "./policy-editor/permissions-summary";
import { policyType, type PolicyTypeLabel } from "./policy-type";
import type { IamPolicy } from "@/lib/api";
import type { PolicyDoc } from "./policy-editor/model";
import { cn } from "@/lib/utils";

/**
 * The AWS "Add permissions" policy picker — the searchable, filterable, checkbox list shared by the
 * Role and User detail Permissions tabs. It lists EVERY attachable policy (out-of-the-box Managed and
 * Customer-managed alike — both tickable), pre-ticking the ones already attached so the modal is the
 * single manager of the attachment set. Each row expands to the same PermissionsSummary table the
 * policy detail page shows, so an admin can see what a policy grants before attaching it.
 *
 * It stages a selection only: `onConfirm` hands the caller the FULL new set of attached names, and the
 * caller persists it (updateIamRole / updateIamUser) behind its own Save — matching the reviewed-before-
 * commit pattern the Role page already uses.
 */

const PLANE_TONE: Record<PolicyTypeLabel, "default" | "accent" | "secondary"> = {
  "Control plane": "default",
  "Data plane": "accent",
  Mixed: "secondary",
  Empty: "secondary",
};

/** The managed/customer axis — AWS's "Filter by Type" dropdown (AWS managed vs Customer managed). */
const ALL = "__all__";
const MANAGED = "__managed__";
const CUSTOMER = "__customer__";

/** Project an IamPolicy onto the PolicyDoc shape the PermissionsSummary table renders. */
function policyDoc(p: IamPolicy): PolicyDoc {
  return {
    description: p.description,
    statements: p.statements,
    dataPlane: p.dataPlane,
    controlPlane: p.controlPlane,
  };
}

/** The Managed vs Customer-managed badge, AWS-managed-style (a lock for the out-of-the-box set). */
export function ManagedBadge({ managed, category }: { managed: boolean; category?: string }) {
  if (managed) {
    return (
      <Badge variant="warning" title={category ? `Managed policy — ${category}` : "Out-of-the-box managed policy (read only)"}>
        <Lock className="size-3" /> Managed{category ? ` · ${category}` : ""}
      </Badge>
    );
  }
  return <Badge variant="muted">Customer managed</Badge>;
}

export interface AttachPolicyPickerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Every attachable policy (Managed + Customer). */
  policies: IamPolicy[];
  /** Names currently attached — pre-ticked when the picker opens. */
  attached: string[];
  /** Receives the FULL new set of attached names on confirm. */
  onConfirm: (next: string[]) => void;
  /** Subject for the header, e.g. "role ops" or "user alice". */
  subjectLabel: string;
}

export function AttachPolicyPicker({
  open,
  onOpenChange,
  policies,
  attached,
  onConfirm,
  subjectLabel,
}: AttachPolicyPickerProps) {
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>(ALL);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Re-seed the staged selection from the live attached set every time the modal opens, so a cancel
  // truly discards and a re-open reflects any change saved in the meantime.
  useEffect(() => {
    if (open) {
      setSel(new Set(attached));
      setSearch("");
      setTypeFilter(ALL);
      setExpanded(new Set());
    }
  }, [open, attached]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return policies
      .filter((p) => {
        if (typeFilter === MANAGED && !p.managed) return false;
        if (typeFilter === CUSTOMER && p.managed) return false;
        if (!q) return true;
        return (
          p.name.toLowerCase().includes(q) ||
          (p.description ?? "").toLowerCase().includes(q) ||
          (p.category ?? "").toLowerCase().includes(q)
        );
      })
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [policies, search, typeFilter]);

  const toggle = (name: string) =>
    setSel((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const toggleExpand = (name: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const filtered = search.trim() !== "" || typeFilter !== ALL;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[85vh] w-full max-w-3xl flex-col gap-4">
        <DialogHeader>
          <DialogTitle>Add permissions</DialogTitle>
          <DialogDescription>
            Attach policies to {subjectLabel}. Out-of-the-box <b>Managed</b> policies and your{" "}
            <b>Customer-managed</b> policies are both attachable — tick the ones to attach, then confirm.
          </DialogDescription>
        </DialogHeader>

        {/* Search + the managed/customer type filter (AWS's "Filter by Type"). */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-48">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search policies by name or description"
              className="pl-8"
              aria-label="Search policies"
            />
          </div>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="h-9 w-auto min-w-44" aria-label="Filter by type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All types</SelectItem>
              <SelectItem value={MANAGED}>Managed</SelectItem>
              <SelectItem value={CUSTOMER}>Customer managed</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <p className="text-xs text-muted-foreground">
          {filtered ? `${rows.length} of ${policies.length} match` : `${policies.length} policies`}
          {sel.size > 0 ? ` · ${sel.size} selected` : ""}
        </p>

        {/* The list — one row per policy, checkbox + expandable per-policy summary. */}
        <div className="min-h-0 flex-1 overflow-y-auto rounded-md border border-border">
          {rows.length === 0 ? (
            <p className="p-6 text-center text-sm text-muted-foreground">
              No policies match the current filter.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {rows.map((p) => {
                const on = sel.has(p.name);
                const isOpen = expanded.has(p.name);
                const plane = policyType(p);
                return (
                  <li key={p.name}>
                    <div className="flex items-start gap-3 p-3">
                      <input
                        type="checkbox"
                        className="mt-1 size-4 shrink-0 accent-[hsl(var(--primary))]"
                        checked={on}
                        onChange={() => toggle(p.name)}
                        aria-label={`Attach ${p.name}`}
                      />
                      <button
                        type="button"
                        onClick={() => toggleExpand(p.name)}
                        className="min-w-0 flex-1 text-left"
                        aria-expanded={isOpen}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium text-foreground">{p.name}</span>
                          <ManagedBadge managed={p.managed} category={p.category} />
                          <Badge variant={PLANE_TONE[plane]}>{plane}</Badge>
                        </div>
                        <p className="mt-0.5 truncate text-xs text-muted-foreground">
                          {p.description || "No description"}
                        </p>
                      </button>
                      <button
                        type="button"
                        onClick={() => toggleExpand(p.name)}
                        className="mt-0.5 shrink-0 rounded p-1 text-muted-foreground hover:bg-muted"
                        aria-label={isOpen ? "Hide summary" : "Show summary"}
                      >
                        {isOpen ? (
                          <ChevronDown className="size-4" />
                        ) : (
                          <ChevronRight className="size-4" />
                        )}
                      </button>
                    </div>
                    {isOpen ? (
                      <div className={cn("border-t border-border bg-muted/20")}>
                        <PermissionsSummary doc={policyDoc(p)} />
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              onConfirm([...sel].sort());
              onOpenChange(false);
            }}
          >
            Add permissions
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
