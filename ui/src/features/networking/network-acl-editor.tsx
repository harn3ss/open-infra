import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, Plus, Trash2, Pencil, X, ChevronDown, ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/common/states";
import { ApiError, k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import type { Subnet, SubnetAcl } from "@/types/k8s";

const CIDR_RE = /^(\d{1,3})(\.\d{1,3}){3}\/\d{1,2}$/;
const DEFAULT_PRIORITY = 1000;

type Direction = "ingress" | "egress";
type Protocol = "all" | "tcp" | "udp" | "icmp";

let SEQ = 0;
const nextId = () => `acl${SEQ++}`;

interface AclDraft {
  id: string;
  direction: Direction;
  action: "allow" | "drop";
  priority: string; // kept as string in the form
  protocol: Protocol;
  cidr: string;
  port: string;
  match: string;
  advanced: boolean;
}

function draftValid(d: AclDraft): boolean {
  const p = Number(d.priority);
  if (!Number.isInteger(p) || p < 0 || p > 32767) return false;
  if (d.advanced && d.match.trim()) return true; // raw match overrides structured fields
  if (d.cidr.trim() && !CIDR_RE.test(d.cidr.trim())) return false;
  if (d.port.trim() && !/^\d{1,5}$/.test(d.port.trim())) return false;
  return true;
}

function aclToDraft(a: SubnetAcl): AclDraft {
  return {
    id: nextId(),
    direction: a.direction,
    action: a.action,
    priority: String(a.priority ?? DEFAULT_PRIORITY),
    protocol: (a.protocol ?? "all") as Protocol,
    cidr: a.cidr ?? "",
    port: a.port != null ? String(a.port) : "",
    match: a.match ?? "",
    advanced: Boolean(a.match),
  };
}

function draftToAcl(d: AclDraft): SubnetAcl {
  const base: SubnetAcl = {
    direction: d.direction,
    action: d.action,
    priority: Number(d.priority),
  };
  if (d.advanced && d.match.trim()) {
    // Raw OVN match overrides the structured fields.
    base.match = d.match.trim();
    if (d.protocol !== "all") base.protocol = d.protocol;
    return base;
  }
  base.protocol = d.protocol;
  if (d.cidr.trim()) base.cidr = d.cidr.trim();
  if (d.port.trim()) base.port = Number(d.port);
  return base;
}

/**
 * Editor for a Subnet's `spec.acls` — a stateless, subnet-wide Network ACL. Two rule
 * tables (inbound / outbound), like AWS's NACL editor, BUT honestly:
 *  - OVN evaluates HIGHEST priority first (the inverse of AWS's lowest-rule-# wins), so
 *    the column is "Priority (higher wins)" and rows sort descending — never faked as
 *    AWS's ascending rule numbers.
 *  - There is no fabricated implicit "* DENY": a private subnet's OVN isolation already
 *    drops un-allowed traffic; a public subnet has no implicit deny. The trailer states
 *    the real default.
 */
export function NetworkAclEditor({
  subnet,
  namespace,
  onSaved,
}: {
  subnet: Subnet;
  namespace: string;
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const name = subnet.metadata.name ?? "";
  const isPrivate = subnet.spec?.private !== false;
  const acls = useMemo<SubnetAcl[]>(() => subnet.spec?.acls ?? [], [subnet.spec?.acls]);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<AclDraft[]>([]);
  const [touched, setTouched] = useState(false);

  const save = useMutation({
    mutationFn: async () => {
      const path = openinfraPaths.subnet(namespace, name);
      const cur = await k8sGet<Subnet>(path);
      const nextAcls = draft.map(draftToAcl);
      const spec = { ...cur.spec, acls: nextAcls };
      return k8sReplace<Subnet>(path, { ...cur, spec } as Subnet);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.subnets()) });
      setEditing(false);
      onSaved();
    },
  });

  const startEdit = () => {
    setDraft(acls.map(aclToDraft));
    setTouched(false);
    save.reset();
    setEditing(true);
  };

  const update = (id: string, patch: Partial<AclDraft>) =>
    setDraft((rows) => rows.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  const allValid = draft.every(draftValid);

  const submit = () => {
    setTouched(true);
    if (!allValid) return;
    save.mutate();
  };

  // Descending priority = OVN evaluation order.
  const byPriority = (a: SubnetAcl, b: SubnetAcl) => (b.priority ?? DEFAULT_PRIORITY) - (a.priority ?? DEFAULT_PRIORITY);
  const inbound = acls.filter((a) => a.direction === "ingress").slice().sort(byPriority);
  const outbound = acls.filter((a) => a.direction === "egress").slice().sort(byPriority);

  const defaultTrailer = isPrivate
    ? "default: isolated — un-allowed traffic is dropped by this subnet's OVN isolation."
    : "default: allow — there is no implicit deny. Add a low-priority drop rule to default-deny.";

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <span>
          Network ACLs are <strong>stateless</strong>, subnet-wide rules on{" "}
          <span className="font-medium text-foreground">{name}</span> (kube-ovn) — unlike a Security Group they
          govern the whole subnet and don't track connection state. OVN evaluates{" "}
          <strong>highest priority first</strong> (the inverse of AWS's lowest-rule-number-first), so rows are
          ordered by priority descending.
        </span>
      </div>

      {!editing ? (
        <>
          <AclTable
            title="Inbound rules"
            peerHeader="Source"
            rules={inbound}
            trailer={defaultTrailer}
            emptyHint="No inbound ACL rules."
          />
          <AclTable
            title="Outbound rules"
            peerHeader="Destination"
            rules={outbound}
            trailer={defaultTrailer}
            emptyHint="No outbound ACL rules."
          />
          <Button variant="outline" onClick={startEdit}>
            <Pencil className="size-4" /> Edit rules
          </Button>
        </>
      ) : (
        <div className="space-y-4">
          <AclEditSection
            title="Inbound rules"
            peerHeader="Source"
            direction="ingress"
            rows={draft.filter((r) => r.direction === "ingress")}
            touched={touched}
            onUpdate={update}
            onRemove={(id) => setDraft((rows) => rows.filter((r) => r.id !== id))}
            onAdd={() =>
              setDraft((rows) => [
                ...rows,
                { id: nextId(), direction: "ingress", action: "allow", priority: String(DEFAULT_PRIORITY), protocol: "all", cidr: "", port: "", match: "", advanced: false },
              ])
            }
          />
          <AclEditSection
            title="Outbound rules"
            peerHeader="Destination"
            direction="egress"
            rows={draft.filter((r) => r.direction === "egress")}
            touched={touched}
            onUpdate={update}
            onRemove={(id) => setDraft((rows) => rows.filter((r) => r.id !== id))}
            onAdd={() =>
              setDraft((rows) => [
                ...rows,
                { id: nextId(), direction: "egress", action: "allow", priority: String(DEFAULT_PRIORITY), protocol: "all", cidr: "", port: "", match: "", advanced: false },
              ])
            }
          />
          <p className="text-xs text-muted-foreground">{defaultTrailer}</p>

          {save.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {save.error instanceof ApiError ? save.error.message : "Failed to save ACL rules."}
            </div>
          ) : null}

          <Card>
            <CardContent className="flex justify-end gap-2 p-3">
              <Button variant="outline" onClick={() => setEditing(false)} disabled={save.isPending}>
                <X className="size-4" /> Cancel
              </Button>
              <Button onClick={submit} disabled={save.isPending || (touched && !allValid)}>
                {save.isPending ? <Spinner className="text-current" /> : <ShieldAlert className="size-4" />}
                Save ACL rules
              </Button>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

function AclTable({
  title,
  peerHeader,
  rules,
  trailer,
  emptyHint,
}: {
  title: string;
  peerHeader: string;
  rules: SubnetAcl[];
  trailer: string;
  emptyHint: string;
}) {
  return (
    <div className="space-y-1">
      <div className="text-sm font-medium">{title}</div>
      <div className="overflow-hidden rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Priority (higher wins)</th>
              <th className="px-3 py-2 text-left font-medium">Protocol</th>
              <th className="px-3 py-2 text-left font-medium">Port</th>
              <th className="px-3 py-2 text-left font-medium">{peerHeader}</th>
              <th className="px-3 py-2 text-left font-medium">Action</th>
              <th className="px-3 py-2 text-left font-medium">Match</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rules.length ? (
              rules.map((r, i) => (
                <tr key={i}>
                  <td className="px-3 py-2">{r.priority ?? DEFAULT_PRIORITY}</td>
                  <td className="px-3 py-2">{r.protocol ?? "all"}</td>
                  <td className="px-3 py-2">{r.port ?? "—"}</td>
                  <td className="px-3 py-2"><code className="text-xs">{r.cidr ?? "0.0.0.0/0"}</code></td>
                  <td className="px-3 py-2">
                    <span className={r.action === "drop" ? "text-destructive" : "text-primary"}>
                      {r.action === "drop" ? "Drop" : "Allow"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{r.match ? <code className="text-xs">{r.match}</code> : "—"}</td>
                </tr>
              ))
            ) : (
              <tr><td colSpan={6} className="px-3 py-3 text-xs text-muted-foreground">{emptyHint}</td></tr>
            )}
            <tr className="bg-muted/20">
              <td colSpan={6} className="px-3 py-2 text-xs italic text-muted-foreground">{trailer}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AclEditSection({
  title,
  peerHeader,
  direction,
  rows,
  touched,
  onUpdate,
  onRemove,
  onAdd,
}: {
  title: string;
  peerHeader: string;
  direction: Direction;
  rows: AclDraft[];
  touched: boolean;
  onUpdate: (id: string, patch: Partial<AclDraft>) => void;
  onRemove: (id: string) => void;
  onAdd: () => void;
}) {
  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">{title}</div>
      <div className="space-y-2">
        {rows
          .slice()
          .sort((a, b) => Number(b.priority) - Number(a.priority))
          .map((row) => {
            const invalid = touched && !draftValid(row);
            return (
              <div key={row.id} className="rounded-md border p-2">
                <div className="flex flex-wrap items-end gap-2">
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Priority (higher wins)</Label>
                    <Input
                      className="w-24"
                      value={row.priority}
                      onChange={(e) => onUpdate(row.id, { priority: e.target.value })}
                      placeholder={String(DEFAULT_PRIORITY)}
                      inputMode="numeric"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Protocol</Label>
                    <Select value={row.protocol} onValueChange={(v) => onUpdate(row.id, { protocol: v as Protocol })}>
                      <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">all</SelectItem>
                        <SelectItem value="tcp">tcp</SelectItem>
                        <SelectItem value="udp">udp</SelectItem>
                        <SelectItem value="icmp">icmp</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Port</Label>
                    <Input
                      className="w-20"
                      value={row.port}
                      onChange={(e) => onUpdate(row.id, { port: e.target.value })}
                      placeholder="any"
                      inputMode="numeric"
                      disabled={row.protocol === "icmp" || row.protocol === "all"}
                    />
                  </div>
                  <div className="space-y-1 min-w-[9rem] flex-1">
                    <Label className="text-xs text-muted-foreground">{peerHeader} (CIDR)</Label>
                    <Input
                      value={row.cidr}
                      onChange={(e) => onUpdate(row.id, { cidr: e.target.value })}
                      placeholder="0.0.0.0/0"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Action</Label>
                    <Select value={row.action} onValueChange={(v) => onUpdate(row.id, { action: v as "allow" | "drop" })}>
                      <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="allow">Allow</SelectItem>
                        <SelectItem value="drop">Drop</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="ml-auto"
                    onClick={() => onRemove(row.id)}
                    title="Remove rule"
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </div>

                <button
                  type="button"
                  className="mt-2 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => onUpdate(row.id, { advanced: !row.advanced })}
                >
                  {row.advanced ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
                  Advanced (raw OVN match)
                </button>
                {row.advanced ? (
                  <div className="mt-2 space-y-1">
                    <Input
                      value={row.match}
                      onChange={(e) => onUpdate(row.id, { match: e.target.value })}
                      placeholder='ip4.src == 10.0.0.0/24 && tcp.dst == 443'
                    />
                    <p className="text-[11px] text-muted-foreground">
                      A raw OVN match expression <strong>overrides</strong> the structured Source/Port fields above
                      for this rule.
                    </p>
                  </div>
                ) : null}

                {invalid ? (
                  <p className="mt-1 text-xs text-destructive">
                    Priority must be 0–32767. Source must be a valid CIDR and port numeric (or use a raw match).
                  </p>
                ) : null}
              </div>
            );
          })}
        <Button size="sm" variant="outline" onClick={onAdd}>
          <Plus className="size-4" /> Add {direction === "ingress" ? "inbound" : "outbound"} rule
        </Button>
      </div>
    </div>
  );
}
