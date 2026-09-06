import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { GitBranch, Plus, Trash2, Pencil, X } from "lucide-react";
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
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import type { Subnet, Vpc, VpcPeering, VpcRoute } from "@/types/k8s";

/**
 * Given the local /30 side of a peering link (e.g. "169.254.0.1/30" or
 * "169.254.0.1"), return the far-side host IP within the same /30 (the peer's
 * connect IP). A /30 has exactly two usable hosts (base+1, base+2); the far side
 * is whichever one the local address is not. Used both here (to add the paired
 * route) and by the route-table editor's peering target resolver.
 */
export function peerFarSide(localConnectIP: string): string {
  const ip = ((localConnectIP ?? "").split("/")[0] ?? "").trim();
  const parts = ip.split(".");
  if (parts.length !== 4) return ip;
  const last = Number(parts[3]);
  if (!Number.isFinite(last)) return ip;
  const base = last & ~3; // /30 network address
  const h1 = base + 1;
  const h2 = base + 2;
  const far = last === h1 ? h2 : h1;
  return `${parts[0]}.${parts[1]}.${parts[2]}.${far}`;
}

const IP_OR_LINK_RE = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/;
const CIDR_RE = /^(\d{1,3})(\.\d{1,3}){3}\/\d{1,2}$/;

let SEQ = 0;
const nextId = () => `pe${SEQ++}`;

interface PeeringDraft {
  id: string;
  remoteVpc: string;
  localConnectIP: string;
  /** Also append a routes[] entry for the remote CIDR (the paired-route helper). */
  addRoute: boolean;
  remoteCidr: string;
}

function draftValid(d: PeeringDraft): boolean {
  if (!d.remoteVpc.trim()) return false;
  if (!IP_OR_LINK_RE.test(d.localConnectIP.trim())) return false;
  if (d.addRoute && !CIDR_RE.test(d.remoteCidr.trim())) return false;
  return true;
}

/**
 * Editor for a VPC's `spec.peerings` — symmetric /30 interconnects. open-infra has
 * NO request/accept handshake: you declare the peering on BOTH VPCs (each names the
 * other + its own /30 side) and add a route for the remote CIDR on each. This editor
 * writes THIS VPC's half (peerings + optionally the paired route); the remote VPC
 * must be configured the same way for traffic to flow.
 */
export function PeeringEditor({
  vpc,
  namespace,
  onSaved,
}: {
  vpc: Vpc;
  namespace: string;
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const name = vpc.metadata.name ?? "";
  const peerings = useMemo<VpcPeering[]>(() => vpc.spec?.peerings ?? [], [vpc.spec?.peerings]);

  const vpcs = useK8sWatch<Vpc>(openinfraPaths.vpcs(namespace));
  const subnets = useK8sWatch<Subnet>(openinfraPaths.subnets(namespace));
  const otherVpcs = useMemo(
    () => vpcs.items.map((v) => v.metadata.name).filter((n): n is string => Boolean(n) && n !== name).sort(),
    [vpcs.items, name],
  );
  // Remote VPC name -> its subnet CIDRs (to suggest the route destination).
  const cidrsByVpc = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const s of subnets.items) {
      const v = s.spec?.vpc;
      const c = s.spec?.cidr;
      if (v && c) m.set(v, [...(m.get(v) ?? []), c]);
    }
    return m;
  }, [subnets.items]);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<PeeringDraft[]>([]);
  const [touched, setTouched] = useState(false);

  const save = useMutation({
    mutationFn: async () => {
      const path = openinfraPaths.vpc(namespace, name);
      const cur = await k8sGet<Vpc>(path);
      const nextPeerings: VpcPeering[] = draft.map((d) => ({
        remoteVpc: d.remoteVpc.trim(),
        localConnectIP: d.localConnectIP.trim(),
      }));
      // Merge paired routes for rows that requested one (dedup by cidr).
      const routes: VpcRoute[] = [...(cur.spec?.routes ?? [])];
      for (const d of draft) {
        if (!d.addRoute || !CIDR_RE.test(d.remoteCidr.trim())) continue;
        const cidr = d.remoteCidr.trim();
        const nextHop = peerFarSide(d.localConnectIP.trim());
        if (!routes.some((r) => r.cidr === cidr)) routes.push({ cidr, nextHop });
      }
      const spec = { ...cur.spec, peerings: nextPeerings, routes };
      return k8sReplace<Vpc>(path, { ...cur, spec } as Vpc);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.vpcs()) });
      setEditing(false);
      onSaved();
    },
  });

  const startEdit = () => {
    setDraft(
      peerings.map((p) => ({
        id: nextId(),
        remoteVpc: p.remoteVpc ?? "",
        localConnectIP: p.localConnectIP ?? "",
        addRoute: false,
        remoteCidr: "",
      })),
    );
    setTouched(false);
    save.reset();
    setEditing(true);
  };

  const update = (id: string, patch: Partial<PeeringDraft>) =>
    setDraft((rows) => rows.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  const allValid = draft.every(draftValid);

  const submit = () => {
    setTouched(true);
    if (!allValid) return;
    save.mutate();
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
        <GitBranch className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <span>
          VPC peering is a symmetric /30 interconnect — <strong>declare it on both VPCs</strong> (each names
          the other and its own link IP) and add a route for the remote CIDR on each side. There is no
          accept step. This editor writes <span className="font-medium text-foreground">{name}</span>'s half;
          configure the remote VPC the same way. Peering is non-transitive — use a Transit Gateway for
          hub-and-spoke.
        </span>
      </div>

      {!editing ? (
        <>
          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Remote VPC</th>
                  <th className="px-3 py-2 text-left font-medium">This VPC's link IP</th>
                  <th className="px-3 py-2 text-left font-medium">Peer link IP</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {peerings.length ? (
                  peerings.map((p, i) => (
                    <tr key={i}>
                      <td className="px-3 py-2">
                        {p.remoteVpc && otherVpcs.includes(p.remoteVpc) ? (
                          <Link
                            to="/vpcs/$namespace/$name"
                            params={{ namespace, name: p.remoteVpc }}
                            className="text-primary hover:underline"
                          >
                            {p.remoteVpc}
                          </Link>
                        ) : (
                          <code className="text-xs">{p.remoteVpc || "—"}</code>
                        )}
                      </td>
                      <td className="px-3 py-2"><code className="text-xs">{p.localConnectIP || "—"}</code></td>
                      <td className="px-3 py-2 text-muted-foreground">
                        <code className="text-xs">{p.localConnectIP ? peerFarSide(p.localConnectIP) : "—"}</code>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={3} className="px-3 py-3 text-xs text-muted-foreground">
                      No peerings declared. Add one to interconnect this VPC with another.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <Button variant="outline" onClick={startEdit}>
            <Pencil className="size-4" /> Edit peerings
          </Button>
        </>
      ) : (
        <div className="space-y-3">
          {draft.map((row) => {
            const remoteCidrs = cidrsByVpc.get(row.remoteVpc) ?? [];
            const rowInvalid = touched && !draftValid(row);
            return (
              <div key={row.id} className="flex flex-wrap items-end gap-2 rounded-md border p-3">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Remote VPC</Label>
                  <Select value={row.remoteVpc || undefined} onValueChange={(v) => update(row.id, { remoteVpc: v })}>
                    <SelectTrigger className="w-44"><SelectValue placeholder="Select a VPC" /></SelectTrigger>
                    <SelectContent>
                      {(otherVpcs.length ? otherVpcs : row.remoteVpc ? [row.remoteVpc] : []).map((v) => (
                        <SelectItem key={v} value={v}>{v}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">This VPC's link IP (/30)</Label>
                  <Input
                    className="w-40"
                    value={row.localConnectIP}
                    onChange={(e) => update(row.id, { localConnectIP: e.target.value })}
                    placeholder="169.254.0.1/30"
                  />
                </div>
                <div className="flex items-center gap-2 pb-2">
                  <input
                    id={`${row.id}-route`}
                    type="checkbox"
                    className="size-4 accent-primary"
                    checked={row.addRoute}
                    onChange={(e) => update(row.id, { addRoute: e.target.checked })}
                  />
                  <Label htmlFor={`${row.id}-route`} className="text-xs">Add route to remote CIDR</Label>
                </div>
                {row.addRoute ? (
                  <div className="space-y-1">
                    <Label className="text-xs text-muted-foreground">Remote CIDR</Label>
                    <Input
                      className="w-40"
                      value={row.remoteCidr}
                      onChange={(e) => update(row.id, { remoteCidr: e.target.value })}
                      placeholder={remoteCidrs[0] ?? "10.1.0.0/24"}
                    />
                    {remoteCidrs.length ? (
                      <p className="text-[11px] text-muted-foreground">
                        {row.remoteVpc}'s subnets: {remoteCidrs.join(", ")}
                      </p>
                    ) : null}
                  </div>
                ) : null}
                <Button
                  size="sm"
                  variant="ghost"
                  className="ml-auto"
                  onClick={() => setDraft((rows) => rows.filter((r) => r.id !== row.id))}
                  title="Remove peering"
                >
                  <Trash2 className="size-4" />
                </Button>
                {rowInvalid ? (
                  <p className="w-full text-xs text-destructive">
                    Pick a remote VPC and a valid link IP (e.g. 169.254.0.1/30). If adding a route, give a valid CIDR.
                  </p>
                ) : null}
              </div>
            );
          })}
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              setDraft((rows) => [
                ...rows,
                { id: nextId(), remoteVpc: "", localConnectIP: "", addRoute: true, remoteCidr: "" },
              ])
            }
          >
            <Plus className="size-4" /> Add peering
          </Button>

          {save.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {save.error instanceof ApiError ? save.error.message : "Failed to save peerings."}
            </div>
          ) : null}

          <Card>
            <CardContent className="flex justify-end gap-2 p-3">
              <Button variant="outline" onClick={() => setEditing(false)} disabled={save.isPending}>
                <X className="size-4" /> Cancel
              </Button>
              <Button onClick={submit} disabled={save.isPending || (touched && !allValid)}>
                {save.isPending ? <Spinner className="text-current" /> : <GitBranch className="size-4" />}
                Save peerings
              </Button>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
