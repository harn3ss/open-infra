import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Route as RouteIcon, Plus, Trash2, Pencil, X } from "lucide-react";
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
import type { NatGateway, TransitGateway, Vpc, VpcRoute } from "@/types/k8s";
import { peerFarSide } from "./peering-editor";

const CIDR_RE = /^(\d{1,3})(\.\d{1,3}){3}\/\d{1,2}$/;
const IP_RE = /^(\d{1,3})(\.\d{1,3}){3}$/;

let SEQ = 0;
const nextId = () => `rt${SEQ++}`;

type TargetType = "nat" | "peering" | "tgw" | "custom";

interface RouteDraft {
  id: string;
  cidr: string;
  targetType: TargetType;
  natGw?: string; // NatGateway name
  peeringVpc?: string; // a peering's remoteVpc
  tgwKey?: string; // "<tgwName>|<vpc>" attachment key
  customIp?: string;
}

interface NatOpt { name: string; ip: string }
interface PeerOpt { remoteVpc: string; farSide: string }
interface TgwOpt { key: string; label: string; hubIp: string }

/**
 * Editor for a VPC's `spec.routes` — the (single) route table shared by every subnet
 * in the VPC. Mirrors AWS's route-table Routes editor: a destination CIDR + a target
 * chosen by TYPE (NAT/Internet gateway, Peering, Transit gateway, or a custom IP),
 * which resolves to the OVN `nextHop` IP that is actually stored. There is one route
 * table per VPC (no per-subnet association) plus an implicit, non-editable local route.
 */
export function RouteTableEditor({
  vpc,
  namespace,
  localCidrs,
  onSaved,
}: {
  vpc: Vpc;
  namespace: string;
  /** The VPC's own address space (union of its subnet CIDRs) — the implicit local route. */
  localCidrs: string[];
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const name = vpc.metadata.name ?? "";
  const routes = useMemo<VpcRoute[]>(() => vpc.spec?.routes ?? [], [vpc.spec?.routes]);

  // Target candidates for the picker.
  const natgws = useK8sWatch<NatGateway>(openinfraPaths.natgateways(namespace));
  const tgws = useK8sWatch<TransitGateway>(openinfraPaths.transitgateways(namespace));

  const natOpts = useMemo<NatOpt[]>(
    () =>
      natgws.items
        .filter((g) => g.spec?.vpc === name && g.metadata.name && g.spec?.internalIp)
        .map((g) => ({ name: g.metadata.name as string, ip: g.spec!.internalIp })),
    [natgws.items, name],
  );
  const peerOpts = useMemo<PeerOpt[]>(
    () =>
      (vpc.spec?.peerings ?? [])
        .filter((p) => p.remoteVpc && p.localConnectIP)
        .map((p) => ({ remoteVpc: p.remoteVpc, farSide: peerFarSide(p.localConnectIP) })),
    [vpc.spec?.peerings],
  );
  const tgwOpts = useMemo<TgwOpt[]>(() => {
    const out: TgwOpt[] = [];
    for (const t of tgws.items) {
      const tn = t.metadata.name ?? "";
      for (const a of t.spec?.attachments ?? []) {
        if (a.vpc === name && a.hubConnectIP) {
          out.push({ key: `${tn}|${a.vpc}`, label: `${tn} (hub ${a.hubConnectIP})`, hubIp: a.hubConnectIP });
        }
      }
    }
    return out;
  }, [tgws.items, name]);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<RouteDraft[]>([]);
  const [touched, setTouched] = useState(false);

  const resolveNextHop = (row: RouteDraft): string => {
    switch (row.targetType) {
      case "nat":
        return natOpts.find((o) => o.name === row.natGw)?.ip ?? "";
      case "peering":
        return peerOpts.find((o) => o.remoteVpc === row.peeringVpc)?.farSide ?? "";
      case "tgw":
        return tgwOpts.find((o) => o.key === row.tgwKey)?.hubIp ?? "";
      case "custom":
        return (row.customIp ?? "").trim();
    }
  };

  const rowValid = (row: RouteDraft) => CIDR_RE.test(row.cidr.trim()) && IP_RE.test(resolveNextHop(row));

  // Best-effort reverse mapping of a stored nextHop back to a target type/selection,
  // so "Edit routes" pre-fills the picker instead of dropping to a bare IP.
  const routeToDraft = (r: VpcRoute): RouteDraft => {
    const base: RouteDraft = { id: nextId(), cidr: r.cidr ?? "", targetType: "custom", customIp: r.nextHop ?? "" };
    const nat = natOpts.find((o) => o.ip === r.nextHop);
    if (nat) return { ...base, targetType: "nat", natGw: nat.name, customIp: undefined };
    const peer = peerOpts.find((o) => o.farSide === r.nextHop);
    if (peer) return { ...base, targetType: "peering", peeringVpc: peer.remoteVpc, customIp: undefined };
    const tgw = tgwOpts.find((o) => o.hubIp === r.nextHop);
    if (tgw) return { ...base, targetType: "tgw", tgwKey: tgw.key, customIp: undefined };
    return base;
  };

  const describeTarget = (nextHop: string): string => {
    const nat = natOpts.find((o) => o.ip === nextHop);
    if (nat) return `NAT gateway · ${nat.name}`;
    const peer = peerOpts.find((o) => o.farSide === nextHop);
    if (peer) return `Peering · ${peer.remoteVpc}`;
    const tgw = tgwOpts.find((o) => o.hubIp === nextHop);
    if (tgw) return `Transit gateway · ${tgw.label}`;
    return "Custom IP";
  };

  const save = useMutation({
    mutationFn: async () => {
      const path = openinfraPaths.vpc(namespace, name);
      const cur = await k8sGet<Vpc>(path);
      const nextRoutes: VpcRoute[] = draft.map((row) => ({ cidr: row.cidr.trim(), nextHop: resolveNextHop(row) }));
      const spec = { ...cur.spec, routes: nextRoutes };
      return k8sReplace<Vpc>(path, { ...cur, spec } as Vpc);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.vpcs()) });
      setEditing(false);
      onSaved();
    },
  });

  const startEdit = () => {
    setDraft(routes.map(routeToDraft));
    setTouched(false);
    save.reset();
    setEditing(true);
  };

  const update = (id: string, patch: Partial<RouteDraft>) =>
    setDraft((rows) => rows.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  const allValid = draft.every(rowValid);

  const submit = () => {
    setTouched(true);
    if (!allValid) return;
    save.mutate();
  };

  const localLabel = localCidrs.length ? localCidrs.join(", ") : "this VPC's subnets";

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
        <RouteIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <span>
          One route table per VPC (kube-ovn). Every subnet in{" "}
          <span className="font-medium text-foreground">{name}</span> shares it — there are no per-subnet
          route tables or explicit associations. A target is chosen by type but stored as its resolved
          next-hop IP.
        </span>
      </div>

      {!editing ? (
        <>
          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Destination</th>
                  <th className="px-3 py-2 text-left font-medium">Target</th>
                  <th className="px-3 py-2 text-left font-medium">Next hop</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                <tr className="bg-muted/20">
                  <td className="px-3 py-2"><code className="text-xs">{localLabel}</code></td>
                  <td className="px-3 py-2 text-muted-foreground">local</td>
                  <td className="px-3 py-2 text-muted-foreground">— (implicit, always present)</td>
                </tr>
                {routes.map((r, i) => (
                  <tr key={i}>
                    <td className="px-3 py-2"><code className="text-xs">{r.cidr}</code></td>
                    <td className="px-3 py-2">{describeTarget(r.nextHop)}</td>
                    <td className="px-3 py-2 text-muted-foreground"><code className="text-xs">{r.nextHop}</code></td>
                  </tr>
                ))}
                {routes.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-3 py-3 text-xs text-muted-foreground">
                      No static routes. Add a default route (0.0.0.0/0 → a NAT gateway) for internet egress.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <Button variant="outline" onClick={startEdit}>
            <Pencil className="size-4" /> Edit routes
          </Button>
        </>
      ) : (
        <div className="space-y-3">
          <div className="rounded-md border">
            <div className="grid grid-cols-[1fr_2fr_auto] gap-2 border-b bg-muted/50 px-3 py-2 text-xs font-medium text-muted-foreground">
              <span>Destination (CIDR)</span>
              <span>Target</span>
              <span />
            </div>
            <div className="grid grid-cols-[1fr_2fr_auto] items-center gap-2 border-b bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
              <code>{localLabel}</code>
              <span>local — implicit, not editable</span>
              <span />
            </div>
            <div className="space-y-2 p-2">
              {draft.map((row) => {
                const invalid = touched && !rowValid(row);
                return (
                  <div key={row.id} className="flex flex-wrap items-end gap-2 rounded-md border p-2">
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Destination</Label>
                      <Input
                        className="w-36"
                        value={row.cidr}
                        onChange={(e) => update(row.id, { cidr: e.target.value })}
                        placeholder="0.0.0.0/0"
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Target type</Label>
                      <Select
                        value={row.targetType}
                        onValueChange={(v) => update(row.id, { targetType: v as TargetType })}
                      >
                        <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="nat">NAT / Internet gateway</SelectItem>
                          <SelectItem value="peering">Peering connection</SelectItem>
                          <SelectItem value="tgw">Transit gateway</SelectItem>
                          <SelectItem value="custom">Custom IP</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Target</Label>
                      {row.targetType === "nat" ? (
                        natOpts.length ? (
                          <Select value={row.natGw} onValueChange={(v) => update(row.id, { natGw: v })}>
                            <SelectTrigger className="w-52"><SelectValue placeholder="Select a NAT gateway" /></SelectTrigger>
                            <SelectContent>
                              {natOpts.map((o) => (
                                <SelectItem key={o.name} value={o.name}>{o.name} ({o.ip})</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <p className="flex h-9 w-52 items-center text-xs text-muted-foreground">
                            No NAT gateways in this VPC — create one, or use Custom IP.
                          </p>
                        )
                      ) : null}
                      {row.targetType === "peering" ? (
                        peerOpts.length ? (
                          <Select value={row.peeringVpc} onValueChange={(v) => update(row.id, { peeringVpc: v })}>
                            <SelectTrigger className="w-52"><SelectValue placeholder="Select a peering" /></SelectTrigger>
                            <SelectContent>
                              {peerOpts.map((o) => (
                                <SelectItem key={o.remoteVpc} value={o.remoteVpc}>{o.remoteVpc} → {o.farSide}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <p className="flex h-9 w-52 items-center text-xs text-muted-foreground">
                            No peerings on this VPC — add one on the Peering tab.
                          </p>
                        )
                      ) : null}
                      {row.targetType === "tgw" ? (
                        tgwOpts.length ? (
                          <Select value={row.tgwKey} onValueChange={(v) => update(row.id, { tgwKey: v })}>
                            <SelectTrigger className="w-52"><SelectValue placeholder="Select an attachment" /></SelectTrigger>
                            <SelectContent>
                              {tgwOpts.map((o) => (
                                <SelectItem key={o.key} value={o.key}>{o.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <p className="flex h-9 w-52 items-center text-xs text-muted-foreground">
                            No transit-gateway attachment for this VPC — use Custom IP.
                          </p>
                        )
                      ) : null}
                      {row.targetType === "custom" ? (
                        <Input
                          className="w-52"
                          value={row.customIp ?? ""}
                          onChange={(e) => update(row.id, { customIp: e.target.value })}
                          placeholder="10.20.0.254"
                        />
                      ) : null}
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Next hop</Label>
                      <div className="flex h-9 w-32 items-center rounded-md border bg-muted px-2 text-xs text-muted-foreground">
                        {resolveNextHop(row) || "—"}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="ml-auto"
                      onClick={() => setDraft((rows) => rows.filter((r) => r.id !== row.id))}
                      title="Remove route"
                    >
                      <Trash2 className="size-4" />
                    </Button>
                    {invalid ? (
                      <p className="w-full text-xs text-destructive">
                        Give a valid destination CIDR (e.g. 0.0.0.0/0) and a target that resolves to an IP.
                      </p>
                    ) : null}
                  </div>
                );
              })}
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  setDraft((rows) => [...rows, { id: nextId(), cidr: "", targetType: "nat" }])
                }
              >
                <Plus className="size-4" /> Add route
              </Button>
            </div>
          </div>

          {save.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {save.error instanceof ApiError ? save.error.message : "Failed to save routes."}
            </div>
          ) : null}

          <Card>
            <CardContent className="flex justify-end gap-2 p-3">
              <Button variant="outline" onClick={() => setEditing(false)} disabled={save.isPending}>
                <X className="size-4" /> Cancel
              </Button>
              <Button onClick={submit} disabled={save.isPending || (touched && !allValid)}>
                {save.isPending ? <Spinner className="text-current" /> : <RouteIcon className="size-4" />}
                Save routes
              </Button>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
