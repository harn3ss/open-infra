import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Shield, Pencil, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { openinfraPaths } from "@/lib/k8s-paths";
import { ruleDisplay, peerText } from "@/features/securitygroups/sg-presets";
import type { SecurityGroup, SecurityGroupRule } from "@/types/k8s";

type AggRule = {
  sg: string;
  type: string;
  protocol: string;
  portRange: string;
  peer: string;
  description?: string;
};

/**
 * The resource-side security view (mirrors the EC2 instance "Security" tab):
 * the attached security groups + the *aggregated, read-only* inbound/outbound
 * rules across all of them, each row tagged with the group it came from. Rule
 * editing lives on the security group itself; here you only change membership.
 */
export function ResourceSecurityTab({
  namespace,
  securityGroups,
  onSave,
  saving,
  exposureNote,
}: {
  namespace: string;
  securityGroups: string[];
  onSave: (next: string[]) => void;
  saving?: boolean;
  exposureNote?: ReactNode;
}) {
  const [changing, setChanging] = useState(false);
  const { items: sgs } = useK8sWatch<SecurityGroup>(openinfraPaths.securitygroups(namespace));
  const sgByName = useMemo(
    () => new Map(sgs.map((s) => [s.metadata.name ?? "", s])),
    [sgs],
  );

  const { inbound, outbound, restrictsEgress } = useMemo(() => {
    const inbound: AggRule[] = [];
    const outbound: AggRule[] = [];
    let restrictsEgress = false;
    for (const name of securityGroups) {
      const sg = sgByName.get(name);
      if (!sg) continue;
      for (const r of (sg.spec?.ingress ?? []) as SecurityGroupRule[]) {
        const d = ruleDisplay(r.protocol, r.ports);
        for (const p of r.from ?? [{}]) {
          inbound.push({ sg: name, ...d, peer: peerText(p), description: r.description });
        }
      }
      if (sg.spec?.egress) {
        restrictsEgress = true;
        for (const r of sg.spec.egress as SecurityGroupRule[]) {
          const d = ruleDisplay(r.protocol, r.ports);
          for (const p of r.to ?? [{}]) {
            outbound.push({ sg: name, ...d, peer: peerText(p), description: r.description });
          }
        }
      }
    }
    return { inbound, outbound, restrictsEgress };
  }, [securityGroups, sgByName]);

  return (
    <div className="space-y-5 max-w-3xl">
      {/* Attached groups */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <div className="text-sm font-medium">Security groups</div>
          <Button size="sm" variant="outline" onClick={() => setChanging(true)} disabled={saving}>
            <Pencil className="size-4" /> Change security groups
          </Button>
        </div>
        {securityGroups.length ? (
          <div className="flex flex-wrap gap-1.5">
            {securityGroups.map((n) => (
              <Link key={n} to="/security-groups/$namespace/$name" params={{ namespace, name: n }}>
                <Badge variant="outline" className="cursor-pointer font-mono text-xs hover:bg-accent">
                  <Shield className="mr-1 size-3" />
                  {n}
                </Badge>
              </Link>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No security groups attached — this resource has no firewall. Click{" "}
            <strong>Change security groups</strong> to attach one.
          </p>
        )}
        {exposureNote ? <div className="mt-2">{exposureNote}</div> : null}
      </div>

      {/* Aggregated inbound */}
      <RulesTable
        title="Inbound rules"
        peerHeader="Source"
        rows={inbound}
        empty="No inbound rules — nothing can reach this resource from outside its security groups."
      />

      {/* Aggregated outbound */}
      <RulesTable
        title="Outbound rules"
        peerHeader="Destination"
        rows={outbound}
        empty={
          restrictsEgress
            ? "Only the rules above (plus DNS) are allowed outbound."
            : "All outbound traffic is allowed (no egress restrictions)."
        }
      />

      <ChangeSecurityGroupsDialog
        open={changing}
        onOpenChange={setChanging}
        available={sgs.map((s) => s.metadata.name ?? "").filter(Boolean)}
        attached={securityGroups}
        onSave={(next) => {
          onSave(next);
          setChanging(false);
        }}
      />
    </div>
  );
}

function RulesTable({
  title,
  peerHeader,
  rows,
  empty,
}: {
  title: string;
  peerHeader: string;
  rows: AggRule[];
  empty: string;
}) {
  return (
    <div>
      <div className="mb-2 text-sm font-medium">{title}</div>
      <div className="overflow-hidden rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Security group</th>
              <th className="px-3 py-2 text-left font-medium">Type</th>
              <th className="px-3 py-2 text-left font-medium">Protocol</th>
              <th className="px-3 py-2 text-left font-medium">Port range</th>
              <th className="px-3 py-2 text-left font-medium">{peerHeader}</th>
              <th className="px-3 py-2 text-left font-medium">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.length ? (
              rows.map((r, i) => (
                <tr key={i}>
                  <td className="px-3 py-2"><code className="text-xs">{r.sg}</code></td>
                  <td className="px-3 py-2">{r.type}</td>
                  <td className="px-3 py-2">{r.protocol}</td>
                  <td className="px-3 py-2">{r.portRange}</td>
                  <td className="px-3 py-2"><code className="text-xs">{r.peer}</code></td>
                  <td className="px-3 py-2 text-muted-foreground">{r.description ?? "—"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} className="px-3 py-3 text-xs text-muted-foreground">{empty}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ChangeSecurityGroupsDialog({
  open,
  onOpenChange,
  available,
  attached,
  onSave,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  available: string[];
  attached: string[];
  onSave: (next: string[]) => void;
}) {
  const [sel, setSel] = useState<string[]>(attached);
  // Reset selection each time the dialog opens.
  useEffect(() => {
    if (open) setSel(attached);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const [toAdd, setToAdd] = useState("");
  const addable = available.filter((n) => !sel.includes(n)).sort((a, b) => a.localeCompare(b));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change security groups</DialogTitle>
          <DialogDescription>
            Attach or detach security groups. Rules are the union of every attached group.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <div className="mb-1 text-xs font-medium text-muted-foreground">Associated security groups</div>
            {sel.length ? (
              <div className="space-y-1">
                {sel.map((n) => (
                  <div key={n} className="flex items-center justify-between rounded-md border px-3 py-1.5">
                    <code className="text-xs">{n}</code>
                    <Button size="sm" variant="ghost" onClick={() => setSel(sel.filter((x) => x !== n))} title="Detach">
                      <X className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">None — this resource will have no firewall.</p>
            )}
          </div>
          {addable.length ? (
            <div className="flex items-end gap-2">
              <div className="flex-1 space-y-1">
                <div className="text-xs font-medium text-muted-foreground">Associate a security group</div>
                <Select value={toAdd} onValueChange={setToAdd}>
                  <SelectTrigger><SelectValue placeholder="Select a security group" /></SelectTrigger>
                  <SelectContent>
                    {addable.map((n) => (
                      <SelectItem key={n} value={n}>{n}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button
                variant="outline"
                disabled={!toAdd}
                onClick={() => {
                  if (toAdd) setSel([...sel, toAdd]);
                  setToAdd("");
                }}
              >
                <Plus className="size-4" /> Add
              </Button>
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => onSave(sel)}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
