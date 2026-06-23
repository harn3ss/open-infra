import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Shield, Plus, Trash2, AlertTriangle } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/common/states";
import { ApiError, k8sCreate } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";
import {
  PEER_KINDS,
  RULE_TYPES,
  emptyRow,
  rowToRule,
  rowValid,
  ruleTypeById,
  type RuleRow,
} from "./sg-presets";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
let SEQ = 0;
const nextId = () => `r${SEQ++}`;

/**
 * AWS-style Security Group create dialog. Inbound/outbound rules are built from a
 * "Type" preset (auto-fills protocol+port) + a source — so the only real question
 * per rule is "who can reach it". Outbound left empty = all outbound allowed
 * (DNS is always auto-allowed once you restrict egress), matching AWS defaults.
 */
export function NewSecurityGroupDialog({
  open,
  onOpenChange,
  namespaces,
  defaultNamespace,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  namespaces: string[];
  defaultNamespace?: string;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [touched, setTouched] = useState(false);
  const [inbound, setInbound] = useState<RuleRow[]>([emptyRow(nextId())]);
  const [outbound, setOutbound] = useState<RuleRow[]>([]);

  function reset() {
    setName("");
    setTouched(false);
    setInbound([emptyRow(nextId())]);
    setOutbound([]);
    create.reset();
  }

  const create = useMutation({
    mutationFn: () => {
      const spec: Record<string, unknown> = {
        // Always present (even if empty) so inbound is default-deny + your allows.
        ingress: inbound.map((r) => rowToRule(r, "from")).filter(Boolean),
      };
      // Only restrict egress if the user added outbound rules (else all outbound
      // is allowed, like a new AWS SG). The composition auto-allows DNS.
      if (outbound.length) {
        spec.egress = outbound.map((r) => rowToRule(r, "to")).filter(Boolean);
      }
      return k8sCreate(openinfraPaths.securitygroups(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "SecurityGroup",
        metadata: { name, namespace },
        spec,
      } as K8sObject);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: watchQueryKey(openinfraPaths.securitygroups()),
      });
      reset();
      onOpenChange(false);
    },
  });

  const nameError =
    touched && !RFC1123.test(name)
      ? "Lowercase letters, numbers and hyphens; must start/end alphanumeric."
      : null;
  const rulesValid =
    inbound.every(rowValid) && outbound.every(rowValid);
  const openToWorld = inbound.some(
    (r) => r.peerKind === "anywhere" && ["ssh", "rdp"].includes(r.typeId),
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (create.isPending) return;
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent className="flex max-h-[90vh] max-w-2xl flex-col gap-0 p-0">
        <DialogHeader className="border-b border-border p-5">
          <DialogTitle className="flex items-center gap-2">
            <Shield className="size-5 text-primary" />
            New Security Group
          </DialogTitle>
          <DialogDescription>
            A reusable firewall rule set. Pick a rule type (it fills in the
            protocol and port) and who's allowed — attach it to apps, functions,
            and VMs.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 space-y-5 overflow-auto p-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="sg-name">Name</Label>
              <Input
                id="sg-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="web"
                autoFocus
              />
              {nameError ? <p className="text-xs text-destructive">{nameError}</p> : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sg-ns">Namespace</Label>
              <Select value={namespace} onValueChange={setNamespace}>
                <SelectTrigger id="sg-ns">
                  <SelectValue placeholder="Namespace" />
                </SelectTrigger>
                <SelectContent>
                  {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                    <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <RuleSection
            title="Inbound rules"
            hint="Who may connect to members of this group. No rules = nothing inbound is allowed."
            dir="from"
            rows={inbound}
            onChange={setInbound}
          />

          {openToWorld ? (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
              <span>
                A rule allows SSH/RDP from <strong>anywhere</strong> (0.0.0.0/0).
                Fine for a quick test; for anything real, scope the source to a
                specific IP/CIDR.
              </span>
            </div>
          ) : null}

          <RuleSection
            title="Outbound rules"
            hint="Where members may connect out. Leave empty to allow all outbound (DNS is always allowed)."
            dir="to"
            rows={outbound}
            onChange={setOutbound}
          />

          {create.error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {create.error instanceof ApiError ? create.error.message : "Failed to create the security group."}
            </div>
          ) : null}
        </div>

        <DialogFooter className="border-t border-border p-4">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => (RFC1123.test(name) ? create.mutate() : setTouched(true))}
            disabled={create.isPending || !RFC1123.test(name) || !rulesValid}
          >
            {create.isPending ? <Spinner className="text-current" /> : <Shield className="size-4" />}
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RuleSection({
  title,
  hint,
  dir,
  rows,
  onChange,
}: {
  title: string;
  hint: string;
  dir: "from" | "to";
  rows: RuleRow[];
  onChange: (rows: RuleRow[]) => void;
}) {
  const update = (id: string, patch: Partial<RuleRow>) =>
    onChange(rows.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  const peerLabel = dir === "from" ? "Source" : "Destination";

  return (
    <div>
      <div className="mb-1 text-sm font-medium">{title}</div>
      <p className="mb-2 text-xs text-muted-foreground">{hint}</p>
      <div className="space-y-2">
        {rows.map((row) => {
          const type = ruleTypeById(row.typeId);
          const peerSpec = PEER_KINDS.find((k) => k.id === row.peerKind)!;
          return (
            <div key={row.id} className="flex flex-wrap items-end gap-2 rounded-md border p-2">
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">Type</Label>
                <Select value={row.typeId} onValueChange={(v) => update(row.id, { typeId: v })}>
                  <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {RULE_TYPES.map((t) => (
                      <SelectItem key={t.id} value={t.id}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {type.custom ? (
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Port</Label>
                  <Input
                    className="w-20"
                    value={row.customPort}
                    onChange={(e) => update(row.id, { customPort: e.target.value })}
                    placeholder="8080"
                    inputMode="numeric"
                  />
                </div>
              ) : (
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Port</Label>
                  <div className="flex h-9 w-20 items-center rounded-md border bg-muted px-2 text-xs text-muted-foreground">
                    {type.ports.length ? type.ports.join(",") : "all"}/{type.protocol}
                  </div>
                </div>
              )}
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">{peerLabel}</Label>
                <Select value={row.peerKind} onValueChange={(v) => update(row.id, { peerKind: v as RuleRow["peerKind"] })}>
                  <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {PEER_KINDS.map((k) => (
                      <SelectItem key={k.id} value={k.id}>{k.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {peerSpec.needsValue ? (
                <div className="space-y-1 flex-1 min-w-[8rem]">
                  <Label className="text-xs text-muted-foreground">&nbsp;</Label>
                  <Input
                    value={row.peerValue}
                    onChange={(e) => update(row.id, { peerValue: e.target.value })}
                    placeholder={peerSpec.placeholder}
                  />
                </div>
              ) : null}
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto"
                onClick={() => onChange(rows.filter((r) => r.id !== row.id))}
                title="Remove rule"
              >
                <Trash2 className="size-4" />
              </Button>
            </div>
          );
        })}
        <Button
          size="sm"
          variant="outline"
          onClick={() => onChange([...rows, emptyRow(nextId())])}
        >
          <Plus className="size-4" /> Add {dir === "from" ? "inbound" : "outbound"} rule
        </Button>
      </div>
    </div>
  );
}
