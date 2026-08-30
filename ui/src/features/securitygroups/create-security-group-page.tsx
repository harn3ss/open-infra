import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Shield, AlertTriangle } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";
import { RuleSection, nextId } from "./new-security-group-dialog";
import { buildSpec, emptyRow, rowValid, type RuleRow } from "./sg-presets";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Single-page create for kind: SecurityGroup (issue #96), matching AWS's VPC "Create security group"
 * page: basic identity + an inbound-rules table + an outbound-rules table. Reuses the same rule editor
 * as the edit dialog; edit stays on the detail page.
 */
export function CreateSecurityGroupPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { scoped } = useNamespace();
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => nsWatch.items.map((n) => n.metadata.name).filter(Boolean).sort() as string[],
    [nsWatch.items],
  );

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [touched, setTouched] = useState(false);
  const [inbound, setInbound] = useState<RuleRow[]>([emptyRow(nextId())]);
  const [outbound, setOutbound] = useState<RuleRow[]>([]);

  const create = useMutation({
    mutationFn: () =>
      k8sCreate(openinfraPaths.securitygroups(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "SecurityGroup",
        metadata: { name, namespace },
        spec: buildSpec(inbound, outbound),
      } as K8sObject),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.securitygroups()) });
      navigate({ to: "/security-groups/$namespace/$name", params: { namespace, name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const rulesValid = inbound.every(rowValid) && outbound.every(rowValid);
  const nameError = touched && !nameOk ? "Lowercase letters, numbers and hyphens; must start/end alphanumeric." : null;
  const openToWorld = inbound.some((r) => r.peerKind === "anywhere" && ["ssh", "rdp"].includes(r.typeId));
  const dirty = name.length > 0 || outbound.length > 0;

  const submit = () => {
    setTouched(true);
    if (!nameOk || !rulesValid) return; // AWS: never disable the button; validate on submit
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Shield className="size-6 text-primary" />}
      title="Create Security Group"
      description="A reusable firewall rule set. Pick a rule type (it fills in the protocol and port) and who's allowed — then attach it to apps, functions, and VMs."
      onCancel={() => navigate({ to: "/security-groups" })}
      onSubmit={submit}
      submitLabel="Create Security Group"
      pending={create.isPending}
      error={create.error}
      dirty={dirty}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Identity</h3>
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
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
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
              A rule allows SSH/RDP from <strong>anywhere</strong> (0.0.0.0/0). Fine for a quick test; for
              anything real, scope the source to a specific IP/CIDR.
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
      </div>
    </CreateShell>
  );
}
