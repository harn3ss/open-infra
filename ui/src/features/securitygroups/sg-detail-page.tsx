import { useState } from "react";
import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Shield, Pencil, Copy } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { ruleDisplay, peerText } from "./sg-presets";
import { NewSecurityGroupDialog } from "./new-security-group-dialog";
import type {
  Application,
  OpenInfraFunction,
  SecurityGroup,
  SecurityGroupRule,
  VirtualMachine,
} from "@/types/k8s";

export function SecurityGroupDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const [edit, setEdit] = useState(false);
  const [copy, setCopy] = useState(false);
  const path = openinfraPaths.securitygroup(namespace, name);

  const { data: sg, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["securitygroup", namespace, name],
    queryFn: () => k8sGet<SecurityGroup>(path),
    refetchInterval: 5000,
  });

  // "Used by": resources in the namespace whose securityGroups include this SG.
  const apps = useK8sWatch<Application>(openinfraPaths.applications(namespace));
  const fns = useK8sWatch<OpenInfraFunction>(openinfraPaths.functions(namespace));
  const vms = useK8sWatch<VirtualMachine>(openinfraPaths.virtualmachines(namespace));
  const usedBy: { kind: string; name: string; to: string; params: Record<string, string> }[] = [];
  for (const a of apps.items)
    if (a.spec?.securityGroups?.includes(name) && a.metadata.name)
      usedBy.push({ kind: "Application", name: a.metadata.name, to: "/applications/$namespace/$name", params: { namespace, name: a.metadata.name } });
  for (const f of fns.items)
    if (f.spec?.securityGroups?.includes(name) && f.metadata.name)
      usedBy.push({ kind: "Function", name: f.metadata.name, to: "/functions/$namespace/$name", params: { namespace, name: f.metadata.name } });
  for (const v of vms.items)
    if (v.spec?.securityGroups?.includes(name) && v.metadata.name)
      usedBy.push({ kind: "Virtual Machine", name: v.metadata.name, to: "/vms/$namespace/$name", params: { namespace, name: v.metadata.name } });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/security-groups" }),
  });

  if (isLoading) return <LoadingState label="Loading security group…" />;
  if (isError || !sg) return <ErrorState error={error} onRetry={refetch} />;

  const ingress = (sg.spec?.ingress ?? []) as SecurityGroupRule[];
  const egress = sg.spec?.egress as SecurityGroupRule[] | undefined;

  return (
    <DetailShell
      backTo="/security-groups"
      backLabel="Security Groups"
      icon={<Shield className="size-5" />}
      title={name}
      subtitle={`Security group · ${namespace}`}
      actions={
        <span className="flex gap-2">
          <Button variant="outline" onClick={() => setCopy(true)}>
            <Copy className="size-4" /> Copy to new
          </Button>
          <Button onClick={() => setEdit(true)}>
            <Pencil className="size-4" /> Edit rules
          </Button>
        </span>
      }
    >
      <Tabs defaultValue="inbound">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList>
          <TabsTrigger value="inbound">Inbound rules</TabsTrigger>
          <TabsTrigger value="outbound">Outbound rules</TabsTrigger>
          <TabsTrigger value="usedby">Used by ({usedBy.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>
            <DangerZone inline
        resourceLabel="Security Group"
        resourceName={name}
        deleting={del.isPending}
        onConfirm={() => del.mutate()}
        confirmDescription={
          <>Permanently delete security group <span className="font-medium text-foreground">{name}</span> and its NetworkPolicy. Detach it from resources first.</>
        }
      />
          </div>

        <TabsContent value="inbound" className="pt-4">
          <RuleTable rules={ingress} peerKey="from" peerHeader="Source"
            empty="No inbound rules — nothing is allowed in to members of this group." />
        </TabsContent>

        <TabsContent value="outbound" className="pt-4">
          {egress ? (
            <RuleTable rules={egress} peerKey="to" peerHeader="Destination"
              empty="Egress restricted, but no destinations listed." note="DNS (UDP/TCP 53) is always allowed." />
          ) : (
            <Card><CardContent className="p-4 text-sm text-muted-foreground">
              All outbound traffic is allowed (no egress rules). Add outbound rules to restrict it.
            </CardContent></Card>
          )}
        </TabsContent>

        <TabsContent value="usedby" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {usedBy.length ? (
                usedBy.map((u) => (
                  <DetailRow key={`${u.kind}/${u.name}`} label={u.kind}>
                    <Link to={u.to} params={u.params} className="text-primary hover:underline">
                      {u.name}
                    </Link>
                  </DetailRow>
                ))
              ) : (
                <div className="p-4 text-sm text-muted-foreground">
                  Not attached to any resource yet. Attach it from a VM/App/Function's Security tab.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={sg} />
        </TabsContent>
      </Tabs>


      <NewSecurityGroupDialog
        open={edit}
        onOpenChange={(o) => { setEdit(o); if (!o) void refetch(); }}
        namespaces={[namespace]}
        defaultNamespace={namespace}
        editing={sg}
      />
      <NewSecurityGroupDialog
        open={copy}
        onOpenChange={setCopy}
        namespaces={[namespace]}
        defaultNamespace={namespace}
        copyFrom={sg}
      />
    </DetailShell>
  );
}

function RuleTable({
  rules,
  peerKey,
  peerHeader,
  empty,
  note,
}: {
  rules: SecurityGroupRule[];
  peerKey: "from" | "to";
  peerHeader: string;
  empty: string;
  note?: string;
}) {
  const rows = rules.flatMap((r) => {
    const d = ruleDisplay(r.protocol, r.ports);
    const peers = (r[peerKey] ?? [{}]) as { cidr?: string; securityGroup?: string; namespace?: string }[];
    return peers.map((p) => ({ ...d, peer: peerText(p), description: r.description }));
  });
  return (
    <div className="space-y-2">
      <div className="overflow-hidden rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
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
                  <td className="px-3 py-2">{r.type}</td>
                  <td className="px-3 py-2">{r.protocol}</td>
                  <td className="px-3 py-2">{r.portRange}</td>
                  <td className="px-3 py-2"><code className="text-xs">{r.peer}</code></td>
                  <td className="px-3 py-2 text-muted-foreground">{r.description ?? "—"}</td>
                </tr>
              ))
            ) : (
              <tr><td colSpan={5} className="px-3 py-3 text-xs text-muted-foreground">{empty}</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
    </div>
  );
}
