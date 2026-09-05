import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { LayoutGrid } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { Application, Subnet, VirtualMachine } from "@/types/k8s";

export function SubnetDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.subnet(namespace, name);

  const { data: sub, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["subnet", namespace, name],
    queryFn: () => k8sGet<Subnet>(path),
    refetchInterval: 5000,
  });

  // "In this subnet": Applications / VMs whose spec.subnet names this subnet.
  const apps = useK8sWatch<Application>(openinfraPaths.applications(namespace));
  const vms = useK8sWatch<VirtualMachine>(openinfraPaths.virtualmachines(namespace));
  const members: { kind: string; name: string; to: string; params: Record<string, string> }[] = [];
  for (const a of apps.items)
    if ((a.spec as { subnet?: string } | undefined)?.subnet === name && a.metadata.name)
      members.push({ kind: "Application", name: a.metadata.name, to: "/applications/$namespace/$name", params: { namespace, name: a.metadata.name } });
  for (const v of vms.items)
    if ((v.spec as { subnet?: string } | undefined)?.subnet === name && v.metadata.name)
      members.push({ kind: "Virtual Machine", name: v.metadata.name, to: "/vms/$namespace/$name", params: { namespace, name: v.metadata.name } });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/subnets" }),
  });

  if (isLoading) return <LoadingState label="Loading subnet…" />;
  if (isError || !sub) return <ErrorState error={error} onRetry={refetch} />;

  const spec = sub.spec ?? { cidr: "" };
  const isPrivate = spec.private !== false;

  return (
    <DetailShell
      backTo="/subnets"
      backLabel="Subnets"
      icon={<LayoutGrid className="size-5" />}
      title={name}
      subtitle={`Subnet · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="members">In this subnet ({members.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="CIDR"><code className="text-xs">{spec.cidr}</code></DetailRow>
              <DetailRow label="VPC">
                {spec.vpc ? (
                  <Link to="/vpcs/$namespace/$name" params={{ namespace, name: spec.vpc }} className="text-primary hover:underline">{spec.vpc}</Link>
                ) : (
                  <span className="text-muted-foreground">default (ovn-cluster)</span>
                )}
              </DetailRow>
              <DetailRow label="Isolation">
                {isPrivate
                  ? "Private — OVN-enforced; only this subnet + allowSubnets may reach it."
                  : "Public — reachable across the cluster network."}
              </DetailRow>
              <DetailRow label="Allowed subnets (holes)">
                {spec.allowSubnets?.length ? (
                  <code className="text-xs">{spec.allowSubnets.join(", ")}</code>
                ) : (
                  <span className="text-muted-foreground">none</span>
                )}
              </DetailRow>
              <DetailRow label="Gateway">
                {spec.gateway ?? <span className="text-muted-foreground">first usable in CIDR</span>}
              </DetailRow>
              <DetailRow label="Bound namespaces">
                {spec.namespaces?.length ? (
                  <code className="text-xs">{spec.namespaces.join(", ")}</code>
                ) : (
                  <span className="text-muted-foreground">none (join via a workload's subnet field)</span>
                )}
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="members" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {members.length ? (
                members.map((m) => (
                  <DetailRow key={`${m.kind}/${m.name}`} label={m.kind}>
                    <Link to={m.to} params={m.params} className="text-primary hover:underline">{m.name}</Link>
                  </DetailRow>
                ))
              ) : (
                <div className="p-4 text-sm text-muted-foreground">
                  No workloads in this subnet yet. Set <code>subnet: {name}</code> on an Application or Virtual Machine.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={sub} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Subnet"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete subnet <span className="font-medium text-foreground">{name}</span> and its kube-ovn Subnet. Move workloads out of it first.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
