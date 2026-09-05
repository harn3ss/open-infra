import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
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
import type { Subnet, Vpc } from "@/types/k8s";

export function VpcDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.vpc(namespace, name);

  const { data: vpc, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["vpc", namespace, name],
    queryFn: () => k8sGet<Vpc>(path),
    refetchInterval: 5000,
  });

  // Subnets that reference this VPC.
  const subnets = useK8sWatch<Subnet>(openinfraPaths.subnets(namespace));
  const inVpc = subnets.items.filter((s) => s.spec?.vpc === name && s.metadata.name);

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/vpcs" }),
  });

  if (isLoading) return <LoadingState label="Loading VPC…" />;
  if (isError || !vpc) return <ErrorState error={error} onRetry={refetch} />;

  return (
    <DetailShell
      backTo="/vpcs"
      backLabel="VPCs"
      icon={<Network className="size-5" />}
      title={name}
      subtitle={`VPC · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subnets">Subnets ({inVpc.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Bound namespaces">
                {vpc.spec?.namespaces?.length ? (
                  <code className="text-xs">{vpc.spec.namespaces.join(", ")}</code>
                ) : (
                  <span className="text-muted-foreground">none</span>
                )}
              </DetailRow>
              <DetailRow label="Subnets">{inVpc.length}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="subnets" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {inVpc.length ? (
                inVpc.map((s) => (
                  <DetailRow key={s.metadata.name} label={s.spec?.cidr ?? "subnet"}>
                    <Link
                      to="/subnets/$namespace/$name"
                      params={{ namespace, name: s.metadata.name ?? "" }}
                      className="text-primary hover:underline"
                    >
                      {s.metadata.name}
                    </Link>
                    {s.spec?.private === false ? " · public" : " · private"}
                  </DetailRow>
                ))
              ) : (
                <div className="p-4 text-sm text-muted-foreground">
                  No subnets in this VPC yet. Create a Subnet with <code>vpc: {name}</code>.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={vpc} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="VPC"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete VPC <span className="font-medium text-foreground">{name}</span> and its kube-ovn Vpc. Delete its subnets first.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
