import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Globe } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Condition, ElasticIp } from "@/types/k8s";

function eipStatus(e: ElasticIp): { label: string; tone: StatusTone } {
  const ready = e.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function ElasticIpDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.elasticip(namespace, name);

  const { data: eip, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["elasticip", namespace, name],
    queryFn: () => k8sGet<ElasticIp>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/elastic-ips" }),
  });

  if (isLoading) return <LoadingState label="Loading Elastic IP…" />;
  if (isError || !eip) return <ErrorState error={error} onRetry={refetch} />;

  const status = eipStatus(eip);
  const spec = eip.spec;
  const address = eip.status?.address ?? spec?.address;
  const mode = spec?.mode ?? "fip";
  const ports = spec?.ports ?? [];

  return (
    <DetailShell
      backTo="/elastic-ips"
      backLabel="Elastic IPs"
      icon={<Globe className="size-5" />}
      title={name}
      subtitle={`Elastic IP · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Address",
                    value: address ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{address}</code>
                        <CopyButton value={address} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">auto-allocated</span>
                    ),
                  },
                  {
                    label: "NAT gateway",
                    value: spec?.natGateway ? (
                      <Link
                        to="/nat-gateways/$namespace/$name"
                        params={{ namespace, name: spec.natGateway }}
                        className="text-primary hover:underline"
                      >
                        {spec.natGateway}
                      </Link>
                    ) : null,
                  },
                  {
                    label: "Status",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                  {
                    label: "Associated target",
                    value: spec?.target ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{spec.target}</code>
                        <CopyButton value={spec.target} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">not associated (allocated only)</span>
                    ),
                  },
                  {
                    label: "Mode",
                    value: (
                      <span>
                        {mode}
                        <span className="ml-1 text-xs text-muted-foreground">
                          {mode === "dnat" ? "(per-port forward)" : "(1:1 floating IP)"}
                        </span>
                      </span>
                    ),
                  },
                  {
                    label: "External network",
                    value: <code className="text-xs">{spec?.externalNetwork ?? "ovn-vpc-external-network"}</code>,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {mode === "dnat" ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Port forwards (DNAT)</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/50 text-xs text-muted-foreground">
                      <tr>
                        <th className="px-4 py-2 text-left font-medium">External port</th>
                        <th className="px-4 py-2 text-left font-medium">Internal port</th>
                        <th className="px-4 py-2 text-left font-medium">Protocol</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {ports.length ? (
                        ports.map((p, i) => (
                          <tr key={i}>
                            <td className="px-4 py-2"><code className="text-xs">{p.external}</code></td>
                            <td className="px-4 py-2"><code className="text-xs">{p.internal}</code></td>
                            <td className="px-4 py-2 text-muted-foreground">{p.protocol ?? "tcp"}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={3} className="px-4 py-3 text-xs text-muted-foreground">
                            No port forwards defined. Add ports to forward specific external ports to the target.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={eip} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Elastic IP"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently release Elastic IP <span className="font-medium text-foreground">{name}</span>. Any workload reached through it will lose this public address.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
