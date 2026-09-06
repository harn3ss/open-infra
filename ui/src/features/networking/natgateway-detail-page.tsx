import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Waypoints, Info } from "lucide-react";
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
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { StatusTone } from "@/lib/format";
import type { Condition, ElasticIp, NatGateway } from "@/types/k8s";

function natStatus(g: NatGateway): { label: string; tone: StatusTone } {
  const ready = g.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function NatGatewayDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.natgateway(namespace, name);

  const { data: gw, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["natgateway", namespace, name],
    queryFn: () => k8sGet<NatGateway>(path),
    refetchInterval: 5000,
  });

  // Elastic IPs allocated on this gateway.
  const eips = useK8sWatch<ElasticIp>(openinfraPaths.elasticips(namespace));
  const onGateway = eips.items.filter((e) => e.spec?.natGateway === name && e.metadata.name);

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/nat-gateways" }),
  });

  if (isLoading) return <LoadingState label="Loading NAT gateway…" />;
  if (isError || !gw) return <ErrorState error={error} onRetry={refetch} />;

  const status = natStatus(gw);
  const spec = gw.spec;
  const internalIp = spec?.internalIp;
  const sourceCidrs = spec?.egress?.sourceCidrs ?? [];
  const nodeSelector = Object.entries(spec?.nodeSelector ?? {});

  return (
    <DetailShell
      backTo="/nat-gateways"
      backLabel="NAT Gateways"
      icon={<Waypoints className="size-5" />}
      title={name}
      subtitle={`NAT gateway · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="elasticips">Elastic IPs ({onGateway.length})</TabsTrigger>
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
                    label: "VPC",
                    value: spec?.vpc ? (
                      <Link
                        to="/vpcs/$namespace/$name"
                        params={{ namespace, name: spec.vpc }}
                        className="text-primary hover:underline"
                      >
                        {spec.vpc}
                      </Link>
                    ) : null,
                  },
                  {
                    label: "Subnet",
                    value: spec?.subnet ? (
                      <Link
                        to="/subnets/$namespace/$name"
                        params={{ namespace, name: spec.subnet }}
                        className="text-primary hover:underline"
                      >
                        {spec.subnet}
                      </Link>
                    ) : null,
                  },
                  {
                    label: "Internal IP",
                    value: internalIp ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{internalIp}</code>
                        <CopyButton value={internalIp} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "External network",
                    value: <code className="text-xs">{spec?.externalNetwork ?? "ovn-vpc-external-network"}</code>,
                  },
                  {
                    label: "Egress public IP",
                    value: spec?.egress?.publicIp ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{spec.egress.publicIp}</code>
                        <CopyButton value={spec.egress.publicIp} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">auto-allocated</span>
                    ),
                  },
                  {
                    label: "Status",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                  {
                    label: "Egress source CIDRs (SNAT)",
                    value: sourceCidrs.length ? (
                      <code className="text-xs">{sourceCidrs.join(", ")}</code>
                    ) : null,
                  },
                  {
                    label: "Node placement",
                    value: nodeSelector.length ? (
                      <code className="text-xs">{nodeSelector.map(([k, v]) => `${k}=${v}`).join(", ")}</code>
                    ) : (
                      <span className="text-muted-foreground">any node</span>
                    ),
                  },
                ]}
              />
            </CardContent>
          </Card>

          {/* Honest model note: kube-ovn folds the internet gateway into the NAT gateway. */}
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              This is the border device for its VPC — it plays both the AWS <span className="font-medium text-foreground">NAT gateway</span> role
              (SNAT egress for the source CIDRs above) and the <span className="font-medium text-foreground">internet gateway</span> role (the
              routable ingress hop an L2 VIP can't provide). There is no separate internet-gateway object on this substrate. For traffic to reach it,
              the VPC needs a default route <code className="text-xs">0.0.0.0/0 → {internalIp ?? "internalIp"}</code> pointing at this gateway, and
              public ingress is attached with an Elastic IP.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="elasticips" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {onGateway.length ? (
                onGateway.map((e) => (
                  <div key={e.metadata.name} className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
                    <Link
                      to="/elastic-ips/$namespace/$name"
                      params={{ namespace, name: e.metadata.name ?? "" }}
                      className="font-medium text-primary hover:underline"
                    >
                      {e.metadata.name}
                    </Link>
                    <div className="flex items-center gap-3 text-muted-foreground">
                      <code className="text-xs">{e.status?.address ?? e.spec?.address ?? "auto"}</code>
                      <span>{e.spec?.mode ?? "fip"}</span>
                      <span>{e.spec?.target ? `→ ${e.spec.target}` : "allocated only"}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-4 text-sm text-muted-foreground">
                  No Elastic IPs on this gateway yet. Allocate one with <code>natGateway: {name}</code> to attach public ingress.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={gw} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="NAT Gateway"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete NAT gateway <span className="font-medium text-foreground">{name}</span>. Release its Elastic IPs and remove the VPC default route that targets it first.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
