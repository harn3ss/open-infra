import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Share2, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { StatusBadge } from "@/components/common/status-badge";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Condition, TransitGateway } from "@/types/k8s";

function tgStatus(t: TransitGateway): { label: string; tone: StatusTone } {
  const ready = (t.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True" || t.status?.ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

/** A monospace value with a copy affordance, for IPs and CIDRs. */
function Mono({ value }: { value: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <code className="text-xs">{value}</code>
      <CopyButton value={value} />
    </span>
  );
}

export function TransitGatewayDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.transitgateway(namespace, name);

  const { data: tg, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["transitgateway", namespace, name],
    queryFn: () => k8sGet<TransitGateway>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/transit-gateways" }),
  });

  if (isLoading) return <LoadingState label="Loading transit gateway…" />;
  if (isError || !tg) return <ErrorState error={error} onRetry={refetch} />;

  const attachments = tg.spec?.attachments ?? [];
  const spokes = attachments.map((a) => a.vpc).filter(Boolean);
  const status = tgStatus(tg);

  return (
    <DetailShell
      backTo="/transit-gateways"
      backLabel="Transit Gateways"
      icon={<Share2 className="size-5" />}
      title={name}
      subtitle={`Transit Gateway · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="attachments">Attachments ({attachments.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="p-5">
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Namespace", value: namespace },
                  { label: "Attachments", value: attachments.length },
                  {
                    label: "Spokes",
                    value: spokes.length ? (
                      <span className="flex flex-wrap gap-x-2">
                        {spokes.map((s) => (
                          <Link
                            key={s}
                            to="/vpcs/$namespace/$name"
                            params={{ namespace, name: s }}
                            className="text-primary hover:underline"
                          >
                            {s}
                          </Link>
                        ))}
                      </span>
                    ) : (
                      ""
                    ),
                  },
                  { label: "Status", value: <StatusBadge status={status.label} tone={status.tone} /> },
                ]}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="attachments" className="space-y-3 pt-4">
          <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-sm">
            <Info className="mt-0.5 size-4 shrink-0 text-warning" />
            <div className="space-y-1">
              <p className="font-medium">Each spoke must also be wired on its own VPC.</p>
              <p className="text-muted-foreground">
                The transit gateway defines only the hub side of each attachment (a /30 peer link + route). There is
                no accept step. For transitive routing to work, every spoke <code className="text-xs">Vpc</code> also
                needs a <code className="text-xs">peering</code> to the hub (its own <code className="text-xs">spokeConnectIP</code> side)
                and <code className="text-xs">routes</code> to every other spoke's CIDR via the hub — edit those on each
                VPC's Route table and Peering tabs.
              </p>
            </div>
          </div>

          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">VPC</th>
                  <th className="px-3 py-2 text-left font-medium">Spoke CIDR</th>
                  <th className="px-3 py-2 text-left font-medium">Hub connect IP</th>
                  <th className="px-3 py-2 text-left font-medium">Spoke connect IP</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {attachments.length ? (
                  attachments.map((a, i) => (
                    <tr key={`${a.vpc}-${i}`}>
                      <td className="px-3 py-2">
                        {a.vpc ? (
                          <Link
                            to="/vpcs/$namespace/$name"
                            params={{ namespace, name: a.vpc }}
                            className="text-primary hover:underline"
                          >
                            {a.vpc}
                          </Link>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2">{a.cidr ? <Mono value={a.cidr} /> : <span className="text-muted-foreground">—</span>}</td>
                      <td className="px-3 py-2">{a.hubConnectIP ? <Mono value={a.hubConnectIP} /> : <span className="text-muted-foreground">—</span>}</td>
                      <td className="px-3 py-2">{a.spokeConnectIP ? <Mono value={a.spokeConnectIP} /> : <span className="text-muted-foreground">—</span>}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 text-xs text-muted-foreground">
                      No attachments. Add spokes on the transit gateway's spec, then wire each spoke VPC.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={tg} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Transit Gateway"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete transit gateway <span className="font-medium text-foreground">{name}</span> and its
                hub attachments. Spoke VPC peerings and routes are not removed — clean those up on each VPC.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
