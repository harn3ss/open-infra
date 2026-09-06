import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Info, ScrollText } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Condition, FlowLog } from "@/types/k8s";

function flowLogStatus(f: FlowLog): { label: string; tone: StatusTone } {
  const ready = (f.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True" || f.status?.ready === true) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function FlowLogDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.flowlog(namespace, name);

  const { data: flowLog, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["flowlog", namespace, name],
    queryFn: () => k8sGet<FlowLog>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/flow-logs" }),
  });

  if (isLoading) return <LoadingState label="Loading flow log…" />;
  if (isError || !flowLog) return <ErrorState error={error} onRetry={refetch} />;

  const status = flowLogStatus(flowLog);
  const nodeSelector = flowLog.spec?.nodeSelector ?? {};
  const nodeEntries = Object.entries(nodeSelector);

  return (
    <DetailShell
      backTo="/flow-logs"
      backLabel="Flow Logs"
      icon={<ScrollText className="size-5" />}
      title={name}
      subtitle={`Flow Log · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="records">Flow records</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="p-5">
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Sampling rate",
                    value: `1:${flowLog.spec?.samplingRate ?? 64}`,
                  },
                  {
                    label: "Collector namespace",
                    value: (
                      <code className="text-xs">{flowLog.spec?.namespace ?? "kube-system"}</code>
                    ),
                  },
                  {
                    label: "Node selector",
                    value: nodeEntries.length ? (
                      <span className="flex flex-wrap gap-1">
                        {nodeEntries.map(([k, v]) => (
                          <code key={k} className="rounded bg-muted px-1.5 py-0.5 text-xs">
                            {k}={v}
                          </code>
                        ))}
                      </span>
                    ) : (
                      "All nodes"
                    ),
                  },
                  {
                    label: "Status",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>
          <div className="mt-4 flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              Flow logging samples <strong>all</strong> node traffic (OVS sFlow, 1:{flowLog.spec?.samplingRate ?? 64}) to
              Loki — it is cluster-wide, not per-VPC or per-ENI. To see a specific VPC or subnet, filter the
              records by its CIDR under the <strong>Flow records</strong> tab. Records carry the 5-tuple
              (source/dest IP + port), protocol, byte count, and node.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="records" className="pt-4">
          <div className="mb-3 flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              Sampled flow records from Loki. Scope to a VPC or subnet by adding a CIDR filter in the panel.
              This is a sampled 1:N stream, not a per-connection ledger.
            </span>
          </div>
          {/* openinfra-flow-logs is the OVS sFlow → Loki records dashboard (provisioned out-of-band,
              like the other openinfra-* dashboards). */}
          <GrafanaEmbed uid="openinfra-flow-logs" height={600} />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={flowLog} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Flow Log"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete flow log <span className="font-medium text-foreground">{name}</span> and stop node traffic sampling. Existing records already in Loki are unaffected.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
