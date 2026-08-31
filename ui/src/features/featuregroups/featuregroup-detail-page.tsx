import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Table2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { FeatureGroup } from "@/types/k8s";

export function FeatureGroupDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: fg, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["featuregroup", namespace, name],
    queryFn: () => k8sGet<FeatureGroup>(openinfraPaths.featuregroup(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.featuregroup(namespace, name)),
    onSuccess: () => navigate({ to: "/feature-store" }),
  });

  if (isLoading) return <LoadingState label="Loading feature group…" />;
  if (isError || !fg) return <ErrorState error={error} onRetry={refetch} />;

  const s = fg.spec;
  const endpoint = fg.status?.endpoint ?? `http://${name}.${namespace}.svc.cluster.local:8080`;
  const idField = s?.recordIdentifier ?? "id";

  return (
    <DetailShell
      backTo="/feature-store"
      backLabel="Feature Store"
      icon={<Table2 className="size-5" />}
      title={name}
      subtitle={`Feature group · ${namespace}`}
      status={claimHealth(fg)}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Record identifier"><code className="text-xs">{idField}</code></DetailRow>
              {s?.eventTime ? <DetailRow label="Event time"><code className="text-xs">{s.eventTime}</code></DetailRow> : null}
              <DetailRow label="Endpoint"><code className="text-xs">{endpoint}</code></DetailRow>
              {s?.ttlSeconds ? <DetailRow label="Online TTL">{s.ttlSeconds}s</DetailRow> : null}
              {s?.features?.length ? (
                <DetailRow label="Features">
                  <span className="flex flex-wrap gap-1">
                    {s.features.map((f) => (
                      <Badge key={f.name} variant="secondary">{f.name}{f.type ? `: ${f.type}` : ""}</Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="usage" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-4 text-sm">
              <p className="text-muted-foreground">The feature store serves two operations over its cluster-local endpoint (call it from a Function, Model, or any in-cluster workload):</p>
              <div>
                <p className="font-medium">PutRecord</p>
                <pre className="mt-1 overflow-auto rounded-md bg-secondary p-3 font-mono text-xs">{`curl -X POST ${endpoint}/records \\
  -d '{"${idField}": "c-123", "amount": 42.5}'`}</pre>
              </div>
              <div>
                <p className="font-medium">GetRecord</p>
                <pre className="mt-1 overflow-auto rounded-md bg-secondary p-3 font-mono text-xs">{`curl ${endpoint}/records/c-123
# → {"${idField}":"c-123","amount":42.5}`}</pre>
              </div>
              <p className="text-xs text-muted-foreground">Values keep their JSON types. v1 is the online store only; an offline (object-store history, for training) store is a planned follow-up.</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={fg} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Feature Group"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
