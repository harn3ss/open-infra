import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Radio, RefreshCw } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { DangerZone } from "@/components/common/danger-zone";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { k8sDelete, k8sGet, listQueues, type StreamInfo } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age, formatBytes, type StatusTone } from "@/lib/format";
import type { Stream } from "@/types/k8s";

function streamStatus(s: Stream): { label: string; tone: StatusTone } {
  const conds = s.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (s.status?.ready || ready?.status === "True")
    return { label: "Ready", tone: "success" };
  if (synced?.status === "False")
    return { label: "Error", tone: "destructive" };
  return { label: s.status?.phase || "Provisioning", tone: "warning" };
}

/**
 * Match a Stream CR to its live JetStream stream (from the BFF /queues stats) so
 * the detail page can show real stored-message counts, size and consumers. The
 * controller records the JetStream stream name in `status.stream`; failing that,
 * fall back to matching a subject under this Stream's `cdc.<name>.` prefix.
 */
function matchJetStream(
  cr: Stream,
  name: string,
  queues: StreamInfo[] | undefined,
): StreamInfo | undefined {
  if (!queues) return undefined;
  const jsName = cr.status?.stream;
  if (jsName) {
    const byName = queues.find((q) => q.name === jsName);
    if (byName) return byName;
  }
  const prefix = `cdc.${name}.`;
  return queues.find((q) => (q.subjects ?? []).some((s) => s.startsWith(prefix)));
}

export function StreamDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["stream", namespace, name],
    queryFn: () => k8sGet<Stream>(openinfraPaths.stream(namespace, name)),
    refetchInterval: 5000,
  });

  const queuesQ = useQuery({
    queryKey: ["queues"],
    queryFn: listQueues,
    refetchInterval: 10_000,
    retry: false,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.stream(namespace, name)),
    onSuccess: () => navigate({ to: "/streams" }),
  });

  if (isLoading) return <LoadingState label="Loading stream…" />;
  if (isError || !data) return <ErrorState error={error} onRetry={refetch} />;

  const src = data.spec?.source;
  const status = streamStatus(data);
  const js = matchJetStream(data, name, queuesQ.data);
  const jsName = data.status?.stream ?? js?.name ?? `${name}`;
  const subjectPattern = data.status?.subjects || `cdc.${name}.>`;
  const scope =
    src?.tables?.length
      ? `${src.tables.length} table${src.tables.length === 1 ? "" : "s"}`
      : src?.schemas?.length
        ? src.schemas.join(", ")
        : "all tables";

  const liveMissing = queuesQ.isError || (queuesQ.data && !js);

  return (
    <DetailShell
      backTo="/streams"
      backLabel="Streams"
      icon={<Radio className="size-5" />}
      title={name}
      subtitle={`CDC Stream · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="consumers">Consumers</TabsTrigger>
          <TabsTrigger value="throughput">Throughput</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="space-y-5 p-5">
              <div>
                <h3 className="mb-3 text-sm font-semibold">Source</h3>
                <KeyValuePairs
                  columns={3}
                  items={[
                    {
                      label: "Engine",
                      value: src?.engine ? (
                        <Badge variant="secondary">{src.engine}</Badge>
                      ) : (
                        "—"
                      ),
                    },
                    { label: "Host", value: src?.host },
                    { label: "Database", value: src?.database },
                    { label: "Scope", value: scope },
                    {
                      label: "SSL",
                      value: src?.ssl ? "Enabled" : "Disabled",
                    },
                    { label: "Namespace", value: namespace },
                  ]}
                />
              </div>

              <div className="border-t border-border pt-4">
                <h3 className="mb-3 text-sm font-semibold">
                  Destination (NATS JetStream)
                </h3>
                <KeyValuePairs
                  columns={3}
                  items={[
                    {
                      label: "JetStream stream",
                      value: (
                        <span className="inline-flex items-center gap-1">
                          <code className="text-xs">{jsName}</code>
                          <CopyButton value={jsName} />
                        </span>
                      ),
                    },
                    {
                      label: "Published subjects",
                      value: (
                        <span className="inline-flex items-center gap-1">
                          <code className="text-xs">{subjectPattern}</code>
                          <CopyButton value={subjectPattern} />
                        </span>
                      ),
                    },
                    {
                      label: "Status",
                      value: (
                        <StatusBadge status={status.label} tone={status.tone} />
                      ),
                    },
                    {
                      label: "Stored messages",
                      value: js ? js.messages.toLocaleString() : "—",
                    },
                    { label: "Size", value: js ? formatBytes(js.bytes) : "—" },
                    {
                      label: "Age",
                      value: age(data.metadata.creationTimestamp),
                    },
                  ]}
                />
                <p className="mt-3 text-xs text-muted-foreground">
                  A Stream taps the source database's change log (Debezium /
                  CDC) and publishes every row change as a real-time event onto
                  the subjects above. Apps, Functions, and sinks subscribe to
                  consume them.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="consumers" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold">Subscribers</h3>
                  <p className="max-w-2xl text-sm text-muted-foreground">
                    Durable JetStream consumers reading this stream — the apps,
                    Functions, and apply-sinks subscribing to its subjects. Each
                    keeps its own cursor, so every subscriber sees the full
                    change feed.
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => queuesQ.refetch()}
                  aria-label="Refresh"
                  disabled={queuesQ.isFetching}
                >
                  <RefreshCw className="size-4" />
                </Button>
              </div>
              {liveMissing ? (
                <EmptyState
                  title="Live consumer stats unavailable"
                  description="The JetStream stream backing this Stream isn't reporting yet (it appears once the source connects and the stream is created)."
                />
              ) : (
                <KeyValuePairs
                  columns={3}
                  items={[
                    {
                      label: "Durable consumers",
                      value: js ? String(js.consumers) : "—",
                    },
                    {
                      label: "Subjects",
                      value: (
                        <span className="flex flex-wrap gap-1">
                          {(js?.subjects ?? [subjectPattern]).map((sub) => (
                            <Badge key={sub} variant="secondary">
                              <code className="text-xs">{sub}</code>
                            </Badge>
                          ))}
                        </span>
                      ),
                    },
                    {
                      label: "Backlog (stored)",
                      value: js ? js.messages.toLocaleString() : "—",
                    },
                  ]}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="throughput" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold">
                    Throughput &amp; retention
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    Live counters for the backing JetStream stream.
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => queuesQ.refetch()}
                  aria-label="Refresh"
                  disabled={queuesQ.isFetching}
                >
                  <RefreshCw className="size-4" />
                </Button>
              </div>
              {liveMissing ? (
                <EmptyState
                  title="No live metrics yet"
                  description="Metrics appear once the JetStream stream is created and begins receiving change events."
                />
              ) : (
                <KeyValuePairs
                  columns={3}
                  items={[
                    {
                      label: "Stored messages",
                      value: js ? js.messages.toLocaleString() : "—",
                    },
                    {
                      label: "Total size",
                      value: js ? formatBytes(js.bytes) : "—",
                    },
                    {
                      label: "Consumers",
                      value: js ? String(js.consumers) : "—",
                    },
                  ]}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={data} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Stream"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete the stream{" "}
                <span className="font-medium text-foreground">{name}</span>. CDC
                capture stops and its JetStream subjects are torn down. This
                cannot be undone.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
