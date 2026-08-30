import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { Link } from "@tanstack/react-router";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Execution } from "@/types/k8s";
import { execTone } from "./statemachine-detail-page";

function pretty(s?: string): string {
  if (!s) return "";
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

function eventLabel(ev: Record<string, unknown>): string {
  const type = String(ev.type ?? "Event");
  const state = ev.state ? ` · ${String(ev.state)}` : "";
  const extra =
    ev.error ? ` (${String(ev.error)})` : ev.next ? ` → ${String(ev.next)}` : ev.attempt ? ` #${String(ev.attempt)}` : "";
  return `${type}${state}${extra}`;
}

export function ExecutionDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: ex, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["execution", namespace, name],
    queryFn: () => k8sGet<Execution>(openinfraPaths.execution(namespace, name)),
    // Poll while the execution is still running so progress appears live.
    refetchInterval: (q) => {
      const phase = (q.state.data as Execution | undefined)?.status?.phase;
      return phase && phase !== "Running" ? false : 2000;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.execution(namespace, name)),
    onSuccess: () => navigate({ to: "/statemachines" }),
  });

  if (isLoading) return <LoadingState label="Loading execution…" />;
  if (isError || !ex) return <ErrorState error={error} onRetry={refetch} />;

  const st = ex.status;
  const smName = ex.spec?.stateMachineRef?.name;
  const history = st?.history ?? [];

  return (
    <DetailShell
      backTo="/statemachines"
      backLabel="State Machines"
      icon={<Activity className="size-5" />}
      title={name}
      subtitle={`Execution · ${namespace}`}
      status={{ label: st?.phase ?? "Pending", tone: execTone(st?.phase) }}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="io">Input / Output</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="State machine">
                {smName ? (
                  <Link
                    to="/statemachines/$namespace/$name"
                    params={{ namespace, name: smName }}
                    className="text-primary hover:underline"
                  >
                    {smName}
                  </Link>
                ) : (
                  "—"
                )}
              </DetailRow>
              <DetailRow label="Phase">
                <StatusBadge status={st?.phase ?? "Pending"} tone={execTone(st?.phase)} />
              </DetailRow>
              <DetailRow label="Current state">{st?.currentState || "—"}</DetailRow>
              <DetailRow label="Started">{st?.startedAt || "—"}</DetailRow>
              <DetailRow label="Stopped">{st?.stoppedAt || "—"}</DetailRow>
              {st?.error ? (
                <DetailRow label="Error">
                  <span className="text-destructive">
                    <code className="text-xs">{st.error}</code>
                    {st.cause ? <span className="ml-2 text-xs text-muted-foreground">{st.cause}</span> : null}
                  </span>
                </DetailRow>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="io" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-2 p-4">
              <h3 className="text-sm font-semibold">Input</h3>
              <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 font-mono text-xs">
                {pretty(ex.spec?.input) || "{}"}
              </pre>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="space-y-2 p-4">
              <h3 className="text-sm font-semibold">Output</h3>
              <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 font-mono text-xs">
                {pretty(st?.output) || (st?.phase === "Succeeded" ? "(empty)" : "— (not finished)")}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="pt-4">
          <Card>
            <CardContent className="p-4">
              {history.length === 0 ? (
                <p className="text-sm text-muted-foreground">No history recorded yet.</p>
              ) : (
                <ol className="space-y-1">
                  {history.map((ev, i) => (
                    <li key={i} className="flex items-baseline gap-3 text-sm">
                      <span className="w-40 shrink-0 font-mono text-xs text-muted-foreground">
                        {ev.time ? String(ev.time) : ""}
                      </span>
                      <span>{eventLabel(ev)}</span>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={ex} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Execution"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
