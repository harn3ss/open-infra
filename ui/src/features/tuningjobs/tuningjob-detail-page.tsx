import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Target } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
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
import type { TuningJob } from "@/types/k8s";
import { tuningTone } from "./tuningjobs-page";

function trialTone(s?: string): "success" | "destructive" | "accent" | "muted" {
  return tuningTone(s);
}

function fmtParams(p?: Record<string, string>): string {
  if (!p) return "";
  return Object.entries(p)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

export function TuningJobDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: tj, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["tuningjob", namespace, name],
    queryFn: () => k8sGet<TuningJob>(openinfraPaths.tuningjob(namespace, name)),
    refetchInterval: (q) => {
      const phase = (q.state.data as TuningJob | undefined)?.status?.phase;
      return phase && phase !== "Running" ? false : 3000;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.tuningjob(namespace, name)),
    onSuccess: () => navigate({ to: "/tuning" }),
  });

  if (isLoading) return <LoadingState label="Loading tuning job…" />;
  if (isError || !tj) return <ErrorState error={error} onRetry={refetch} />;

  const st = tj.status;
  const trials = st?.trials ?? [];
  const goal = tj.spec?.objective?.goal ?? "Minimize";

  return (
    <DetailShell
      backTo="/tuning"
      backLabel="Tuning Jobs"
      icon={<Target className="size-5" />}
      title={name}
      subtitle={`Tuning job · ${namespace}`}
      status={{ label: st?.phase ?? "Pending", tone: tuningTone(st?.phase) }}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="trials">Trials</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Phase">
                <StatusBadge status={st?.phase ?? "Pending"} tone={tuningTone(st?.phase)} />
              </DetailRow>
              <DetailRow label="Objective">{tj.spec?.objective?.metric ?? "OPENINFRA_METRIC"} · <Badge variant="secondary">{goal}</Badge></DetailRow>
              <DetailRow label="Trials">{st?.trialsComplete ?? 0} / {st?.trialsTotal ?? 0} complete</DetailRow>
              <DetailRow label="Image"><code className="text-xs">{tj.spec?.training?.image}</code></DetailRow>
              {st?.bestTrial ? (
                <DetailRow label="Best trial">
                  <Link
                    to="/trainingjobs/$namespace/$name"
                    params={{ namespace, name: st.bestTrial }}
                    className="text-primary hover:underline"
                  >
                    {st.bestTrial}
                  </Link>
                  <span className="ml-2 text-xs text-muted-foreground">metric <code>{st.bestValue}</code></span>
                </DetailRow>
              ) : null}
              {st?.bestParameters ? (
                <DetailRow label="Best hyperparameters"><code className="text-xs">{st.bestParameters}</code></DetailRow>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trials" className="pt-4">
          <Card>
            <CardContent className="p-0">
              {trials.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No trials yet.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead className="border-b border-border text-left text-xs text-muted-foreground">
                    <tr>
                      <th className="p-3 font-medium">Trial</th>
                      <th className="p-3 font-medium">Hyperparameters</th>
                      <th className="p-3 font-medium">Status</th>
                      <th className="p-3 font-medium">Metric</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trials.map((tr) => (
                      <tr
                        key={tr.name}
                        className={`border-b border-border last:border-0 ${tr.name === st?.bestTrial ? "bg-primary/5" : ""}`}
                      >
                        <td className="p-3">
                          <Link
                            to="/trainingjobs/$namespace/$name"
                            params={{ namespace, name: tr.name }}
                            className="text-primary hover:underline"
                          >
                            {tr.name}
                          </Link>
                          {tr.name === st?.bestTrial ? <Badge variant="secondary" className="ml-2">best</Badge> : null}
                        </td>
                        <td className="p-3 text-xs text-muted-foreground"><code>{fmtParams(tr.parameters)}</code></td>
                        <td className="p-3"><StatusBadge status={tr.status ?? "Pending"} tone={trialTone(tr.status)} /></td>
                        <td className="p-3"><code className="text-xs">{tr.metric ?? "—"}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={tj} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Tuning Job"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
