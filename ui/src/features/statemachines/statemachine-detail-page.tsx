import { useMemo, useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Route } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { claimHealth } from "@/lib/resource-health";
import { age } from "@/lib/format";
import { ApiError, k8sCreate, k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Execution,
  type StateMachine,
} from "@/types/k8s";

/** Phase → StatusBadge tone. */
export function execTone(phase?: string): "success" | "destructive" | "muted" | "accent" {
  switch (phase) {
    case "Succeeded":
      return "success";
    case "Failed":
    case "TimedOut":
      return "destructive";
    case "Running":
      return "accent";
    default:
      return "muted";
  }
}

function prettyJson(s?: string): string {
  if (!s) return "";
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

/** Start a new Execution against this state machine, with a JSON input. */
function StartExecution({ namespace, name }: { namespace: string; name: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [input, setInput] = useState("{}");
  const inputError = (() => {
    try {
      JSON.parse(input);
      return "";
    } catch (e) {
      return "Input is not valid JSON: " + (e instanceof Error ? e.message : String(e));
    }
  })();

  const start = useMutation({
    mutationFn: () =>
      k8sCreate<Execution>(openinfraPaths.executions(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Execution",
        metadata: { generateName: `${name}-`, namespace },
        spec: { stateMachineRef: { name }, input },
      } as unknown as Execution),
    onSuccess: (created) => {
      void qc.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.executions(namespace)) });
      const execName = created?.metadata?.name;
      if (execName) navigate({ to: "/executions/$namespace/$name", params: { namespace, name: execName } });
    },
  });

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <h3 className="text-sm font-semibold">Start execution</h3>
        <p className="text-xs text-muted-foreground">Provide the input JSON passed to the workflow's StartAt state.</p>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          className="min-h-[120px] w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
          aria-label="Execution input JSON"
        />
        {inputError ? <p className="text-xs text-destructive">{inputError}</p> : null}
        {start.isError ? (
          <p className="text-xs text-destructive">
            {start.error instanceof ApiError ? start.error.message : "Failed to start execution."}
          </p>
        ) : null}
        <Button onClick={() => start.mutate()} disabled={start.isPending || Boolean(inputError)}>
          <Play className="size-4" />
          Start execution
        </Button>
      </CardContent>
    </Card>
  );
}

export function StateMachineDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: sm, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["statemachine", namespace, name],
    queryFn: () => k8sGet<StateMachine>(openinfraPaths.statemachine(namespace, name)),
  });

  const execWatch = useK8sWatch<Execution>(openinfraPaths.executions(namespace));
  const executions = useMemo(
    () =>
      execWatch.items
        .filter((e) => e.spec?.stateMachineRef?.name === name)
        .sort((a, b) =>
          (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""),
        ),
    [execWatch.items, name],
  );

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.statemachine(namespace, name)),
    onSuccess: () => navigate({ to: "/statemachines" }),
  });

  if (isLoading) return <LoadingState label="Loading state machine…" />;
  if (isError || !sm) return <ErrorState error={error} onRetry={refetch} />;

  return (
    <DetailShell
      backTo="/statemachines"
      backLabel="State Machines"
      icon={<Route className="size-5" />}
      title={name}
      subtitle={`State machine · ${namespace}`}
      status={claimHealth(sm)}
    >
      <Tabs defaultValue="executions">
        <TabsList>
          <TabsTrigger value="executions">Executions</TabsTrigger>
          <TabsTrigger value="definition">Definition</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="executions" className="space-y-4 pt-4">
          <StartExecution namespace={namespace} name={name} />
          <Card>
            <CardContent className="p-0">
              {executions.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No executions yet.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead className="border-b border-border text-left text-xs text-muted-foreground">
                    <tr>
                      <th className="p-3 font-medium">Name</th>
                      <th className="p-3 font-medium">Phase</th>
                      <th className="p-3 font-medium">State</th>
                      <th className="p-3 font-medium">Started</th>
                    </tr>
                  </thead>
                  <tbody>
                    {executions.map((e) => (
                      <tr
                        key={e.metadata.name}
                        className="cursor-pointer border-b border-border last:border-0 hover:bg-secondary/50"
                        onClick={() =>
                          navigate({
                            to: "/executions/$namespace/$name",
                            params: { namespace, name: e.metadata.name ?? "" },
                          })
                        }
                      >
                        <td className="p-3 font-medium">{e.metadata.name}</td>
                        <td className="p-3">
                          <StatusBadge status={e.status?.phase ?? "Pending"} tone={execTone(e.status?.phase)} />
                        </td>
                        <td className="p-3 text-muted-foreground">{e.status?.currentState ?? "—"}</td>
                        <td className="p-3 text-muted-foreground">
                          {e.status?.startedAt ? age(e.status.startedAt) : age(e.metadata.creationTimestamp)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="definition" className="pt-4">
          <Card>
            <CardContent className="p-4">
              <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 font-mono text-xs">
                {prettyJson(sm.spec?.definition)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={sm} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="State Machine"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
