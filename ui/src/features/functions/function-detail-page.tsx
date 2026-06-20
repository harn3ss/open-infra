import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ExternalLink, Trash2, Zap } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { OpenInfraFunction } from "@/types/k8s";

export function FunctionDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data: fn, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["function", namespace, name],
    queryFn: () =>
      k8sGet<OpenInfraFunction>(openinfraPaths.function(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.function(namespace, name)),
    onSuccess: () => navigate({ to: "/functions" }),
  });

  if (isLoading) return <LoadingState label="Loading function…" />;
  if (isError || !fn) return <ErrorState error={error} onRetry={refetch} />;

  const s = fn.spec;
  const url = fn.status?.url;

  return (
    <DetailShell
      backTo="/functions"
      backLabel="Functions"
      icon={<Zap className="size-5" />}
      title={name}
      subtitle={`Serverless function · ${namespace}`}
      status={claimHealth(fn)}
      actions={
        <Button variant="destructive" onClick={() => setConfirmDelete(true)}>
          <Trash2 className="size-4" />
          Delete
        </Button>
      }
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Image">
                <code className="text-xs">{s?.image ?? "—"}</code>
              </DetailRow>
              <DetailRow label="Port">{s?.port ?? 8080}</DetailRow>
              <DetailRow label="Scaling">
                {s?.scaling?.min ?? 0}–{s?.scaling?.max ?? 10} pods · target{" "}
                {s?.scaling?.target ?? 100} concurrent
                {(s?.gpu ?? 0) > 0 ? ` · ${s?.gpu}×GPU` : ""}
              </DetailRow>
              {url ? (
                <DetailRow label="URL">
                  <a
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    <code className="text-xs">{url}</code>
                    <ExternalLink className="size-3" />
                  </a>
                </DetailRow>
              ) : null}
              {s?.queues?.length ? (
                <DetailRow label="Queues">
                  <span className="flex flex-wrap gap-1">
                    {s.queues.map((q) => (
                      <Badge key={q} variant="secondary">
                        {q}
                      </Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
              {s?.secrets?.length ? (
                <DetailRow label="Secrets">
                  <span className="flex flex-wrap gap-1">
                    {s.secrets.map((sec) => (
                      <Badge key={sec} variant="secondary">
                        {sec}
                      </Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{ "var-namespace": namespace }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={fn} />
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete Function?"
        description={
          <>
            Permanently delete{" "}
            <span className="font-medium text-foreground">{name}</span>.
          </>
        }
        confirmLabel="Delete"
        loading={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
      />
    </DetailShell>
  );
}
