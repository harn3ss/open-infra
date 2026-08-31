import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Package, Check, X, Rocket } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { ApiError, k8sCreate, k8sDelete, k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type Model, type ModelPackage } from "@/types/k8s";
import { approvalTone } from "./modelpackages-page";

export function ModelPackageDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: pkg, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["modelpackage", namespace, name],
    queryFn: () => k8sGet<ModelPackage>(openinfraPaths.modelpackage(namespace, name)),
  });

  const setApproval = useMutation({
    mutationFn: async (status: "Approved" | "Rejected") => {
      const path = openinfraPaths.modelpackage(namespace, name);
      const cur = await k8sGet<ModelPackage>(path);
      return k8sReplace<ModelPackage>(path, {
        ...cur,
        spec: { ...cur.spec, approvalStatus: status },
      } as ModelPackage);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["modelpackage", namespace, name] });
      void refetch();
    },
  });

  // Promote an Approved package to a served Model (spec.serve copied from the package).
  const deploy = useMutation({
    mutationFn: () => {
      const s = pkg?.spec;
      if (!s) throw new Error("package not loaded");
      const modelName = `${name}-serve`;
      return k8sCreate<Model>(openinfraPaths.models(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Model",
        metadata: { name: modelName, namespace },
        spec: {
          serve: {
            image: s.image,
            port: s.port ?? 8000,
            artifact: { bucket: s.artifact?.bucket, key: s.artifact?.key },
            modelPackage: name,
          },
        },
      } as Model);
    },
    onSuccess: (created) => {
      const mn = created?.metadata?.name;
      if (mn) navigate({ to: "/models/$namespace/$name", params: { namespace, name: mn } });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.modelpackage(namespace, name)),
    onSuccess: () => navigate({ to: "/model-registry" }),
  });

  if (isLoading) return <LoadingState label="Loading model package…" />;
  if (isError || !pkg) return <ErrorState error={error} onRetry={refetch} />;

  const s = pkg.spec;
  const status = s?.approvalStatus ?? "PendingManualApproval";
  const approved = status === "Approved";

  return (
    <DetailShell
      backTo="/model-registry"
      backLabel="Model Registry"
      icon={<Package className="size-5" />}
      title={name}
      subtitle={`${s?.modelName} · v${s?.version ?? "1"} · ${namespace}`}
      status={{ label: status, tone: approvalTone(status) }}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardContent className="flex flex-wrap items-center gap-3 p-4">
              <span className="text-sm font-medium">Approval</span>
              <StatusBadge status={status} tone={approvalTone(status)} />
              <div className="ml-auto flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={approved || setApproval.isPending}
                  onClick={() => setApproval.mutate("Approved")}
                >
                  <Check className="size-4" /> Approve
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={status === "Rejected" || setApproval.isPending}
                  onClick={() => setApproval.mutate("Rejected")}
                >
                  <X className="size-4" /> Reject
                </Button>
                <Button size="sm" disabled={!approved || deploy.isPending} onClick={() => deploy.mutate()}>
                  <Rocket className="size-4" /> Deploy endpoint
                </Button>
              </div>
            </CardContent>
          </Card>
          {deploy.isError ? (
            <p className="text-sm text-destructive">
              {deploy.error instanceof ApiError ? deploy.error.message : "Failed to deploy the endpoint."}
            </p>
          ) : null}
          {!approved ? (
            <p className="text-xs text-muted-foreground">
              Deploy is enabled once the package is <strong>Approved</strong> (separation of the registry from
              promotion, like SageMaker). The serving image must serve HTTP on its port.
            </p>
          ) : null}

          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Model / version">
                <span className="font-medium">{s?.modelName}</span> <Badge variant="secondary">v{s?.version ?? "1"}</Badge>
              </DetailRow>
              {s?.framework ? <DetailRow label="Framework"><Badge variant="secondary">{s.framework}</Badge></DetailRow> : null}
              <DetailRow label="Artifact"><code className="text-xs">s3://{s?.artifact?.bucket}/{s?.artifact?.key ?? ""}</code></DetailRow>
              <DetailRow label="Serving image"><code className="text-xs">{s?.image}</code></DetailRow>
              <DetailRow label="Port">{s?.port ?? 8000}</DetailRow>
              {s?.metrics ? (
                <DetailRow label="Metrics"><code className="text-xs">{s.metrics}</code></DetailRow>
              ) : null}
              {s?.description ? <DetailRow label="Description">{s.description}</DetailRow> : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={pkg} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Model Package"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
