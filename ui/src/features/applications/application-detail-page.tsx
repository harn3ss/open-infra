import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Boxes } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { ResourceSecurityTab } from "@/components/common/resource-security-tab";
import { k8sDelete, k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Application } from "@/types/k8s";

export function ApplicationDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const appPath = openinfraPaths.application(namespace, name);

  const { data: app, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["application", namespace, name],
    queryFn: () => k8sGet<Application>(appPath),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(appPath),
    onSuccess: () => navigate({ to: "/applications" }),
  });

  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const cur = await k8sGet<Application>(appPath);
      return k8sReplace<Application>(appPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as Application);
    },
    onSuccess: () => void refetch(),
  });

  if (isLoading) return <LoadingState label="Loading application…" />;
  if (isError || !app) return <ErrorState error={error} onRetry={refetch} />;

  const s = app.spec;

  return (
    <DetailShell
      backTo="/applications"
      backLabel="Applications"
      icon={<Boxes className="size-5" />}
      title={name}
      subtitle={`Application · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>
            <DangerZone inline
        resourceLabel="Application"
        resourceName={name}
        deleting={del.isPending}
        onConfirm={() => del.mutate()}
        confirmDescription={
          <>Permanently delete application <span className="font-medium text-foreground">{name}</span> and its resources. This cannot be undone.</>
        }
      />
          </div>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="application" name={name} namespace={namespace} />
              <DetailRow label="Image">
                {s?.image ? <code className="text-xs">{s.image}</code> : "—"}
              </DetailRow>
              <DetailRow label="Port">{s?.port ?? "—"}</DetailRow>
              <DetailRow label="Domain">
                {s?.domain ? <code className="text-xs">{s.domain}</code> : "—"}
              </DetailRow>
              <DetailRow label="Database">
                {s?.database ? `${s.database.engine ?? "postgres"}${s.database.name ? ` · ${s.database.name}` : ""}` : "—"}
              </DetailRow>
              <DetailRow label="URL">
                {app.status?.url ? <code className="text-xs">{app.status.url}</code> : "—"}
              </DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="pt-4">
          <ResourceSecurityTab
            namespace={namespace}
            securityGroups={s?.securityGroups ?? []}
            onSave={(next) => saveSgs.mutate(next)}
            saving={saveSgs.isPending}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={app} />
        </TabsContent>
      </Tabs>

    </DetailShell>
  );
}
