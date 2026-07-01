import type { ReactNode } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import type { K8sObject } from "@/types/k8s";

type Obj = K8sObject<Record<string, unknown>, Record<string, unknown>>;

export type SimpleDetailConfig = {
  /** Human label, e.g. "Volume". */
  kindLabel: string;
  /** List route to go back to (and after delete). */
  backTo: string;
  backLabel: string;
  /** React-query cache key prefix. */
  queryKey: string;
  icon: ReactNode;
  getPath: (ns: string, name: string) => string;
  deletePath: (ns: string, name: string) => string;
  /** Extra Overview rows (spec is untyped — cast inside the accessor). */
  fields?: { label: string; value: (obj: Obj) => ReactNode }[];
  /** Optional confirm-dialog body override. */
  deleteWarning?: ReactNode;
};

/**
 * Factory for a consistent, minimal resource detail page (Overview + YAML +
 * Danger Zone tabs) for resources that don't need a bespoke page. Keeps the
 * "click a row -> detail page with a tab group; delete lives in Danger Zone"
 * flow uniform across every resource type.
 */
export function makeSimpleDetailPage(cfg: SimpleDetailConfig) {
  return function SimpleDetailPage() {
    const { namespace, name } = useParams({ strict: false }) as {
      namespace: string;
      name: string;
    };
    const navigate = useNavigate();
    const { data, isLoading, isError, error, refetch } = useQuery({
      queryKey: [cfg.queryKey, namespace, name],
      queryFn: () => k8sGet<Obj>(cfg.getPath(namespace, name)),
      refetchInterval: 5000,
    });
    const del = useMutation({
      mutationFn: () => k8sDelete(cfg.deletePath(namespace, name)),
      onSuccess: () => navigate({ to: cfg.backTo }),
    });

    if (isLoading)
      return <LoadingState label={`Loading ${cfg.kindLabel.toLowerCase()}…`} />;
    if (isError || !data) return <ErrorState error={error} onRetry={refetch} />;

    const status = data.status as
      | { phase?: string; conditions?: { type?: string; status?: string }[] }
      | undefined;
    const statusText =
      status?.phase ??
      status?.conditions?.find((c) => c.type === "Ready")?.status ??
      "—";

    return (
      <DetailShell
        backTo={cfg.backTo}
        backLabel={cfg.backLabel}
        icon={cfg.icon}
        title={name}
        subtitle={`${cfg.kindLabel} · ${namespace}`}
      >
        <Tabs defaultValue="overview">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
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
              <CardContent className="divide-y divide-border p-0">
                <DetailRow label="Namespace">{namespace}</DetailRow>
                {(cfg.fields ?? []).map((f) => (
                  <DetailRow key={f.label} label={f.label}>
                    {f.value(data)}
                  </DetailRow>
                ))}
                <DetailRow label="Status">{String(statusText)}</DetailRow>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="yaml" className="pt-4">
            <YamlViewer value={data} />
          </TabsContent>

          <TabsContent value="danger" className="pt-4">
            <DangerZone
              resourceLabel={cfg.kindLabel}
              resourceName={name}
              deleting={del.isPending}
              onConfirm={() => del.mutate()}
              confirmDescription={cfg.deleteWarning}
            />
          </TabsContent>
        </Tabs>
      </DetailShell>
    );
  };
}
