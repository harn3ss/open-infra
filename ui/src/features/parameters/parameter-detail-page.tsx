import { useMemo } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { SlidersHorizontal, Lock, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Parameter } from "@/types/k8s";

/** Placeholder used everywhere a SecureString value would otherwise be shown. */
const SECURE_PLACEHOLDER = "<SecureString — hidden>";

export function ParameterDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.parameter(namespace, name);

  const { data: param, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["parameter", namespace, name],
    queryFn: () => k8sGet<Parameter>(path),
    refetchInterval: 5000,
  });

  // CRITICAL: a SecureString value must never reach the browser's rendered YAML either — redact
  // spec.value before handing the object to the viewer. String values are safe to show verbatim.
  const yamlValue = useMemo(() => {
    if (!param) return param;
    if (param.spec?.type !== "SecureString") return param;
    return { ...param, spec: { ...param.spec, value: SECURE_PLACEHOLDER } };
  }, [param]);

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/parameters" }),
  });

  if (isLoading) return <LoadingState label="Loading parameter…" />;
  if (isError || !param) return <ErrorState error={error} onRetry={refetch} />;

  const spec = param.spec;
  const type = spec?.type ?? "String";
  const tier = spec?.tier ?? "Standard";
  const paramPath = param.status?.path ?? spec?.path ?? "";
  const ready = param.status?.ready === true;
  const isSecure = type === "SecureString";
  const status: { label: string; tone: StatusTone } = ready
    ? { label: "Ready", tone: "success" }
    : { label: "Provisioning", tone: "warning" };

  return (
    <DetailShell
      backTo="/parameters"
      backLabel="Parameters"
      icon={<SlidersHorizontal className="size-5" />}
      title={name}
      subtitle={`Parameter · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Path",
                    value: paramPath ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{paramPath}</code>
                        <CopyButton value={paramPath} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "Type",
                    value: (
                      <StatusBadge status={type} tone={isSecure ? "accent" : "muted"} />
                    ),
                  },
                  {
                    label: "Value",
                    value: isSecure ? (
                      <span className="inline-flex items-center gap-1.5 text-muted-foreground">
                        <Lock className="size-3.5" />
                        SecureString (hidden)
                      </span>
                    ) : spec?.value ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs break-all">{spec.value}</code>
                        <CopyButton value={spec.value} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "Tier",
                    value: <span>{tier}</span>,
                  },
                  {
                    label: "Expires at",
                    value: spec?.expiresAt ? (
                      <code className="text-xs">{spec.expiresAt}</code>
                    ) : (
                      <span className="text-muted-foreground">Never</span>
                    ),
                  },
                  {
                    label: "Ready",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {isSecure ? (
            <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
              <Info className="mt-0.5 size-4 shrink-0" />
              <span>
                This is a <span className="font-medium text-foreground">SecureString</span> — its value is stored encrypted
                (Vault-backed) and materialized into a namespace Secret for workloads to consume. The plaintext is never
                displayed in the console, including in the YAML tab. Read it from an application via <code className="text-xs">spec.secrets</code>.
              </span>
            </div>
          ) : null}
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={yamlValue} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Parameter"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete parameter <span className="font-medium text-foreground">{name}</span> (<code className="text-xs">{paramPath || name}</code>). Applications reading this path will no longer resolve it.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
