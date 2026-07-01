import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FolderTree } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { FileShare, K8sObject } from "@/types/k8s";

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

type Svc = K8sObject<
  unknown,
  { loadBalancer?: { ingress?: { ip?: string }[] } }
>;

export function FileShareDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.fileshare(namespace, name);

  const { data: fs, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["fileshare", namespace, name],
    queryFn: () => k8sGet<FileShare>(path),
    refetchInterval: 5000,
  });
  // LAN IP from the per-share LoadBalancer Service (svc name == share name).
  const { data: svc } = useQuery({
    queryKey: ["service", namespace, name],
    queryFn: () =>
      k8sGet<Svc>(`/api/v1/namespaces/${namespace}/services/${name}`),
    retry: false,
    refetchInterval: 5000,
  });
  const { data: secret } = useQuery({
    queryKey: ["fileshare-secret", namespace, name],
    queryFn: () =>
      k8sGet<K8sObject & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-fileshare`,
      ),
    retry: false,
  });
  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/fileshares" }),
  });

  if (isLoading) return <LoadingState label="Loading file share…" />;
  if (isError || !fs) return <ErrorState error={error} onRetry={refetch} />;

  const ip = svc?.status?.loadBalancer?.ingress?.[0]?.ip;
  const host = ip ?? `${name}.${namespace}.svc.cluster.local`;
  const user = decode(secret?.data?.USERNAME) || "openinfra";
  const pass = decode(secret?.data?.PASSWORD);
  const winCmd = `net use Z: \\\\${host}\\${name} /user:${user} ${pass}`;
  const linCmd = `sudo mount -t cifs //${host}/${name} /mnt -o username=${user},password=${pass}`;
  const ready = (fs.status as { conditions?: { type?: string; status?: string }[] })
    ?.conditions?.find((c) => c.type === "Ready")?.status === "True";

  return (
    <DetailShell
      backTo="/fileshares"
      backLabel="File Shares"
      icon={<FolderTree className="size-5" />}
      title={name}
      subtitle={`File Share · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="connect">Connect</TabsTrigger>
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
              <DetailRow label="Size">{fs.spec?.size ?? "—"}</DetailRow>
              <DetailRow label="SMB endpoint">
                {ip ? (
                  <code className="text-xs">
                    \\{ip}\{name}
                  </code>
                ) : (
                  <span className="text-xs text-muted-foreground">pending IP…</span>
                )}
              </DetailRow>
              <DetailRow label="Status">{ready ? "Ready" : "Provisioning"}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="connect" className="pt-4">
          <Card>
            <CardContent className="min-w-0 space-y-3 p-5 text-sm">
              <p className="text-muted-foreground">
                {ip
                  ? "Reachable on the LAN at the address below."
                  : "LAN IP pending — using the in-cluster name for now."}
              </p>
              <ConnRow label="Username" value={user} />
              <ConnRow label="Password" value={pass || "—"} />
              <ConnRow label="Windows (net use)" value={winCmd} />
              <ConnRow label="Linux (mount -t cifs)" value={linCmd} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={fs} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="File Share"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

function ConnRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className="flex min-w-0 items-center gap-1">
        <code
          title={value}
          className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 text-xs"
        >
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}
