import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Building2 } from "lucide-react";
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
import type { Directory, K8sObject } from "@/types/k8s";

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

export function DirectoryDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.directory(namespace, name);

  const { data: dir, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["directory", namespace, name],
    queryFn: () => k8sGet<Directory>(path),
    refetchInterval: 5000,
  });
  const { data: svc } = useQuery({
    queryKey: ["service", namespace, name],
    queryFn: () =>
      k8sGet<Svc>(`/api/v1/namespaces/${namespace}/services/${name}`),
    retry: false,
    refetchInterval: 5000,
  });
  const { data: secret } = useQuery({
    queryKey: ["directory-secret", namespace, name],
    queryFn: () =>
      k8sGet<K8sObject & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-directory`,
      ),
    retry: false,
  });
  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/directories" }),
  });

  if (isLoading) return <LoadingState label="Loading directory…" />;
  if (isError || !dir) return <ErrorState error={error} onRetry={refetch} />;

  const ip = svc?.status?.loadBalancer?.ingress?.[0]?.ip;
  const domain = dir.spec?.domain ?? decode(secret?.data?.DOMAIN);
  const netbios = decode(secret?.data?.NETBIOS) || domain.split(".")[0]?.toUpperCase();
  const user = decode(secret?.data?.ADMIN_USER) || "Administrator";
  const pass = decode(secret?.data?.ADMIN_PASSWORD);
  const dc = ip ?? "<DC address>";
  const winCmd = `netsh interface ip set dns name="Ethernet" static ${dc}; Add-Computer -DomainName ${domain} -Credential (New-Object System.Management.Automation.PSCredential("${netbios}\\${user}",(ConvertTo-SecureString "${pass}" -AsPlainText -Force))) -Restart`;
  const linCmd = `echo "${pass}" | sudo realm join --user=${user} ${domain}`;
  const ready = (dir.status as { conditions?: { type?: string; status?: string }[] })
    ?.conditions?.find((c) => c.type === "Ready")?.status === "True";

  return (
    <DetailShell
      backTo="/directories"
      backLabel="Active Directory"
      icon={<Building2 className="size-5" />}
      title={name}
      subtitle={`Directory · ${namespace}`}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="join">Join</TabsTrigger>
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
              <DetailRow label="Domain">
                <code className="text-xs">{domain || "—"}</code>
              </DetailRow>
              <DetailRow label="DC address">
                {ip ? (
                  <code className="text-xs">{ip}</code>
                ) : (
                  <span className="text-xs text-muted-foreground">pending IP…</span>
                )}
              </DetailRow>
              <DetailRow label="Status">{ready ? "Ready" : "Provisioning"}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="join" className="pt-4">
          <Card>
            <CardContent className="min-w-0 space-y-3 p-5 text-sm">
              <p className="text-muted-foreground">
                {ip
                  ? "Point the machine's DNS at the DC, then join with the admin credentials below."
                  : "DC address pending — give it a moment to get an IP."}
              </p>
              <ConnRow label="Domain" value={domain} />
              <ConnRow label="DC address (use as the client's DNS)" value={dc} />
              <ConnRow label="Admin user" value={`${netbios}\\${user}`} />
              <ConnRow label="Admin password" value={pass || "—"} />
              <ConnRow label="Windows (PowerShell, admin)" value={winCmd} />
              <ConnRow label="Linux (realmd)" value={linCmd} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={dir} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Directory"
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
