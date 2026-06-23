import { useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, Monitor, Play, Power } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet, k8sReplace } from "@/lib/api";
import { kubevirtPaths, openinfraPaths, resourcePaths } from "@/lib/k8s-paths";
import type { K8sObject, VirtualMachine, Vmi } from "@/types/k8s";
import { osFamily, osLabel, vmIp, vmStatus } from "./vm-shared";
import { VmVolumesTab } from "./vm-volumes";
import { VmNetworkTab } from "./vm-network";

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

type SvcStatus = K8sObject<
  unknown,
  { loadBalancer?: { ingress?: { ip?: string }[] } }
>;

export function VmDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const [showPass, setShowPass] = useState(false);

  const vmPath = openinfraPaths.virtualmachine(namespace, name);

  const { data: vm, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["vm", namespace, name],
    queryFn: () => k8sGet<VirtualMachine>(vmPath),
    refetchInterval: 5000,
  });

  const { data: vmi } = useQuery({
    queryKey: ["vmi", namespace, name],
    queryFn: () => k8sGet<Vmi>(kubevirtPaths.vmi(namespace, name)),
    refetchInterval: 5000,
    retry: false,
  });

  const { data: secret } = useQuery({
    queryKey: ["vm-secret", namespace, name],
    enabled: Boolean(vm),
    queryFn: () =>
      k8sGet<K8sObject & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-vm`,
      ),
    retry: false,
  });

  const { data: lanSvc } = useQuery({
    queryKey: ["vm-lan", namespace, name],
    enabled: Boolean(vm?.spec?.expose) || (vm?.spec?.ports?.length ?? 0) > 0,
    queryFn: () =>
      k8sGet<SvcStatus>(resourcePaths.service(namespace, `${name}-lan`)),
    retry: false,
    refetchInterval: 5000,
  });

  const power = useMutation({
    mutationFn: async (running: boolean) => {
      const cur = await k8sGet<VirtualMachine>(vmPath);
      return k8sReplace<VirtualMachine>(vmPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), running },
      } as VirtualMachine);
    },
    onSuccess: () => void refetch(),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(vmPath),
    onSuccess: () => navigate({ to: "/vms" }),
  });

  if (isLoading) return <LoadingState label="Loading VM…" />;
  if (isError || !vm) return <ErrorState error={error} onRetry={refetch} />;

  const spec = vm.spec;
  const family = osFamily(spec?.os);
  const isWin = family === "windows";
  const running = spec?.running !== false;
  const status = vmStatus(vm, vmi);
  const ip = vmIp(vmi);
  const lanIp = lanSvc?.status?.loadBalancer?.ingress?.[0]?.ip;

  const username = decode(secret?.data?.USERNAME) || (isWin ? "Administrator" : "openinfra");
  const password = decode(secret?.data?.PASSWORD);
  const port = decode(secret?.data?.PORT) || (isWin ? "3389" : "22");

  const reachHost = lanIp ?? "<port-forward>";
  const connectCmd = isWin
    ? `mstsc /v:${reachHost}:${port}`
    : `ssh ${username}@${reachHost}`;
  const portForward = `kubectl port-forward -n ${namespace} svc/${name} ${port}:${port}`;

  return (
    <DetailShell
      backTo="/vms"
      backLabel="Virtual Machines"
      icon={<Monitor className="size-5" />}
      title={name}
      subtitle={`${osLabel(spec?.os)} · ${namespace}`}
      status={status}
      actions={
        running ? (
          <Button
            variant="outline"
            onClick={() => power.mutate(false)}
            disabled={power.isPending}
          >
            <Power className="size-4" /> Stop
          </Button>
        ) : (
          <Button onClick={() => power.mutate(true)} disabled={power.isPending}>
            <Play className="size-4" /> Start
          </Button>
        )
      }
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="access">Access</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="storage">Storage</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="vm" name={name} namespace={namespace} />
              <DetailRow label="Operating system">
                <Badge variant="secondary">{osLabel(spec?.os)}</Badge>
              </DetailRow>
              <DetailRow label="Size">
                <span className="font-mono text-xs">
                  {spec?.cpu ?? 2} vCPU · {spec?.memory ?? "2Gi"} RAM ·{" "}
                  {spec?.diskSize ?? "20Gi"} disk
                </span>
              </DetailRow>
              <DetailRow label="Power">{running ? "On" : "Off (disk retained)"}</DetailRow>
              <DetailRow label="IP address">
                {ip ? <code className="text-xs">{ip}</code> : "—"}
              </DetailRow>
              <DetailRow label="Node">{vmi?.status?.nodeName ?? "—"}</DetailRow>
              <DetailRow label="Security groups">
                {spec?.securityGroups?.length ? (
                  <span className="flex flex-wrap gap-1">
                    {spec.securityGroups.map((sg) => (
                      <Badge key={sg} variant="outline" className="font-mono text-xs">
                        {sg}
                      </Badge>
                    ))}
                  </span>
                ) : (
                  "—"
                )}
              </DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="access" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label={isWin ? "Connect (RDP)" : "Connect (SSH)"}>
                <span className="flex items-center gap-1">
                  <code className="text-xs">{connectCmd}</code>
                  <CopyButton value={connectCmd} />
                </span>
              </DetailRow>
              <DetailRow label="Username">
                <span className="flex items-center gap-1">
                  <code className="text-xs">{username}</code>
                  <CopyButton value={username} />
                </span>
              </DetailRow>
              <DetailRow label="Password">
                <span className="flex items-center gap-1">
                  <code className="text-xs">
                    {password ? (showPass ? password : "•".repeat(16)) : "—"}
                  </code>
                  {password ? (
                    <>
                      <button
                        onClick={() => setShowPass((s) => !s)}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label={showPass ? "Hide password" : "Show password"}
                      >
                        {showPass ? (
                          <EyeOff className="size-4" />
                        ) : (
                          <Eye className="size-4" />
                        )}
                      </button>
                      <CopyButton value={password} />
                    </>
                  ) : null}
                </span>
              </DetailRow>
              {!isWin ? (
                <DetailRow label="Key login">
                  {spec?.sshKey
                    ? "Your SSH key was installed via cloud-init."
                    : "No key set — use the password above."}
                </DetailRow>
              ) : null}
              <DetailRow label={spec?.expose ? "LAN endpoint" : "LAN endpoint"}>
                {spec?.expose ? (
                  lanIp ? (
                    <code className="text-xs">
                      {lanIp}:{port}
                    </code>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      pending MetalLB IP…
                    </span>
                  )
                ) : (
                  <span className="text-xs text-muted-foreground">
                    not exposed — use port-forward below
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Port-forward">
                <span className="flex items-center gap-1">
                  <code className="text-xs">{portForward}</code>
                  <CopyButton value={portForward} />
                </span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network" className="pt-4">
          <VmNetworkTab
            namespace={namespace}
            vmName={name}
            ports={spec?.ports ?? []}
            securityGroups={spec?.securityGroups ?? []}
            lanIp={lanIp}
            accessPort={port}
            accessLabel={isWin ? "RDP" : "SSH"}
            onChange={() => void refetch()}
          />
        </TabsContent>

        <TabsContent value="storage" className="pt-4">
          <VmVolumesTab namespace={namespace} vmName={name} vmi={vmi} />
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          {/* Scoped to this VM's virt-launcher pod (the VM's host process). */}
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{
              "var-namespace": namespace,
              "var-pod": `virt-launcher-${name}-.*`,
            }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={vm} />
        </TabsContent>
      </Tabs>

      <DangerZone
        resourceLabel="Virtual Machine"
        resourceName={name}
        deleting={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
        confirmDescription={
          <>
            Permanently delete the VM{" "}
            <span className="font-medium text-foreground">{name}</span> and its
            disk. This cannot be undone.
          </>
        }
      />
    </DetailShell>
  );
}
