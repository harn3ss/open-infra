import { useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, Monitor, Play, Power, Camera, Trash2 } from "lucide-react";
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
import {
  k8sDelete,
  k8sGet,
  k8sReplace,
  createVmSnapshot,
  listVmSnapshots,
  deleteVmSnapshot,
  type VmSnapshot,
} from "@/lib/api";
import { age, formatBytes, formatTimestamp } from "@/lib/format";
import {
  cdiPaths,
  kubevirtPaths,
  openinfraPaths,
  resourcePaths,
} from "@/lib/k8s-paths";
import type { DataVolume, K8sObject, VirtualMachine, Vmi } from "@/types/k8s";
import {
  WINDOWS_ROOT_DISK,
  osFamily,
  osLabel,
  rootDvName,
  vmIp,
  vmStatus,
} from "./vm-shared";
import { VmVolumesTab } from "./vm-volumes";
import { VmNetworkTab } from "./vm-network";
import { ResourceSecurityTab } from "@/components/common/resource-security-tab";

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

  // Root-disk DataVolume — surfaces clone/import progress + failures on status.
  const { data: rootDv } = useQuery({
    queryKey: ["vm-root-dv", namespace, name],
    queryFn: () =>
      k8sGet<DataVolume>(cdiPaths.datavolume(namespace, rootDvName(name))),
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

  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const cur = await k8sGet<VirtualMachine>(vmPath);
      return k8sReplace<VirtualMachine>(vmPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as VirtualMachine);
    },
    onSuccess: () => void refetch(),
  });

  // ── Snapshots (Longhorn-rooted VMs → durable CSI backup of the root disk). ──
  const snapsQ = useQuery({
    queryKey: ["vm-snapshots", namespace, name],
    queryFn: listVmSnapshots,
    select: (all: VmSnapshot[]) =>
      all
        .filter((s) => s.namespace === namespace && s.sourceName === name)
        .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? "")),
    refetchInterval: 8000,
  });
  const takeSnap = useMutation({
    mutationFn: () => createVmSnapshot(namespace, name),
    onSuccess: () => void snapsQ.refetch(),
  });
  const delSnap = useMutation({
    mutationFn: (s: VmSnapshot) => deleteVmSnapshot(s.namespace, s.id),
    onSuccess: () => void snapsQ.refetch(),
  });
  const [finalSnap, setFinalSnap] = useState(false);
  const [snapPhase, setSnapPhase] = useState<string | null>(null);
  async function deleteWithOptionalSnapshot() {
    try {
      if (finalSnap) {
        setSnapPhase("Taking a final snapshot…");
        await createVmSnapshot(namespace, name);
        for (let i = 0; i < 400; i++) {
          const mine = (await listVmSnapshots())
            .filter((s) => s.namespace === namespace && s.sourceName === name)
            .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""));
          if (mine[0]?.status === "ready") break;
          if (mine[0]?.status === "failed") throw new Error("the final snapshot failed — not deleting");
          await new Promise((r) => setTimeout(r, 3000));
        }
        setSnapPhase("Deleting…");
      }
      deleteMutation.mutate();
    } catch (err) {
      setSnapPhase(null);
      alert((err as Error).message);
    }
  }

  if (isLoading) return <LoadingState label="Loading VM…" />;
  if (isError || !vm) return <ErrorState error={error} onRetry={refetch} />;

  const spec = vm.spec;
  const family = osFamily(spec?.os);
  const isWin = family === "windows";
  const running = spec?.running !== false;
  const status = vmStatus(vm, vmi, rootDv);
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
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="storage">Storage</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="snapshots">Snapshots</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
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
                  {isWin ? `${WINDOWS_ROOT_DISK} (fixed)` : spec?.diskSize ?? "20Gi"} disk
                </span>
              </DetailRow>
              {status.detail ? (
                <DetailRow label="Disk status">
                  <span className="text-xs text-destructive">{status.detail}</span>
                </DetailRow>
              ) : null}
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

        <TabsContent value="security" className="pt-4">
          <ResourceSecurityTab
            namespace={namespace}
            securityGroups={spec?.securityGroups ?? []}
            onSave={(next) => saveSgs.mutate(next)}
            saving={saveSgs.isPending}
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

        <TabsContent value="snapshots" className="pt-4">
          <Card>
            <CardContent className="space-y-4 pt-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="font-medium">Snapshots</div>
                  <p className="text-sm text-muted-foreground">
                    A durable backup of this VM's root disk (Longhorn → object storage). It
                    survives the VM's deletion; restore it into a new VM from the{" "}
                    <span className="font-medium text-foreground">Backup → Snapshots</span> page.
                  </p>
                </div>
                <Button
                  onClick={() => takeSnap.mutate()}
                  disabled={takeSnap.isPending || !spec?.highAvailability}
                >
                  <Camera className="size-4" />
                  {takeSnap.isPending ? "Snapshotting…" : "Take snapshot"}
                </Button>
              </div>

              {!spec?.highAvailability ? (
                <p className="text-sm text-muted-foreground">
                  This VM's root disk is on local storage (node-pinned), which has no snapshot
                  support. Enable <span className="font-medium">highAvailability</span> (Longhorn
                  root disk) to snapshot it.
                </p>
              ) : null}
              {takeSnap.isError ? (
                <p className="text-sm text-destructive">{(takeSnap.error as Error).message}</p>
              ) : null}

              {(snapsQ.data?.length ?? 0) === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No snapshots yet. Take one before you deprovision this VM.
                </p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="py-2 font-medium">Taken</th>
                      <th className="py-2 text-right font-medium">Size</th>
                      <th className="py-2 font-medium">Status</th>
                      <th className="py-2 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapsQ.data?.map((s) => (
                      <tr key={s.id} className="border-b last:border-0">
                        <td className="py-2 text-muted-foreground" title={s.createdAt ? `${age(s.createdAt)} ago` : undefined}>
                          {formatTimestamp(s.createdAt)}
                        </td>
                        <td className="py-2 text-right tabular-nums">
                          {s.sizeBytes ? formatBytes(s.sizeBytes) : "—"}
                        </td>
                        <td className="py-2">
                          <Badge
                            variant={s.status === "ready" ? "default" : "secondary"}
                            className={s.status === "failed" ? "bg-destructive" : ""}
                          >
                            {s.status}
                          </Badge>
                        </td>
                        <td className="py-2 text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-destructive"
                            disabled={delSnap.isPending}
                            onClick={() => delSnap.mutate(s)}
                          >
                            <Trash2 className="size-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={vm} />
        </TabsContent>
      <TabsContent value="danger" className="space-y-4 pt-4">
        {spec?.highAvailability ? (
          <label className="flex items-start gap-3 rounded-lg border p-4 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 size-4"
              checked={finalSnap}
              onChange={(ev) => setFinalSnap(ev.target.checked)}
            />
            <span>
              <span className="font-medium">Take a final snapshot before deleting</span>
              <span className="block text-muted-foreground">
                A durable backup of the root disk is taken and confirmed complete before the VM
                is removed, so you can restore it later. {snapPhase ?? ""}
              </span>
            </span>
          </label>
        ) : null}
        <DangerZone
        resourceLabel="Virtual Machine"
        resourceName={name}
        deleting={deleteMutation.isPending || snapPhase !== null}
        onConfirm={() => void deleteWithOptionalSnapshot()}
        confirmDescription={
          <>
            Permanently delete the VM{" "}
            <span className="font-medium text-foreground">{name}</span> and its
            disk. This cannot be undone.
            {finalSnap ? " A final snapshot will be taken first." : ""}
          </>
        }
      />
        </TabsContent>
      </Tabs>

    </DetailShell>
  );
}
