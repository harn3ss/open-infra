import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CopyPlus } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { InstanceTypeLabel } from "@/components/common/instance-type-label";
import { EC2_INSTANCE_TYPES } from "@/lib/instance-types";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { claimHealth, type Health } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths, poolPaths } from "@/lib/k8s-paths";
import { age, statusTone } from "@/lib/format";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { AutoScalingGroup, KubevirtVm, VirtualMachinePool } from "@/types/k8s";
import { osLabel } from "@/features/vms/vm-shared";

/** A member VM's live status, derived from the KubeVirt VM's printableStatus / ready. */
function memberStatus(vm: KubevirtVm): Health {
  if (vm.metadata.deletionTimestamp) return { label: "Terminating", tone: "warning" };
  const ps = vm.status?.printableStatus;
  if (ps) return { label: ps, tone: statusTone(ps) };
  if (vm.status?.ready) return { label: "Running", tone: "success" };
  return { label: "Pending", tone: "muted" };
}

export function AutoScalingGroupDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: asg, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["autoscalinggroup", namespace, name],
    queryFn: () => k8sGet<AutoScalingGroup>(openinfraPaths.autoscalinggroup(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.autoscalinggroup(namespace, name)),
    onSuccess: () => navigate({ to: "/auto-scaling-groups" }),
  });

  if (isLoading) return <LoadingState label="Loading auto scaling group…" />;
  if (isError || !asg) return <ErrorState error={error} onRetry={refetch} />;

  const s = asg.spec;
  const lt = s?.launchTemplate;
  const poolName = asg.status?.poolName ?? name;
  const desired = asg.status?.desiredCapacity ?? s?.desiredCapacity ?? 0;
  const ready = asg.status?.readyReplicas;

  return (
    <DetailShell
      backTo="/auto-scaling-groups"
      backLabel="Auto Scaling Groups"
      icon={<CopyPlus className="size-5" />}
      title={name}
      subtitle={`Auto scaling group · ${namespace}`}
      status={claimHealth(asg)}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="instances">Instances</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          {/* Capacity */}
          <Card>
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-sm">Capacity</CardTitle>
              <CardDescription>The desired size the group is kept at, and its allowed range.</CardDescription>
            </CardHeader>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Desired capacity">
                <span className="font-medium">{desired}</span>
                {ready !== undefined ? (
                  <span className="ml-2 text-xs text-muted-foreground">{ready} ready</span>
                ) : null}
              </DetailRow>
              <DetailRow label="Minimum size">{s?.minSize ?? 0}</DetailRow>
              <DetailRow label="Maximum size">{s?.maxSize ?? desired}</DetailRow>
              <DetailRow label="Pool">
                <span className="flex items-center gap-1">
                  <code className="text-xs">{poolName}</code>
                  <CopyButton value={poolName} label="Copy pool name" />
                </span>
                <span className="ml-1 text-xs text-muted-foreground">— see the <strong>Instances</strong> tab</span>
              </DetailRow>
            </CardContent>
          </Card>

          {/* Launch template */}
          <Card className="mt-4">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-sm">Launch template</CardTitle>
              <CardDescription>The recipe every member VM is created from.</CardDescription>
            </CardHeader>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Operating system">{osLabel(lt?.os)}</DetailRow>
              <DetailRow label="Instance type">
                <InstanceTypeLabel
                  groups={EC2_INSTANCE_TYPES}
                  spec={lt as Record<string, unknown> | undefined}
                  detail={`${lt?.cpu ?? 2} vCPU · ${lt?.memory ?? "2Gi"}`}
                />
              </DetailRow>
              <DetailRow label="Root disk"><code className="text-xs">{lt?.diskSize ?? "20Gi"}</code></DetailRow>
              <DetailRow label="Network"><code className="text-xs">{lt?.network ?? "masquerade"}</code></DetailRow>
              {lt?.subnet ? <DetailRow label="Subnet"><code className="text-xs">{lt.subnet}</code></DetailRow> : null}
              <DetailRow label="High availability">
                {lt?.highAvailability ? (
                  <Badge variant="secondary">Enabled (live-migratable disk)</Badge>
                ) : (
                  <span className="text-xs text-muted-foreground">Disabled</span>
                )}
              </DetailRow>
              {lt?.cpuModel ? <DetailRow label="CPU model"><code className="text-xs">{lt.cpuModel}</code></DetailRow> : null}
              {lt?.securityGroups?.length ? (
                <DetailRow label="Security groups">
                  <span className="flex flex-wrap gap-1">
                    {lt.securityGroups.map((g) => (
                      <Badge key={g} variant="secondary">{g}</Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
            </CardContent>
          </Card>

          {/* Health check */}
          <Card className="mt-4">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-sm">Health check</CardTitle>
              <CardDescription>How the group decides a member is unhealthy and replaces it.</CardDescription>
            </CardHeader>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Replace unhealthy">
                {s?.healthCheck?.replaceUnhealthy === false ? (
                  <span className="text-xs text-muted-foreground">Disabled</span>
                ) : (
                  <Badge variant="secondary">Enabled</Badge>
                )}
              </DetailRow>
              <DetailRow label="Startup failure threshold">
                {s?.healthCheck?.startUpFailureThreshold ?? <span className="text-xs text-muted-foreground">default</span>}
              </DetailRow>
              <DetailRow label="Min failing duration">
                {s?.healthCheck?.minFailingDuration ? (
                  <code className="text-xs">{s.healthCheck.minFailingDuration}</code>
                ) : (
                  <span className="text-xs text-muted-foreground">default</span>
                )}
              </DetailRow>
            </CardContent>
          </Card>

          {/* Instance refresh */}
          <Card className="mt-4">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-sm">Instance refresh</CardTitle>
              <CardDescription>How a launch-template change is rolled across existing members.</CardDescription>
            </CardHeader>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Strategy">
                <code className="text-xs">{s?.instanceRefresh?.strategy ?? "opportunistic"}</code>
              </DetailRow>
              <DetailRow label="Max unavailable">
                {s?.instanceRefresh?.maxUnavailable ? (
                  <code className="text-xs">{s.instanceRefresh.maxUnavailable}</code>
                ) : (
                  <span className="text-xs text-muted-foreground">default</span>
                )}
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="instances" className="pt-4">
          <InstancesTab namespace={namespace} name={name} poolName={poolName} desired={desired} />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={asg} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Auto Scaling Group"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

/**
 * The group's members: the backing VirtualMachinePool's replica counts plus every member VM it
 * manages (label openinfra.dev/autoscalinggroup=<name>), each with its live status. Honest-empty when
 * the pool hasn't been created or has no members yet — never fabricated instances.
 */
function InstancesTab({
  namespace,
  name,
  poolName,
  desired,
}: {
  namespace: string;
  name: string;
  poolName: string;
  desired: number;
}) {
  // The pool may not exist yet (still provisioning); treat a miss as "pending", not a hard error.
  const poolQuery = useQuery({
    queryKey: ["vmpool", namespace, poolName],
    queryFn: () => k8sGet<VirtualMachinePool>(poolPaths.virtualmachinepool(namespace, poolName)),
    retry: false,
  });
  const pool = poolQuery.data;

  const vmWatch = useK8sWatch<KubevirtVm>(poolPaths.memberVms(namespace));
  const members = useMemo(
    () =>
      vmWatch.items
        .filter((v) => v.metadata.labels?.["openinfra.dev/autoscalinggroup"] === name)
        .sort((a, b) => (a.metadata.name ?? "").localeCompare(b.metadata.name ?? "")),
    [vmWatch.items, name],
  );

  const replicas = pool?.status?.replicas;
  const readyReplicas = pool?.status?.readyReplicas;

  return (
    <div className="space-y-6">
      <Card>
        <CardContent className="divide-y divide-border p-0">
          <DetailRow label="Desired">{desired}</DetailRow>
          <DetailRow label="Current replicas">
            {replicas !== undefined ? (
              replicas
            ) : (
              <span className="text-xs text-muted-foreground">pool pending</span>
            )}
          </DetailRow>
          <DetailRow label="Ready replicas">
            {readyReplicas !== undefined ? (
              readyReplicas
            ) : (
              <span className="text-xs text-muted-foreground">—</span>
            )}
          </DetailRow>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="p-5 pb-3">
          <CardTitle className="text-sm">Instances</CardTitle>
          <CardDescription>Member VMs managed by this group, by name.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {members.length === 0 ? (
            <p className="px-5 pb-5 text-sm text-muted-foreground">
              No member instances yet. Members appear here once the pool provisions them.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-y border-border text-left text-xs text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Instance</th>
                  <th className="p-3 font-medium">Status</th>
                  <th className="p-3 font-medium">Age</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => {
                  const st = memberStatus(m);
                  return (
                    <tr key={m.metadata.uid ?? m.metadata.name} className="border-b border-border last:border-0">
                      <td className="p-3"><code className="text-xs">{m.metadata.name}</code></td>
                      <td className="p-3"><StatusBadge status={st.label} tone={st.tone} /></td>
                      <td className="p-3 text-xs text-muted-foreground">{age(m.metadata.creationTimestamp)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
