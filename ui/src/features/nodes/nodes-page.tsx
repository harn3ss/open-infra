import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cpu, FileCode2, HardDrive, MemoryStick, Server, Zap } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/common/status-badge";
import { LiveIndicator } from "@/components/common/live-indicator";
import { ResourceYamlSheet } from "@/components/common/resource-yaml-sheet";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useListFilter } from "@/hooks/use-list-filter";
import { corePaths } from "@/lib/k8s-paths";
import { age, formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";
import { getNodeDisk, type NodeDisk } from "@/lib/api";
import {
  nodeCapacity,
  nodeInternalIP,
  nodeReady,
  nodeRoles,
  nodeWarnings,
  totalGpus,
} from "@/features/nodes/node-utils";
import type { Node } from "@/types/k8s";

function NodeCard({
  node,
  disk,
  onViewYaml,
}: {
  node: Node;
  disk?: NodeDisk;
  onViewYaml: (n: Node) => void;
}) {
  const ready = nodeReady(node);
  const roles = nodeRoles(node);
  const cap = nodeCapacity(node);
  const ip = nodeInternalIP(node);
  const warnings = nodeWarnings(node);

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Server className="size-5" />
            </div>
            <div className="min-w-0">
              <div className="truncate font-semibold">{node.metadata.name}</div>
              <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                {roles.map((r) => (
                  <Badge key={r} variant="secondary">
                    {r}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <StatusBadge status={ready.label} tone={ready.tone} />
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="flex items-center gap-2">
            <Cpu className="size-4 text-muted-foreground" />
            <span className="text-muted-foreground">CPU</span>
            <span className="ml-auto font-medium">{cap.cpuCores} cores</span>
          </div>
          <div className="flex items-center gap-2">
            <MemoryStick className="size-4 text-muted-foreground" />
            <span className="text-muted-foreground">Memory</span>
            <span className="ml-auto font-medium">{cap.memoryBytes}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Pods cap.</span>
            <span className="ml-auto font-medium">{cap.pods}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Age</span>
            <span className="ml-auto font-medium">
              {age(node.metadata.creationTimestamp)}
            </span>
          </div>
        </div>

        {disk ? (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-sm">
              <HardDrive className="size-4 text-muted-foreground" />
              <span className="text-muted-foreground">Disk</span>
              <span className="ml-auto font-medium tabular-nums">
                {formatBytes(disk.usedBytes)} / {formatBytes(disk.sizeBytes)}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-secondary">
              <div
                className={cn(
                  "h-full rounded-full transition-all",
                  disk.usedPercent >= 90
                    ? "bg-destructive"
                    : disk.usedPercent >= 75
                      ? "bg-warning"
                      : "bg-primary",
                )}
                style={{ width: `${Math.min(100, Math.max(2, disk.usedPercent))}%` }}
              />
            </div>
            <div className="text-right text-xs text-muted-foreground tabular-nums">
              {disk.usedPercent.toFixed(0)}% used · {formatBytes(disk.availBytes)} free
            </div>
          </div>
        ) : null}

        {cap.gpus > 0 ? (
          <div className="flex items-center gap-2 rounded-md bg-primary/5 px-2.5 py-2 text-sm ring-1 ring-primary/20">
            <Zap className="size-4 text-primary" />
            <span className="text-muted-foreground">GPU</span>
            <span className="ml-auto font-medium text-primary">
              {cap.gpus}× {cap.gpuModel ?? "GPU"}
            </span>
          </div>
        ) : null}

        <div className="space-y-1 text-xs text-muted-foreground">
          {ip ? (
            <div className="flex justify-between">
              <span>Internal IP</span>
              <code>{ip}</code>
            </div>
          ) : null}
          <div className="flex justify-between">
            <span>Kubelet</span>
            <code>{node.status?.nodeInfo?.kubeletVersion ?? "—"}</code>
          </div>
          <div className="flex justify-between gap-3">
            <span>OS</span>
            <span className="truncate text-right">
              {node.status?.nodeInfo?.osImage ?? "—"}
            </span>
          </div>
        </div>

        {warnings.length ? (
          <div className="flex flex-wrap gap-1.5">
            {warnings.map((w) => (
              <Badge key={w} variant="destructive">
                {w}
              </Badge>
            ))}
          </div>
        ) : null}

        <div className="flex justify-end">
          <Button variant="ghost" size="sm" onClick={() => onViewYaml(node)}>
            <FileCode2 className="size-4" />
            View YAML
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export function NodesPage() {
  const { items, isLoading, isError, error, live, refetch } =
    useK8sWatch<Node>(corePaths.nodes());
  // Live disk usage from Prometheus (node-exporter), keyed by node IP. Fails soft to {} —
  // the disk row simply doesn't render when metrics are unavailable.
  const { data: diskByIP } = useQuery<Record<string, NodeDisk>>({
    queryKey: ["node-disk"],
    queryFn: getNodeDisk,
    refetchInterval: 30000,
  });
  const { filtered } = useListFilter(items, (n) => [
    n.metadata.name,
    nodeInternalIP(n),
    ...nodeRoles(n),
  ]);

  const [yamlNode, setYamlNode] = useState<Node | null>(null);
  const [yamlOpen, setYamlOpen] = useState(false);

  const readyCount = items.filter((n) => nodeReady(n).ready).length;
  const gpus = totalGpus(items);

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Server />}
        title="Nodes"
        description={
          items.length
            ? `${readyCount} of ${items.length} nodes ready${gpus ? ` · ${gpus} GPU${gpus > 1 ? "s" : ""}` : ""}`
            : "Cluster nodes, capacity, and health."
        }
        actions={<LiveIndicator live={live} />}
      />

      {isLoading ? (
        <LoadingState label="Loading nodes…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<Server className="size-6" />}
          title="No nodes found"
          description="The cluster reported no nodes. This is unusual — check the BFF connection."
        />
      ) : filtered.length === 0 ? (
        <EmptyState title="No matches" description="No nodes match the filter." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((node) => (
            <NodeCard
              key={node.metadata.uid ?? node.metadata.name}
              node={node}
              disk={diskByIP?.[nodeInternalIP(node) ?? ""]}
              onViewYaml={(n) => {
                setYamlNode(n);
                setYamlOpen(true);
              }}
            />
          ))}
        </div>
      )}

      <ResourceYamlSheet
        resource={yamlNode}
        open={yamlOpen}
        onOpenChange={setYamlOpen}
      />
    </div>
  );
}
