import { useState } from "react";
import { Cpu, FileCode2, MemoryStick, Server } from "lucide-react";
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
import { age } from "@/lib/format";
import {
  nodeCapacity,
  nodeInternalIP,
  nodeReady,
  nodeRoles,
  nodeWarnings,
} from "@/features/nodes/node-utils";
import type { Node } from "@/types/k8s";

function NodeCard({
  node,
  onViewYaml,
}: {
  node: Node;
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
  const { filtered } = useListFilter(items, (n) => [
    n.metadata.name,
    nodeInternalIP(n),
    ...nodeRoles(n),
  ]);

  const [yamlNode, setYamlNode] = useState<Node | null>(null);
  const [yamlOpen, setYamlOpen] = useState(false);

  const readyCount = items.filter((n) => nodeReady(n).ready).length;

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Server />}
        title="Nodes"
        description={
          items.length
            ? `${readyCount} of ${items.length} nodes ready`
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
