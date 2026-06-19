import { Boxes, Layers, Network, Server } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { StatCard } from "@/features/dashboard/stat-card";
import { HealthPanel } from "@/features/dashboard/health-panel";
import { EventsFeed } from "@/features/dashboard/events-feed";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import {
  appsPaths,
  corePaths,
  openinfraPaths,
} from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import { useConfig } from "@/lib/config-context";
import type { Application, Deployment, Node, Pod } from "@/types/k8s";

export function DashboardPage() {
  const { scoped } = useNamespace();
  const config = useConfig();

  const apps = useK8sWatch<Application>(openinfraPaths.applications(scoped));
  const pods = useK8sWatch<Pod>(corePaths.pods(scoped));
  const deployments = useK8sWatch<Deployment>(appsPaths.deployments(scoped));
  const nodes = useK8sWatch<Node>(corePaths.nodes());

  const runningPods = pods.items.filter(
    (p) => p.status?.phase === "Running",
  ).length;
  const readyNodes = nodes.items.filter(
    (n) => n.status?.conditions?.some((c) => c.type === "Ready" && c.status === "True"),
  ).length;
  const healthyApps = apps.items.filter((a) => {
    const ready = a.status?.conditions?.find((c) => c.type === "Ready");
    return ready?.status === "True";
  }).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Welcome to ${config.clusterName || "open-infra"}`}
        description="Your self-hosted mini-cloud at a glance."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Applications"
          value={apps.items.length}
          sub={`${healthyApps} ready`}
          icon={Boxes}
          to="/applications"
          loading={apps.isLoading}
          error={apps.isError}
          accent="primary"
        />
        <StatCard
          label="Pods"
          value={pods.items.length}
          sub={`${runningPods} running`}
          icon={Layers}
          to="/workloads"
          loading={pods.isLoading}
          error={pods.isError}
          accent="accent"
        />
        <StatCard
          label="Deployments"
          value={deployments.items.length}
          icon={Network}
          to="/workloads"
          loading={deployments.isLoading}
          error={deployments.isError}
          accent="success"
        />
        <StatCard
          label="Nodes"
          value={nodes.items.length}
          sub={`${readyNodes} ready`}
          icon={Server}
          to="/nodes"
          loading={nodes.isLoading}
          error={nodes.isError}
          accent="warning"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <HealthPanel
          pods={pods.items}
          nodes={nodes.items}
          deployments={deployments.items}
          applications={apps.items}
        />
        <EventsFeed namespace={scoped} />
      </div>
    </div>
  );
}
