import {
  BrainCircuit,
  Boxes,
  Database,
  HardDrive,
  Layers,
  Send,
  Server,
  Zap,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/common/page-header";
import { StatCard } from "@/features/dashboard/stat-card";
import { HealthPanel } from "@/features/dashboard/health-panel";
import { EventsFeed } from "@/features/dashboard/events-feed";
import { listBuckets, listQueues } from "@/lib/api";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import {
  appsPaths,
  cnpgPaths,
  corePaths,
  openinfraPaths,
} from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import { useConfig } from "@/lib/config-context";
import type {
  Application,
  CnpgCluster,
  Deployment,
  Model,
  Node,
  OpenInfraFunction,
  Pod,
} from "@/types/k8s";

const isReady = (conditions?: { type: string; status: string }[]) =>
  conditions?.some((c) => c.type === "Ready" && c.status === "True") ?? false;

export function DashboardPage() {
  const { scoped } = useNamespace();
  const config = useConfig();

  const apps = useK8sWatch<Application>(openinfraPaths.applications(scoped));
  const fns = useK8sWatch<OpenInfraFunction>(openinfraPaths.functions(scoped));
  const models = useK8sWatch<Model>(openinfraPaths.models(scoped));
  const databases = useK8sWatch<CnpgCluster>(cnpgPaths.clusters(scoped));
  const pods = useK8sWatch<Pod>(corePaths.pods(scoped));
  const deployments = useK8sWatch<Deployment>(appsPaths.deployments(scoped));
  const nodes = useK8sWatch<Node>(corePaths.nodes());

  const runningPods = pods.items.filter(
    (p) => p.status?.phase === "Running",
  ).length;
  const readyNodes = nodes.items.filter((n) => isReady(n.status?.conditions)).length;
  const healthyApps = apps.items.filter((a) => isReady(a.status?.conditions)).length;
  const readyFns = fns.items.filter((f) => isReady(f.status?.conditions)).length;
  const readyModels = models.items.filter((m) => isReady(m.status?.conditions)).length;
  const bucketsQuery = useQuery({ queryKey: ["buckets"], queryFn: listBuckets });
  const queuesQuery = useQuery({ queryKey: ["queues"], queryFn: listQueues });
  const bucketCount = bucketsQuery.data?.length ?? 0;
  const queueCount = queuesQuery.data?.length ?? 0;

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
          label="Functions"
          value={fns.items.length}
          sub={`${readyFns} ready`}
          icon={Zap}
          to="/functions"
          loading={fns.isLoading}
          error={fns.isError}
          accent="accent"
        />
        <StatCard
          label="Models"
          value={models.items.length}
          sub={`${readyModels} ready`}
          icon={BrainCircuit}
          to="/models"
          loading={models.isLoading}
          error={models.isError}
          accent="primary"
        />
        <StatCard
          label="Databases"
          value={databases.items.length}
          icon={Database}
          to="/databases"
          loading={databases.isLoading}
          error={databases.isError}
          accent="success"
        />
        <StatCard
          label="Buckets"
          value={bucketCount}
          icon={HardDrive}
          to="/buckets"
          loading={bucketsQuery.isLoading}
          error={bucketsQuery.isError}
          accent="warning"
        />
        <StatCard
          label="Queues"
          value={queueCount}
          icon={Send}
          to="/queues"
          loading={queuesQuery.isLoading}
          error={queuesQuery.isError}
          accent="accent"
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
