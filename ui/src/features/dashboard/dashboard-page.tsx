import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/common/page-header";
import { GettingStarted } from "@/features/dashboard/getting-started";
import { HealthPanel } from "@/features/dashboard/health-panel";
import { EventsFeed } from "@/features/dashboard/events-feed";
import { RecentlyVisitedWidget } from "@/features/dashboard/recently-visited-widget";
import { ServicesLauncherWidget } from "@/features/dashboard/services-launcher-widget";
import { ApplicationsWidget } from "@/features/dashboard/applications-widget";
import { CostWidget } from "@/features/dashboard/cost-widget";
import { BuildASolutionWidget } from "@/features/dashboard/build-a-solution-widget";
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

/**
 * Console Home — the post-login landing, modeled on AWS Console Home: a
 * responsive grid of widget cards (Recently visited, Applications, Cost and
 * usage, Build a solution, Service health, Recent activity, and a Services
 * launcher). The cluster-specific truths (health, events, cost estimate) map
 * onto AWS's widgets rather than being faked.
 */
export function DashboardPage() {
  const { scoped } = useNamespace();
  const config = useConfig();

  // Health + events widgets need live cluster state; the emptiness check gates
  // the first-run Getting started card (AWS's welcome panel).
  const apps = useK8sWatch<Application>(openinfraPaths.applications(scoped));
  const fns = useK8sWatch<OpenInfraFunction>(openinfraPaths.functions(scoped));
  const models = useK8sWatch<Model>(openinfraPaths.models(scoped));
  const databases = useK8sWatch<CnpgCluster>(cnpgPaths.clusters(scoped));
  const pods = useK8sWatch<Pod>(corePaths.pods(scoped));
  const deployments = useK8sWatch<Deployment>(appsPaths.deployments(scoped));
  const nodes = useK8sWatch<Node>(corePaths.nodes());
  const bucketsQuery = useQuery({ queryKey: ["buckets"], queryFn: listBuckets });
  const queuesQuery = useQuery({ queryKey: ["queues"], queryFn: listQueues });

  // First-run onboarding: only once every primary list has loaded and the
  // cluster genuinely has nothing yet (avoids a flash during load).
  const primaryLoaded =
    !apps.isLoading &&
    !fns.isLoading &&
    !models.isLoading &&
    !databases.isLoading &&
    !bucketsQuery.isLoading &&
    !queuesQuery.isLoading;
  const clusterEmpty =
    primaryLoaded &&
    apps.items.length === 0 &&
    fns.items.length === 0 &&
    models.items.length === 0 &&
    databases.items.length === 0 &&
    (bucketsQuery.data?.length ?? 0) === 0 &&
    (queuesQuery.data?.length ?? 0) === 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Console Home"
        description={`Welcome to ${config.clusterName || "open-infra"} — your self-hosted mini-cloud at a glance.`}
      />

      {clusterEmpty ? <GettingStarted /> : null}

      {/* AWS Console Home widget grid: a responsive board of titled cards. The
          6-col track on xl tiles the widgets cleanly (full / 2+2+2 / 3+3 / full). */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4 xl:grid-cols-6">
        <RecentlyVisitedWidget className="lg:col-span-4 xl:col-span-6" />

        <ApplicationsWidget scoped={scoped} className="lg:col-span-2 xl:col-span-2" />
        <CostWidget className="lg:col-span-2 xl:col-span-2" />
        <BuildASolutionWidget className="lg:col-span-4 xl:col-span-2" />

        <div className="lg:col-span-2 xl:col-span-3">
          <HealthPanel
            pods={pods.items}
            nodes={nodes.items}
            deployments={deployments.items}
            applications={apps.items}
          />
        </div>
        <div className="lg:col-span-2 xl:col-span-3">
          <EventsFeed namespace={scoped} />
        </div>

        <ServicesLauncherWidget className="lg:col-span-4 xl:col-span-6" />
      </div>
    </div>
  );
}
