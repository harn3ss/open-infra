import {
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";
import { AppShell } from "@/components/layout/app-shell";
import { NotFound } from "@/components/layout/not-found";
import { RouteErrorBoundary } from "@/components/layout/route-error";
import { DashboardPage } from "@/features/dashboard/dashboard-page";
import { ApplicationsPage } from "@/features/applications/applications-page";
import { FunctionsPage } from "@/features/functions/functions-page";
import { FunctionDetailPage } from "@/features/functions/function-detail-page";
import { ModelsPage } from "@/features/models/models-page";
import { ModelDetailPage } from "@/features/models/model-detail-page";
import { DatabasesPage } from "@/features/databases/databases-page";
import { DatabaseDetailPage } from "@/features/databases/database-detail-page";
import { ManagedDatabaseDetailPage } from "@/features/databases/managed-detail-page";
import { QueueDetailPage } from "@/features/queues/queue-detail-page";
import { BucketsPage } from "@/features/buckets/buckets-page";
import { BucketDetailPage } from "@/features/buckets/bucket-detail-page";
import { QueuesPage } from "@/features/queues/queues-page";
import { WorkloadsPage } from "@/features/workloads/workloads-page";
import { NodesPage } from "@/features/nodes/nodes-page";
import { NetworkPage } from "@/features/network/network-page";
import { MonitoringPage } from "@/features/monitoring/monitoring-page";

const rootRoute = createRootRoute({
  component: AppShell,
  notFoundComponent: NotFound,
  errorComponent: RouteErrorBoundary,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

const applicationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/applications",
  component: ApplicationsPage,
});

const functionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/functions",
  component: FunctionsPage,
});

const functionDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/functions/$namespace/$name",
  component: FunctionDetailPage,
});

const modelsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/models",
  component: ModelsPage,
});

const modelDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/models/$namespace/$name",
  component: ModelDetailPage,
});

const databasesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/databases",
  component: DatabasesPage,
});

const databaseDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/databases/$namespace/$name",
  component: DatabaseDetailPage,
});

const managedDbDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/databases/managed/$namespace/$name",
  component: ManagedDatabaseDetailPage,
});

const bucketsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/buckets",
  component: BucketsPage,
});

const bucketDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/buckets/$bucket",
  component: BucketDetailPage,
});

const queuesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/queues",
  component: QueuesPage,
});

const queueDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/queues/$stream",
  component: QueueDetailPage,
});

const workloadsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workloads",
  component: WorkloadsPage,
});

const nodesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/nodes",
  component: NodesPage,
});

const networkRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network",
  component: NetworkPage,
});

const monitoringRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/monitoring",
  component: MonitoringPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  applicationsRoute,
  functionsRoute,
  functionDetailRoute,
  modelsRoute,
  modelDetailRoute,
  databasesRoute,
  databaseDetailRoute,
  managedDbDetailRoute,
  bucketsRoute,
  bucketDetailRoute,
  queuesRoute,
  queueDetailRoute,
  workloadsRoute,
  nodesRoute,
  networkRoute,
  monitoringRoute,
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultPreloadStaleTime: 0,
  scrollRestoration: true,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
