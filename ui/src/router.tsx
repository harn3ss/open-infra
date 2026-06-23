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
import { VmsPage } from "@/features/vms/vms-page";
import { VmDetailPage } from "@/features/vms/vm-detail-page";
import { VmImagesPage } from "@/features/vms/vm-images-page";
import { VolumesPage } from "@/features/volumes/volumes-page";
import { FileSharesPage } from "@/features/fileshares/fileshares-page";
import { DirectoriesPage } from "@/features/directories/directories-page";
import { SecurityGroupsPage } from "@/features/securitygroups/securitygroups-page";
import { MigrationsPage } from "@/features/migrations/migrations-page";
import { StreamsPage } from "@/features/streams/streams-page";
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

const vmsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vms",
  component: VmsPage,
});

const vmImagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vms/images",
  component: VmImagesPage,
});

const vmDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vms/$namespace/$name",
  component: VmDetailPage,
});

const volumesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/volumes",
  component: VolumesPage,
});

const fileSharesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/fileshares",
  component: FileSharesPage,
});

const directoriesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/directories",
  component: DirectoriesPage,
});

const securityGroupsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/security-groups",
  component: SecurityGroupsPage,
});

const migrationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/migrations",
  component: MigrationsPage,
});

const streamsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/streams",
  component: StreamsPage,
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
  vmsRoute,
  vmImagesRoute,
  vmDetailRoute,
  volumesRoute,
  fileSharesRoute,
  directoriesRoute,
  securityGroupsRoute,
  migrationsRoute,
  streamsRoute,
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
