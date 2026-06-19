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
import { WorkloadsPage } from "@/features/workloads/workloads-page";
import { NodesPage } from "@/features/nodes/nodes-page";
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

const monitoringRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/monitoring",
  component: MonitoringPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  applicationsRoute,
  workloadsRoute,
  nodesRoute,
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
