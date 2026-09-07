import { Link } from "@tanstack/react-router";
import { Boxes } from "lucide-react";
import { Widget } from "@/features/dashboard/widget";
import { StatusBadge } from "@/components/common/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { applicationHealth } from "@/features/applications/application-status";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { openinfraPaths } from "@/lib/k8s-paths";
import { kindDocsUrl } from "@/lib/kind-docs";
import type { Application } from "@/types/k8s";

/**
 * Applications — the AWS myApplications widget. Surfaces `kind: Application`
 * (count in the header + the most recently created few), each deep-linking to
 * its detail page, with the AWS empty-state "create your first" call to action.
 */
export function ApplicationsWidget({
  scoped,
  className,
}: {
  scoped?: string;
  className?: string;
}) {
  const apps = useK8sWatch<Application>(openinfraPaths.applications(scoped));

  const recent = [...apps.items]
    .sort((a, b) => {
      const ta = new Date(a.metadata.creationTimestamp ?? 0).getTime();
      const tb = new Date(b.metadata.creationTimestamp ?? 0).getTime();
      return tb - ta;
    })
    .slice(0, 5);

  return (
    <Widget
      title={`Applications${apps.items.length ? ` (${apps.items.length})` : ""}`}
      icon={Boxes}
      className={className}
      footerHref={apps.items.length > 0 ? "/applications" : undefined}
      footerLabel="View all applications"
    >
      {apps.isLoading ? (
        <LoadingState label="Loading applications…" />
      ) : apps.isError ? (
        <ErrorState error={apps.error} onRetry={apps.refetch} />
      ) : recent.length === 0 ? (
        <EmptyState
          icon={<Boxes className="size-6" />}
          title="No applications yet"
          description="An Application is an autoscaling HTTPS service with an optional database, buckets, and queues."
          action={
            <Link
              to="/applications/new"
              className="text-sm font-medium text-primary hover:underline"
            >
              Create an application
            </Link>
          }
          learnMore={kindDocsUrl("Application")}
        />
      ) : (
        <ul className="divide-y divide-border">
          {recent.map((app) => {
            const health = applicationHealth(app);
            return (
              <li key={app.metadata.uid ?? app.metadata.name}>
                <Link
                  to="/applications/$namespace/$name"
                  params={{
                    namespace: app.metadata.namespace ?? "default",
                    name: app.metadata.name ?? "",
                  }}
                  className="flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-secondary/40"
                >
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium">
                      {app.metadata.name}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      {app.metadata.namespace}
                    </div>
                  </div>
                  <StatusBadge status={health.label} tone={health.tone} />
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Widget>
  );
}
