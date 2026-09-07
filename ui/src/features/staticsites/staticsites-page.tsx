import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { AppWindow, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import type { Condition, StaticSite } from "@/types/k8s";

/** Ready when the Ready condition is True (or status.ready is set); else provisioning. */
function siteStatus(s: StaticSite): { label: string; tone: StatusTone } {
  const ready = s.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True" || s.status?.ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function StaticSitesPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<StaticSite, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/staticsites/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 200,
      },
      {
        id: "domain",
        header: "Domain",
        accessorFn: (s) => s.spec?.domain ?? "",
        cell: ({ row }) =>
          row.original.spec?.domain ? (
            <code className="text-xs">{row.original.spec.domain}</code>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 220,
      },
      {
        id: "url",
        header: "URL",
        accessorFn: (s) => s.status?.url ?? "",
        cell: ({ row }) => {
          const url = row.original.status?.url;
          return url ? (
            <a
              href={url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-primary hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {url}
            </a>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
        size: 240,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => siteStatus(s).label,
        cell: ({ row }) => {
          const st = siteStatus(row.original);
          return <StatusBadge status={st.label} tone={st.tone} />;
        },
        size: 130,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<StaticSite>[]>(
    () => [
      { key: "name", label: "Name", getValue: (s) => s.metadata.name },
      { key: "domain", label: "Domain", getValue: (s) => s.spec?.domain },
      {
        key: "status",
        label: "Status",
        getValue: (s) => siteStatus(s).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<StaticSite>
      icon={<AppWindow />}
      title="Static Sites"
      description="Host a built static site or single-page app (AWS Amplify / S3 static website + CloudFront). open-infra serves the contents of an object-store bucket on your domain over TLS, with SPA history fallback."
      listPath={openinfraPaths.staticsites}
      columns={columns}
      onRowClick={(s) =>
        navigate({
          to: "/staticsites/$namespace/$name",
          params: {
            namespace: s.metadata.namespace ?? "default",
            name: s.metadata.name ?? "",
          },
        })
      }
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.domain, s.status?.url]}
      singular="static site"
      plural="static sites"
      emptyTitle="No static sites yet"
      emptyDescription="Create a static site to serve a built SPA or static bundle from an object-store bucket on your own domain."
      docsHref={kindDocsUrl("StaticSite")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      headerActions={
        <Button onClick={() => navigate({ to: "/staticsites/new" })}>
          <Plus className="size-4" /> Create static site
        </Button>
      }
    />
  );
}
