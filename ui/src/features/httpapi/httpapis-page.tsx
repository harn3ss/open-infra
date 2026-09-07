import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Webhook, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type HttpApi } from "@/types/k8s";

function apiStatus(a: HttpApi): { label: string; tone: StatusTone } {
  const ready = (a.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

/** List of kind: HttpApi (API Gateway HTTP API) — a hostname routing paths onto Function/Application backends. */
export function HttpApisPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<HttpApi, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (a) => a.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/http-apis/$namespace/$name"
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
        accessorFn: (a) => a.spec?.domain ?? "",
        cell: ({ row }) =>
          row.original.spec?.domain ? (
            <code className="text-xs">{row.original.spec.domain}</code>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 240,
      },
      {
        id: "routes",
        header: "Routes",
        accessorFn: (a) => a.spec?.routes?.length ?? 0,
        cell: ({ row }) => {
          const n = row.original.spec?.routes?.length ?? 0;
          return <span className="text-muted-foreground">{n}</span>;
        },
        size: 90,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (a) => apiStatus(a).label,
        cell: ({ row }) => {
          const s = apiStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 130,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (a) => a.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<HttpApi>[]>(
    () => [
      { key: "name", label: "Name", getValue: (a) => a.metadata.name },
      { key: "domain", label: "Domain", getValue: (a) => a.spec?.domain },
      {
        key: "status",
        label: "Status",
        getValue: (a) => apiStatus(a).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<HttpApi>
      icon={<Webhook />}
      title="HTTP APIs"
      description="An HTTP API front door (API Gateway HTTP API) — one hostname whose path routes forward to Function or Application backends, with optional JWT authorization, CORS, throttling, TLS, and WAF. One Traefik Ingress + cert-manager TLS under the hood."
      listPath={openinfraPaths.httpapis}
      columns={columns}
      onRowClick={(a) =>
        navigate({
          to: "/http-apis/$namespace/$name",
          params: {
            namespace: a.metadata.namespace ?? "default",
            name: a.metadata.name ?? "",
          },
        })
      }
      search={(a) => [a.metadata.name, a.metadata.namespace, a.spec?.domain]}
      singular="HTTP API"
      plural="HTTP APIs"
      emptyTitle="No HTTP APIs yet"
      emptyDescription="Create an HTTP API to route a hostname's paths onto your Functions and Applications, with optional JWT auth, CORS, and throttling."
      docsHref={kindDocsUrl("HttpApi")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      headerActions={
        <Button onClick={() => navigate({ to: "/http-apis/new" })}>
          <Plus className="size-4" /> Create HTTP API
        </Button>
      }
    />
  );
}
