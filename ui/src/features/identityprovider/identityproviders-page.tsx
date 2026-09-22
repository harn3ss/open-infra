import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Fingerprint, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type IdentityProvider } from "@/types/k8s";

/** Ready when status.ready is true (or a Ready=True condition); otherwise still registering. */
export function identityProviderStatus(p: IdentityProvider): { label: string; tone: StatusTone } {
  const ready =
    p.status?.ready === true ||
    (p.status?.conditions as Condition[] | undefined)?.find((c) => c.type === "Ready")?.status ===
      "True";
  if (ready) return { label: "Ready", tone: "success" };
  return { label: "Registering", tone: "warning" };
}

export function IdentityProvidersPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<IdentityProvider, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/identity-providers/$namespace/$name"
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
        id: "issuer",
        header: "OIDC issuer",
        accessorFn: (p) => p.spec?.issuerURL ?? p.status?.issuer ?? "",
        cell: ({ row }) => {
          const issuer = row.original.spec?.issuerURL ?? row.original.status?.issuer;
          return issuer ? (
            <code className="max-w-[24rem] truncate text-xs">{issuer}</code>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
        size: 340,
      },
      {
        id: "audiences",
        header: "Audiences",
        accessorFn: (p) => (p.spec?.audiences ?? []).length,
        cell: ({ row }) => {
          const auds = row.original.spec?.audiences ?? [];
          return auds.length ? (
            <code className="text-xs">{auds.join(", ")}</code>
          ) : (
            <span className="text-muted-foreground">none</span>
          );
        },
        size: 200,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (p) => identityProviderStatus(p).label,
        cell: ({ row }) => {
          const s = identityProviderStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (p) => p.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<IdentityProvider>[]>(
    () => [
      { key: "name", label: "Name", getValue: (p) => p.metadata.name },
      { key: "issuer", label: "Issuer", getValue: (p) => p.spec?.issuerURL },
      {
        key: "status",
        label: "Status",
        getValue: (p) => identityProviderStatus(p).label,
        options: [{ value: "Ready" }, { value: "Registering" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<IdentityProvider>
      icon={<Fingerprint />}
      title="Identity Providers"
      description="External OIDC identity providers the platform trusts for federated access — the AWS 'Identity providers' registry. A Role whose trust names OIDC::<name> can be assumed by that issuer's tokens (AssumeRoleWithWebIdentity). Point one at a User Pool's issuer to let its tokens assume roles."
      listPath={openinfraPaths.identityproviders}
      columns={columns}
      onRowClick={(p) =>
        navigate({
          to: "/identity-providers/$namespace/$name",
          params: {
            namespace: p.metadata.namespace ?? "default",
            name: p.metadata.name ?? "",
          },
        })
      }
      search={(p) => [p.metadata.name, p.metadata.namespace, p.spec?.issuerURL]}
      singular="identity provider"
      plural="identity providers"
      emptyTitle="No identity providers yet"
      emptyDescription="Register an external OIDC issuer so a Role can trust its tokens (OIDC::<name>) for AssumeRoleWithWebIdentity."
      docsHref={kindDocsUrl("IdentityProvider")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{ issuer: "OIDC issuer", audiences: "Audiences" }}
      headerActions={
        <Button onClick={() => navigate({ to: "/identity-providers/new" })}>
          <Plus className="size-4" /> Create identity provider
        </Button>
      }
    />
  );
}
