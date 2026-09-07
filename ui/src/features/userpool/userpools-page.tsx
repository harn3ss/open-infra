import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { IdCard, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type UserPool } from "@/types/k8s";

/** Ready when status.ready is true (or a Ready=True condition); otherwise still provisioning. */
export function userPoolStatus(p: UserPool): { label: string; tone: StatusTone } {
  const ready =
    p.status?.ready === true ||
    (p.status?.conditions as Condition[] | undefined)?.find((c) => c.type === "Ready")?.status ===
      "True";
  if (ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function UserPoolsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<UserPool, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/user-pools/$namespace/$name"
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
        accessorFn: (p) => p.status?.issuer ?? "",
        cell: ({ row }) => {
          const issuer = row.original.status?.issuer;
          return issuer ? (
            <code className="max-w-[22rem] truncate text-xs">{issuer}</code>
          ) : (
            <span className="text-muted-foreground">pending</span>
          );
        },
        size: 320,
      },
      {
        id: "realm",
        header: "Realm",
        accessorFn: (p) => p.status?.realm ?? p.spec?.realm ?? "",
        cell: ({ row }) => {
          const realm = row.original.status?.realm ?? row.original.spec?.realm;
          return realm ? (
            <code className="text-xs">{realm}</code>
          ) : (
            <span className="text-muted-foreground">{row.original.metadata.name}</span>
          );
        },
        size: 160,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (p) => userPoolStatus(p).label,
        cell: ({ row }) => {
          const s = userPoolStatus(row.original);
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

  const filterProperties = useMemo<FilterPropertyDef<UserPool>[]>(
    () => [
      { key: "name", label: "Name", getValue: (p) => p.metadata.name },
      { key: "realm", label: "Realm", getValue: (p) => p.status?.realm ?? p.spec?.realm },
      {
        key: "status",
        label: "Status",
        getValue: (p) => userPoolStatus(p).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<UserPool>
      icon={<IdCard />}
      title="User Pools"
      description="Customer-facing identity (AWS Cognito analog) — each User Pool is a Keycloak realm behind an OIDC issuer. Point your applications' OIDC/JWT sign-in at a pool's issuer + client ID. This is distinct from the internal IAM Users who administer this console."
      listPath={openinfraPaths.userpools}
      columns={columns}
      onRowClick={(p) =>
        navigate({
          to: "/user-pools/$namespace/$name",
          params: {
            namespace: p.metadata.namespace ?? "default",
            name: p.metadata.name ?? "",
          },
        })
      }
      search={(p) => [p.metadata.name, p.metadata.namespace, p.status?.realm, p.spec?.realm]}
      singular="user pool"
      plural="user pools"
      emptyTitle="No user pools yet"
      emptyDescription="Create a user pool to give your applications a customer-facing OIDC identity provider (a Keycloak realm) they can point sign-in at."
      docsHref={kindDocsUrl("UserPool")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{ issuer: "OIDC issuer", realm: "Realm" }}
      headerActions={
        <Button onClick={() => navigate({ to: "/user-pools/new" })}>
          <Plus className="size-4" /> Create user pool
        </Button>
      }
    />
  );
}
