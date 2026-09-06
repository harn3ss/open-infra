import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  type ColumnDef,
  type SortingState,
  type VisibilityState,
} from "@tanstack/react-table";
import { Users, UserPlus, AlertTriangle, KeyRound, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/common/status-badge";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  PropertyFilter,
  applyFilterTokens,
  type FilterOperation,
  type FilterPropertyDef,
  type FilterToken,
} from "@/components/common/property-filter";
import {
  CollectionPreferences,
  useCollectionPreferences,
} from "@/components/common/collection-preferences";
import { Pagination, usePagination } from "@/components/common/pagination";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { useListFilter } from "@/hooks/use-list-filter";
import { age } from "@/lib/format";
import { getAccessReview, listIamUsers, type IamUser } from "@/lib/api";

/**
 * Users list — the roster of console sign-in identities (kind: User), brought to AWS-IAM
 * table fidelity: a tokenized property filter, a column/page-size preferences gear, and
 * discrete pagination over the same VirtualDataTable the resource lists use. Data comes
 * from the SAR-gated BFF (`/api/iam/users`), not the k8s proxy, so it can't ride the
 * K8sObject-typed ResourceTablePage; the same primitives are composed here instead.
 *
 * Row-click → user detail (no inline row actions — house convention). The break-glass
 * root account is separate and never appears here.
 */
export function UsersPage() {
  const navigate = useNavigate();

  const { data = [], isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["iam", "users"],
    queryFn: listIamUsers,
    refetchInterval: 15000,
  });

  // Last-activity is the access-review lastSeen (Loki-derived). Best-effort: if it errors
  // or is blank, the column falls back to "—" rather than blocking the roster.
  const review = useQuery({
    queryKey: ["access-review"],
    queryFn: getAccessReview,
    staleTime: 60000,
  });
  const lastSeenByName = useMemo(() => {
    const m = new Map<string, string>();
    for (const p of review.data?.principals ?? []) if (p.lastSeen) m.set(p.name, p.lastSeen);
    return m;
  }, [review.data]);

  // Global text search (topbar) → tokenized property filter → the rows we render.
  const { filtered: textFiltered } = useListFilter(data, (u) => [
    u.name,
    u.displayName,
    u.source,
    ...(u.groups ?? []),
  ]);
  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [operation, setOperation] = useState<FilterOperation>("and");
  const filtered = useMemo(
    () => (tokens.length ? applyFilterTokens(textFiltered, tokens, FILTER_PROPERTIES, operation) : textFiltered),
    [textFiltered, tokens, operation],
  );

  const [sorting, setSorting] = useState<SortingState>([{ id: "name", desc: false }]);

  const columns = useMemo<ColumnDef<IamUser, unknown>[]>(
    () => [
      {
        id: "name",
        header: "User name",
        accessorFn: (u) => u.name,
        cell: ({ row }) => {
          const u = row.original;
          return (
            <div className="flex flex-col">
              <span className="font-medium text-primary">{u.name}</span>
              {u.displayName ? (
                <span className="text-xs text-muted-foreground">{u.displayName}</span>
              ) : null}
            </div>
          );
        },
      },
      {
        id: "groups",
        header: "Groups",
        enableSorting: false,
        cell: ({ row }) => {
          const u = row.original;
          const groups = u.groups ?? [];
          const unbound = u.unboundGroups ?? [];
          if (groups.length === 0)
            return <span className="text-xs text-muted-foreground">none</span>;
          return (
            <div className="flex flex-wrap items-center gap-1">
              {groups.map((g) => {
                const isUnbound = unbound.includes(g);
                return (
                  <Badge
                    key={g}
                    variant={isUnbound ? "outline" : "secondary"}
                    className={
                      isUnbound ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : ""
                    }
                  >
                    {isUnbound ? <AlertTriangle className="size-3" /> : null}
                    {g}
                  </Badge>
                );
              })}
            </div>
          );
        },
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (u) => u.source || "local",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.source || "local"}</span>
        ),
      },
      {
        id: "console",
        header: "Console access",
        accessorFn: (u) => (u.disabled ? "Disabled" : "Enabled"),
        cell: ({ row }) =>
          row.original.disabled ? (
            <StatusBadge status="Disabled" tone="muted" />
          ) : (
            <StatusBadge status="Enabled" tone="success" />
          ),
      },
      {
        id: "signin",
        header: "Sign-in",
        enableSorting: false,
        cell: ({ row }) => {
          const u = row.original;
          const isLocal = u.source === "local" || !u.source;
          if (!isLocal)
            return <span className="text-xs text-muted-foreground">via {u.source}</span>;
          return u.hasPassword ? (
            <span className="text-xs text-muted-foreground">Password set</span>
          ) : (
            <span
              className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400"
              title="No password is set — this user can't sign in until one is."
            >
              <KeyRound className="size-3" /> no password
            </span>
          );
        },
      },
      {
        id: "activity",
        header: "Last activity",
        accessorFn: (u) => lastSeenByName.get(u.name) ?? "",
        cell: ({ row }) => {
          const seen = lastSeenByName.get(row.original.name);
          return seen ? (
            <span className="text-xs text-muted-foreground" title={seen}>
              {age(seen)} ago
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          );
        },
      },
    ],
    [lastSeenByName],
  );

  const columnMeta = useMemo(
    () => [
      { id: "name", label: "User name", alwaysVisible: true },
      { id: "groups", label: "Groups" },
      { id: "source", label: "Source" },
      { id: "console", label: "Console access" },
      { id: "signin", label: "Sign-in" },
      { id: "activity", label: "Last activity" },
    ],
    [],
  );

  const [prefs, setPrefs] = useCollectionPreferences("iam-users", {
    pageSize: 25,
    visibleColumns: columnMeta.map((m) => m.id),
    wrapLines: false,
  });

  const columnVisibility = useMemo<VisibilityState>(() => {
    const vis: VisibilityState = {};
    for (const m of columnMeta) vis[m.id] = m.alwaysVisible || prefs.visibleColumns.includes(m.id);
    return vis;
  }, [columnMeta, prefs.visibleColumns]);

  const pg = usePagination(filtered, prefs.pageSize);

  const createButton = (
    <Button onClick={() => navigate({ to: "/users/new" })}>
      <UserPlus className="size-4" /> Create user
    </Button>
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Users />}
        title="Users"
        description="Console sign-ins, stored as kind: User. Permissions come from group membership; the break-glass root account is separate and isn't listed here."
        actions={
          <>
            <Button variant="outline" size="icon" onClick={() => refetch()} aria-label="Refresh">
              <RefreshCw className={isFetching ? "size-4 animate-spin" : "size-4"} />
            </Button>
            {createButton}
          </>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading users…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<Users />}
          title="No users yet"
          description="Create one, or note that people can also be defined as kind: User in Git. The break-glass root account signs in regardless."
          action={createButton}
        />
      ) : (
        <>
          <PropertyFilter
            properties={FILTER_PROPERTIES}
            tokens={tokens}
            onChange={setTokens}
            operation={operation}
            onOperationChange={setOperation}
          />

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              {filtered.length} of {data.length} {data.length === 1 ? "user" : "users"}
            </p>
            <div className="flex items-center gap-2">
              <Pagination
                currentPage={pg.page}
                pageCount={pg.pageCount}
                onPageChange={pg.setPage}
              />
              <CollectionPreferences
                value={prefs}
                onChange={setPrefs}
                columnOptions={columnMeta}
                pageSizeOptions={[10, 25, 50, 100]}
                showDensity
              />
            </div>
          </div>

          <VirtualDataTable
            data={pg.pageItems}
            columns={columns}
            getRowId={(u) => u.name}
            sorting={sorting}
            onSortingChange={setSorting}
            columnVisibility={columnVisibility}
            onRowClick={(u) => navigate({ to: "/users/$name", params: { name: u.name } })}
            emptyState={
              <EmptyState title="No matches" description="No users match the current filter." />
            }
          />
        </>
      )}
    </div>
  );
}

/** Filterable properties (Cloudscape PropertyFilter) with how to read each off a user. */
const FILTER_PROPERTIES: FilterPropertyDef<IamUser>[] = [
  { key: "name", label: "User name", getValue: (u) => u.name },
  { key: "displayName", label: "Display name", getValue: (u) => u.displayName },
  {
    key: "source",
    label: "Source",
    options: [{ value: "local" }, { value: "ldap" }, { value: "oidc" }],
    getValue: (u) => u.source || "local",
  },
  {
    key: "console",
    label: "Console access",
    options: [{ value: "Enabled" }, { value: "Disabled" }],
    getValue: (u) => (u.disabled ? "Disabled" : "Enabled"),
  },
  { key: "group", label: "Group", getValue: (u) => u.groups ?? [] },
];
