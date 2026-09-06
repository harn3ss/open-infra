import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  UsersRound,
  Plus,
  AlertTriangle,
  ChevronsUpDown,
  ChevronUp,
  ChevronDown,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import {
  PropertyFilter,
  applyFilterTokens,
  type FilterToken,
  type FilterPropertyDef,
} from "@/components/common/property-filter";
import { listIamGroups, listIamUsers, type IamGroup } from "@/lib/api";
import { cn } from "@/lib/utils";

type GroupStatus = "Ready" | "Provisioning" | "Inert";

function groupStatus(g: IamGroup): GroupStatus {
  if (!g.impersonable) return "Inert";
  return g.ready ? "Ready" : "Provisioning";
}

/** A group row enriched with its live member count (membership lives on the User CRs). */
interface GroupRow extends IamGroup {
  members: number;
  status: GroupStatus;
}

type SortKey = "name" | "members" | "status";

/**
 * Groups list — the sets of permissions users are placed into (AWS IAM "User groups").
 * A group binds its members to ONE ClusterRole (the only field that grants), and takes
 * effect only if its name is inside the impersonation ceiling; otherwise it is inert.
 */
export function GroupsPage() {
  const navigate = useNavigate();

  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "groups"],
    queryFn: listIamGroups,
    refetchInterval: 15000,
  });
  // Membership is stored on each User (spec.groups), not on the Group — derive counts.
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });

  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const rows = useMemo<GroupRow[]>(() => {
    const memberCount = new Map<string, number>();
    for (const u of users.data ?? []) {
      for (const g of u.groups ?? []) memberCount.set(g, (memberCount.get(g) ?? 0) + 1);
    }
    return data.map((g) => ({
      ...g,
      members: memberCount.get(g.name) ?? 0,
      status: groupStatus(g),
    }));
  }, [data, users.data]);

  const filterDefs = useMemo<FilterPropertyDef<GroupRow>[]>(
    () => [
      { key: "name", label: "Name", getValue: (g) => g.name },
      { key: "clusterRole", label: "Grants (ClusterRole)", getValue: (g) => g.clusterRole },
      { key: "description", label: "Description", getValue: (g) => g.description },
      {
        key: "status",
        label: "Status",
        options: [{ value: "Ready" }, { value: "Provisioning" }, { value: "Inert" }],
        getValue: (g) => g.status,
      },
    ],
    [],
  );

  const filtered = useMemo(
    () => applyFilterTokens(rows, tokens, filterDefs),
    [rows, tokens, filterDefs],
  );

  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sortKey === "members") return (a.members - b.members) * dir;
      const av = sortKey === "status" ? a.status : a.name;
      const bv = sortKey === "status" ? b.status : b.name;
      return av.localeCompare(bv) * dir;
    });
  }, [filtered, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const SortHeader = ({
    label,
    col,
    className,
  }: {
    label: string;
    col: SortKey;
    className?: string;
  }) => (
    <th className={cn("p-3 font-medium", className)}>
      <button
        type="button"
        onClick={() => toggleSort(col)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        {sortKey === col ? (
          sortDir === "asc" ? (
            <ChevronUp className="size-3.5" />
          ) : (
            <ChevronDown className="size-3.5" />
          )
        ) : (
          <ChevronsUpDown className="size-3.5 opacity-40" />
        )}
      </button>
    </th>
  );

  const createButton = (
    <Button onClick={() => navigate({ to: "/groups/new" })}>
      <Plus className="size-4" /> Create group
    </Button>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<UsersRound />}
        title={data.length ? `Groups (${data.length})` : "Groups"}
        description="Permission sets. A group binds its members to a ClusterRole — the only thing that grants access — and takes effect only if its name is in the impersonation ceiling."
        actions={createButton}
      />

      {isLoading ? (
        <LoadingState label="Loading groups…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<UsersRound />}
          title="No groups yet"
          description="The built-in admins / powerusers / readers groups work without being created here. Create a Group to bind members to a specific ClusterRole."
          action={createButton}
        />
      ) : (
        <div className="space-y-3">
          <PropertyFilter
            properties={filterDefs}
            tokens={tokens}
            onChange={setTokens}
            placeholder="Filter groups"
          />
          <p className="text-xs text-muted-foreground">
            {sorted.length === rows.length
              ? `${rows.length} group${rows.length === 1 ? "" : "s"}`
              : `${sorted.length} of ${rows.length} groups`}
          </p>

          {sorted.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-sm text-muted-foreground">
                No groups match the current filter.{" "}
                <button
                  type="button"
                  onClick={() => setTokens([])}
                  className="font-medium text-primary hover:underline"
                >
                  Clear filters
                </button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <SortHeader label="Name" col="name" />
                      <th className="p-3 font-medium">Grants (ClusterRole)</th>
                      <th className="p-3 font-medium">Description</th>
                      <SortHeader label="Users" col="members" />
                      <SortHeader label="Status" col="status" />
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((g) => (
                      <tr
                        key={g.name}
                        className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                        onClick={() =>
                          navigate({ to: "/groups/$name", params: { name: g.name } })
                        }
                      >
                        <td className="p-3 font-medium text-primary">{g.name}</td>
                        <td className="p-3">
                          <code className="text-xs text-muted-foreground">{g.clusterRole}</code>
                        </td>
                        <td className="p-3 text-muted-foreground">{g.description || "—"}</td>
                        <td className="p-3 text-muted-foreground">
                          {users.isError ? "—" : g.members}
                        </td>
                        <td className="p-3">
                          {g.status === "Inert" ? (
                            <span
                              className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400"
                              title="Not in the impersonation ceiling — members gain nothing until an operator widens it."
                            >
                              <AlertTriangle className="size-3" /> Inert
                            </span>
                          ) : (
                            <Badge variant={g.status === "Ready" ? "success" : "secondary"}>
                              {g.status}
                            </Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
