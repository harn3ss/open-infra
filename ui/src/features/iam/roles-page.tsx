import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, ArrowUpDown, Boxes, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/common/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import {
  applyFilterTokens,
  PropertyFilter,
  type FilterProperty,
  type FilterPropertyDef,
  type FilterToken,
} from "@/components/common/property-filter";
import { listIamRoles, type IamRole } from "@/lib/api";
import { cn } from "@/lib/utils";
import { principalLabel } from "./trust-editor";

type SortKey = "name" | "trust" | "policies" | "status";

const FILTER_PROPERTIES: FilterProperty[] = [
  { key: "name", label: "Name" },
  { key: "trust", label: "Trusted entity" },
  { key: "policy", label: "Policy" },
  {
    key: "status",
    label: "Status",
    operators: ["=", "!="],
    options: [
      { value: "Ready" },
      { value: "Compiling" },
    ],
  },
];

const FILTER_DEFS: FilterPropertyDef<IamRole>[] = [
  { key: "name", label: "Name", getValue: (r) => r.name },
  { key: "trust", label: "Trusted entity", getValue: (r) => (r.trust ?? []).map(principalLabel) },
  { key: "policy", label: "Policy", getValue: (r) => r.policies },
  { key: "status", label: "Status", getValue: (r) => (r.ready ? "Ready" : "Compiling") },
];

export function RolesPage() {
  const navigate = useNavigate();
  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "name",
    dir: "asc",
  });

  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "roles"],
    queryFn: listIamRoles,
    refetchInterval: 15000,
  });

  const rows = useMemo(() => {
    const filtered = applyFilterTokens(data, tokens, FILTER_DEFS);
    const dir = sort.dir === "asc" ? 1 : -1;
    const cmp = (a: IamRole, b: IamRole) => {
      switch (sort.key) {
        case "trust":
          return ((a.trust ?? []).length - (b.trust ?? []).length) * dir;
        case "policies":
          return (a.policies.length - b.policies.length) * dir;
        case "status":
          return (Number(a.ready) - Number(b.ready)) * dir;
        default:
          return a.name.localeCompare(b.name) * dir;
      }
    };
    return [...filtered].sort(cmp);
  }, [data, tokens, sort]);

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));

  const SortHeader = ({ label, sortKey }: { label: string; sortKey: SortKey }) => {
    const active = sort.key === sortKey;
    const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
    return (
      <th className="p-3 font-medium">
        <button
          type="button"
          onClick={() => toggleSort(sortKey)}
          className="inline-flex items-center gap-1 hover:text-foreground"
        >
          {label}
          <Icon className={cn("size-3.5", active ? "text-foreground" : "text-muted-foreground/50")} />
        </button>
      </th>
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Boxes />}
        title={`Roles${data.length ? ` (${data.length})` : ""}`}
        description="Assumable identities: a bundle of policies plus a trust policy naming who may assume it. Point a Group at a role to grant it to members; the aws-shim honors the trust policy for sts:AssumeRole."
        actions={
          <Button onClick={() => navigate({ to: "/roles/new" })}>
            <Plus className="size-4" /> Create role
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading roles…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<Boxes />}
          title="No roles yet"
          description="Create a role, choose a trusted entity that may assume it, attach policies, then point a Group at openinfra-role-<name>."
          action={
            <Button onClick={() => navigate({ to: "/roles/new" })}>
              <Plus className="size-4" /> Create role
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          <PropertyFilter properties={FILTER_PROPERTIES} tokens={tokens} onChange={setTokens} />
          <p className="text-xs text-muted-foreground">
            {tokens.length > 0 ? `${rows.length} of ${data.length} match` : `${data.length} role${data.length === 1 ? "" : "s"}`}
          </p>

          {rows.length === 0 ? (
            <Card>
              <CardContent className="py-12">
                <EmptyState
                  title="No matches"
                  description="No roles match the current filter."
                  action={
                    <Button variant="outline" size="sm" onClick={() => setTokens([])}>
                      Clear filters
                    </Button>
                  }
                />
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <SortHeader label="Name" sortKey="name" />
                      <SortHeader label="Trusted entities" sortKey="trust" />
                      <SortHeader label="Policies" sortKey="policies" />
                      <th className="p-3 font-medium">Binds as</th>
                      <SortHeader label="Status" sortKey="status" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => {
                      const trust = r.trust ?? [];
                      const shownTrust = trust.slice(0, 3);
                      return (
                        <tr
                          key={r.name}
                          className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                          onClick={() => navigate({ to: "/roles/$name", params: { name: r.name } })}
                        >
                          <td className="p-3 font-medium text-primary">{r.name}</td>
                          <td className="p-3">
                            {trust.length === 0 ? (
                              <Badge
                                variant="outline"
                                className="border-amber-500/40 text-amber-600 dark:text-amber-400"
                              >
                                None — not assumable
                              </Badge>
                            ) : (
                              <div className="flex flex-wrap gap-1">
                                {shownTrust.map((p) => (
                                  <Badge
                                    key={p}
                                    variant={p === "*" ? "outline" : "secondary"}
                                    className={
                                      p === "*"
                                        ? "border-amber-500/40 text-amber-600 dark:text-amber-400"
                                        : ""
                                    }
                                  >
                                    {principalLabel(p)}
                                  </Badge>
                                ))}
                                {trust.length > shownTrust.length ? (
                                  <span className="text-xs text-muted-foreground">
                                    +{trust.length - shownTrust.length}
                                  </span>
                                ) : null}
                              </div>
                            )}
                          </td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1">
                              {r.policies.length === 0 ? (
                                <span className="text-xs text-muted-foreground">none</span>
                              ) : (
                                r.policies.map((p) => (
                                  <Badge key={p} variant="secondary">
                                    {p}
                                  </Badge>
                                ))
                              )}
                            </div>
                          </td>
                          <td className="p-3">
                            <code className="text-xs text-muted-foreground">
                              {r.clusterRole || `openinfra-role-${r.name}`}
                            </code>
                          </td>
                          <td className="p-3">
                            <StatusBadge
                              status={r.ready ? "Ready" : "Compiling"}
                              tone={r.ready ? "success" : "warning"}
                            />
                          </td>
                        </tr>
                      );
                    })}
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
