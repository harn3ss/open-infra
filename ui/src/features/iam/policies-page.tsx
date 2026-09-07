import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileText, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import {
  applyFilterTokens,
  PropertyFilter,
  type FilterProperty,
  type FilterPropertyDef,
  type FilterToken,
} from "@/components/common/property-filter";
import { listIamPolicies, listIamRoles, type IamPolicy } from "@/lib/api";
import { policyType, type PolicyTypeLabel } from "./policy-type";

const TYPE_TONE: Record<PolicyTypeLabel, "default" | "accent" | "secondary"> = {
  "Control plane": "default",
  "Data plane": "accent",
  Mixed: "secondary",
  Empty: "secondary",
};

/** AWS's "Filter by type" control — open-infra's type axis is the enforcement plane. */
const TYPE_OPTIONS: PolicyTypeLabel[] = ["Control plane", "Data plane", "Mixed", "Empty"];
const ALL_TYPES = "__all__";

const FILTER_PROPERTIES: FilterProperty[] = [
  { key: "name", label: "Name" },
  {
    key: "status",
    label: "Status",
    operators: ["=", "!="],
    options: [{ value: "Ready" }, { value: "Compiling" }],
  },
];

const FILTER_DEFS: FilterPropertyDef<IamPolicy>[] = [
  { key: "name", label: "Name", getValue: (p) => p.name },
  { key: "status", label: "Status", getValue: (p) => (p.ready ? "Ready" : "Compiling") },
];

export function PoliciesPage() {
  const navigate = useNavigate();
  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [typeFilter, setTypeFilter] = useState<string>(ALL_TYPES);

  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "policies"],
    queryFn: listIamPolicies,
    refetchInterval: 15000,
  });
  // Attachment counts: how many Roles include each policy (the control-plane attachment).
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const attachCount = (name: string) =>
    (roles.data ?? []).filter((r) => r.policies.includes(name)).length;

  const rows = useMemo(() => {
    const byType =
      typeFilter === ALL_TYPES ? data : data.filter((p) => policyType(p) === typeFilter);
    return applyFilterTokens(byType, tokens, FILTER_DEFS);
  }, [data, tokens, typeFilter]);

  const filtered = tokens.length > 0 || typeFilter !== ALL_TYPES;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<FileText />}
        title="Policies"
        description="Attachable permission sets — AWS-style managed policies. Platform permissions compile to Kubernetes RBAC (the boundary); data-service permissions are enforced by Cedar (S3/DynamoDB/Lambda) and can Deny, scope, and set conditions. A policy grants nothing until a Role includes it or a principal is named."
        actions={
          <Button onClick={() => navigate({ to: "/policies/new" })}>
            <Plus className="size-4" /> New policy
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading policies…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<FileText />}
          title="No policies yet"
          description="Create one, attach it to a Role, then point a Group at that Role."
          action={
            <Button onClick={() => navigate({ to: "/policies/new" })}>
              <Plus className="size-4" /> New policy
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          {/* AWS policies list is defined by its "Filter by type" dropdown + search. */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-muted-foreground">Filter by type</span>
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="h-9 w-auto min-w-40" aria-label="Filter by type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL_TYPES}>All types</SelectItem>
                  {TYPE_OPTIONS.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <PropertyFilter
              className="flex-1"
              properties={FILTER_PROPERTIES}
              tokens={tokens}
              onChange={setTokens}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {filtered
              ? `${rows.length} of ${data.length} match`
              : `${data.length} polic${data.length === 1 ? "y" : "ies"}`}
          </p>

          {rows.length === 0 ? (
            <Card>
              <CardContent className="py-12">
                <EmptyState
                  title="No matches"
                  description="No policies match the current filter."
                  action={
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setTokens([]);
                        setTypeFilter(ALL_TYPES);
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="p-3 font-medium">Name</th>
                        <th className="p-3 font-medium">Type</th>
                        <th className="p-3 font-medium">Description</th>
                        <th className="p-3 font-medium">Permissions</th>
                        <th className="p-3 font-medium">Attached</th>
                        <th className="p-3 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((p) => {
                        const type = policyType(p);
                        const n = attachCount(p.name);
                        return (
                          <tr
                            key={p.name}
                            className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                            onClick={() =>
                              navigate({ to: "/policies/$name", params: { name: p.name } })
                            }
                          >
                            <td className="p-3 font-medium text-primary">{p.name}</td>
                            <td className="p-3">
                              <Badge variant={TYPE_TONE[type]}>{type}</Badge>
                            </td>
                            <td className="p-3 text-muted-foreground">{p.description || "—"}</td>
                            <td className="p-3 text-muted-foreground tabular-nums">
                              {p.ruleCount} rule{p.ruleCount === 1 ? "" : "s"}
                            </td>
                            <td className="p-3 text-muted-foreground tabular-nums">
                              {roles.isLoading ? "…" : n === 0 ? "—" : `${n} role${n === 1 ? "" : "s"}`}
                            </td>
                            <td className="p-3">
                              <Badge variant={p.ready ? "success" : "warning"}>
                                {p.ready ? "Ready" : "Compiling"}
                              </Badge>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
