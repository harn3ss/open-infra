import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileText, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { listIamPolicies, listIamRoles } from "@/lib/api";
import { policyType, type PolicyTypeLabel } from "./policy-type";

const TYPE_TONE: Record<PolicyTypeLabel, "default" | "accent" | "secondary"> = {
  "Control plane": "default",
  "Data plane": "accent",
  Mixed: "secondary",
  Empty: "secondary",
};

export function PoliciesPage() {
  const navigate = useNavigate();
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "policies"],
    queryFn: listIamPolicies,
    refetchInterval: 15000,
  });
  // Attachment counts: how many Roles include each policy (the control-plane attachment).
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const attachCount = (name: string) =>
    (roles.data ?? []).filter((r) => r.policies.includes(name)).length;

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
                  {data.map((p) => {
                    const type = policyType(p);
                    const n = attachCount(p.name);
                    return (
                      <tr
                        key={p.name}
                        className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                        onClick={() => navigate({ to: "/policies/$name", params: { name: p.name } })}
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
  );
}
