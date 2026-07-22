import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileText, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getIamConfig, listIamPolicies } from "@/lib/api";
import { NewPolicyDialog } from "./new-policy-dialog";

export function PoliciesPage() {
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "policies"],
    queryFn: listIamPolicies,
    refetchInterval: 15000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<FileText />}
        title="Policies"
        description="Attachable permission sets over open-infra resources — AWS-style managed policies. A policy grants nothing until a Role includes it, and can only ever grant on openinfra.dev kinds (the permission boundary)."
        actions={
          <Button onClick={() => setNewOpen(true)}>
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
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" /> New policy
            </Button>
          }
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Name</th>
                  <th className="p-3 font-medium">Description</th>
                  <th className="p-3 font-medium">Permissions</th>
                  <th className="p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.map((p) => (
                  <tr
                    key={p.name}
                    className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                    onClick={() => navigate({ to: "/policies/$name", params: { name: p.name } })}
                  >
                    <td className="p-3 font-medium text-primary">{p.name}</td>
                    <td className="p-3 text-muted-foreground">{p.description || "—"}</td>
                    <td className="p-3 text-muted-foreground tabular-nums">
                      {p.ruleCount} rule{p.ruleCount === 1 ? "" : "s"}
                    </td>
                    <td className="p-3">
                      <Badge variant={p.ready ? "default" : "secondary"}>
                        {p.ready ? "Ready" : "Compiling"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      <NewPolicyDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        resources={cfg.data?.policyResources ?? []}
      />
    </div>
  );
}
