import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { UsersRound, Plus, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getIamConfig, listIamGroups } from "@/lib/api";
import { NewGroupDialog } from "./new-group-dialog";

export function GroupsPage() {
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "groups"],
    queryFn: listIamGroups,
    refetchInterval: 15000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<UsersRound />}
        title="Groups"
        description="Permission sets. A group binds its members to a ClusterRole — the only thing that grants access — and takes effect only if its name is in the impersonation ceiling."
        actions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New group
          </Button>
        }
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
          action={
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" /> New group
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
                  <th className="p-3 font-medium">Grants (ClusterRole)</th>
                  <th className="p-3 font-medium">Description</th>
                  <th className="p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.map((g) => (
                  <tr
                    key={g.name}
                    className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                    onClick={() => navigate({ to: "/groups/$name", params: { name: g.name } })}
                  >
                    <td className="p-3 font-medium text-primary">{g.name}</td>
                    <td className="p-3">
                      <code className="text-xs text-muted-foreground">{g.clusterRole}</code>
                    </td>
                    <td className="p-3 text-muted-foreground">{g.description || "—"}</td>
                    <td className="p-3">
                      {g.impersonable ? (
                        <Badge variant={g.ready ? "default" : "secondary"}>
                          {g.ready ? "Ready" : "Provisioning"}
                        </Badge>
                      ) : (
                        <span
                          className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400"
                          title="Not in the impersonation ceiling — members gain nothing until an operator widens it."
                        >
                          <AlertTriangle className="size-3" /> inert
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      <NewGroupDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        builtins={cfg.data?.builtinGroups ?? []}
      />
    </div>
  );
}
