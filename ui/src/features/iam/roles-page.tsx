import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Plus } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { listIamRoles } from "@/lib/api";
import { NewRoleDialog } from "./new-role-dialog";

export function RolesPage() {
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "roles"],
    queryFn: listIamRoles,
    refetchInterval: 15000,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Boxes />}
        title="Roles"
        description="Bundles of policies — the union of their permissions. Point a Group at a role to grant it. A role takes effect only once a Group uses it and that group is impersonable."
        actions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New role
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
          description="Create a role, attach policies to it, then point a Group at openinfra-role-<name>."
          action={
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" /> New role
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
                  <th className="p-3 font-medium">Policies</th>
                  <th className="p-3 font-medium">Binds as</th>
                  <th className="p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.map((r) => (
                  <tr
                    key={r.name}
                    className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                    onClick={() => navigate({ to: "/roles/$name", params: { name: r.name } })}
                  >
                    <td className="p-3 font-medium text-primary">{r.name}</td>
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
                      <Badge variant={r.ready ? "default" : "secondary"}>
                        {r.ready ? "Ready" : "Compiling"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      <NewRoleDialog open={newOpen} onOpenChange={setNewOpen} />
    </div>
  );
}
