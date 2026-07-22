import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Users, UserPlus, AlertTriangle, KeyRound } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { getIamConfig, listIamGroups, listIamUsers } from "@/lib/api";
import { NewUserDialog } from "./new-user-dialog";

export function UsersPage() {
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const { data = [], isLoading, isError, error } = useQuery({
    queryKey: ["iam", "users"],
    queryFn: listIamUsers,
    refetchInterval: 15000,
  });

  const builtins = cfg.data?.builtinGroups ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Users />}
        title="Users"
        description="Console sign-ins, stored as kind: User. Permissions come from group membership; the root account is separate break-glass and isn't listed here."
        actions={
          <Button onClick={() => setNewOpen(true)}>
            <UserPlus className="size-4" /> New user
          </Button>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading users…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<Users />}
          title="No users yet"
          description="Create one, or note that people can also be defined as kind: User in Git. The break-glass root account signs in regardless."
          action={
            <Button onClick={() => setNewOpen(true)}>
              <UserPlus className="size-4" /> New user
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
                  <th className="p-3 font-medium">Groups</th>
                  <th className="p-3 font-medium">Source</th>
                  <th className="p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.map((u) => (
                  <tr
                    key={u.name}
                    className="cursor-pointer border-b last:border-0 hover:bg-muted/40"
                    onClick={() => navigate({ to: "/users/$name", params: { name: u.name } })}
                  >
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-primary">{u.name}</span>
                        {u.displayName ? (
                          <span className="text-muted-foreground">· {u.displayName}</span>
                        ) : null}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap items-center gap-1">
                        {u.groups.length === 0 ? (
                          <span className="text-xs text-muted-foreground">none</span>
                        ) : (
                          u.groups.map((g) => (
                            <Badge
                              key={g}
                              variant={u.unboundGroups.includes(g) ? "outline" : "secondary"}
                              className={
                                u.unboundGroups.includes(g)
                                  ? "border-amber-500/40 text-amber-600 dark:text-amber-400"
                                  : ""
                              }
                            >
                              {u.unboundGroups.includes(g) ? (
                                <AlertTriangle className="size-3" />
                              ) : null}
                              {g}
                            </Badge>
                          ))
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-muted-foreground">{u.source || "local"}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        {u.disabled ? (
                          <Badge variant="outline" className="text-muted-foreground">
                            Disabled
                          </Badge>
                        ) : (
                          <Badge variant="default">Active</Badge>
                        )}
                        {!u.hasPassword && (u.source === "local" || !u.source) ? (
                          <span
                            className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400"
                            title="No password is set — this user can't sign in until one is."
                          >
                            <KeyRound className="size-3" /> no password
                          </span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      <NewUserDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        builtins={builtins}
        groups={groups.data ?? []}
      />
    </div>
  );
}
