import { useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UsersRound, AlertTriangle } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { deleteIamGroup, listIamGroups, listIamUsers } from "@/lib/api";

export function GroupDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [forcePrompt, setForcePrompt] = useState(false);

  const { data: groups, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "groups"],
    queryFn: listIamGroups,
  });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });

  const group = groups?.find((g) => g.name === name);
  const members = (users.data ?? []).filter((u) => u.groups.includes(name));

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamGroup(name, force),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      navigate({ to: "/groups" });
    },
  });

  if (isLoading) return <LoadingState label="Loading group…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (!group) return <ErrorState error={new Error(`Group "${name}" not found`)} />;

  return (
    <DetailShell
      backTo="/groups"
      backLabel="Groups"
      icon={<UsersRound className="size-5" />}
      title={group.name}
      subtitle={group.description || "Permission group"}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="members">Members ({members.length})</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          {!group.impersonable ? (
            <Card className="mb-4 border-amber-500/40">
              <CardContent className="flex items-start gap-2 p-4 text-sm text-amber-600 dark:text-amber-400">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <span>
                  This group is <b>inert</b>: <code>openinfra:{group.name}</code> is not in the
                  impersonator ClusterRole's allow-list, so members gain nothing from it. An
                  operator must add it to <code>open-infra-console-impersonator</code> — this is
                  a deliberate ceiling that stops the console impersonating privileged groups.
                </span>
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Name">{group.name}</DetailRow>
              <DetailRow label="Description">{group.description || "—"}</DetailRow>
              <DetailRow label="Grants (ClusterRole)">
                <code className="text-xs">{group.clusterRole}</code>
              </DetailRow>
              <DetailRow label="Bound to">
                <code className="text-xs">{group.boundTo || `openinfra:${group.name}`}</code>
              </DetailRow>
              <DetailRow label="Status">
                {group.impersonable ? (
                  <Badge variant={group.ready ? "default" : "secondary"}>
                    {group.ready ? "Ready" : "Provisioning"}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-amber-600 dark:text-amber-400">
                    Inert
                  </Badge>
                )}
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="members" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {members.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  No users are in this group. Add it from a user's Groups tab.
                </div>
              ) : (
                members.map((u) => (
                  <DetailRow key={u.name} label={u.displayName || "User"}>
                    <Link
                      to="/users/$name"
                      params={{ name: u.name }}
                      className="text-primary hover:underline"
                    >
                      {u.name}
                    </Link>
                  </DetailRow>
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Group"
            resourceName={group.name}
            deleting={del.isPending}
            onConfirm={() => {
              // If members remain, the server 409s unless forced — surface that as a
              // second, explicit confirm rather than silently orphaning them.
              if (members.length > 0) setForcePrompt(true);
              else del.mutate(false);
            }}
            confirmDescription={
              <>
                Delete group <span className="font-medium text-foreground">{group.name}</span> and
                its ClusterRoleBinding.{" "}
                {members.length > 0
                  ? `${members.length} user(s) are still in it and will lose whatever it granted.`
                  : "It has no members."}
              </>
            }
          />
          <ConfirmDialog
            open={forcePrompt}
            onOpenChange={setForcePrompt}
            title="Remove a group with members?"
            confirmLabel="Delete anyway"
            loading={del.isPending}
            onConfirm={() => del.mutate(true)}
            description={
              <>
                <span className="font-medium text-foreground">{members.length}</span> user(s) still
                reference <span className="font-medium text-foreground">{group.name}</span>. Deleting
                it leaves them pointing at a group that grants nothing. Their User objects are not
                changed — remove the group from them afterward.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
