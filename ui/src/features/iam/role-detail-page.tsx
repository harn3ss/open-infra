import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Check, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import {
  deleteIamRole,
  getIamRole,
  listIamGroups,
  listIamPolicies,
  updateIamRole,
} from "@/lib/api";

export function RoleDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [forcePrompt, setForcePrompt] = useState(false);

  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const { data: role, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "role", name],
    queryFn: () => getIamRole(name),
    refetchInterval: 5000,
  });

  const clusterRole = role?.clusterRole || `openinfra-role-${name}`;
  const usedByGroups = (groups.data ?? []).filter((g) => g.clusterRole === clusterRole);

  const [attached, setAttached] = useState<string[]>([]);
  useEffect(() => {
    if (role) setAttached(role.policies);
  }, [role]);

  const savePolicies = useMutation({
    mutationFn: () => updateIamRole(name, { description: role?.description ?? "", policies: attached }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "role", name] });
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
    },
  });

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamRole(name, force),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
      navigate({ to: "/roles" });
    },
  });

  if (isLoading) return <LoadingState label="Loading role…" />;
  if (isError || !role) return <ErrorState error={error} onRetry={refetch} />;

  const dirty =
    attached.length !== role.policies.length ||
    attached.some((p) => !role.policies.includes(p));
  const toggle = (p: string) =>
    setAttached(attached.includes(p) ? attached.filter((x) => x !== p) : [...attached, p]);

  return (
    <DetailShell
      backTo="/roles"
      backLabel="Roles"
      icon={<Boxes className="size-5" />}
      title={role.name}
      subtitle={role.description || "Role"}
    >
      <Tabs defaultValue="policies">
        <TabsList>
          <TabsTrigger value="policies">Policies</TabsTrigger>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="policies" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <p className="text-sm text-muted-foreground">
                This role grants the union of the policies below. Toggle to attach or detach.
              </p>
              {policies.data && policies.data.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {policies.data.map((p) => {
                    const on = attached.includes(p.name);
                    return (
                      <button
                        key={p.name}
                        type="button"
                        onClick={() => toggle(p.name)}
                        className={[
                          "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                          on
                            ? "border-primary/40 bg-primary/15 text-primary"
                            : "border-border text-muted-foreground hover:bg-muted",
                        ].join(" ")}
                      >
                        {on ? <Check className="size-3" /> : null}
                        {p.name}
                      </button>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No policies exist yet.</p>
              )}
              <div className="flex items-center gap-3">
                <Button disabled={!dirty || savePolicies.isPending} onClick={() => savePolicies.mutate()}>
                  {savePolicies.isPending ? <Spinner className="size-4" /> : null}
                  Save
                </Button>
                {dirty ? (
                  <Button variant="ghost" onClick={() => setAttached(role.policies)}>
                    Reset
                  </Button>
                ) : null}
                {savePolicies.isError ? (
                  <span className="text-sm text-destructive">
                    {(savePolicies.error as Error).message}
                  </span>
                ) : null}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="usage" className="space-y-4 pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Binds as (ClusterRole)">
                <code className="text-xs">{clusterRole}</code>
              </DetailRow>
              <DetailRow label="Status">
                <Badge variant={role.ready ? "default" : "secondary"}>
                  {role.ready ? "Ready" : "Compiling"}
                </Badge>
              </DetailRow>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                <Info className="size-4" /> How to grant this role
              </div>
              <p className="text-sm text-muted-foreground">
                Create or edit a <Link to="/groups" className="text-primary hover:underline">Group</Link>{" "}
                and set its <b>Grants</b> to <code className="text-xs">{clusterRole}</code>. Members
                of that group then get this role's permissions. The group must be one of the
                built-in impersonable names (admins / powerusers / readers) or one an operator has
                added to the impersonation ceiling — otherwise it stays inert.
              </p>
              {usedByGroups.length > 0 ? (
                <div className="mt-3 space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Used by groups:</p>
                  {usedByGroups.map((g) => (
                    <Link
                      key={g.name}
                      to="/groups/$name"
                      params={{ name: g.name }}
                      className="mr-3 text-sm text-primary hover:underline"
                    >
                      {g.name}
                    </Link>
                  ))}
                </div>
              ) : (
                <p className="mt-3 text-xs text-muted-foreground">
                  No group uses this role yet — it currently grants nothing to anyone.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Role"
            resourceName={role.name}
            deleting={del.isPending}
            onConfirm={() => {
              if (usedByGroups.length > 0) setForcePrompt(true);
              else del.mutate(false);
            }}
            confirmDescription={
              <>
                Delete role <span className="font-medium text-foreground">{role.name}</span> and its
                aggregated ClusterRole.{" "}
                {usedByGroups.length > 0
                  ? `${usedByGroups.length} group(s) point at it and will grant nothing.`
                  : "No group uses it."}
              </>
            }
          />
          <ConfirmDialog
            open={forcePrompt}
            onOpenChange={setForcePrompt}
            title="Delete a role in use?"
            confirmLabel="Delete anyway"
            loading={del.isPending}
            onConfirm={() => del.mutate(true)}
            description={
              <>
                <span className="font-medium text-foreground">{usedByGroups.length}</span> group(s)
                bind <span className="font-medium text-foreground">{clusterRole}</span>. Deleting the
                role leaves them granting nothing until you repoint them.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
