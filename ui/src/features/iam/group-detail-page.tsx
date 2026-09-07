import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  UsersRound,
  AlertTriangle,
  Check,
  UserPlus,
  X,
  ShieldCheck,
  FileText,
} from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useFlash } from "@/components/common/flashbar";
import {
  ApiError,
  deleteIamGroup,
  listIamGroups,
  listIamPolicies,
  listIamRoles,
  listIamUsers,
  updateIamUser,
  type IamUser,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { PendingTab } from "./pending-notice";

/** What the three shipped console ClusterRoles confer, for the Permissions tab. */
const BUILTIN_ROLES: Record<string, { label: string; blurb: string }> = {
  "open-infra-console": {
    label: "Full access",
    blurb: "Manage everything, including identities, secrets and RBAC.",
  },
  "open-infra-poweruser": {
    label: "Power user",
    blurb: "Manage product resources, but not secrets or cluster RBAC.",
  },
  "open-infra-readonly": {
    label: "Read-only",
    blurb: "View resources across the console; no changes.",
  },
};

export function GroupDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();
  const [forcePrompt, setForcePrompt] = useState(false);
  const [adding, setAdding] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);

  const { data: groups, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "groups"],
    queryFn: listIamGroups,
    refetchInterval: 5000,
  });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });

  const group = groups?.find((g) => g.name === name);
  const members = useMemo(
    () => (users.data ?? []).filter((u) => (u.groups ?? []).includes(name)),
    [users.data, name],
  );
  const nonMembers = useMemo(
    () => (users.data ?? []).filter((u) => !(u.groups ?? []).includes(name)),
    [users.data, name],
  );

  // Resolve what the bound ClusterRole grants: a built-in, or a kind: Role we manage.
  const boundRole = useMemo(
    () =>
      (roles.data ?? []).find(
        (r) =>
          r.clusterRole === group?.clusterRole ||
          `openinfra-role-${r.name}` === group?.clusterRole,
      ),
    [roles.data, group?.clusterRole],
  );
  const builtin = group ? BUILTIN_ROLES[group.clusterRole] : undefined;
  const rolePolicies = useMemo(
    () => (boundRole?.policies ?? []).map((pn) => (policies.data ?? []).find((p) => p.name === pn) ?? { name: pn, ruleCount: 0, description: "" }),
    [boundRole, policies.data],
  );

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamGroup(name, force),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      flash.success(`Group ${name} deleted.`);
      navigate({ to: "/groups" });
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to delete group."),
  });

  const addUsers = useMutation({
    mutationFn: async (names: string[]) => {
      const targets = (users.data ?? []).filter((u) => names.includes(u.name));
      const results = await Promise.allSettled(
        targets.map((u) =>
          updateIamUser(u.name, {
            groups: Array.from(new Set([...(u.groups ?? []), name])),
          }),
        ),
      );
      const failed = targets
        .filter((_, i) => results[i]?.status === "rejected")
        .map((u) => u.name);
      return { added: targets.length - failed.length, failed };
    },
    onSuccess: ({ added, failed }) => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      if (added > 0)
        flash.success(`Added ${added} user${added === 1 ? "" : "s"} to ${name}.`);
      if (failed.length > 0) flash.error(`Couldn't add: ${failed.join(", ")}.`);
      setAdding(false);
      setPicked([]);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to add users."),
  });

  const removeUser = useMutation({
    mutationFn: (u: IamUser) =>
      updateIamUser(u.name, { groups: (u.groups ?? []).filter((g) => g !== name) }),
    onSuccess: (_d, u) => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      flash.success(`Removed ${u.name} from ${name}.`);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to remove user."),
  });

  if (isLoading) return <LoadingState label="Loading group…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (!group) return <ErrorState error={new Error(`Group "${name}" not found`)} />;

  const togglePick = (n: string) =>
    setPicked((p) => (p.includes(n) ? p.filter((x) => x !== n) : [...p, n]));

  return (
    <DetailShell
      backTo="/groups"
      backLabel="Groups"
      icon={<UsersRound className="size-5" />}
      title={group.name}
      subtitle={group.description || "Permission group"}
      status={
        group.impersonable
          ? group.ready
            ? { label: "Ready", tone: "success" }
            : { label: "Provisioning", tone: "warning" }
          : { label: "Inert", tone: "warning" }
      }
    >
      {/* Summary — AWS shows the group's facts above the tab strip, then leads with Users. */}
      {!group.impersonable ? <InertWarning name={group.name} /> : null}
      <Card>
        <CardContent className="p-5">
          <KeyValuePairs
            columns={2}
            items={[
              { label: "Name", value: group.name },
              { label: "Description", value: group.description || "—" },
              {
                label: "Grants (ClusterRole)",
                value: (
                  <span className="inline-flex items-center gap-1">
                    <code className="text-xs">{group.clusterRole}</code>
                    <CopyButton value={group.clusterRole} />
                  </span>
                ),
              },
              {
                label: "Bound to",
                value: <code className="text-xs">{group.boundTo || `openinfra:${group.name}`}</code>,
              },
              { label: "Users", value: String(members.length) },
              {
                label: "Status",
                value: group.impersonable ? (
                  <Badge variant={group.ready ? "success" : "secondary"}>
                    {group.ready ? "Ready" : "Provisioning"}
                  </Badge>
                ) : (
                  <Badge variant="warning">Inert</Badge>
                ),
              },
            ]}
          />
        </CardContent>
      </Card>

      <Tabs defaultValue="users" className="mt-5">
        <TabsList>
          <TabsTrigger value="users">Users ({members.length})</TabsTrigger>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="advisor">Access Advisor</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        {/* ------------------------------------------------------- Permissions */}
        <TabsContent value="permissions" className="pt-4 space-y-4">
          {!group.impersonable ? <InertWarning name={group.name} /> : null}
          <p className="text-sm text-muted-foreground">
            These permissions are conferred to members <b>via this group</b>&apos;s bound
            ClusterRole. A group binds exactly one ClusterRole — that binding is the only thing
            that grants access.
          </p>

          {builtin ? (
            <Card>
              <CardContent className="flex items-start gap-3 p-4">
                <ShieldCheck className="mt-0.5 size-5 shrink-0 text-primary" />
                <div>
                  <div className="text-sm font-medium">
                    {builtin.label}{" "}
                    <code className="text-xs text-muted-foreground">({group.clusterRole})</code>
                  </div>
                  <p className="text-sm text-muted-foreground">{builtin.blurb}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Built-in console role — its rules are shipped, not editable here.
                  </p>
                </div>
              </CardContent>
            </Card>
          ) : boundRole ? (
            <Card>
              <CardContent className="p-0">
                <div className="flex items-center justify-between border-b p-4">
                  <div className="flex items-center gap-2 text-sm">
                    <ShieldCheck className="size-4 text-primary" />
                    <span className="text-muted-foreground">Role</span>
                    <Link
                      to="/roles/$name"
                      params={{ name: boundRole.name }}
                      className="font-medium text-primary hover:underline"
                    >
                      {boundRole.name}
                    </Link>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {rolePolicies.length} attached polic{rolePolicies.length === 1 ? "y" : "ies"}
                  </span>
                </div>
                {rolePolicies.length === 0 ? (
                  <div className="p-4 text-sm text-muted-foreground">
                    This role has no attached policies, so it grants nothing yet.
                  </div>
                ) : (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="p-3 font-medium">Policy</th>
                        <th className="p-3 font-medium">Description</th>
                        <th className="p-3 font-medium">Rules</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rolePolicies.map((p) => (
                        <tr key={p.name} className="border-b last:border-0">
                          <td className="p-3">
                            <Link
                              to="/policies/$name"
                              params={{ name: p.name }}
                              className="inline-flex items-center gap-1.5 font-medium text-primary hover:underline"
                            >
                              <FileText className="size-3.5" />
                              {p.name}
                            </Link>
                          </td>
                          <td className="p-3 text-muted-foreground">{p.description || "—"}</td>
                          <td className="p-3 text-muted-foreground">{p.ruleCount ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="flex items-start gap-3 p-4 text-sm text-muted-foreground">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <span>
                  This group binds <code className="text-xs">{group.clusterRole}</code>, a
                  ClusterRole that isn&apos;t a built-in console role and isn&apos;t managed as a{" "}
                  <Link to="/roles" className="text-primary hover:underline">
                    Role
                  </Link>{" "}
                  here. Its rules are defined outside the console.
                </span>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ------------------------------------------------------------- Users */}
        <TabsContent value="users" className="pt-4 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs text-muted-foreground">
              Membership is stored on each User (<code>spec.groups</code>), not on the group —
              adding a user here patches that User.
            </p>
            {!adding ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAdding(true)}
                disabled={nonMembers.length === 0}
              >
                <UserPlus className="size-4" /> Add users
              </Button>
            ) : null}
          </div>

          {adding ? (
            <Card>
              <CardContent className="space-y-3 p-4">
                <div className="text-sm font-medium">Add users to {group.name}</div>
                {nonMembers.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Every user is already a member.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {nonMembers.map((u) => {
                      const on = picked.includes(u.name);
                      return (
                        <button
                          key={u.name}
                          type="button"
                          onClick={() => togglePick(u.name)}
                          className={cn(
                            "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                            on
                              ? "border-primary/40 bg-primary/15 text-primary"
                              : "border-border text-muted-foreground hover:bg-muted",
                          )}
                        >
                          {on ? <Check className="size-3" /> : null}
                          {u.name}
                        </button>
                      );
                    })}
                  </div>
                )}
                <div className="flex items-center gap-2 pt-1">
                  <Button
                    size="sm"
                    onClick={() => addUsers.mutate(picked)}
                    disabled={picked.length === 0 || addUsers.isPending}
                  >
                    {addUsers.isPending ? <Spinner className="text-current" /> : null}
                    Add {picked.length > 0 ? `${picked.length} ` : ""}user
                    {picked.length === 1 ? "" : "s"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setAdding(false);
                      setPicked([]);
                    }}
                    disabled={addUsers.isPending}
                  >
                    Cancel
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardContent className="p-0">
              {members.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  No users are in this group yet.
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="p-3 font-medium">User</th>
                      <th className="p-3 font-medium">Display name</th>
                      <th className="p-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((u) => (
                      <tr key={u.name} className="border-b last:border-0">
                        <td className="p-3">
                          <Link
                            to="/users/$name"
                            params={{ name: u.name }}
                            className="font-medium text-primary hover:underline"
                          >
                            {u.name}
                          </Link>
                        </td>
                        <td className="p-3 text-muted-foreground">{u.displayName || "—"}</td>
                        <td className="p-3 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-muted-foreground hover:text-destructive"
                            onClick={() => removeUser.mutate(u)}
                            disabled={removeUser.isPending}
                          >
                            <X className="size-4" /> Remove
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---------------------------------------------------- Access Advisor */}
        <TabsContent value="advisor" className="pt-4">
          <PendingTab title="Access Advisor — services last accessed">
            Per-service last-used data for this group's members (through its bound ClusterRole) is not
            available yet. Only aggregate last-seen exists today (in Access Review); the per-service
            breakdown AWS shows here needs richer audit parsing (k8s-audit + shim logs via Loki,
            attributed to the group's members).
          </PendingTab>
        </TabsContent>

        {/* -------------------------------------------------------- Danger Zone */}
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

/** The load-bearing "this group grants nothing" ceiling warning (shown on Overview + Permissions). */
function InertWarning({ name }: { name: string }) {
  return (
    <Card className="mb-4 border-amber-500/40">
      <CardContent className="flex items-start gap-2 p-4 text-sm text-amber-600 dark:text-amber-400">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />
        <span>
          This group is <b>inert</b>: <code>openinfra:{name}</code> is not in the impersonator
          ClusterRole&apos;s allow-list, so members gain nothing from it. An operator must add it to{" "}
          <code>open-infra-console-impersonator</code> — this is a deliberate ceiling that stops the
          console impersonating privileged groups.
        </span>
      </CardContent>
    </Card>
  );
}
