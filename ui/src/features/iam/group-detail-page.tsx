import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UsersRound, AlertTriangle, Check, UserPlus, X, FileText, Plus } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
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
  getIamGroup,
  listIamPolicies,
  listIamUsers,
  updateIamGroup,
  updateIamUser,
  type InlinePolicy,
  type IamUser,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { AccessAdvisorTab } from "./access-advisor-tab";
import { AttachPolicyPicker, ManagedBadge } from "./attach-policy-picker";
import { InlinePoliciesPanel } from "./inline-policies-panel";

/**
 * A group, as AWS IAM has it: a container of policies. Its members get every policy attached to it
 * (and its inline policies), on top of their own. A group still carrying a legacy permission tier
 * shows it, marked deprecated, until it is migrated to the equivalent managed policy.
 */
export function GroupDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();
  const [forcePrompt, setForcePrompt] = useState(false);
  const [adding, setAdding] = useState(false);
  const [attaching, setAttaching] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);

  const { data: group, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "groups", name],
    queryFn: () => getIamGroup(name),
    refetchInterval: 5000,
  });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });

  const members = useMemo(
    () => (users.data ?? []).filter((u) => (u.groups ?? []).includes(name)),
    [users.data, name],
  );
  const nonMembers = useMemo(
    () => (users.data ?? []).filter((u) => !(u.groups ?? []).includes(name)),
    [users.data, name],
  );
  const attached = group?.policies ?? [];
  const attachedPolicies = useMemo(
    () =>
      attached.map(
        (pn) =>
          (policies.data ?? []).find((p) => p.name === pn) ?? {
            name: pn,
            description: "",
            managed: false,
            category: undefined,
          },
      ),
    [attached, policies.data],
  );

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
  };

  const savePolicies = useMutation({
    mutationFn: (next: string[]) => updateIamGroup(name, { description: group?.description, policies: next }),
    onSuccess: () => {
      invalidate();
      flash.success(`Permissions of ${name} updated.`);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to update the group's policies."),
  });

  const saveInline = useMutation({
    mutationFn: (next: InlinePolicy[]) =>
      updateIamGroup(name, { description: group?.description, inlinePolicies: next }),
    onSuccess: (r) => {
      invalidate();
      flash.success(`Inline policies of ${name} updated.`);
      for (const w of r.warnings ?? []) flash.info?.(w);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to update inline policies."),
  });

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamGroup(name, force),
    onSuccess: () => {
      invalidate();
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
      const failed = targets.filter((_, i) => results[i]?.status === "rejected").map((u) => u.name);
      return { added: targets.length - failed.length, failed };
    },
    onSuccess: ({ added, failed }) => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      if (added > 0) flash.success(`Added ${added} user${added === 1 ? "" : "s"} to ${name}.`);
      if (failed.length > 0) flash.error(`Couldn't add: ${failed.join(", ")}.`);
      setAdding(false);
      setPicked([]);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to add users."),
  });

  const removeUser = useMutation({
    mutationFn: (u: IamUser) => updateIamUser(u.name, { groups: (u.groups ?? []).filter((g) => g !== name) }),
    onSuccess: (_d, u) => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      flash.success(`Removed ${u.name} from ${name}.`);
    },
    onError: (e) => flash.error(e instanceof ApiError ? e.message : "Failed to remove user."),
  });

  if (isLoading) return <LoadingState label="Loading group…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (!group) return <ErrorState error={new Error(`Group "${name}" not found`)} />;

  const togglePick = (n: string) => setPicked((p) => (p.includes(n) ? p.filter((x) => x !== n) : [...p, n]));
  const legacyTier = group.clusterRole;

  return (
    <DetailShell
      backTo="/groups"
      backLabel="Groups"
      icon={<UsersRound className="size-5" />}
      title={group.name}
      subtitle={group.description || "User group"}
    >
      <Card>
        <CardContent className="p-5">
          <KeyValuePairs
            columns={2}
            items={[
              { label: "User group name", value: group.name },
              { label: "Description", value: group.description || "—" },
              {
                label: "ARN",
                value: group.arn ? (
                  <span className="inline-flex items-center gap-1 break-all">
                    <code className="text-xs">{group.arn}</code>
                    <CopyButton value={group.arn} />
                  </span>
                ) : (
                  "—"
                ),
              },
              { label: "Users", value: String(members.length) },
              { label: "Attached policies", value: String(attached.length) },
              { label: "Inline policies", value: String(group.inlinePolicies?.length ?? 0) },
            ]}
          />
        </CardContent>
      </Card>

      <Tabs defaultValue="users" className="mt-5">
        <TabsList>
          <TabsTrigger value="users">Users ({members.length})</TabsTrigger>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="advisor">Access Advisor</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        {/* ------------------------------------------------------- Permissions */}
        <TabsContent value="permissions" className="space-y-4 pt-4">
          <p className="text-sm text-muted-foreground">
            Every member of this group gets the permissions of its attached and inline policies, in addition
            to their own.
          </p>
          {legacyTier ? <LegacyTierNotice tier={legacyTier} impersonable={group.impersonable} /> : null}

          <Card>
            <CardContent className="p-0">
              <div className="flex items-center justify-between border-b p-4">
                <div className="text-sm font-medium">Attached policies ({attached.length})</div>
                <Button variant="outline" size="sm" onClick={() => setAttaching(true)} disabled={savePolicies.isPending}>
                  <Plus className="size-4" /> Attach policies
                </Button>
              </div>
              {attachedPolicies.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  No policies are attached, so this group grants nothing.
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="p-3 font-medium">Policy name</th>
                      <th className="p-3 font-medium">Type</th>
                      <th className="p-3 font-medium">Description</th>
                      <th className="p-3 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attachedPolicies.map((p) => (
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
                        <td className="p-3">
                          <ManagedBadge managed={!!p.managed} category={p.category} />
                        </td>
                        <td className="p-3 text-muted-foreground">{p.description || "—"}</td>
                        <td className="p-3 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-muted-foreground hover:text-destructive"
                            disabled={savePolicies.isPending}
                            onClick={() => savePolicies.mutate(attached.filter((n) => n !== p.name))}
                          >
                            <X className="size-4" /> Detach
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>

          <InlinePoliciesPanel
            policies={group.inlinePolicies ?? []}
            onSave={(next) => saveInline.mutate(next)}
            subjectLabel={`group ${group.name}`}
            saving={saveInline.isPending}
          />

          <AttachPolicyPicker
            open={attaching}
            onOpenChange={setAttaching}
            policies={policies.data ?? []}
            attached={attached}
            onConfirm={(next) => {
              savePolicies.mutate(next);
              setAttaching(false);
            }}
            subjectLabel={`group ${group.name}`}
          />
        </TabsContent>

        {/* ------------------------------------------------------------- Users */}
        <TabsContent value="users" className="space-y-4 pt-4">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs text-muted-foreground">Members get this group&apos;s permissions.</p>
            {!adding ? (
              <Button variant="outline" size="sm" onClick={() => setAdding(true)} disabled={nonMembers.length === 0}>
                <UserPlus className="size-4" /> Add users
              </Button>
            ) : null}
          </div>

          {adding ? (
            <Card>
              <CardContent className="space-y-3 p-4">
                <div className="text-sm font-medium">Add users to {group.name}</div>
                {nonMembers.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Every user is already a member.</p>
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
                  <Button size="sm" onClick={() => addUsers.mutate(picked)} disabled={picked.length === 0 || addUsers.isPending}>
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
                <div className="p-4 text-sm text-muted-foreground">No users are in this group yet.</div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="p-3 font-medium">User</th>
                      <th className="p-3 font-medium">Display name</th>
                      <th className="p-3 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((u) => (
                      <tr key={u.name} className="border-b last:border-0">
                        <td className="p-3">
                          <Link to="/users/$name" params={{ name: u.name }} className="font-medium text-primary hover:underline">
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
          <AccessAdvisorTab kind="group" name={name} />
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
                Delete group <span className="font-medium text-foreground">{group.name}</span>.{" "}
                {members.length > 0
                  ? `${members.length} user(s) are still in it and will lose what its policies granted.`
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
                <span className="font-medium text-foreground">{members.length}</span> user(s) still reference{" "}
                <span className="font-medium text-foreground">{group.name}</span>. Deleting it leaves them in a
                group that no longer exists. Their User objects are not changed — remove the group from them
                afterward.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

/** A group that still carries a legacy permission tier: shown, marked deprecated, until migrated. */
function LegacyTierNotice({ tier, impersonable }: { tier: string; impersonable: boolean }) {
  return (
    <Card className="border-amber-500/40">
      <CardContent className="flex items-start gap-2 p-4 text-sm text-amber-600 dark:text-amber-400">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />
        <span>
          This group also carries the legacy permission tier <code className="text-xs">{tier}</code>
          {impersonable ? "" : " (inert: outside the console's impersonation ceiling)"}. Tiers are deprecated:
          attach the equivalent managed policy (AdministratorAccess, PowerUserAccess or ReadOnlyAccess)
          instead. With IAM policy deciding, only policies grant access.
        </span>
      </CardContent>
    </Card>
  );
}
