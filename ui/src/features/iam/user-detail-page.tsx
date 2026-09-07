import { useEffect, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { User, KeyRound, Ban, CircleCheck } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import { useFlash } from "@/components/common/flashbar";
import {
  deleteIamUser,
  getIamConfig,
  getIamUser,
  listIamGroups,
  resetIamPassword,
  updateIamUser,
} from "@/lib/api";
import { GroupPicker } from "./group-picker";
import { UserPermissionsTab } from "./user-permissions-tab";
import { PendingTab } from "./pending-notice";
import { AccessKeysPanel } from "./access-keys-panel";

export function UserDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const { data: user, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "user", name],
    queryFn: () => getIamUser(name),
  });

  const builtins = cfg.data?.builtinGroups ?? [];

  // Group editing (staged, saved with a button).
  const [editGroups, setEditGroups] = useState<string[]>([]);
  useEffect(() => {
    if (user) setEditGroups(user.groups ?? []);
  }, [user]);

  const invalidateUser = () => {
    void qc.invalidateQueries({ queryKey: ["iam", "user", name] });
    void qc.invalidateQueries({ queryKey: ["iam", "users"] });
  };

  const saveGroups = useMutation({
    mutationFn: () => updateIamUser(name, { groups: editGroups }),
    onSuccess: () => {
      invalidateUser();
      flash.success(`Updated group membership for ${name}.`);
    },
  });

  const toggleDisabled = useMutation({
    mutationFn: (disabled: boolean) => updateIamUser(name, { disabled }),
    onSuccess: (_res, disabled) => {
      invalidateUser();
      flash.success(`${disabled ? "Disabled" : "Enabled"} console access for ${name}.`);
    },
  });

  const [pw, setPw] = useState("");
  const resetPw = useMutation({
    mutationFn: () => resetIamPassword(name, pw),
    onSuccess: () => {
      setPw("");
      invalidateUser();
      flash.success(`Password updated for ${name}.`);
    },
  });

  const del = useMutation({
    mutationFn: () => deleteIamUser(name),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      flash.success(`Deleted user ${name}.`);
      navigate({ to: "/users" });
    },
  });

  if (isLoading) return <LoadingState label="Loading user…" />;
  if (isError || !user) return <ErrorState error={error} onRetry={refetch} />;

  const isLocal = user.source === "local" || !user.source;
  const groupsDirty =
    editGroups.length !== (user.groups ?? []).length ||
    editGroups.some((g) => !(user.groups ?? []).includes(g));

  return (
    <DetailShell
      backTo="/users"
      backLabel="Users"
      icon={<User className="size-5" />}
      title={user.name}
      subtitle={user.displayName ? user.displayName : "Console user"}
      status={
        user.disabled
          ? { label: "Disabled", tone: "muted" }
          : { label: "Enabled", tone: "success" }
      }
      actions={
        user.disabled ? (
          <Button variant="outline" onClick={() => toggleDisabled.mutate(false)}>
            <CircleCheck className="size-4" /> Enable
          </Button>
        ) : (
          <Button variant="outline" onClick={() => toggleDisabled.mutate(true)}>
            <Ban className="size-4" /> Disable
          </Button>
        )
      }
    >
      {/* Summary — AWS puts the identity facts above the tab strip, then leads with Permissions. */}
      <Card>
        <CardContent className="p-5">
          <KeyValuePairs
            columns={3}
            items={[
              {
                label: "User name",
                value: (
                  <span className="inline-flex items-center gap-1">
                    {user.name}
                    <CopyButton value={user.name} label="Copy user name" />
                  </span>
                ),
              },
              { label: "Display name", value: user.displayName || "" },
              { label: "Source", value: user.source || "local" },
              {
                label: "Console access",
                value: user.disabled ? (
                  <Badge variant="muted">Disabled</Badge>
                ) : (
                  <Badge variant="success">Enabled</Badge>
                ),
              },
              {
                label: "Sign-in credential",
                value: !isLocal ? (
                  `Managed by ${user.source}`
                ) : user.hasPassword ? (
                  "Password set"
                ) : (
                  <span className="text-amber-600 dark:text-amber-400">
                    No password — set one on Security credentials
                  </span>
                ),
              },
              {
                label: "Groups",
                value:
                  (user.groups ?? []).length === 0 ? (
                    "none"
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {(user.groups ?? []).map((g) => (
                        <Badge
                          key={g}
                          variant={(user.unboundGroups ?? []).includes(g) ? "outline" : "secondary"}
                        >
                          {g}
                        </Badge>
                      ))}
                    </div>
                  ),
              },
            ]}
          />
        </CardContent>
      </Card>

      <Tabs defaultValue="permissions" className="mt-5">
        <TabsList>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="groups">Groups ({(user.groups ?? []).length})</TabsTrigger>
          <TabsTrigger value="tags">Tags</TabsTrigger>
          <TabsTrigger value="security">Security credentials</TabsTrigger>
          <TabsTrigger value="advisor">Access Advisor</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="permissions" className="pt-4">
          <UserPermissionsTab user={user} />
        </TabsContent>

        <TabsContent value="groups" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <p className="text-sm text-muted-foreground">
                A user's access is exactly the union of its groups' ClusterRoles. Everyone is
                also in <code>openinfra:users</code> automatically.
              </p>
              <GroupPicker
                builtins={builtins}
                known={(groups.data ?? []).map((g) => g.name)}
                value={editGroups}
                onChange={setEditGroups}
              />
              <div className="flex items-center gap-3">
                <Button disabled={!groupsDirty || saveGroups.isPending} onClick={() => saveGroups.mutate()}>
                  {saveGroups.isPending ? <Spinner className="size-4" /> : null}
                  Save groups
                </Button>
                {groupsDirty ? (
                  <Button variant="ghost" onClick={() => setEditGroups(user.groups ?? [])}>
                    Reset
                  </Button>
                ) : null}
                {saveGroups.isError ? (
                  <span className="text-sm text-destructive">
                    {(saveGroups.error as Error).message}
                  </span>
                ) : null}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tags — backend-blocked (the user view carries no labels/annotations yet). */}
        <TabsContent value="tags" className="pt-4">
          <PendingTab title="Tags">
            Tags are not yet surfaced for users. The IAM user view (<code>iamUserView</code>) does not
            carry labels or annotations today, so there is nothing to show or edit here. When the BFF
            exposes them, this tab wires the shared tag editor (add/remove key–value rows).
          </PendingTab>
        </TabsContent>

        <TabsContent value="security" className="space-y-4 pt-4">
          {/* Console access */}
          <Card>
            <CardContent className="flex flex-wrap items-center justify-between gap-4 p-5">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold">Console access</h3>
                <p className="text-sm text-muted-foreground">
                  {user.disabled
                    ? "This user can't sign in. Enable to restore console access."
                    : "This user can sign in to the console."}
                </p>
              </div>
              {user.disabled ? (
                <Button variant="outline" onClick={() => toggleDisabled.mutate(false)}>
                  <CircleCheck className="size-4" /> Enable access
                </Button>
              ) : (
                <Button variant="outline" onClick={() => toggleDisabled.mutate(true)}>
                  <Ban className="size-4" /> Disable access
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Password */}
          {isLocal ? (
            <Card>
              <CardContent className="max-w-md space-y-3 p-5">
                <div className="space-y-1.5">
                  <Label htmlFor="new-pw" className="flex items-center gap-1.5">
                    <KeyRound className="size-4" /> Set a new password
                  </Label>
                  <Input
                    id="new-pw"
                    type="password"
                    value={pw}
                    onChange={(e) => setPw(e.target.value)}
                    placeholder="At least 8 characters"
                  />
                  <p className="text-xs text-muted-foreground">
                    Stored as a bcrypt hash in a Secret — the console never keeps the plaintext.
                  </p>
                </div>
                <Button
                  disabled={pw.length < 8 || resetPw.isPending}
                  onClick={() => resetPw.mutate()}
                >
                  {resetPw.isPending ? <Spinner className="size-4" /> : null}
                  Set password
                </Button>
                {resetPw.isError ? (
                  <p className="text-sm text-destructive">{(resetPw.error as Error).message}</p>
                ) : null}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-5 text-sm text-muted-foreground">
                This user's source is <code>{user.source}</code> — sign-in credentials are managed
                by the directory, not the console. There is no password to set here.
              </CardContent>
            </Card>
          )}

          {/* Access keys — the aws-shim SigV4 sub-resource. The secret is shown exactly once. */}
          <AccessKeysPanel user={user.name} />

          {/* MFA — deferred (Part A). Kept as an honest note, not a fake widget. */}
          <Card>
            <CardContent className="space-y-1 p-5 text-sm text-muted-foreground">
              <h3 className="text-sm font-semibold text-foreground">Multi-factor authentication (MFA)</h3>
              <p>
                MFA device registration is not yet supported.{" "}
                {isLocal
                  ? "It is on the roadmap for local users."
                  : `For this user, sign-in (and any MFA) is handled by the ${user.source} directory.`}{" "}
                No MFA widget is shown until it lands.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Access Advisor — backend-blocked (no per-service last-used data plumbing yet). */}
        <TabsContent value="advisor" className="pt-4">
          <PendingTab title="Access Advisor — services last accessed">
            Per-service, per-permission last-used data for this user is not available yet. Only
            aggregate last-seen exists today (in Access Review); the per-service breakdown AWS shows
            here needs richer audit parsing (k8s-audit + shim logs via Loki, attributed by
            <code> impersonatedUser</code>).
          </PendingTab>
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="User"
            resourceName={user.name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete user{" "}
                <span className="font-medium text-foreground">{user.name}</span> and its password
                Secret. They will no longer be able to sign in.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
