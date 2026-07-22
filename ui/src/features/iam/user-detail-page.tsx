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
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import {
  deleteIamUser,
  getIamConfig,
  getIamUser,
  listIamGroups,
  resetIamPassword,
  updateIamUser,
} from "@/lib/api";
import { GroupPicker } from "./group-picker";

export function UserDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();

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
    if (user) setEditGroups(user.groups);
  }, [user]);

  const saveGroups = useMutation({
    mutationFn: () => updateIamUser(name, { groups: editGroups }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "user", name] });
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
    },
  });

  const toggleDisabled = useMutation({
    mutationFn: (disabled: boolean) => updateIamUser(name, { disabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "user", name] });
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
    },
  });

  const [pw, setPw] = useState("");
  const resetPw = useMutation({
    mutationFn: () => resetIamPassword(name, pw),
    onSuccess: () => {
      setPw("");
      void qc.invalidateQueries({ queryKey: ["iam", "user", name] });
    },
  });

  const del = useMutation({
    mutationFn: () => deleteIamUser(name),
    onSuccess: () => navigate({ to: "/users" }),
  });

  if (isLoading) return <LoadingState label="Loading user…" />;
  if (isError || !user) return <ErrorState error={error} onRetry={refetch} />;

  const groupsDirty =
    editGroups.length !== user.groups.length ||
    editGroups.some((g) => !user.groups.includes(g));

  return (
    <DetailShell
      backTo="/users"
      backLabel="Users"
      icon={<User className="size-5" />}
      title={user.name}
      subtitle={user.displayName ? user.displayName : "Console user"}
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
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="groups">Groups</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Username">{user.name}</DetailRow>
              <DetailRow label="Display name">{user.displayName || "—"}</DetailRow>
              <DetailRow label="Source">{user.source || "local"}</DetailRow>
              <DetailRow label="Status">
                {user.disabled ? (
                  <Badge variant="outline" className="text-muted-foreground">Disabled</Badge>
                ) : (
                  <Badge variant="default">Active</Badge>
                )}
              </DetailRow>
              <DetailRow label="Password">
                {user.hasPassword ? (
                  "Set"
                ) : (
                  <span className="text-amber-600 dark:text-amber-400">
                    Not set — can't sign in until a password is set (Security tab)
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Groups">
                <div className="flex flex-wrap gap-1">
                  {user.groups.length === 0
                    ? "none"
                    : user.groups.map((g) => (
                        <Badge
                          key={g}
                          variant={user.unboundGroups.includes(g) ? "outline" : "secondary"}
                        >
                          {g}
                        </Badge>
                      ))}
                </div>
              </DetailRow>
            </CardContent>
          </Card>
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
                  <Button variant="ghost" onClick={() => setEditGroups(user.groups)}>
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

        <TabsContent value="security" className="pt-4">
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
              </div>
              <Button
                disabled={pw.length < 8 || resetPw.isPending}
                onClick={() => resetPw.mutate()}
              >
                {resetPw.isPending ? <Spinner className="size-4" /> : null}
                Set password
              </Button>
              {resetPw.isSuccess ? (
                <p className="text-sm text-emerald-600 dark:text-emerald-400">Password updated.</p>
              ) : null}
              {resetPw.isError ? (
                <p className="text-sm text-destructive">{(resetPw.error as Error).message}</p>
              ) : null}
            </CardContent>
          </Card>
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
