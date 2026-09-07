import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Boxes, Info, Plus, ShieldCheck, ShieldX, X } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { CopyButton } from "@/components/common/copy-button";
import { LoadingState, ErrorState, Spinner } from "@/components/common/states";
import {
  deleteIamRole,
  getIamRole,
  listIamGroups,
  listIamPolicies,
  listIamUsers,
  updateIamRole,
  updateIamRoleTags,
} from "@/lib/api";
import { TrustEditor, principalLabel } from "./trust-editor";
import { PendingTab } from "./pending-notice";
import { TagsTab } from "./tags-tab";
import { AttachPolicyPicker, ManagedBadge } from "./attach-policy-picker";
import { policyType } from "./policy-type";

export function RoleDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [forcePrompt, setForcePrompt] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);

  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const { data: role, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "role", name],
    queryFn: () => getIamRole(name),
    refetchInterval: 5000,
  });

  const clusterRole = role?.clusterRole || `openinfra-role-${name}`;
  const roleArn = `arn:openinfra:iam::open-infra:role/${name}`;
  const usedByGroups = (groups.data ?? []).filter((g) => g.clusterRole === clusterRole);

  const [attached, setAttached] = useState<string[]>([]);
  const [trust, setTrust] = useState<string[]>([]);
  useEffect(() => {
    if (role) {
      setAttached(role.policies);
      setTrust(role.trust ?? []);
    }
  }, [role]);

  const savePolicies = useMutation({
    // trust omitted → the BFF leaves the stored trust policy untouched.
    mutationFn: () => updateIamRole(name, { description: role?.description ?? "", policies: attached }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "role", name] });
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
    },
  });

  const saveTrust = useMutation({
    // pass the server's policies so a trust save never clobbers unsaved policy edits.
    mutationFn: () =>
      updateIamRole(name, {
        description: role?.description ?? "",
        policies: role?.policies ?? [],
        trust,
      }),
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

  const storedTrust = role.trust ?? [];
  const policiesDirty =
    attached.length !== role.policies.length || attached.some((p) => !role.policies.includes(p));
  const trustDirty =
    trust.length !== storedTrust.length ||
    trust.some((p) => !storedTrust.includes(p)) ||
    storedTrust.some((p) => !trust.includes(p));
  const toggle = (p: string) =>
    setAttached(attached.includes(p) ? attached.filter((x) => x !== p) : [...attached, p]);
  const policyByName = new Map((policies.data ?? []).map((p) => [p.name, p]));

  return (
    <DetailShell
      backTo="/roles"
      backLabel="Roles"
      icon={<Boxes className="size-5" />}
      title={role.name}
      subtitle={role.description || "Role"}
      status={{ label: role.ready ? "Ready" : "Compiling", tone: role.ready ? "success" : "warning" }}
    >
      {/* Summary — AWS surfaces the role ARN + who may assume above the tab strip. */}
      <Card>
        <CardContent className="p-5">
          <KeyValuePairs
            columns={3}
            items={[
              {
                label: "Role ARN",
                value: (
                  <span className="inline-flex items-center gap-1">
                    <code className="break-all text-xs">{roleArn}</code>
                    <CopyButton value={roleArn} label="Copy role ARN" />
                  </span>
                ),
              },
              {
                label: "Binds as (ClusterRole)",
                value: <code className="text-xs">{clusterRole}</code>,
              },
              {
                label: "Trusted entities",
                value:
                  storedTrust.length === 0 ? (
                    <span className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="size-3.5" /> none — not assumable
                    </span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {storedTrust.slice(0, 4).map((p) => (
                        <Badge
                          key={p}
                          variant={p === "*" ? "outline" : "secondary"}
                          className={p === "*" ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : ""}
                        >
                          {principalLabel(p)}
                        </Badge>
                      ))}
                      {storedTrust.length > 4 ? (
                        <span className="text-xs text-muted-foreground">+{storedTrust.length - 4}</span>
                      ) : null}
                    </div>
                  ),
              },
              {
                label: "Max session duration",
                value: (
                  <span className="text-sm text-muted-foreground">
                    Set per <code className="text-xs">AssumeRole</code> call (STS DurationSeconds)
                  </span>
                ),
              },
            ]}
          />
        </CardContent>
      </Card>

      <Tabs defaultValue="permissions" className="mt-5">
        <TabsList>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="trust">Trust relationships</TabsTrigger>
          <TabsTrigger value="tags">Tags</TabsTrigger>
          <TabsTrigger value="advisor">Access Advisor</TabsTrigger>
          <TabsTrigger value="revoke">Revoke sessions</TabsTrigger>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        {/* Permissions — attached policies (the aggregated union), managed via the Add-permissions picker. */}
        <TabsContent value="permissions" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-4 p-5">
              <div className="flex items-start justify-between gap-3">
                <p className="text-sm text-muted-foreground">
                  This role grants the union of the policies below. Use <b>Add permissions</b> to
                  attach out-of-the-box managed or customer-managed policies; remove one with its ✕.
                </p>
                <Button variant="outline" className="shrink-0" onClick={() => setPickerOpen(true)}>
                  <Plus className="size-4" /> Add permissions
                </Button>
              </div>

              {attached.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No policies attached — this role grants nothing until you add one.
                </p>
              ) : (
                <ul className="divide-y divide-border rounded-md border border-border">
                  {attached.map((name) => {
                    const p = policyByName.get(name);
                    return (
                      <li key={name} className="flex items-center justify-between gap-3 p-3">
                        <div className="flex min-w-0 flex-wrap items-center gap-2">
                          <Link
                            to="/policies/$name"
                            params={{ name }}
                            className="font-medium text-primary hover:underline"
                          >
                            {name}
                          </Link>
                          {p ? (
                            <>
                              <ManagedBadge managed={p.managed} category={p.category} />
                              <Badge variant="secondary">{policyType(p)}</Badge>
                            </>
                          ) : (
                            <Badge variant="outline">not found</Badge>
                          )}
                        </div>
                        <button
                          type="button"
                          onClick={() => toggle(name)}
                          className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-destructive"
                          aria-label={`Detach ${name}`}
                        >
                          <X className="size-4" />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}

              <div className="flex items-center gap-3 border-t border-border pt-4">
                <Button disabled={!policiesDirty || savePolicies.isPending} onClick={() => savePolicies.mutate()}>
                  {savePolicies.isPending ? <Spinner className="size-4" /> : null}
                  Save
                </Button>
                {policiesDirty ? (
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

          <AttachPolicyPicker
            open={pickerOpen}
            onOpenChange={setPickerOpen}
            policies={policies.data ?? []}
            attached={attached}
            onConfirm={setAttached}
            subjectLabel={`role ${role.name}`}
          />
        </TabsContent>

        {/* Trust relationships — who may assume the role (spec.trust). */}
        <TabsContent value="trust" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-4 p-5">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold">Trusted entities</h3>
                <p className="text-sm text-muted-foreground">
                  The principals allowed to assume this role via <code>sts:AssumeRole</code> (and
                  service accounts via web identity). A role with no trusted entities is assumable by
                  no one — fail closed, exactly as an AWS role needs a trust policy.
                </p>
              </div>

              <TrustEditor value={trust} onChange={setTrust} users={(users.data ?? []).map((u) => u.name)} />

              <div className="flex items-center gap-3 border-t border-border pt-4">
                <Button disabled={!trustDirty || saveTrust.isPending} onClick={() => saveTrust.mutate()}>
                  {saveTrust.isPending ? <Spinner className="size-4" /> : null}
                  Update trust policy
                </Button>
                {trustDirty ? (
                  <Button variant="ghost" onClick={() => setTrust(storedTrust)}>
                    Reset
                  </Button>
                ) : null}
                {saveTrust.isError ? (
                  <span className="text-sm text-destructive">{(saveTrust.error as Error).message}</span>
                ) : null}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                <ShieldCheck className="size-4" /> How to assume this role
              </div>
              <p className="text-sm text-muted-foreground">
                A trusted principal calls the aws-shim STS endpoint with the role ARN:
              </p>
              <div className="mt-2 flex items-center gap-2 rounded-md border border-border bg-muted/30 p-2 font-mono text-xs">
                <span className="break-all">
                  aws sts assume-role --role-arn {roleArn} --role-session-name s1
                </span>
                <CopyButton
                  value={`aws sts assume-role --role-arn ${roleArn} --role-session-name s1`}
                  label="Copy command"
                />
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                The returned session credentials carry this role's aggregated policies. Pods assume it
                instead via <code>AssumeRoleWithWebIdentity</code> using their projected ServiceAccount token.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tags — free-form key/value pairs, stored as openinfra.dev/tag-* annotations on the Role. */}
        <TabsContent value="tags" className="pt-4">
          <TagsTab
            tags={role.tags ?? {}}
            resourceLabel="role"
            save={(tags) => updateIamRoleTags(name, tags)}
            onSaved={() => {
              void qc.invalidateQueries({ queryKey: ["iam", "role", name] });
              void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
            }}
          />
        </TabsContent>

        {/* Access Advisor — backend-blocked (no per-service last-used data plumbing yet). */}
        <TabsContent value="advisor" className="pt-4">
          <PendingTab title="Access Advisor — services last accessed">
            Per-service, per-permission last-used data for this role is not available yet. Only
            aggregate last-seen exists today (in Access Review); the per-service breakdown AWS shows
            here needs richer audit parsing (k8s-audit + shim logs via Loki, attributed by role).
          </PendingTab>
        </TabsContent>

        {/* Revoke sessions — Part-B blocked (no revoked-before stamp honored by the shim yet). */}
        <TabsContent value="revoke" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <div className="flex items-start gap-3">
                <ShieldX className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
                <div className="space-y-1">
                  <h3 className="text-sm font-semibold">Revoke active sessions</h3>
                  <p className="text-sm text-muted-foreground">
                    AWS revokes in-flight role sessions by denying credentials issued before a cutoff
                    time. In open-infra the aws-shim issues the session credentials, so the clean fit
                    is a <code>revokedBefore</code> timestamp the shim honors on <code>AssumeRole</code> —
                    but that mechanism is not built yet (Part B). The control is shown for structural
                    parity and is disabled until it lands.
                  </p>
                </div>
              </div>
              <Button variant="outline" disabled>
                <ShieldX className="size-4" /> Revoke active sessions
              </Button>
              <p className="text-xs text-muted-foreground">
                Not available yet — needs the shim session-revocation mechanism.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Usage — open-infra-native: how the role becomes effective. Kept after the AWS tabs. */}
        <TabsContent value="usage" className="space-y-4 pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Binds as (ClusterRole)">
                <code className="text-xs">{clusterRole}</code>
              </DetailRow>
              <DetailRow label="Trusted entities">
                {storedTrust.length === 0 ? (
                  <span className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                    <AlertTriangle className="size-3.5" /> none — not assumable
                  </span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {storedTrust.map((p) => (
                      <Badge
                        key={p}
                        variant={p === "*" ? "outline" : "secondary"}
                        className={p === "*" ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : ""}
                      >
                        {principalLabel(p)}
                      </Badge>
                    ))}
                  </div>
                )}
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
