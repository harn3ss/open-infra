import { useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, Pencil } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { CopyButton } from "@/components/common/copy-button";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import { deleteIamPolicy, getIamPolicy, listIamRoles } from "@/lib/api";
import { PermissionsSummary } from "./policy-editor/permissions-summary";
import { policyType, type PolicyTypeLabel } from "./policy-type";
import { PendingTab } from "./pending-notice";
import { cn } from "@/lib/utils";

const TYPE_TONE: Record<PolicyTypeLabel, "default" | "accent" | "secondary"> = {
  "Control plane": "default",
  "Data plane": "accent",
  Mixed: "secondary",
  Empty: "secondary",
};

export function PolicyDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [forcePrompt, setForcePrompt] = useState(false);
  // AWS's Permissions tab carries a { } / Summary toggle at the top-right; open-infra's JSON view is
  // the Policy CR (the source of truth), so the toggle switches the summary table ⇄ the raw CR.
  const [permView, setPermView] = useState<"summary" | "json">("summary");

  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const { data: policy, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "policy", name],
    queryFn: () => getIamPolicy(name),
    refetchInterval: 5000,
  });

  // The /policies/$name/edit route is registered via this unit's router snippet (see report). Until the
  // integrator applies it, the generated route table doesn't know it, so navigate via a locally-typed
  // shim rather than the typed route id.
  const goEdit = () =>
    (navigate as unknown as (o: { to: string; params: { name: string } }) => void)({
      to: "/policies/$name/edit",
      params: { name },
    });

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamPolicy(name, force),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "policies"] });
      navigate({ to: "/policies" });
    },
  });

  if (isLoading) return <LoadingState label="Loading policy…" />;
  if (isError || !policy) return <ErrorState error={error} onRetry={refetch} />;

  const doc = {
    description: policy.description,
    statements: policy.statements,
    dataPlane: policy.dataPlane,
    controlPlane: policy.controlPlane,
  };
  const type = policyType(policy);
  const attachedRoles = (roles.data ?? []).filter((r) => r.policies.includes(name));
  const appliesTo = policy.dataPlane?.appliesTo?.filter((p) => p && p !== "*") ?? [];
  const hasDataPlane = (policy.dataPlane?.statements ?? []).length > 0;

  // The read-only CR view (the JSON toggle's source of truth).
  const cr = {
    apiVersion: "iam.openinfra.dev/v1",
    kind: "Policy",
    metadata: { name: policy.name },
    spec: {
      description: policy.description || undefined,
      statements: policy.statements?.length ? policy.statements : undefined,
      dataPlane: policy.dataPlane?.statements?.length ? policy.dataPlane : undefined,
      controlPlane: policy.controlPlane?.statements?.length ? policy.controlPlane : undefined,
    },
  };

  return (
    <DetailShell
      backTo="/policies"
      backLabel="Policies"
      icon={<FileText className="size-5" />}
      title={policy.name}
      subtitle={policy.description || "Policy"}
      status={{ label: policy.ready ? "Ready" : "Compiling", tone: policy.ready ? "success" : "warning" }}
      actions={
        <Button onClick={goEdit}>
          <Pencil className="size-4" /> Edit
        </Button>
      }
    >
      <Tabs defaultValue="permissions">
        <TabsList>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="entities">Entities attached ({attachedRoles.length})</TabsTrigger>
          <TabsTrigger value="tags">Tags</TabsTrigger>
          <TabsTrigger value="versions">Policy versions</TabsTrigger>
          <TabsTrigger value="advisor">Access Advisor</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        {/* Permissions — the AWS permissions-summary table with a Summary ⇄ JSON/CR toggle. */}
        <TabsContent value="permissions" className="space-y-4 pt-4">
          <Card>
            <CardContent className="p-4">
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Type", value: <Badge variant={TYPE_TONE[type]}>{type}</Badge> },
                  {
                    label: "Compiled ClusterRole",
                    value: (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{policy.clusterRole || `openinfra-policy-${name}`}</code>
                        <CopyButton value={policy.clusterRole || `openinfra-policy-${name}`} />
                      </span>
                    ),
                  },
                  {
                    label: "RBAC rules",
                    value: (
                      <span className="flex items-center gap-2">
                        {policy.ruleCount}
                        <Badge variant={policy.ready ? "success" : "warning"}>
                          {policy.ready ? "Ready" : "Compiling"}
                        </Badge>
                      </span>
                    ),
                  },
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-0">
              <div className="flex items-start justify-between gap-3 border-b border-border p-3">
                <div>
                  <h3 className="text-sm font-semibold">
                    {permView === "summary" ? "Permissions summary" : "Policy resource (CR)"}
                  </h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {permView === "summary"
                      ? "Platform (control-plane) permissions compile to RBAC — Allow-only, all resources of the kind. Data-service permissions are enforced by Cedar and may Deny, scope, and set conditions."
                      : "The Policy CR is the authored artifact — the same object GitOps would apply. Edit it on the policy editor's JSON tab."}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {/* Summary | JSON toggle (AWS parity). */}
                  <div className="inline-flex overflow-hidden rounded-md border border-border">
                    <button
                      type="button"
                      onClick={() => setPermView("summary")}
                      className={cn(
                        "px-2.5 py-1 text-xs font-medium transition-colors",
                        permView === "summary"
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:bg-muted",
                      )}
                    >
                      Summary
                    </button>
                    <button
                      type="button"
                      onClick={() => setPermView("json")}
                      className={cn(
                        "border-l border-border px-2.5 py-1 font-mono text-xs font-medium transition-colors",
                        permView === "json"
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:bg-muted",
                      )}
                    >
                      {"{ }"} JSON / CR
                    </button>
                  </div>
                  {permView === "json" ? <CopyButton value={yamlOf(cr)} label="Copy YAML" /> : null}
                </div>
              </div>
              {permView === "summary" ? (
                <PermissionsSummary doc={doc} />
              ) : (
                <div className="space-y-4 p-4">
                  <YamlViewer value={cr} />
                  {policy.dataPlane?.statements?.length || policy.controlPlane?.statements?.length ? (
                    <div className="space-y-2">
                      <h4 className="text-sm font-semibold">Cedar policy set (data / control plane)</h4>
                      <p className="text-xs text-muted-foreground">
                        What the aws-shim (data plane) and the shadow webhook (control plane) evaluate —
                        the Allow/Deny + conditions RBAC cannot express.
                      </p>
                      <YamlViewer
                        value={{ dataPlane: policy.dataPlane, controlPlane: policy.controlPlane }}
                        maxHeightClassName="max-h-[40vh]"
                      />
                    </div>
                  ) : null}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Entities attached — the reverse "who has this?" view (roles + data-plane principals). */}
        <TabsContent value="entities" className="space-y-4 pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <div className="p-3 text-xs font-medium text-muted-foreground">
                Roles that include this policy (control plane)
              </div>
              {attachedRoles.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  Not attached to any role. Add it from a Role's Policies tab — a control-plane policy does
                  nothing until a Role includes it and a Group binds that Role.
                </div>
              ) : (
                attachedRoles.map((r) => (
                  <DetailRow key={r.name} label="Role">
                    <Link
                      to="/roles/$name"
                      params={{ name: r.name }}
                      className="text-primary hover:underline"
                    >
                      {r.name}
                    </Link>
                  </DetailRow>
                ))
              )}
            </CardContent>
          </Card>
          {hasDataPlane ? (
            <Card>
              <CardContent className="divide-y divide-border p-0">
                <div className="p-3 text-xs font-medium text-muted-foreground">
                  Principals governed by the data plane (spec.dataPlane.appliesTo)
                </div>
                {appliesTo.length === 0 ? (
                  <div className="p-4 text-sm text-muted-foreground">
                    Applies to <code className="text-xs">*</code> — every principal. Scope it on the editor's
                    Visual tab to narrow which Users/Groups the data-plane rules govern.
                  </div>
                ) : (
                  appliesTo.map((p) => (
                    <DetailRow key={p} label="Principal">
                      <code className="text-xs">{p}</code>
                    </DetailRow>
                  ))
                )}
              </CardContent>
            </Card>
          ) : null}

          {/* AWS lists "Attached as a permissions boundary" here; open-infra has no per-identity
              boundary — the platform boundary is structural, so this subsection stays honest. */}
          <Card>
            <CardContent className="p-4">
              <h3 className="text-sm font-semibold">Attached as a permissions boundary</h3>
              <p className="mt-1 text-sm text-muted-foreground">
                open-infra does not use per-identity permission boundaries, so a policy is never
                attached as one. The effective ceiling is the always-on <b>structural platform
                boundary</b> (a Policy can only ever grant on the ~33 <code>openinfra.dev</code>
                resources) — it applies to every identity and is not attached or detached here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tags — backend-blocked (the policy view carries no labels/annotations yet). */}
        <TabsContent value="tags" className="pt-4">
          <PendingTab title="Tags">
            Tags are not yet surfaced for policies. The IAM policy view carries no labels or
            annotations today, so there is nothing to show or edit here. When the BFF exposes them,
            this tab wires the shared tag editor (add/remove key–value rows).
          </PendingTab>
        </TabsContent>

        {/* Policy versions — backend-blocked (CR generations/revisions not exposed yet). */}
        <TabsContent value="versions" className="pt-4">
          <PendingTab title="Policy versions">
            open-infra does not keep AWS's 5-version model. The honest analog is the Policy CR's
            revision history (generations / GitOps revisions), and the BFF does not expose that yet.
            When it does, this tab lists prior CR revisions with a "set as current" action — labelled
            as revisions, not AWS versions.
          </PendingTab>
        </TabsContent>

        {/* Access Advisor — backend-blocked (no per-service last-used via this policy yet). */}
        <TabsContent value="advisor" className="pt-4">
          <PendingTab title="Access Advisor — services last accessed via this policy">
            Per-service last-used data attributed to this policy is not available yet. Only aggregate
            last-seen exists today (in Access Review); the per-service breakdown AWS shows here needs
            richer audit parsing (k8s-audit + shim logs via Loki).
          </PendingTab>
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Policy"
            resourceName={policy.name}
            deleting={del.isPending}
            onConfirm={() => {
              if (attachedRoles.length > 0) setForcePrompt(true);
              else del.mutate(false);
            }}
            confirmDescription={
              <>
                Delete policy <span className="font-medium text-foreground">{policy.name}</span> and its
                compiled ClusterRole.{" "}
                {attachedRoles.length > 0
                  ? `${attachedRoles.length} role(s) attach it and will lose these permissions.`
                  : "No role attaches it."}
              </>
            }
          />
          <ConfirmDialog
            open={forcePrompt}
            onOpenChange={setForcePrompt}
            title="Delete a policy in use?"
            confirmLabel="Delete anyway"
            loading={del.isPending}
            onConfirm={() => del.mutate(true)}
            description={
              <>
                <span className="font-medium text-foreground">{attachedRoles.length}</span> role(s) still
                attach <span className="font-medium text-foreground">{policy.name}</span>. Deleting it
                removes those permissions from them.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

// Small local YAML serializer for the copy button (YamlViewer renders its own; this matches it closely
// enough for a clipboard copy).
function yamlOf(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}
