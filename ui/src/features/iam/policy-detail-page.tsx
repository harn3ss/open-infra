import { useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, Pencil } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { LoadingState, ErrorState } from "@/components/common/states";
import {
  deleteIamPolicy,
  getIamConfig,
  getIamPolicy,
  listIamRoles,
} from "@/lib/api";
import { NewPolicyDialog } from "./new-policy-dialog";

export function PolicyDetailPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [edit, setEdit] = useState(false);
  const [forcePrompt, setForcePrompt] = useState(false);

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const { data: policy, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["iam", "policy", name],
    queryFn: () => getIamPolicy(name),
    refetchInterval: 5000,
  });

  const attachedRoles = (roles.data ?? []).filter((r) => r.policies.includes(name));

  const del = useMutation({
    mutationFn: (force: boolean) => deleteIamPolicy(name, force),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "policies"] });
      navigate({ to: "/policies" });
    },
  });

  if (isLoading) return <LoadingState label="Loading policy…" />;
  if (isError || !policy) return <ErrorState error={error} onRetry={refetch} />;

  const actions = policy.statements.flatMap((s) => s.actions ?? []);

  return (
    <DetailShell
      backTo="/policies"
      backLabel="Policies"
      icon={<FileText className="size-5" />}
      title={policy.name}
      subtitle={policy.description || "Policy"}
      actions={
        <Button onClick={() => setEdit(true)}>
          <Pencil className="size-4" /> Edit
        </Button>
      }
    >
      <Tabs defaultValue="permissions">
        <TabsList>
          <TabsTrigger value="permissions">Permissions</TabsTrigger>
          <TabsTrigger value="usedby">Used by ({attachedRoles.length})</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="permissions" className="space-y-4 pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Compiled ClusterRole">
                <code className="text-xs">{policy.clusterRole || `openinfra-policy-${name}`}</code>
              </DetailRow>
              <DetailRow label="Rules">
                <span className="flex items-center gap-2">
                  {policy.ruleCount}
                  <Badge variant={policy.ready ? "default" : "secondary"}>
                    {policy.ready ? "Ready" : "Compiling"}
                  </Badge>
                </span>
              </DetailRow>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="p-3 font-medium">Effect</th>
                    <th className="p-3 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {actions.length === 0 ? (
                    <tr>
                      <td colSpan={2} className="p-3 text-xs text-muted-foreground">
                        No actions — this policy grants nothing.
                      </td>
                    </tr>
                  ) : (
                    actions.map((a) => (
                      <tr key={a} className="border-b last:border-0">
                        <td className="p-3">
                          <Badge variant="default">Allow</Badge>
                        </td>
                        <td className="p-3">
                          <code className="text-xs">{a}</code>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="usedby" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {attachedRoles.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  Not attached to any role. Add it from a Role's Policies tab — a policy does
                  nothing on its own.
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
                Delete policy <span className="font-medium text-foreground">{policy.name}</span> and
                its compiled ClusterRole.{" "}
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
                <span className="font-medium text-foreground">{attachedRoles.length}</span> role(s)
                still attach <span className="font-medium text-foreground">{policy.name}</span>.
                Deleting it removes those permissions from them.
              </>
            }
          />
        </TabsContent>
      </Tabs>

      <NewPolicyDialog
        open={edit}
        onOpenChange={(o) => {
          setEdit(o);
          if (!o) void refetch();
        }}
        resources={cfg.data?.policyResources ?? []}
        editing={policy}
      />
    </DetailShell>
  );
}
