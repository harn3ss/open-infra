import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamPolicy, getIamConfig } from "@/lib/api";
import { PermissionEditor, rowsToActions, type PermRow } from "./permission-editor";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Single-page create for kind: Policy (issue #96) — a set of permissions over openinfra.dev resources
 * (the boundary), reusing the same visual PermissionEditor as the edit dialog. Edit stays on the policy
 * detail page.
 */
export function CreatePolicyPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rows, setRows] = useState<PermRow[]>([{ resource: "", verbs: [] }]);
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () => {
      const statements = [{ effect: "Allow", actions: rowsToActions(rows), resources: ["*"] }];
      return createIamPolicy({ name, description, statements });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "policies"] });
      navigate({ to: "/policies/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const actionCount = rowsToActions(rows).length;
  const submit = () => {
    setTouched(true);
    if (!nameOk || actionCount === 0) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<FileText className="size-6 text-primary" />}
      title="Create Policy"
      description="An attachable set of permissions over open-infra resources. It grants nothing until a Role includes it, and can only ever grant on openinfra.dev kinds — the permission boundary."
      onCancel={() => navigate({ to: "/policies" })}
      onSubmit={submit}
      submitLabel="Create Policy"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || description.length > 0 || actionCount > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Policy</h3>
        <div className="space-y-1.5">
          <Label htmlFor="p-name">Name</Label>
          <Input id="p-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="virtual-machine-operator" autoFocus />
          {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p> : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="p-desc">Description (optional)</Label>
          <Input id="p-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Full control of VMs and their disks" />
        </div>
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Permissions</h3>
        <PermissionEditor resources={cfg.data?.policyResources ?? []} rows={rows} onChange={setRows} />
        {touched && actionCount === 0 ? <p className="text-xs text-destructive">Add at least one permission.</p> : null}
      </div>
    </CreateShell>
  );
}
