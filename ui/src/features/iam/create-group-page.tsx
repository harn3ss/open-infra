import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, UsersRound } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamGroup, getIamConfig, listIamRoles } from "@/lib/api";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const ROLE_OPTIONS = [
  { value: "open-infra-console", label: "Full access (open-infra-console)" },
  { value: "open-infra-poweruser", label: "Power user — manage resources, not secrets/RBAC" },
  { value: "open-infra-readonly", label: "Read-only" },
];

/** Single-page create for kind: Group (issue #96). */
export function CreateGroupPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const builtins = cfg.data?.builtinGroups ?? [];

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [clusterRole, setClusterRole] = useState("open-infra-readonly");
  const [touched, setTouched] = useState(false);

  const roleOptions = [
    ...ROLE_OPTIONS,
    ...(roles.data ?? []).map((r) => ({ value: r.clusterRole || `openinfra-role-${r.name}`, label: `Role: ${r.name}` })),
  ];

  const create = useMutation({
    mutationFn: () => createIamGroup({ name, description, clusterRole }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      navigate({ to: "/groups/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const isBuiltin = builtins.includes(name);
  const submit = () => {
    setTouched(true);
    if (!nameOk) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<UsersRound className="size-6 text-primary" />}
      title="Create Group"
      description="A kind: Group binds its members to a ClusterRole. That role is the only thing that grants access — choose it deliberately."
      onCancel={() => navigate({ to: "/groups" })}
      onSubmit={submit}
      submitLabel="Create Group"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || description.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Group</h3>
        <div className="space-y-1.5">
          <Label htmlFor="g-name">Name</Label>
          <Input id="g-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="dba" autoFocus />
          {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only (a DNS label).</p> : null}
          {nameOk && !isBuiltin ? (
            <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              <span>
                This is not one of the built-in group names, so it won't take effect until an operator adds{" "}
                <code>openinfra:{name}</code> to the impersonator ClusterRole. The group is still created.
              </span>
            </p>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="g-desc">Description (optional)</Label>
          <Input id="g-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Database administrators" />
        </div>
        <div className="space-y-1.5">
          <Label>Grants (ClusterRole)</Label>
          <Select value={clusterRole} onValueChange={setClusterRole}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {roleOptions.map((r) => (
                <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </CreateShell>
  );
}
