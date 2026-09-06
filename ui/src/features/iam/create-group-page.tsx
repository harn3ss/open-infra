import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check, ShieldCheck, UsersRound } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useFlash } from "@/components/common/flashbar";
import {
  createIamGroup,
  getIamConfig,
  listIamRoles,
  listIamUsers,
  updateIamUser,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Built-in console ClusterRoles a group may bind (the same three the console ships). */
const BUILTIN_OPTIONS = [
  {
    value: "open-infra-console",
    label: "Full access",
    blurb: "Manage everything, including identities, secrets and RBAC.",
  },
  {
    value: "open-infra-poweruser",
    label: "Power user",
    blurb: "Manage product resources, but not secrets or cluster RBAC.",
  },
  {
    value: "open-infra-readonly",
    label: "Read-only",
    blurb: "View resources across the console; no changes.",
  },
];

/**
 * Single-page create for kind: Group (mirrors AWS's create-group page: name → attach
 * permissions → add users). Honest to open-infra: a group binds exactly ONE ClusterRole
 * (built-in or a Role), so "attach permissions" is a single choice, not a policy checklist;
 * membership is stored on each User, so "add users" patches the selected Users' spec.groups.
 */
export function CreateGroupPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const builtins = cfg.data?.builtinGroups ?? [];

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [clusterRole, setClusterRole] = useState("open-infra-readonly");
  const [picked, setPicked] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);

  const roleOptions = [
    ...BUILTIN_OPTIONS,
    ...(roles.data ?? []).map((r) => ({
      value: r.clusterRole || `openinfra-role-${r.name}`,
      label: `Role: ${r.name}`,
      blurb: r.description || `Aggregated policies: ${(r.policies ?? []).join(", ") || "none"}`,
    })),
  ];

  const create = useMutation({
    mutationFn: () => createIamGroup({ name, description, clusterRole }),
    onSuccess: async () => {
      const targets = (users.data ?? []).filter((u) => picked.includes(u.name));
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
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      if (failed.length > 0)
        flash.warning(`Group ${name} created, but couldn't add: ${failed.join(", ")}.`);
      else if (targets.length > 0)
        flash.success(
          `Group ${name} created with ${targets.length} member${targets.length === 1 ? "" : "s"}.`,
        );
      else flash.success(`Group ${name} created.`);
      navigate({ to: "/groups/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const isBuiltin = builtins.includes(name);
  const togglePick = (n: string) =>
    setPicked((p) => (p.includes(n) ? p.filter((x) => x !== n) : [...p, n]));

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
      submitLabel="Create group"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || description.length > 0 || picked.length > 0}
    >
      {/* ------------------------------------------------------ Group details */}
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Group details</h3>
        <div className="space-y-1.5">
          <Label htmlFor="g-name">Name</Label>
          <Input
            id="g-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => setTouched(true)}
            placeholder="dba"
            autoFocus
          />
          {touched && !nameOk ? (
            <p className="text-xs text-destructive">
              Lowercase letters, digits and dashes only (a DNS label).
            </p>
          ) : null}
          {nameOk && !isBuiltin ? (
            <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              <span>
                This is not one of the built-in group names, so it won&apos;t take effect until an
                operator adds <code>openinfra:{name}</code> to the impersonator ClusterRole. The
                group is still created.
              </span>
            </p>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="g-desc">Description - optional</Label>
          <Input
            id="g-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Database administrators"
          />
        </div>
      </div>

      {/* -------------------------------------------------- Attach permissions */}
      <div className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">Attach permissions</h3>
          <p className="text-xs text-muted-foreground">
            A group binds exactly one ClusterRole — the built-in console roles, or a{" "}
            <span className="font-medium">Role</span> you defined. That binding is the only thing
            that grants access.
          </p>
        </div>
        <div className="space-y-2">
          {roleOptions.map((r) => {
            const on = clusterRole === r.value;
            return (
              <button
                key={r.value}
                type="button"
                onClick={() => setClusterRole(r.value)}
                className={cn(
                  "flex w-full items-start gap-3 rounded-md border p-3 text-left transition-colors",
                  on
                    ? "border-primary/50 bg-primary/5"
                    : "border-border hover:bg-muted/40",
                )}
              >
                <span
                  className={cn(
                    "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border",
                    on ? "border-primary bg-primary text-primary-foreground" : "border-border",
                  )}
                >
                  {on ? <Check className="size-3" /> : null}
                </span>
                <span className="min-w-0">
                  <span className="flex items-center gap-1.5 text-sm font-medium">
                    <ShieldCheck className="size-3.5 text-primary" />
                    {r.label}
                  </span>
                  <span className="block text-xs text-muted-foreground">{r.blurb}</span>
                  <code className="text-[11px] text-muted-foreground">{r.value}</code>
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* -------------------------------------------------------- Add users */}
      <div className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">
            Add users to the group - optional
          </h3>
          <p className="text-xs text-muted-foreground">
            Membership is stored on each User (<code>spec.groups</code>); selecting a user here
            patches that User when the group is created.
          </p>
        </div>
        {(users.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No users exist yet.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {(users.data ?? []).map((u) => {
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
      </div>
    </CreateShell>
  );
}
