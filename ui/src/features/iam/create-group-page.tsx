import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Search, UsersRound } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useFlash } from "@/components/common/flashbar";
import { createIamGroup, listIamPolicies, listIamUsers, updateIamUser } from "@/lib/api";
import { cn } from "@/lib/utils";
import { ManagedBadge } from "./attach-policy-picker";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Single-page create for a user group, as AWS's: name it, attach permissions policies (the managed
 * AdministratorAccess / PowerUserAccess / ReadOnlyAccess and any customer policy), and add users. A
 * group is a container of policies; its members get what its policies grant.
 */
export function CreateGroupPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [attached, setAttached] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);

  const visiblePolicies = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (policies.data ?? [])
      .filter((p) => !q || p.name.toLowerCase().includes(q) || (p.description ?? "").toLowerCase().includes(q))
      .sort((a, b) => Number(b.managed) - Number(a.managed) || a.name.localeCompare(b.name));
  }, [policies.data, search]);

  const create = useMutation({
    mutationFn: () => createIamGroup({ name, description, policies: attached }),
    onSuccess: async () => {
      const targets = (users.data ?? []).filter((u) => picked.includes(u.name));
      const results = await Promise.allSettled(
        targets.map((u) =>
          updateIamUser(u.name, {
            groups: Array.from(new Set([...(u.groups ?? []), name])),
          }),
        ),
      );
      const failed = targets.filter((_, i) => results[i]?.status === "rejected").map((u) => u.name);
      void qc.invalidateQueries({ queryKey: ["iam", "groups"] });
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      if (failed.length > 0) flash.warning(`Group ${name} created, but couldn't add: ${failed.join(", ")}.`);
      else if (targets.length > 0)
        flash.success(`Group ${name} created with ${targets.length} member${targets.length === 1 ? "" : "s"}.`);
      else flash.success(`Group ${name} created.`);
      navigate({ to: "/groups/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const toggle = (list: string[], set: (v: string[]) => void, n: string) =>
    set(list.includes(n) ? list.filter((x) => x !== n) : [...list, n]);

  const submit = () => {
    setTouched(true);
    if (!nameOk) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<UsersRound className="size-6 text-primary" />}
      title="Create user group"
      description="A user group is a collection of users. Attach policies to it and every member gets their permissions."
      onCancel={() => navigate({ to: "/groups" })}
      onSubmit={submit}
      submitLabel="Create user group"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || description.length > 0 || picked.length > 0 || attached.length > 0}
    >
      {/* ------------------------------------------------------ Group details */}
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Name the group</h3>
        <div className="space-y-1.5">
          <Label htmlFor="g-name">User group name</Label>
          <Input
            id="g-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => setTouched(true)}
            placeholder="dba"
            autoFocus
          />
          {touched && !nameOk ? (
            <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p>
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

      {/* -------------------------------------------------------- Add users */}
      <div className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">Add users to the group - optional</h3>
          <p className="text-xs text-muted-foreground">A user can be in up to ten groups.</p>
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
                  onClick={() => toggle(picked, setPicked, u.name)}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                    on ? "border-primary/40 bg-primary/15 text-primary" : "border-border text-muted-foreground hover:bg-muted",
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

      {/* -------------------------------------------------- Attach permissions */}
      <div className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">
            Attach permissions policies - optional ({attached.length} selected)
          </h3>
          <p className="text-xs text-muted-foreground">
            Members get the permissions of every policy you attach. You can change them later.
          </p>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input className="pl-8" placeholder="Filter policies" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="max-h-80 overflow-y-auto rounded-md border">
          {visiblePolicies.length === 0 ? (
            <p className="p-3 text-sm text-muted-foreground">No policies match.</p>
          ) : (
            visiblePolicies.map((p) => {
              const on = attached.includes(p.name);
              return (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => toggle(attached, setAttached, p.name)}
                  className={cn(
                    "flex w-full items-start gap-3 border-b p-3 text-left last:border-0 transition-colors",
                    on ? "bg-primary/5" : "hover:bg-muted/40",
                  )}
                >
                  <span
                    className={cn(
                      "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded border",
                      on ? "border-primary bg-primary text-primary-foreground" : "border-border",
                    )}
                  >
                    {on ? <Check className="size-3" /> : null}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2 text-sm font-medium">
                      {p.name}
                      <ManagedBadge managed={p.managed} category={p.category} />
                    </span>
                    <span className="block text-xs text-muted-foreground">{p.description || "—"}</span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>
    </CreateShell>
  );
}
