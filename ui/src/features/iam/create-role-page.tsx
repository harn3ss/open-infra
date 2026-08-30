import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Check } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamRole, listIamPolicies } from "@/lib/api";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Single-page create for kind: Role (issue #96) — a named bundle of policies. */
export function CreateRolePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () => createIamRole({ name, description, policies: selected }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
      navigate({ to: "/roles/$name", params: { name } });
    },
  });

  const toggle = (p: string) => setSelected(selected.includes(p) ? selected.filter((x) => x !== p) : [...selected, p]);
  const nameOk = RFC1123.test(name);
  const submit = () => {
    setTouched(true);
    if (!nameOk) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Boxes className="size-6 text-primary" />}
      title="Create Role"
      description="A named bundle of policies. Point a Group at it (Grants → openinfra-role-…) to give its members the union of those policies."
      onCancel={() => navigate({ to: "/roles" })}
      onSubmit={submit}
      submitLabel="Create Role"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || description.length > 0 || selected.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Role</h3>
        <div className="space-y-1.5">
          <Label htmlFor="r-name">Name</Label>
          <Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="vm-operator" autoFocus />
          {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p> : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="r-desc">Description (optional)</Label>
          <Input id="r-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Operate VMs and their storage" />
        </div>
        <div className="space-y-1.5">
          <Label>Attached policies</Label>
          {policies.data && policies.data.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {policies.data.map((p) => {
                const on = selected.includes(p.name);
                return (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => toggle(p.name)}
                    className={[
                      "inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                      on ? "border-primary/40 bg-primary/15 text-primary" : "border-border text-muted-foreground hover:bg-muted",
                    ].join(" ")}
                  >
                    {on ? <Check className="size-3" /> : null}
                    {p.name}
                  </button>
                );
              })}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No policies yet — create a Policy first, then attach it here.</p>
          )}
        </div>
      </div>
    </CreateShell>
  );
}
