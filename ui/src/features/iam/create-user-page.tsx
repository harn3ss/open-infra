import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamUser, getIamConfig, listIamGroups } from "@/lib/api";
import { GroupPicker } from "./group-picker";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Single-page create for kind: User (issue #96). Same fields as the old dialog, via the BFF. */
export function CreateUserPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const builtins = cfg.data?.builtinGroups ?? [];

  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [password, setPassword] = useState("");
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () => createIamUser({ name, displayName, groups: selected, password }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      navigate({ to: "/users/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const pwOk = password.length >= 8;
  const submit = () => {
    setTouched(true);
    if (!nameOk || !pwOk) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<UserPlus className="size-6 text-primary" />}
      title="Create User"
      description="A console sign-in stored as a kind: User. The password is saved as a bcrypt hash in a Secret — never in the User itself."
      onCancel={() => navigate({ to: "/users" })}
      onSubmit={submit}
      submitLabel="Create User"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || password.length > 0 || displayName.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">User</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="u-name">Username</Label>
            <Input id="u-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="alice" autoFocus />
            {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only (a DNS label).</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-display">Display name (optional)</Label>
            <Input id="u-display" value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Alice Example" />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="u-pw">Password</Label>
          <Input id="u-pw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" />
          {touched && !pwOk ? <p className="text-xs text-destructive">At least 8 characters.</p> : null}
        </div>
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Groups</h3>
        <p className="text-xs text-muted-foreground">
          Permissions come entirely from group membership. No groups = can sign in, but do nothing.
        </p>
        <GroupPicker builtins={builtins} known={(groups.data ?? []).map((g) => g.name)} value={selected} onChange={setSelected} />
      </div>
    </CreateShell>
  );
}
