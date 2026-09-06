import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, UsersRound } from "lucide-react";
import { Wizard, WizardReview, type WizardStep } from "@/components/create/wizard";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { useFlash } from "@/components/common/flashbar";
import { createIamUser, getIamConfig, listIamGroups, listIamUsers } from "@/lib/api";
import { cn } from "@/lib/utils";
import { GroupPicker } from "./group-picker";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

type PermMode = "group" | "copy" | "direct";

/**
 * Create user — the AWS multi-step wizard: Specify user details → Set permissions → Review and
 * create. Written on the shared Wizard (left step nav + Review step). The permission step mirrors
 * AWS's three options as radio cards; "Attach policies directly" is honestly disabled because
 * Kubernetes RBAC has no user-direct policy attachment (permissions come through groups). Creates
 * via the SAR-gated BFF (`POST /api/iam/users`), which stores the password as a bcrypt hash.
 */
export function CreateUserPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groupsQ = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const usersQ = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const builtins = cfg.data?.builtinGroups ?? [];

  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [permMode, setPermMode] = useState<PermMode>("group");
  const [selected, setSelected] = useState<string[]>([]);
  const [copyFrom, setCopyFrom] = useState<string>("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const copySource = useMemo(
    () => (usersQ.data ?? []).find((u) => u.name === copyFrom),
    [usersQ.data, copyFrom],
  );

  // The groups this user will actually be created with, per the chosen permission mode.
  const resultingGroups = useMemo<string[]>(() => {
    if (permMode === "group") return selected;
    if (permMode === "copy") return copySource?.groups ?? [];
    return []; // "direct" attaches nothing on the control plane (see the disabled card).
  }, [permMode, selected, copySource]);

  const unboundResulting = resultingGroups.filter((g) => !builtins.includes(g));

  const create = useMutation({
    mutationFn: () =>
      createIamUser({ name, displayName, groups: resultingGroups, password }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "users"] });
      flash.success(`Created user ${name}.`);
      navigate({ to: "/users/$name", params: { name } });
    },
  });

  function validateStep(i: number): boolean {
    const e: Record<string, string> = {};
    if (i === 0) {
      if (!name.trim()) e.name = "A user name is required.";
      else if (!RFC1123.test(name)) e.name = "Lowercase letters, digits and dashes only (a DNS label).";
      if (password.length < 8) e.password = "At least 8 characters.";
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  function handleSubmit() {
    // Re-validate the earlier steps and jump back to the first broken one.
    if (!validateStep(0)) {
      setStep(0);
      return;
    }
    create.mutate();
  }

  const steps: WizardStep[] = [
    {
      title: "Specify user details",
      description: "Name the user and set an initial console password.",
      info: {
        title: "Console users",
        body: (
          <div className="space-y-2 text-sm">
            <p>
              A console user is a <code>kind: User</code>. Its password is stored as a bcrypt hash in
              a Secret — never in the User object.
            </p>
            <p>
              The break-glass <code>root</code> account is separate: it lives in the console-auth
              Secret, is checked before any User, and never appears in the Users list.
            </p>
          </div>
        ),
      },
      content: (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="u-name">User name</Label>
              <Input
                id="u-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="alice"
                autoFocus
              />
              {errors.name ? <p className="text-xs text-destructive">{errors.name}</p> : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="u-display">Display name - optional</Label>
              <Input
                id="u-display"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Alice Example"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-pw">Password</Label>
            <Input
              id="u-pw"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
            />
            <p className="text-xs text-muted-foreground">
              Stored as a bcrypt hash. The user can change it later; an admin can reset it from the
              user's Security credentials tab.
            </p>
            {errors.password ? <p className="text-xs text-destructive">{errors.password}</p> : null}
          </div>
        </div>
      ),
    },
    {
      title: "Set permissions",
      description: "Choose how this user gets its access. Permissions come from group membership.",
      content: (
        <div className="space-y-4">
          <PermCard
            checked={permMode === "group"}
            onSelect={() => setPermMode("group")}
            icon={<UsersRound className="size-4" />}
            title="Add user to group"
            hint="Recommended. Membership grants the union of each group's ClusterRole."
          >
            {permMode === "group" ? (
              <div className="space-y-3 pt-1">
                <GroupPicker
                  builtins={builtins}
                  known={(groupsQ.data ?? []).map((g) => g.name)}
                  value={selected}
                  onChange={setSelected}
                />
              </div>
            ) : null}
          </PermCard>

          <PermCard
            checked={permMode === "copy"}
            onSelect={() => setPermMode("copy")}
            icon={<Copy className="size-4" />}
            title="Copy permissions"
            hint="Copy the group memberships of an existing user."
          >
            {permMode === "copy" ? (
              <div className="space-y-2 pt-1">
                <Select value={copyFrom} onValueChange={setCopyFrom}>
                  <SelectTrigger aria-label="Copy from user">
                    <SelectValue placeholder="Select a user to copy from" />
                  </SelectTrigger>
                  <SelectContent>
                    {(usersQ.data ?? [])
                      .filter((u) => u.name !== name)
                      .map((u) => (
                        <SelectItem key={u.name} value={u.name}>
                          {u.name}
                          {u.displayName ? ` · ${u.displayName}` : ""}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
                {copySource ? (
                  <div className="flex flex-wrap items-center gap-1 text-sm">
                    <span className="text-muted-foreground">Copies groups:</span>
                    {(copySource.groups ?? []).length === 0 ? (
                      <span className="text-muted-foreground">none</span>
                    ) : (
                      (copySource.groups ?? []).map((g) => (
                        <Badge key={g} variant="secondary">
                          {g}
                        </Badge>
                      ))
                    )}
                  </div>
                ) : null}
              </div>
            ) : null}
          </PermCard>

          <PermCard
            checked={permMode === "direct"}
            onSelect={() => setPermMode("direct")}
            icon={<AlertTriangle className="size-4" />}
            title="Attach policies directly"
            hint="Not available on this platform."
            disabled
          >
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                Kubernetes RBAC has no user-direct policy attachment — a user's authority is exactly
                the union of its groups' ClusterRoles. Attach a Policy or Role by pointing a Group at
                it, then add the user to that group. Create the group first from the Groups page.
              </span>
            </div>
          </PermCard>

          {resultingGroups.length === 0 && permMode !== "direct" ? (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                No groups selected. This user will be able to sign in but is authorized for nothing.
              </span>
            </div>
          ) : null}
        </div>
      ),
    },
    {
      title: "Review and create",
      content: (
        <WizardReview
          onEditStep={setStep}
          sections={[
            {
              title: "Specify user details",
              stepIndex: 0,
              pairs: [
                { label: "User name", value: name || "—" },
                { label: "Display name", value: displayName || "—" },
                { label: "Console access", value: "Enabled (password set)" },
              ],
            },
            {
              title: "Set permissions",
              stepIndex: 1,
              content: (
                <div className="space-y-2 text-sm">
                  <p className="text-muted-foreground">
                    {permMode === "group"
                      ? "Added to groups:"
                      : permMode === "copy"
                        ? `Copied from ${copyFrom || "—"}:`
                        : "No permissions attached (direct attach is not supported)."}
                  </p>
                  {permMode !== "direct" ? (
                    <div className="flex flex-wrap gap-1">
                      {resultingGroups.length === 0 ? (
                        <span className="text-amber-600 dark:text-amber-400">
                          none — authorized for nothing
                        </span>
                      ) : (
                        resultingGroups.map((g) => (
                          <Badge
                            key={g}
                            variant={unboundResulting.includes(g) ? "outline" : "secondary"}
                            className={
                              unboundResulting.includes(g)
                                ? "border-amber-500/40 text-amber-600 dark:text-amber-400"
                                : ""
                            }
                          >
                            {g}
                          </Badge>
                        ))
                      )}
                    </div>
                  ) : null}
                  {unboundResulting.length > 0 ? (
                    <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                      {unboundResulting.join(", ")} {unboundResulting.length === 1 ? "is" : "are"} not
                      a built-in group — members gain nothing until an operator widens the impersonator
                      ClusterRole.
                    </p>
                  ) : null}
                </div>
              ),
            },
          ]}
        />
      ),
    },
  ];

  return (
    <Wizard
      title="Create user"
      steps={steps}
      activeStepIndex={step}
      onNavigate={setStep}
      onValidateStep={validateStep}
      onCancel={() => navigate({ to: "/users" })}
      onSubmit={handleSubmit}
      submitLabel="Create user"
      submitting={create.isPending}
      error={create.error}
    />
  );
}

/** A selectable radio card for a permission option (AWS's "Set permissions" cards). */
function PermCard({
  checked,
  onSelect,
  icon,
  title,
  hint,
  disabled = false,
  children,
}: {
  checked: boolean;
  onSelect: () => void;
  icon: React.ReactNode;
  title: string;
  hint: string;
  disabled?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-md border p-3 transition-colors",
        disabled
          ? "border-border opacity-70"
          : checked
            ? "border-primary bg-secondary"
            : "border-border hover:bg-secondary/50",
      )}
    >
      <label className={cn("flex items-start gap-3", disabled ? "cursor-not-allowed" : "cursor-pointer")}>
        <input
          type="radio"
          name="perm-mode"
          checked={checked}
          onChange={onSelect}
          disabled={disabled}
          className="mt-1"
        />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5 text-sm font-medium">
            {icon}
            {title}
          </span>
          <span className="block text-xs text-muted-foreground">{hint}</span>
        </span>
      </label>
      {children ? <div className="pl-7">{children}</div> : null}
    </div>
  );
}
