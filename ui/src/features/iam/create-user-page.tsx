import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, FileText, Info, Plus, UsersRound, X } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { useFlash } from "@/components/common/flashbar";
import {
  createIamUser,
  getIamConfig,
  listIamGroups,
  listIamPolicies,
  listIamUsers,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { GroupPicker } from "./group-picker";
import { AttachPolicyPicker, ManagedBadge } from "./attach-policy-picker";
import { policyType } from "./policy-type";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

type PermMode = "group" | "copy" | "direct";

/**
 * Create user — the AWS multi-step wizard: Specify user details → Set permissions → Review and
 * create. Written on the shared Wizard (left step nav + Review step). The permission step mirrors
 * AWS's three options as radio cards. "Attach policies directly" is enabled with honest plane
 * framing: attaching a Policy to the user (spec.policies) grants that policy's DATA-plane access
 * (S3 / DynamoDB / Lambda via the aws-shim, §3), while CONTROL-plane authority (console / kubectl)
 * takes effect only through group membership. Creates via the SAR-gated BFF (`POST /api/iam/users`),
 * which stores the password as a bcrypt hash.
 */
export function CreateUserPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const flash = useFlash();

  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const groupsQ = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const usersQ = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const policiesQ = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const builtins = cfg.data?.builtinGroups ?? [];

  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [permMode, setPermMode] = useState<PermMode>("group");
  const [selected, setSelected] = useState<string[]>([]);
  const [copyFrom, setCopyFrom] = useState<string>("");
  // Policies attached directly to the user (spec.policies) when permMode === "direct" — the AWS
  // "Attach policies directly" set. Grants the user's data-plane authority; see the card note.
  const [directPolicies, setDirectPolicies] = useState<string[]>([]);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const policyByName = useMemo(
    () => new Map((policiesQ.data ?? []).map((p) => [p.name, p])),
    [policiesQ.data],
  );

  const copySource = useMemo(
    () => (usersQ.data ?? []).find((u) => u.name === copyFrom),
    [usersQ.data, copyFrom],
  );

  // The groups this user will actually be created with, per the chosen permission mode.
  const resultingGroups = useMemo<string[]>(() => {
    if (permMode === "group") return selected;
    if (permMode === "copy") return copySource?.groups ?? [];
    return []; // "direct" attaches nothing on the control plane — access comes via spec.policies.
  }, [permMode, selected, copySource]);

  const unboundResulting = resultingGroups.filter((g) => !builtins.includes(g));

  const create = useMutation({
    mutationFn: () =>
      // Direct mode grants the data plane via spec.policies (no groups); group/copy mode grants
      // the control plane via group membership (no direct policies).
      createIamUser(
        permMode === "direct"
          ? { name, displayName, groups: [], policies: directPolicies, password }
          : { name, displayName, groups: resultingGroups, policies: [], password },
      ),
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
      description:
        "Choose how this user gets its access. Group membership grants control-plane (console / kubectl) access; attaching policies directly grants data-plane access.",
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
            icon={<FileText className="size-4" />}
            title="Attach policies directly"
            hint="Grant policies' data-plane access directly to this user."
          >
            {permMode === "direct" ? (
              <div className="space-y-3 pt-1">
                <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
                  <Info className="mt-0.5 size-4 shrink-0" />
                  <span>
                    Attaching a policy to the user directly grants that policy's{" "}
                    <b className="text-foreground">data-plane</b> permissions (object storage, tables,
                    functions) to this user. A policy's{" "}
                    <b className="text-foreground">control-plane</b> permissions (console / kubectl)
                    take effect only through group membership — so for console access, also add this
                    user to a group (you can do both from the user's page after creating).
                  </span>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-muted-foreground">
                    {directPolicies.length === 0
                      ? "No policies attached."
                      : `${directPolicies.length} ${
                          directPolicies.length === 1 ? "policy" : "policies"
                        } attached.`}
                  </span>
                  <Button
                    variant="outline"
                    className="shrink-0"
                    onClick={() => setPickerOpen(true)}
                  >
                    <Plus className="size-4" /> Add permissions
                  </Button>
                </div>

                {directPolicies.length > 0 ? (
                  <ul className="divide-y divide-border rounded-md border border-border">
                    {directPolicies.map((nm) => {
                      const p = policyByName.get(nm);
                      return (
                        <li key={nm} className="flex items-center justify-between gap-3 p-3">
                          <div className="flex min-w-0 flex-wrap items-center gap-2">
                            <span className="font-medium text-foreground">{nm}</span>
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
                            onClick={() =>
                              setDirectPolicies((cur) => cur.filter((x) => x !== nm))
                            }
                            className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-destructive"
                            aria-label={`Detach ${nm}`}
                          >
                            <X className="size-4" />
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                ) : null}
              </div>
            ) : null}
          </PermCard>

          {permMode !== "direct" && resultingGroups.length === 0 ? (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                No groups selected. This user will be able to sign in but is authorized for nothing.
              </span>
            </div>
          ) : null}

          {permMode === "direct" && directPolicies.length === 0 ? (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                No policies attached. This user will be able to sign in but is authorized for nothing.
                Attach a policy for data-plane access, or add the user to a group for console access.
              </span>
            </div>
          ) : null}

          <AttachPolicyPicker
            open={pickerOpen}
            onOpenChange={setPickerOpen}
            policies={policiesQ.data ?? []}
            attached={directPolicies}
            onConfirm={setDirectPolicies}
            subjectLabel={name ? `user ${name}` : "this user"}
          />
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
                      ? "Added to groups (control plane):"
                      : permMode === "copy"
                        ? `Copied groups from ${copyFrom || "—"} (control plane):`
                        : "Policies attached directly (data plane):"}
                  </p>
                  {permMode === "direct" ? (
                    <div className="flex flex-wrap gap-1">
                      {directPolicies.length === 0 ? (
                        <span className="text-amber-600 dark:text-amber-400">
                          none — authorized for nothing
                        </span>
                      ) : (
                        directPolicies.map((p) => (
                          <Badge key={p} variant="secondary">
                            {p}
                          </Badge>
                        ))
                      )}
                    </div>
                  ) : (
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
                  )}
                  {permMode === "direct" && directPolicies.length > 0 ? (
                    <p className="text-xs text-muted-foreground">
                      Grants data-plane access only. For console / kubectl access, add this user to a
                      group from its page after creating.
                    </p>
                  ) : null}
                  {permMode !== "direct" && unboundResulting.length > 0 ? (
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
