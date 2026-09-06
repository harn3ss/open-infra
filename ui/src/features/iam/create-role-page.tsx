import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check } from "lucide-react";
import { Wizard, WizardReview, type WizardStep } from "@/components/create/wizard";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { createIamRole, listIamPolicies, listIamUsers } from "@/lib/api";
import { TrustEditor, principalLabel } from "./trust-editor";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Create kind: Role as an AWS-style stepped wizard: Select trusted entity → Add permissions →
 * Name, review, and create. A role starts assumable by no one until a trusted entity is named
 * (fail closed), and grants nothing until a Group points at its ClusterRole.
 */
export function CreateRolePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });

  const [step, setStep] = useState(0);
  const [trust, setTrust] = useState<string[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () => createIamRole({ name, description, policies: selected, trust }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "roles"] });
      navigate({ to: "/roles/$name", params: { name } });
    },
  });

  const toggle = (p: string) =>
    setSelected(selected.includes(p) ? selected.filter((x) => x !== p) : [...selected, p]);
  const nameOk = RFC1123.test(name);

  const submit = () => {
    setTouched(true);
    if (!nameOk) {
      setStep(2);
      return;
    }
    create.mutate();
  };

  const steps: WizardStep[] = [
    {
      title: "Select trusted entity",
      description: "Choose who may assume this role. Leave empty to fail closed (assumable by no one).",
      info: {
        title: "Trusted entities",
        body: (
          <p>
            The trust policy names the principals allowed to <code>sts:AssumeRole</code> this role — a
            kind: User, a workload ServiceAccount (web identity), or any authenticated principal
            (<code>*</code>). The aws-shim enforces it. A role with an empty trust policy cannot be
            assumed by anyone.
          </p>
        ),
      },
      content: (
        <TrustEditor value={trust} onChange={setTrust} users={(users.data ?? []).map((u) => u.name)} />
      ),
    },
    {
      title: "Add permissions",
      description: "Attach the policies this role aggregates. The role grants their union.",
      isOptional: true,
      content:
        policies.data && policies.data.length > 0 ? (
          <div className="space-y-2">
            <Label>Attached policies</Label>
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
                      on
                        ? "border-primary/40 bg-primary/15 text-primary"
                        : "border-border text-muted-foreground hover:bg-muted",
                    ].join(" ")}
                  >
                    {on ? <Check className="size-3" /> : null}
                    {p.name}
                  </button>
                );
              })}
            </div>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No policies yet — you can create a Policy first, then attach it here or from the role later.
          </p>
        ),
    },
    {
      title: "Name, review, and create",
      content: (
        <div className="space-y-5">
          <div className="space-y-1.5">
            <Label htmlFor="r-name">Role name</Label>
            <Input
              id="r-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="vm-operator"
              autoFocus
            />
            {touched && !nameOk ? (
              <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="r-desc">Description - optional</Label>
            <Input
              id="r-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Operate VMs and their storage"
            />
          </div>

          <WizardReview
            onEditStep={setStep}
            sections={[
              {
                title: "Trusted entity",
                stepIndex: 0,
                content:
                  trust.length === 0 ? (
                    <p className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                      <AlertTriangle className="size-3.5" /> No trusted entities — the role will be
                      assumable by no one until you add some.
                    </p>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {trust.map((p) => (
                        <Badge
                          key={p}
                          variant={p === "*" ? "outline" : "secondary"}
                          className={p === "*" ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : ""}
                        >
                          {principalLabel(p)}
                        </Badge>
                      ))}
                    </div>
                  ),
              },
              {
                title: "Permissions",
                stepIndex: 1,
                content:
                  selected.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No policies attached.</p>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {selected.map((p) => (
                        <Badge key={p} variant="secondary">
                          {p}
                        </Badge>
                      ))}
                    </div>
                  ),
              },
            ]}
          />
        </div>
      ),
    },
  ];

  return (
    <Wizard
      title="Create role"
      steps={steps}
      activeStepIndex={step}
      onNavigate={setStep}
      onCancel={() => navigate({ to: "/roles" })}
      onSubmit={submit}
      submitLabel="Create role"
      submitting={create.isPending}
      error={create.error}
    />
  );
}
