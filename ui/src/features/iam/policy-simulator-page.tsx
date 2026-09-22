import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FlaskConical, Play } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ErrorState, LoadingState } from "@/components/common/states";
import { InfoLink } from "@/components/help/info-link";
import { getIamConfig, simulatePolicy, type DraftPolicyInput, type SimulateRequest } from "@/lib/api";
import { CEDAR_CONDITION_KEYS } from "@/lib/iam-cedar-vocab";
import { PrincipalPicker, type PrincipalValue } from "./simulator/principal-picker";
import { ActionPicker } from "./simulator/action-picker";
import { ResultTable } from "./simulator/result-table";

/**
 * Policy Simulator (the open-infra analog of AWS's IAM Policy Simulator). Pick a principal, one or more
 * actions (control-plane "<resource>:<verb>" and/or data-plane "s3:GetObject"), and an optional resource +
 * request context; "Run simulation" asks the BFF "Allow or Deny under the CURRENT policies?" using the
 * REAL enforcement paths (an impersonated SubjectAccessReview for the control plane, and the same Cedar
 * engine the aws-shim enforces spec.dataPlane with for the data plane). Nothing is performed. The per-action
 * verdicts, plus the honest warnings/limitations the response carries, render below.
 */
export function PolicySimulatorPage() {
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });

  const [mode, setMode] = useState<"principal" | "custom">("principal");
  const [principal, setPrincipal] = useState<PrincipalValue>({ type: "User", name: "" });
  const [actions, setActions] = useState<string[]>([]);
  const [resource, setResource] = useState("");
  const [namespace, setNamespace] = useState("");
  const [ctx, setCtx] = useState<Record<string, string>>({});
  const [draftText, setDraftText] = useState("");
  const [attempted, setAttempted] = useState(false);

  const sim = useMutation({
    mutationFn: (req: SimulateRequest) => simulatePolicy(req),
  });

  // Custom mode: parse the pasted draft. Accepts a full policy doc ({dataPlane:{…}}), a data-plane block
  // ({appliesTo,statements}), or a bare statements array — so the AWS-import "Copy dataPlane JSON" output
  // pastes straight in.
  const draft = useMemo<{ value: DraftPolicyInput | null; error: string | null }>(() => {
    if (mode !== "custom" || !draftText.trim()) return { value: null, error: null };
    try {
      let block: unknown = JSON.parse(draftText);
      if (block && typeof block === "object" && !Array.isArray(block) && "dataPlane" in block) {
        block = (block as { dataPlane: unknown }).dataPlane;
      }
      if (Array.isArray(block)) block = { statements: block };
      const b = block as { appliesTo?: string[]; statements?: unknown } | null;
      if (!b || typeof b !== "object" || !Array.isArray(b.statements)) {
        throw new Error("Expected a data-plane block with a statements array (or a bare statements array).");
      }
      return { value: { appliesTo: b.appliesTo, statements: b.statements as DraftPolicyInput["statements"] }, error: null };
    } catch (e) {
      return { value: null, error: (e as Error).message };
    }
  }, [mode, draftText]);

  const principalOk = principal.name.trim().length > 0;
  const actionsOk = actions.length > 0;
  const inputsOk = actionsOk && (mode === "custom" ? Boolean(draft.value) : principalOk);

  const buildContext = (): Record<string, unknown> | undefined => {
    const out: Record<string, unknown> = {};
    for (const k of CEDAR_CONDITION_KEYS) {
      const v = ctx[k.key];
      if (!v) continue;
      out[k.key] = k.type === "boolean" ? v === "true" : v;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  };

  const run = () => {
    setAttempted(true);
    if (!inputsOk) return;
    const base = {
      actions,
      resource: resource.trim() || undefined,
      namespace: namespace.trim() || undefined,
      context: buildContext(),
    };
    if (mode === "custom") {
      sim.mutate({
        ...base,
        principal: principal.name.trim() ? `${principal.type}::${principal.name}` : undefined,
        draft: draft.value ?? undefined,
      });
    } else {
      sim.mutate({ ...base, principal: `${principal.type}::${principal.name}` });
    }
  };

  const runButton = (
    <Button onClick={run} disabled={sim.isPending}>
      <Play className="size-4" /> Run simulation
    </Button>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<FlaskConical />}
        title="Policy Simulator"
        description="Test whether a principal is allowed an action under the current policies — without performing it. Evaluated against the real enforcement paths, across both the control and data planes."
        actions={runButton}
      />

      {cfg.isLoading ? (
        <LoadingState label="Loading policy vocabulary…" />
      ) : cfg.isError ? (
        <ErrorState error={cfg.error} onRetry={() => void cfg.refetch()} />
      ) : (
        <>
          {/* Mode: evaluate the current stored policies (Principal), or a pasted not-yet-attached draft
              (Custom — AWS's "Custom" simulator mode). */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex overflow-hidden rounded-md border border-border text-xs">
              {(
                [
                  ["principal", "Principal — stored policies"],
                  ["custom", "Custom — a draft policy"],
                ] as const
              ).map(([m, label]) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMode(m)}
                  className={[
                    "px-3 py-1.5 font-medium transition-colors",
                    mode === m ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-muted",
                  ].join(" ")}
                >
                  {label}
                </button>
              ))}
            </div>
            <span className="text-[11px] text-muted-foreground">
              {mode === "custom"
                ? "Simulate a not-yet-attached draft policy's data plane before you attach it."
                : "Evaluate the principal's current, attached policies."}
            </span>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Left — the principal (or draft) + the request context. */}
            <div className="space-y-6">
              {mode === "principal" ? (
                <Card>
                  <CardContent className="space-y-3 p-4">
                    <h3 className="flex items-center gap-2 text-sm font-semibold">
                      Principal
                      <InfoLink
                        title="Principal"
                        body={
                          <>
                            <p>
                              The identity to evaluate. The control plane is checked as this principal via an
                              impersonated SubjectAccessReview — exactly what the API server would decide for a
                              real request. Data-plane policies are matched by their <code>appliesTo</code>.
                            </p>
                            <p>
                              A Group evaluates the access its ClusterRole binding confers; a Role evaluates the
                              union of its policies.
                            </p>
                          </>
                        }
                      />
                    </h3>
                    <PrincipalPicker value={principal} onChange={setPrincipal} invalid={attempted} />
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="space-y-3 p-4">
                    <h3 className="flex items-center gap-2 text-sm font-semibold">
                      Draft policy
                      <InfoLink
                        title="Draft policy (custom mode)"
                        body={
                          <>
                            <p>
                              Paste a not-yet-attached policy's <strong>data plane</strong> and simulate it
                              directly — "what would this policy decide?" — before attaching it. Accepts a full
                              document (<code>{"{ dataPlane: { … } }"}</code>), a data-plane block (
                              <code>{"{ appliesTo, statements }"}</code>), or a bare statements array — so the
                              "Copy dataPlane JSON" output from Import policy pastes straight in.
                            </p>
                            <p>
                              Only the data plane is simulated in custom mode; control-plane actions are RBAC /
                              Phase-2 shadow and must be attached to test.
                            </p>
                          </>
                        }
                      />
                    </h3>
                    <textarea
                      className="h-48 w-full resize-y rounded-md border border-border bg-background p-2.5 font-mono text-xs outline-none focus:ring-2 focus:ring-ring"
                      placeholder={'{\n  "appliesTo": ["*"],\n  "statements": [\n    { "effect": "Allow", "actions": ["s3:GetObject"], "resources": ["Bucket::assets"] }\n  ]\n}'}
                      value={draftText}
                      onChange={(e) => setDraftText(e.target.value)}
                      spellCheck={false}
                    />
                    {draft.error ? (
                      <p className="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
                        {draft.error}
                      </p>
                    ) : null}
                    <div className="space-y-1.5">
                      <Label>Principal (optional)</Label>
                      <PrincipalPicker value={principal} onChange={setPrincipal} invalid={false} />
                      <p className="text-[11px] text-muted-foreground">
                        Only needed if the draft's <code>appliesTo</code> is scoped to a specific principal.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardContent className="space-y-4 p-4">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">
                    Simulation settings
                    <InfoLink
                      title="Resource & context"
                      body={
                        <>
                          <p>
                            The resource and request conditions are used by the <strong>data plane</strong>{" "}
                            (Cedar) only. A typed resource scopes a data-plane action, e.g.{" "}
                            <code>Bucket::assets</code>. Control-plane (RBAC) decisions do not use them —
                            Kubernetes RBAC has no per-resource-name or condition matching for list/watch.
                          </p>
                        </>
                      }
                    />
                  </h3>

                  <div className="space-y-1.5">
                    <Label htmlFor="sim-resource">Resource (optional)</Label>
                    <Input
                      id="sim-resource"
                      value={resource}
                      onChange={(e) => setResource(e.target.value)}
                      placeholder="Bucket::assets, Table::orders, Function::worker"
                    />
                    <p className="text-xs text-muted-foreground">
                      Typed data-plane resource. Leave blank to test service-wide access.
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="sim-namespace">Namespace (optional)</Label>
                    <Input
                      id="sim-namespace"
                      value={namespace}
                      onChange={(e) => setNamespace(e.target.value)}
                      placeholder={cfg.data?.namespace ?? "console namespace"}
                    />
                    <p className="text-xs text-muted-foreground">
                      Control-plane SAR namespace. Defaults to the console namespace.
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Request context (optional)</Label>
                    {CEDAR_CONDITION_KEYS.map((k) => (
                      <div key={k.key} className="space-y-1">
                        <div className="flex items-center gap-2">
                          <code className="w-28 shrink-0 text-xs text-muted-foreground">{k.key}</code>
                          {k.type === "boolean" ? (
                            <Select
                              value={ctx[k.key] ?? ""}
                              onValueChange={(v) =>
                                setCtx((c) => ({ ...c, [k.key]: v === "any" ? "" : v }))
                              }
                            >
                              <SelectTrigger className="h-8 w-40 text-xs">
                                <SelectValue placeholder="Any (unset)" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="any">Any (unset)</SelectItem>
                                <SelectItem value="true">true</SelectItem>
                                <SelectItem value="false">false</SelectItem>
                              </SelectContent>
                            </Select>
                          ) : (
                            <Input
                              value={ctx[k.key] ?? ""}
                              onChange={(e) => setCtx((c) => ({ ...c, [k.key]: e.target.value }))}
                              placeholder="10.0.0.1"
                              className="h-8 text-xs"
                            />
                          )}
                        </div>
                        <p className="pl-[7.5rem] text-[11px] text-muted-foreground">{k.description}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Right — the actions. */}
            <Card>
              <CardContent className="space-y-3 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  Actions
                  <InfoLink
                    title="Actions"
                    body={
                      <>
                        <p>
                          Pick a platform resource to test control-plane access (emits{" "}
                          <code>&lt;resource&gt;:&lt;verb&gt;</code>), or a data service (S3/DynamoDB/Lambda)
                          to test data-plane access (e.g. <code>s3:GetObject</code>). Selections accumulate
                          across services, so one run can span both planes.
                        </p>
                        <p>
                          Actions marked <span className="font-mono">≈</span> are recognized for authorization
                          but not yet fully implemented at the data layer.
                        </p>
                      </>
                    }
                  />
                </h3>
                <ActionPicker
                  policyResources={cfg.data?.policyResources ?? []}
                  policyVerbs={cfg.data?.policyVerbs ?? []}
                  selected={actions}
                  onChange={setActions}
                  invalid={attempted}
                />
              </CardContent>
            </Card>
          </div>

          {/* Results. */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Results</h2>
              {sim.data ? runButton : null}
            </div>

            {sim.isPending ? (
              <LoadingState label="Simulating…" />
            ) : sim.isError ? (
              <ErrorState error={sim.error} onRetry={run} />
            ) : sim.data ? (
              <ResultTable result={sim.data} />
            ) : (
              <Card>
                <CardContent className="py-12 text-center text-sm text-muted-foreground">
                  Choose a principal and one or more actions, then run the simulation to see per-action
                  Allow / Deny verdicts.
                </CardContent>
              </Card>
            )}
          </div>
        </>
      )}
    </div>
  );
}
