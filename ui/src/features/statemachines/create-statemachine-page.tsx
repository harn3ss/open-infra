import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Route } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

const STARTER = `{
  "Comment": "A minimal workflow: call a Function, then succeed.",
  "StartAt": "DoWork",
  "States": {
    "DoWork": {
      "Type": "Task",
      "Resource": "function:my-function",
      "Retry": [
        { "ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 3, "IntervalSeconds": 2, "BackoffRate": 2 }
      ],
      "Next": "Done"
    },
    "Done": { "Type": "Succeed" }
  }
}`;

/** Validate the ASL enough to catch the common mistakes before submit (the engine
 *  does the full validation server-side). Returns an error string, or "". */
function validateAsl(text: string): string {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return "Definition is not valid JSON: " + (e instanceof Error ? e.message : String(e));
  }
  if (typeof doc !== "object" || doc === null) return "Definition must be a JSON object.";
  const d = doc as Record<string, unknown>;
  if (typeof d.StartAt !== "string" || !d.StartAt) return 'Definition needs a top-level "StartAt".';
  if (typeof d.States !== "object" || d.States === null) return 'Definition needs a "States" object.';
  if (!(d.StartAt in (d.States as Record<string, unknown>)))
    return `StartAt "${d.StartAt}" is not one of the States.`;
  return "";
}

/**
 * Single-page create for kind: StateMachine (issue #96, AWS Step Functions parity). The
 * definition is an Amazon States Language document — the same JSON you would put in
 * aws_sfn_state_machine.definition — so this is a code editor, not a schema form.
 */
export function CreateStateMachinePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { scoped } = useNamespace();
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => nsWatch.items.map((n) => n.metadata.name).filter(Boolean).sort() as string[],
    [nsWatch.items],
  );

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [definition, setDefinition] = useState(STARTER);
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () =>
      k8sCreate<K8sObject>(openinfraPaths.statemachines(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "StateMachine",
        metadata: { name, namespace },
        spec: { definition, type: "Standard" },
      } as K8sObject),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.statemachines()) });
      navigate({ to: "/statemachines/$namespace/$name", params: { namespace, name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const aslError = validateAsl(definition);
  const submit = () => {
    setTouched(true);
    if (!nameOk || aslError) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Route className="size-6 text-primary" />}
      title="Create State Machine"
      description="Define a workflow in Amazon States Language (ASL). Task states invoke a Function via `function:<name>`; add Choice, Wait, Retry and Catch for branching and error handling. Start runs from the state machine's page once created."
      onCancel={() => navigate({ to: "/statemachines" })}
      onSubmit={submit}
      submitLabel="Create State Machine"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || definition !== STARTER}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">State machine</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="sm-name">Name</Label>
            <Input id="sm-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="order-workflow" autoFocus />
            {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, numbers and hyphens; must start/end alphanumeric.</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sm-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="sm-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="space-y-3 rounded-lg border border-border p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">Definition (Amazon States Language)</h3>
          <Button variant="outline" size="sm" onClick={() => setDefinition(STARTER)}>Reset to template</Button>
        </div>
        <textarea
          value={definition}
          onChange={(e) => setDefinition(e.target.value)}
          onBlur={() => setTouched(true)}
          spellCheck={false}
          className="min-h-[360px] w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
          aria-label="Amazon States Language definition"
        />
        {touched && aslError ? (
          <p className="text-xs text-destructive">{aslError}</p>
        ) : (
          <p className="text-xs text-muted-foreground">
            v1 supports Task, Choice, Wait, Pass, Succeed and Fail (with Retry/Catch, TimeoutSeconds and
            JSONPath shaping). Parallel, Map and Express are not yet available.
          </p>
        )}
      </div>
    </CreateShell>
  );
}
