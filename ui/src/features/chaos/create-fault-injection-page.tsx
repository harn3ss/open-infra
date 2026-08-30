import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { Bomb } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState } from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { useConfig } from "@/lib/config-context";
import { k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type FaultInjectionType, type K8sObject } from "@/types/k8s";
import { TYPES } from "./chaos-page";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Single-page create for kind: FaultInjection (issue #96). Chaos is gated (NIST CM-7): the route
 * backstops the nav — if the deployment hasn't opted in, the tool isn't rendered even on a hand-typed URL.
 */
export function CreateFaultInjectionPage() {
  const config = useConfig();
  if (!config.chaosUiEnabled) {
    return (
      <EmptyState
        icon={<Bomb />}
        title="Chaos tooling is disabled"
        description="Fault injection is turned off on this deployment. An operator can enable it by setting CHAOS_UI_ENABLED=true on the console."
      />
    );
  }
  return <CreateFaultInjectionInner />;
}

function CreateFaultInjectionInner() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => nsWatch.items.map((n) => n.metadata.name).filter(Boolean).sort() as string[],
    [nsWatch.items],
  );

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [type, setType] = useState<FaultInjectionType>("pod-kill");
  const [selKey, setSelKey] = useState("app");
  const [selVal, setSelVal] = useState("");
  const [mode, setMode] = useState<"one" | "all" | "fixed-percent">("one");
  const [value, setValue] = useState("50");
  const [duration, setDuration] = useState("60s");
  const [latency, setLatency] = useState("200ms");
  const [loss, setLoss] = useState("50");
  const [direction, setDirection] = useState<"to" | "from" | "both">("to");
  const [cpuWorkers, setCpuWorkers] = useState("1");
  const [cpuLoad, setCpuLoad] = useState("80");
  const [memory, setMemory] = useState("256MB");
  const [timeOffset, setTimeOffset] = useState("+5m");
  const [volumePath, setVolumePath] = useState("/data");
  const [touched, setTouched] = useState(false);

  const isNet = type.startsWith("network");
  const create = useMutation({
    mutationFn: () => {
      const spec: Record<string, unknown> = {
        type,
        target: { namespace, labelSelector: { [selKey]: selVal } },
        mode,
        duration,
      };
      if (mode === "fixed-percent") spec.value = value;
      if (type === "network-latency" || type === "io-latency") spec.latency = latency;
      if (type === "network-loss") spec.loss = loss;
      if (isNet) spec.direction = direction;
      if (type === "stress-cpu") {
        spec.cpuWorkers = Number(cpuWorkers);
        spec.cpuLoad = Number(cpuLoad);
      }
      if (type === "stress-memory") spec.memory = memory;
      if (type === "clock-skew") spec.timeOffset = timeOffset;
      if (type === "io-latency") spec.volumePath = volumePath;
      return k8sCreate(openinfraPaths.faultinjections(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "FaultInjection",
        metadata: { name, namespace },
        spec,
      } as K8sObject);
    },
    onSuccess: () => navigate({ to: "/chaos" }),
  });

  const nameOk = RFC1123.test(name);
  const valid = nameOk && Boolean(selKey) && Boolean(selVal);
  const submit = () => {
    setTouched(true);
    if (!valid) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Bomb className="size-6 text-primary" />}
      title="Create Fault Injection"
      description="Inject a fault into a scoped set of pods to test resilience. It only ever touches pods matching the label selector in the chosen namespace, for the duration below."
      onCancel={() => navigate({ to: "/chaos" })}
      onSubmit={submit}
      submitLabel="Inject fault"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || selVal.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Experiment</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="fi-name">Name</Label>
            <Input id="fi-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="kill-pg-primary" autoFocus />
            {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, numbers and hyphens.</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fi-type">Fault</Label>
            <Select value={type} onValueChange={(v) => setType(v as FaultInjectionType)}>
              <SelectTrigger id="fi-type"><SelectValue /></SelectTrigger>
              <SelectContent>
                {TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Target (blast radius)</h3>
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          This experiment only affects pods matching <code>{selKey || "key"}={selVal || "value"}</code> in namespace <code>{namespace}</code>.
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="fi-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="fi-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fi-selk">Selector key</Label>
            <Input id="fi-selk" value={selKey} onChange={(e) => setSelKey(e.target.value)} placeholder="app" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fi-selv">Selector value</Label>
            <Input id="fi-selv" value={selVal} onChange={(e) => setSelVal(e.target.value)} placeholder="pg" />
            {touched && !selVal ? <p className="text-xs text-destructive">Required.</p> : null}
          </div>
        </div>
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Behavior</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="fi-mode">Mode</Label>
            <Select value={mode} onValueChange={(v) => setMode(v as "one" | "all" | "fixed-percent")}>
              <SelectTrigger id="fi-mode"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="one">one (a single pod)</SelectItem>
                <SelectItem value="all">all matching pods</SelectItem>
                <SelectItem value="fixed-percent">a percentage</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {mode === "fixed-percent" ? (
            <div className="space-y-1.5">
              <Label htmlFor="fi-value">Percent</Label>
              <Input id="fi-value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="50" />
            </div>
          ) : null}
          <div className="space-y-1.5">
            <Label htmlFor="fi-dur">Duration</Label>
            <Input id="fi-dur" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="60s" disabled={type === "pod-kill"} />
          </div>
          {(type === "network-latency" || type === "io-latency") && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-lat">Latency</Label>
              <Input id="fi-lat" value={latency} onChange={(e) => setLatency(e.target.value)} placeholder="200ms" />
            </div>
          )}
          {type === "network-loss" && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-loss">Loss %</Label>
              <Input id="fi-loss" value={loss} onChange={(e) => setLoss(e.target.value)} placeholder="50" />
            </div>
          )}
          {isNet && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-dir">Direction</Label>
              <Select value={direction} onValueChange={(v) => setDirection(v as "to" | "from" | "both")}>
                <SelectTrigger id="fi-dir"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="to">to</SelectItem>
                  <SelectItem value="from">from</SelectItem>
                  <SelectItem value="both">both</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
          {type === "stress-cpu" && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="fi-cw">CPU workers</Label>
                <Input id="fi-cw" value={cpuWorkers} onChange={(e) => setCpuWorkers(e.target.value)} placeholder="1" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="fi-cl">CPU load %</Label>
                <Input id="fi-cl" value={cpuLoad} onChange={(e) => setCpuLoad(e.target.value)} placeholder="80" />
              </div>
            </>
          )}
          {type === "stress-memory" && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-mem">Memory</Label>
              <Input id="fi-mem" value={memory} onChange={(e) => setMemory(e.target.value)} placeholder="256MB" />
            </div>
          )}
          {type === "clock-skew" && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-off">Time offset</Label>
              <Input id="fi-off" value={timeOffset} onChange={(e) => setTimeOffset(e.target.value)} placeholder="+5m or -1h" />
            </div>
          )}
          {type === "io-latency" && (
            <div className="space-y-1.5">
              <Label htmlFor="fi-vol">Volume path</Label>
              <Input id="fi-vol" value={volumePath} onChange={(e) => setVolumePath(e.target.value)} placeholder="/data" />
            </div>
          )}
        </div>
      </div>
    </CreateShell>
  );
}
