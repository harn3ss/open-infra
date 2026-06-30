import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation } from "@tanstack/react-query";
import { Bomb, Plus, Trash2 } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, k8sCreate, k8sDelete } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Condition,
  type FaultInjection,
  type FaultInjectionType,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

// type -> friendly label + which extra knobs to show in the form.
const TYPES: { value: FaultInjectionType; label: string; group: string }[] = [
  { value: "pod-kill", label: "Pod kill", group: "Pod" },
  { value: "pod-failure", label: "Pod failure (unavailable)", group: "Pod" },
  { value: "network-latency", label: "Network latency", group: "Network" },
  { value: "network-loss", label: "Network packet loss", group: "Network" },
  { value: "network-partition", label: "Network partition", group: "Network" },
  { value: "stress-cpu", label: "CPU stress", group: "Stress" },
  { value: "stress-memory", label: "Memory stress", group: "Stress" },
  { value: "clock-skew", label: "Clock skew", group: "Time" },
  { value: "io-latency", label: "Disk I/O latency", group: "IO" },
];
const TYPE_LABEL = Object.fromEntries(TYPES.map((t) => [t.value, t.label]));

function fiStatus(f: FaultInjection): { label: string; tone: StatusTone } {
  const ready = (f.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Active", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function targetSummary(f: FaultInjection): string {
  const t = f.spec?.target;
  if (!t) return "—";
  const sel = Object.entries(t.labelSelector ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(",");
  return `${t.namespace ?? f.metadata.namespace}/${sel || "*"}`;
}

export function ChaosPage() {
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const remove = useMutation({
    mutationFn: (f: FaultInjection) =>
      k8sDelete(openinfraPaths.faultinjection(f.metadata.namespace ?? "default", f.metadata.name ?? "")),
  });

  const columns = useMemo<ColumnDef<FaultInjection, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (f) => f.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 180,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (f) => f.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 110,
      },
      {
        id: "type",
        header: "Fault",
        accessorFn: (f) => f.spec?.type,
        cell: ({ row }) => <Badge variant="secondary">{TYPE_LABEL[row.original.spec?.type ?? ""] ?? row.original.spec?.type}</Badge>,
        size: 150,
      },
      {
        id: "target",
        header: "Target (blast radius)",
        accessorFn: (f) => targetSummary(f),
        cell: ({ row }) => <code className="text-xs">{targetSummary(row.original)}</code>,
        size: 220,
      },
      {
        id: "duration",
        header: "Duration",
        accessorFn: (f) => f.spec?.duration ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.spec?.type === "pod-kill" ? "instant" : row.original.spec?.duration ?? "60s"}
          </span>
        ),
        size: 90,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => fiStatus(f).label,
        cell: ({ row }) => {
          const s = fiStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (f) => f.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 70,
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onClick={() => remove.mutate(row.original)}
              disabled={remove.isPending}
              title="Delete this experiment"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 80,
      },
    ],
    [remove],
  );

  return (
    <>
      <ResourceTablePage<FaultInjection>
        icon={<Bomb />}
        title="Chaos"
        description="Fault injection — open-infra's Fault Injection Simulator (Chaos Mesh). Inject pod kills, network faults, resource stress, clock skew, or disk-IO latency to prove the platform's resilience. Every experiment is scoped to a namespace + label selector (blast radius enforced) and time-boxed."
        listPath={openinfraPaths.faultinjections}
        columns={columns}
        search={(f) => [f.metadata.name, f.metadata.namespace, f.spec?.type, targetSummary(f)]}
        singular="Fault Injection"
        plural="Fault Injections"
        emptyTitle="No experiments yet"
        emptyDescription="Run a fault injection scoped to a namespace + label selector."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Fault Injection
          </Button>
        }
      />
      <NewFaultInjectionDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}

function NewFaultInjectionDialog({
  open,
  onOpenChange,
  namespaces,
  defaultNamespace,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  namespaces: string[];
  defaultNamespace?: string;
}) {
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [type, setType] = useState<FaultInjectionType>("pod-kill");
  const [selKey, setSelKey] = useState("app");
  const [selVal, setSelVal] = useState("");
  const [mode, setMode] = useState<"one" | "all" | "fixed-percent">("one");
  const [value, setValue] = useState("50");
  const [duration, setDuration] = useState("60s");
  // type-specific
  const [latency, setLatency] = useState("200ms");
  const [loss, setLoss] = useState("50");
  const [direction, setDirection] = useState<"to" | "from" | "both">("to");
  const [cpuWorkers, setCpuWorkers] = useState("1");
  const [cpuLoad, setCpuLoad] = useState("80");
  const [memory, setMemory] = useState("256MB");
  const [timeOffset, setTimeOffset] = useState("+5m");
  const [volumePath, setVolumePath] = useState("/data");

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
    onSuccess: () => {
      setName("");
      setSelVal("");
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New Fault Injection</DialogTitle>
          <DialogDescription>
            Inject a fault into a scoped set of pods to test resilience. It only ever touches
            pods matching the label selector in the chosen namespace, for the duration below.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="fi-name">Name</Label>
            <Input id="fi-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="kill-pg-primary" autoFocus />
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

          {/* Blast radius */}
          <div className="col-span-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            Blast radius: this experiment only affects pods matching <code>{selKey || "key"}={selVal || "value"}</code> in
            namespace <code>{namespace}</code>.
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="fi-ns">Target namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="fi-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <Label htmlFor="fi-selk">Selector key</Label>
              <Input id="fi-selk" value={selKey} onChange={(e) => setSelKey(e.target.value)} placeholder="app" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fi-selv">Selector value</Label>
              <Input id="fi-selv" value={selVal} onChange={(e) => setSelVal(e.target.value)} placeholder="pg" />
            </div>
          </div>

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
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="fi-dur">Duration</Label>
              <Input id="fi-dur" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="60s" disabled={type === "pod-kill"} />
            </div>
          )}
          {mode === "fixed-percent" ? (
            <div className="space-y-1.5">
              <Label htmlFor="fi-dur2">Duration</Label>
              <Input id="fi-dur2" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="60s" disabled={type === "pod-kill"} />
            </div>
          ) : null}

          {/* type-specific knobs */}
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

        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the experiment."}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>Cancel</Button>
          <Button
            onClick={() => create.mutate()}
            disabled={create.isPending || !RFC1123.test(name) || !selKey || !selVal}
          >
            {create.isPending ? "Injecting…" : "Inject"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
