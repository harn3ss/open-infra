import { useMemo } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Cpu,
  GitBranch,
  Clock,
  Split,
  Repeat,
  SkipForward,
  CircleCheck,
  CircleX,
  CircleDot,
  Flag,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { EmptyState } from "@/components/common/states";

/**
 * A read-only visual graph of an Amazon States Language (ASL) workflow — the
 * open-infra equivalent of the AWS Step Functions definition/execution graph.
 *
 * Two modes:
 *  - definition graph (no `statusByState`): each state coloured by its type role.
 *  - execution graph (`statusByState` provided): each state coloured by outcome
 *    (green succeeded / red failed / pulsing-blue running / grey pending).
 *
 * Layout is a dependency-free top-to-bottom layered DAG (longest-path ranks). It
 * reuses the custom-node + accent-rail visual grammar from the networking
 * Resource Map and the DataFlow canvas. React Flow paints inline SVG/styles, so
 * colours are inline hex (not Tailwind classes), matching those components.
 */

// ── status ───────────────────────────────────────────────────────────────────
export type StateStatus = "succeeded" | "failed" | "running" | "pending";

const STATUS_META: Record<StateStatus, { color: string; label: string }> = {
  succeeded: { color: "#10b981", label: "Succeeded" }, // emerald
  failed: { color: "#ef4444", label: "Failed" }, // red
  running: { color: "#3b82f6", label: "Running" }, // blue (pulses)
  pending: { color: "#94a3b8", label: "Not run" }, // slate
};

/**
 * Derive a per-state status map from an Execution's `status.history` +
 * `status.currentState` + `status.phase`. The ASL engine records these event
 * types (see statemachine/engine.go): StateEntered, ExecutionSucceeded,
 * ExecutionFailed, TaskFailed, TaskRetry, TaskCaught — each carrying a `state`
 * (except ExecutionSucceeded).
 *
 * A state that was entered and then transitioned onward (a later StateEntered)
 * succeeded; the state named by ExecutionFailed failed; a TaskFailed marks a
 * failed attempt (a following TaskRetry/StateEntered rewinds it to running/
 * succeeded, so a caught-but-not-retried error stays red like AWS shows it).
 */
export function deriveStateStatus(
  history: ReadonlyArray<Record<string, unknown>> | undefined,
  currentState: string | undefined,
  phase: string | undefined,
): Record<string, StateStatus> {
  const status: Record<string, StateStatus> = {};
  let last: string | undefined;

  for (const ev of history ?? []) {
    const type = String(ev.type ?? "");
    const state = ev.state ? String(ev.state) : "";
    if (type === "StateEntered" && state) {
      // The previously-entered state completed by transitioning here.
      if (last && last !== state && status[last] === "running") status[last] = "succeeded";
      status[state] = "running";
      last = state;
    } else if (type === "ExecutionSucceeded") {
      for (const k of Object.keys(status)) if (status[k] === "running") status[k] = "succeeded";
      last = undefined;
    } else if (type === "ExecutionFailed" && state) {
      for (const k of Object.keys(status)) if (status[k] === "running" && k !== state) status[k] = "succeeded";
      status[state] = "failed";
      last = undefined;
    } else if (type === "TaskFailed" && state) {
      // A task attempt failed; a later TaskRetry/StateEntered undoes this.
      status[state] = "failed";
    } else if (type === "TaskRetry" && state) {
      status[state] = "running";
    }
  }

  // Reconcile with the terminal phase / live current state.
  if (phase === "Succeeded") {
    for (const k of Object.keys(status)) if (status[k] === "running") status[k] = "succeeded";
  } else if (phase === "Failed" || phase === "TimedOut" || phase === "Aborted") {
    const target = currentState || last;
    if (target && status[target] !== "succeeded") status[target] = "failed";
  } else {
    // Running or unknown — the current state is actively executing.
    if (currentState) {
      if (last && last !== currentState && status[last] === "running") status[last] = "succeeded";
      status[currentState] = "running";
    }
  }
  return status;
}

// ── state-type visual grammar ──────────────────────────────────────────────────
type StateRole =
  | "Task"
  | "Choice"
  | "Wait"
  | "Parallel"
  | "Map"
  | "Pass"
  | "Succeed"
  | "Fail"
  | "Start"
  | "End"
  | "Unknown";

const ROLE_META: Record<StateRole, { label: string; icon: LucideIcon; accent: string }> = {
  Task: { label: "Task", icon: Cpu, accent: "#3b82f6" },
  Choice: { label: "Choice", icon: GitBranch, accent: "#f59e0b" },
  Wait: { label: "Wait", icon: Clock, accent: "#8b5cf6" },
  Parallel: { label: "Parallel", icon: Split, accent: "#0ea5e9" },
  Map: { label: "Map", icon: Repeat, accent: "#14b8a6" },
  Pass: { label: "Pass", icon: SkipForward, accent: "#64748b" },
  Succeed: { label: "Succeed", icon: CircleCheck, accent: "#10b981" },
  Fail: { label: "Fail", icon: CircleX, accent: "#ef4444" },
  Start: { label: "Start", icon: CircleDot, accent: "#6366f1" },
  End: { label: "End", icon: Flag, accent: "#64748b" },
  Unknown: { label: "State", icon: Workflow, accent: "#94a3b8" },
};

function asRole(type: unknown): StateRole {
  const t = String(type ?? "");
  return (["Task", "Choice", "Wait", "Parallel", "Map", "Pass", "Succeed", "Fail"] as StateRole[]).includes(
    t as StateRole,
  )
    ? (t as StateRole)
    : "Unknown";
}

// ── the raw ASL shapes we read (untrusted JSON — everything optional) ───────────
interface RawState {
  Type?: string;
  Comment?: string;
  Next?: string;
  End?: boolean;
  Resource?: string;
  Default?: string;
  Choices?: Array<Record<string, unknown>>;
  Catch?: Array<{ ErrorEquals?: string[]; Next?: string }>;
  Branches?: Array<{ StartAt?: string; States?: Record<string, RawState> }>;
  Iterator?: { StartAt?: string; States?: Record<string, RawState> };
  ItemProcessor?: { StartAt?: string; States?: Record<string, RawState> };
  Seconds?: number;
}
interface RawDefinition {
  Comment?: string;
  StartAt?: string;
  States?: Record<string, RawState>;
}

interface GraphNodeData extends Record<string, unknown> {
  role: StateRole;
  /** Display name (the ASL key). */
  name: string;
  /** The ASL state key used to look up execution status (top-level states only). */
  stateName?: string;
  subtitle: string;
  /** Resolved execution status (execution mode only); undefined = definition mode. */
  status?: StateStatus;
}

type EdgeKind = "next" | "choice" | "default" | "catch" | "branch";
const EDGE_STYLE: Record<EdgeKind, { color: string; dash?: string }> = {
  next: { color: "#94a3b8" }, // solid slate — normal transition
  choice: { color: "#f59e0b" }, // amber — a matched Choice rule
  default: { color: "#f59e0b", dash: "6 4" }, // amber dashed — Choice Default
  catch: { color: "#ef4444", dash: "6 4" }, // red dashed — error catch
  branch: { color: "#0ea5e9", dash: "4 4" }, // sky dashed — Parallel/Map fan-out
};

function edge(source: string, target: string, kind: EdgeKind, label?: string): Edge<Record<string, unknown>> {
  const st = EDGE_STYLE[kind];
  return {
    id: `e:${source}->${target}:${kind}:${label ?? ""}`,
    source,
    target,
    label,
    type: "smoothstep",
    animated: false,
    data: { kind },
    style: { stroke: st.color, strokeWidth: 1.6, strokeDasharray: st.dash ?? "none" },
    labelBgStyle: { fill: "var(--card)", fillOpacity: 0.85 },
    labelStyle: { fontSize: 10, fill: st.color },
    markerEnd: undefined,
  };
}

/** A one-line human label for a Choice rule (best-effort; ASL rules are open-ended). */
function choiceLabel(rule: Record<string, unknown>, i: number): string {
  const variable = typeof rule.Variable === "string" ? rule.Variable : "";
  const op = Object.keys(rule).find(
    (k) => k !== "Variable" && k !== "Next" && k !== "Comment",
  );
  if (variable && op) {
    const raw = rule[op];
    const val = typeof raw === "object" ? "…" : String(raw);
    // Trim a long JSONPath to its leaf for legibility.
    const leaf = variable.replace(/^\$\.?/, "").split(".").pop() || variable;
    return `${leaf} ${humanOp(op)} ${val}`.slice(0, 40);
  }
  if (op) return op; // And / Or / Not composite
  return `rule ${i + 1}`;
}

function humanOp(op: string): string {
  const m: Record<string, string> = {
    StringEquals: "=",
    NumericEquals: "=",
    BooleanEquals: "=",
    NumericGreaterThan: ">",
    NumericGreaterThanEquals: "≥",
    NumericLessThan: "<",
    NumericLessThanEquals: "≤",
    StringGreaterThan: ">",
    StringLessThan: "<",
    IsPresent: "present?",
    IsNull: "null?",
  };
  return m[op] ?? op.replace(/^(String|Numeric|Boolean|Timestamp)/, "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
}

function subtitleFor(role: StateRole, s: RawState): string {
  if (role === "Task") return s.Resource || "task";
  if (role === "Wait") return s.Seconds != null ? `wait ${s.Seconds}s` : "wait";
  if (role === "Choice") return `${s.Choices?.length ?? 0} rule${(s.Choices?.length ?? 0) === 1 ? "" : "s"}`;
  if (role === "Parallel") return `${s.Branches?.length ?? 0} branches`;
  if (role === "Map") return "for each item";
  return ROLE_META[role].label;
}

interface BuiltGraph {
  nodes: Node<GraphNodeData>[];
  edges: Edge<Record<string, unknown>>[];
}

/** Add the `Next` (or `End: true` → synthetic End) transition for a state. */
function addSequential(
  out: BuiltGraph,
  id: string,
  prefix: string,
  s: RawState,
  endNodeId: string,
  usedEnd: { value: boolean },
): void {
  if (s.Next) {
    out.edges.push(edge(id, prefix + s.Next, "next"));
  } else if (s.End) {
    usedEnd.value = true;
    out.edges.push(edge(id, endNodeId, "next"));
  }
}

/**
 * Walk one ASL `States` map (a scope) into nodes + edges. `prefix` namespaces
 * ids so nested Parallel/Map branches never collide; `topLevel` marks whether a
 * node's status should be keyed off its ASL name (only top-level states appear
 * in execution history). Recurses into Parallel branches and Map iterators.
 */
function walkStates(
  states: Record<string, RawState>,
  prefix: string,
  topLevel: boolean,
  out: BuiltGraph,
  endNodeId: string,
  usedEnd: { value: boolean },
): void {
  for (const [name, s] of Object.entries(states)) {
    const role = asRole(s.Type);
    const id = prefix + name;
    out.nodes.push({
      id,
      type: "state",
      position: { x: 0, y: 0 },
      data: {
        role,
        name,
        stateName: topLevel ? name : undefined,
        subtitle: subtitleFor(role, s),
      },
    });

    // Outgoing transitions per state type.
    if (role === "Choice") {
      (s.Choices ?? []).forEach((rule, i) => {
        const next = typeof rule.Next === "string" ? rule.Next : "";
        if (next) out.edges.push(edge(id, prefix + next, "choice", choiceLabel(rule, i)));
      });
      if (s.Default) out.edges.push(edge(id, prefix + s.Default, "default", "Default"));
    } else if (role === "Parallel") {
      (s.Branches ?? []).forEach((b, bi) => {
        const bp = `${id}#${bi}:`;
        if (b.States) {
          walkStates(b.States, bp, false, out, endNodeId, usedEnd);
          if (b.StartAt) out.edges.push(edge(id, bp + b.StartAt, "branch", `branch ${bi + 1}`));
        }
      });
      addSequential(out, id, prefix, s, endNodeId, usedEnd);
    } else if (role === "Map") {
      const iter = s.Iterator ?? s.ItemProcessor;
      if (iter?.States) {
        const ip = `${id}#map:`;
        walkStates(iter.States, ip, false, out, endNodeId, usedEnd);
        if (iter.StartAt) out.edges.push(edge(id, ip + iter.StartAt, "branch", "each item"));
      }
      addSequential(out, id, prefix, s, endNodeId, usedEnd);
    } else if (role === "Succeed" || role === "Fail") {
      // Terminal — no outgoing transition.
    } else {
      // Task / Pass / Wait / Unknown.
      addSequential(out, id, prefix, s, endNodeId, usedEnd);
    }

    // Error catchers (Task / Parallel / Map).
    for (const c of s.Catch ?? []) {
      if (c.Next) {
        const errs = (c.ErrorEquals ?? []).join(", ");
        out.edges.push(edge(id, prefix + c.Next, "catch", errs ? `catch ${errs}` : "catch"));
      }
    }
  }
}

/** Parse an ASL definition string into a graph, or return a human error reason. */
function buildGraph(definition: string): { graph?: BuiltGraph; error?: string } {
  let def: RawDefinition;
  try {
    def = JSON.parse(definition) as RawDefinition;
  } catch (e) {
    return { error: "Definition is not valid JSON: " + (e instanceof Error ? e.message : String(e)) };
  }
  if (!def || typeof def !== "object") return { error: "Definition is empty or not an object." };
  if (!def.StartAt) return { error: 'Definition is missing a top-level "StartAt".' };
  if (!def.States || typeof def.States !== "object" || Object.keys(def.States).length === 0) {
    return { error: 'Definition has no "States".' };
  }

  const out: BuiltGraph = { nodes: [], edges: [] };
  const endNodeId = "__end__";
  const usedEnd = { value: false };

  walkStates(def.States, "", true, out, endNodeId, usedEnd);

  // Synthetic Start pill → the entry state (mirrors the AWS graph).
  const startId = "__start__";
  out.nodes.unshift({
    id: startId,
    type: "state",
    position: { x: 0, y: 0 },
    data: { role: "Start", name: "Start", subtitle: "entry point" },
  });
  if (def.States[def.StartAt]) out.edges.push(edge(startId, def.StartAt, "next"));

  // Synthetic End pill, only if some state ends the flow with `End: true`.
  if (usedEnd.value) {
    out.nodes.push({
      id: endNodeId,
      type: "state",
      position: { x: 0, y: 0 },
      data: { role: "End", name: "End", subtitle: "workflow end" },
    });
  }

  return { graph: out };
}

// ── layered top-to-bottom layout (longest-path ranks, no deps) ──────────────────
const NODE_W = 210;
const X_STEP = 250;
const Y_STEP = 120;

function layout(g: BuiltGraph): Node<GraphNodeData>[] {
  const rank = new Map<string, number>(g.nodes.map((n) => [n.id, 0]));
  // Relax edges up to |V| times: longest path in a DAG; bounded so cycles (a
  // Choice loop, or a Catch back to an earlier state) terminate instead of hang.
  for (let iter = 0; iter < g.nodes.length; iter++) {
    let changed = false;
    for (const e of g.edges) {
      const r = (rank.get(e.source) ?? 0) + 1;
      if (r > (rank.get(e.target) ?? 0)) {
        rank.set(e.target, r);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // Group by rank, preserving insertion order within each row, and centre rows.
  const byRank = new Map<number, Node<GraphNodeData>[]>();
  for (const n of g.nodes) {
    const r = rank.get(n.id) ?? 0;
    const row = byRank.get(r) ?? [];
    row.push(n);
    byRank.set(r, row);
  }
  const positioned: Node<GraphNodeData>[] = [];
  for (const [r, row] of [...byRank.entries()].sort((a, b) => a[0] - b[0])) {
    const rowWidth = (row.length - 1) * X_STEP;
    row.forEach((n, i) => {
      positioned.push({ ...n, position: { x: i * X_STEP - rowWidth / 2, y: r * Y_STEP } });
    });
  }
  return positioned;
}

// ── custom node renderer ────────────────────────────────────────────────────────
function StateNode({ data, selected }: NodeProps) {
  const d = data as GraphNodeData;
  const meta = ROLE_META[d.role] ?? ROLE_META.Unknown;
  const Icon = meta.icon;
  const isSynthetic = d.role === "Start" || d.role === "End";

  // In execution mode the accent + ring follow the outcome; otherwise the type.
  const statusMeta = d.status ? STATUS_META[d.status] : undefined;
  const accent = statusMeta ? statusMeta.color : meta.accent;
  const running = d.status === "running";
  const pending = d.status === "pending";
  const decorated = Boolean(statusMeta) && !pending; // execution mode + this state ran

  return (
    <div
      className={`rounded-md border bg-card py-2 pl-2 pr-3 shadow-sm transition-colors ${
        selected ? "ring-2 ring-primary" : ""
      } ${running ? "animate-pulse" : ""}`}
      style={{
        minWidth: isSynthetic ? 120 : NODE_W,
        borderLeft: `4px solid ${accent}`,
        boxShadow: decorated ? `0 0 0 1px ${accent}` : undefined,
        opacity: pending ? 0.55 : 1,
      }}
      title={d.name}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="flex items-center gap-2">
        <Icon className="size-4 shrink-0" style={{ color: accent }} />
        <span className="truncate font-medium" style={{ maxWidth: 200 }}>
          {d.name}
        </span>
        {statusMeta && !isSynthetic ? (
          <span
            className="ml-auto shrink-0 rounded-sm px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wide"
            style={{ color: accent, background: `${accent}1a` }}
          >
            {statusMeta.label}
          </span>
        ) : null}
      </div>
      {!isSynthetic ? (
        <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <span className="shrink-0 font-medium" style={{ color: meta.accent }}>
            {meta.label}
          </span>
          <span className="truncate" style={{ maxWidth: 170 }}>
            · {d.subtitle}
          </span>
        </div>
      ) : (
        <div className="mt-0.5 text-[11px] text-muted-foreground">{d.subtitle}</div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { state: StateNode };

// ── the component ────────────────────────────────────────────────────────────────
export interface AslGraphProps {
  /** The ASL definition JSON string (state machine's spec.definition). */
  definition?: string;
  /**
   * Optional per-state execution outcome. When provided, nodes are coloured by
   * status (execution graph); when absent, by state type (definition graph).
   */
  statusByState?: Record<string, StateStatus>;
  /** Panel height (Tailwind height utility class). */
  className?: string;
}

function AslGraphInner({ definition, statusByState, className }: AslGraphProps) {
  const { graph, error } = useMemo(
    () => (definition && definition.trim() ? buildGraph(definition) : { error: "empty" as const }),
    [definition],
  );

  const nodes = useMemo(() => {
    if (!graph) return [];
    const laid = layout(graph);
    if (!statusByState) return laid;
    // Execution mode: inject each state's status (unreached states → pending).
    return laid.map((n) => {
      if (n.data.role === "Start" || n.data.role === "End") return n;
      const key = n.data.stateName;
      const status: StateStatus = (key && statusByState[key]) || "pending";
      return { ...n, data: { ...n.data, status } };
    });
  }, [graph, statusByState]);

  const edges = graph?.edges ?? [];

  const roleLegend = useMemo(() => {
    const present = new Set<StateRole>();
    for (const n of graph?.nodes ?? []) if (!["Start", "End"].includes(n.data.role)) present.add(n.data.role);
    return [...present];
  }, [graph]);

  if (error) {
    if (error === "empty") {
      return (
        <div className={className ?? "h-[560px]"}>
          <EmptyState
            icon={<Workflow className="size-6" />}
            title="No workflow definition"
            description="This state machine has no ASL definition to visualize yet."
          />
        </div>
      );
    }
    return (
      <div className={className ?? "h-[560px]"}>
        <EmptyState
          icon={<CircleX className="size-6" />}
          title="Couldn't render the workflow graph"
          description={error}
        />
      </div>
    );
  }

  return (
    <div className={`relative rounded-md border ${className ?? "h-[560px]"}`}>
      {/* Legend — status grammar in execution mode, state-type grammar otherwise. */}
      <div className="absolute right-2 top-2 z-10 flex flex-col gap-1 rounded-md border bg-card/90 p-2 text-[11px] backdrop-blur">
        <span className="font-medium text-muted-foreground">{statusByState ? "Status" : "State types"}</span>
        {statusByState
          ? (Object.keys(STATUS_META) as StateStatus[]).map((s) => (
              <LegendDot key={s} color={STATUS_META[s].color} label={STATUS_META[s].label} />
            ))
          : roleLegend.map((r) => <LegendDot key={r} color={ROLE_META[r].accent} label={ROLE_META[r].label} />)}
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable
        fitView
        minZoom={0.2}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="size-2.5 rounded-sm" style={{ background: color }} aria-hidden />
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

/** Read-only ASL workflow graph (definition or status-coloured execution view). */
export function AslGraph(props: AslGraphProps) {
  return (
    <ReactFlowProvider>
      <AslGraphInner {...props} />
    </ReactFlowProvider>
  );
}
