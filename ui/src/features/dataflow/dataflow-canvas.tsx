import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Handle,
  Position,
  ConnectionMode,
  type Node,
  type Edge,
  type Connection,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Database,
  Radio,
  Zap,
  Archive,
  Plus,
  Trash2,
  Save,
  SlidersHorizontal,
  Activity,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError, k8sGet, k8sCreate, getDataFlowStatus, getDbStats, type DataFlowDirection } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION } from "@/types/k8s";
import type { DataFlow } from "@/types/k8s";

type Role = "database" | "topic" | "function" | "bucket";
type EdgeType = "replication" | "migration" | "stream" | "pipe";

const ENGINES = ["postgres", "mysql", "mariadb", "sqlserver"];
const PORTS: Record<string, string> = { postgres: "5432", mysql: "3306", mariadb: "3306", sqlserver: "1433" };
const ENGINE_LABEL: Record<string, string> = { postgres: "PostgreSQL", mysql: "MySQL", mariadb: "MariaDB", sqlserver: "SQL Server" };

const ROLE_META: Record<Role, { label: string; icon: LucideIcon; accent: string }> = {
  database: { label: "Database", icon: Database, accent: "#3b82f6" },
  topic: { label: "Topic", icon: Radio, accent: "#8b5cf6" },
  function: { label: "Function", icon: Zap, accent: "#f59e0b" },
  bucket: { label: "Bucket", icon: Archive, accent: "#10b981" },
};
const EDGE_GLYPH: Record<EdgeType, string> = { replication: "⇄", migration: "→", stream: "→", pipe: "→" };
const EDGE_LABEL: Record<EdgeType, string> = { replication: "replication", migration: "migration", stream: "stream", pipe: "pipe" };
const EDGE_COLOR: Record<EdgeType, string> = { replication: "#3b82f6", migration: "#3b82f6", stream: "#8b5cf6", pipe: "#64748b" };

// Live edge health, encoded with THREE redundant cues so it never relies on color alone
// (WCAG 1.4.1 / colorblind-safe): a line PATTERN (solid/dashed/dotted), a distinct SHAPE
// glyph + word, and a colorblind-safe palette (Okabe-Ito — avoids red/green confusion).
type EdgeState = "synced" | "lag" | "dead" | "pending";
const EDGE_STATE: Record<EdgeState, { color: string; dash?: string; width: number; glyph: string; word: string }> = {
  synced:  { color: "#009E73", width: 2, glyph: "✓", word: "in sync" },          // solid, bluish-green
  lag:     { color: "#E69F00", dash: "8 5", width: 2, glyph: "▲", word: "lag" }, // long dashes, orange
  dead:    { color: "#D55E00", dash: "2 4", width: 3, glyph: "✕", word: "dead" },// dotted + thick, vermillion
  pending: { color: "#94a3b8", dash: "1 6", width: 2, glyph: "○", word: "pending" }, // sparse dots, slate
};

interface NodeData extends Record<string, unknown> {
  role: Role;
  name: string;
  // database
  engine: string;
  host: string;
  port: string;
  database: string;
  username: string;
  password: string; // only used at deploy; never read back
  schema: string;
  ssl: boolean;
  // credential secret ref (populated on load; used for live Peek db-stats)
  secretName: string;
  secretKey: string;
  // function
  functionUrl: string;
  functionRef: string;
  // bucket
  bucket: string;
  prefix: string;
}
interface EdgeData extends Record<string, unknown> {
  type: EdgeType;
  mode: string;
  bootstrap: boolean;
}

function makeNode(role: Role, seq: number, engine = "postgres"): NodeData {
  const base: NodeData = {
    role,
    name: `${role === "database" ? engine : role}-${seq}`,
    engine: "",
    host: "",
    port: "",
    database: "",
    username: "",
    password: "",
    schema: "",
    ssl: false,
    secretName: "",
    secretKey: "",
    functionUrl: "",
    functionRef: "",
    bucket: "",
    prefix: "",
  };
  if (role === "database") {
    return {
      ...base,
      engine,
      port: PORTS[engine] ?? "5432",
      database: "app",
      username: engine === "sqlserver" ? "sa" : "postgres",
      schema: engine === "sqlserver" ? "dbo" : "public",
    };
  }
  return base;
}

// infer a sensible edge type from the roles being connected
function inferEdge(fromRole: Role, toRole: Role): EdgeData {
  if (toRole === "topic") return { type: "stream", mode: "", bootstrap: false };
  if (fromRole === "database" && toRole === "database") return { type: "replication", mode: "full-load-and-cdc", bootstrap: false };
  return { type: "pipe", mode: "", bootstrap: false };
}
function allowedTypes(fromRole: Role, toRole: Role): EdgeType[] {
  if (toRole === "topic") return ["stream"];
  if (fromRole === "database" && toRole === "database") return ["replication", "migration", "pipe"];
  return ["pipe"];
}

// ── one node renderer for every role ─────────────────────────────────────────
function RoleNode({ data, selected }: NodeProps) {
  const d = data as NodeData;
  const meta = ROLE_META[d.role] ?? ROLE_META.database;
  const Icon = meta.icon;
  let subtitle = meta.label;
  if (d.role === "database") subtitle = `${ENGINE_LABEL[d.engine] ?? d.engine}${d.host ? ` · ${d.host}` : ""}`;
  else if (d.role === "function") subtitle = d.functionRef || d.functionUrl || "transform";
  else if (d.role === "bucket") subtitle = d.bucket || "object store";
  else if (d.role === "topic") subtitle = "message stream";
  return (
    <div
      className={`rounded-md border bg-card py-2 pl-2 pr-3 shadow-sm ${selected ? "ring-2 ring-primary" : ""}`}
      style={{ minWidth: 170, borderLeft: `4px solid ${meta.accent}` }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-2">
        <Icon className="size-4" style={{ color: meta.accent }} />
        <span className="font-medium">{d.name || "unnamed"}</span>
      </div>
      <div className="mt-0.5 truncate text-[11px] text-muted-foreground" style={{ maxWidth: 200 }}>{subtitle}</div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { node: RoleNode };

function CanvasInner() {
  const params = useParams({ strict: false }) as { namespace?: string; name?: string };
  const navigate = useNavigate();
  const editing = Boolean(params.name);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<EdgeData>>([]);
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number; id: string } | null>(null);
  const [peek, setPeek] = useState<string | null>(null);
  const [name, setName] = useState(params.name ?? "");
  const [namespace, setNamespace] = useState(params.namespace ?? "default");
  const [tables, setTables] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [seq, setSeq] = useState(1);

  const nsWatch = useQuery({
    queryKey: ["namespaces-list"],
    queryFn: () => k8sGet<{ items: { metadata: { name?: string } }[] }>(corePaths.namespaces()),
  });
  const namespaces = (nsWatch.data?.items ?? [])
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const { data: df } = useQuery({
    queryKey: ["dataflow", params.namespace, params.name],
    queryFn: () => k8sGet<DataFlow>(openinfraPaths.dataflow(params.namespace!, params.name!)),
    enabled: editing,
  });
  useEffect(() => {
    if (!df) return;
    setName(df.metadata.name ?? "");
    setNamespace(df.metadata.namespace ?? "default");
    setTables((df.spec?.tables ?? []).join(", "));
    setNodes(
      (df.spec?.nodes ?? []).map((n) => ({
        id: n.name ?? "",
        type: "node",
        position: { x: n.x ?? 0, y: n.y ?? 0 },
        data: {
          role: ((n as { role?: Role }).role ?? "database") as Role,
          name: n.name ?? "",
          engine: n.engine ?? "postgres",
          host: n.host ?? "",
          port: String(n.port ?? 5432),
          database: n.database ?? "",
          username: n.username ?? "",
          password: "",
          schema: n.schema ?? "public",
          ssl: Boolean(n.ssl),
          secretName: n.passwordSecretRef?.name ?? "",
          secretKey: n.passwordSecretRef?.key ?? "password",
          functionUrl: (n as { functionUrl?: string }).functionUrl ?? "",
          functionRef: (n as { functionRef?: string }).functionRef ?? "",
          bucket: (n as { bucket?: string }).bucket ?? "",
          prefix: (n as { prefix?: string }).prefix ?? "",
        },
      })),
    );
    setEdges(
      (df.spec?.edges ?? []).map((e, i) => {
        const t = (e.type as EdgeType) ?? "replication";
        return {
          id: `e${i}`,
          source: e.from ?? "",
          target: e.to ?? "",
          data: { type: t, mode: e.mode ?? "full-load-and-cdc", bootstrap: Boolean((e as { bootstrap?: boolean }).bootstrap) },
        };
      }),
    );
  }, [df, setNodes, setEdges]);

  const roleOf = useCallback(
    (id: string): Role => (nodes.find((n) => n.id === id)?.data as NodeData | undefined)?.role ?? "database",
    [nodes],
  );

  const onConnect = useCallback(
    (c: Connection) =>
      setEdges((eds) =>
        addEdge(
          { ...c, id: `e-${c.source}-${c.target}-${eds.length}`, data: inferEdge(roleOf(c.source!), roleOf(c.target!)) },
          eds,
        ),
      ),
    [setEdges, roleOf],
  );

  function addNode(role: Role, engine = "postgres") {
    const id = `node-${seq}`;
    setSeq((s) => s + 1);
    setNodes((ns) => [
      ...ns,
      { id, type: "node", position: { x: 100 + ns.length * 36, y: 90 + ns.length * 28 }, data: makeNode(role, seq, engine) },
    ]);
    setSelNode(id);
    setSelEdge(null);
  }

  const node = nodes.find((n) => n.id === selNode);
  const edge = edges.find((e) => e.id === selEdge);

  // ── live per-edge status overlay (replication/migration) ───────────────────
  const nameOf = useMemo(() => new Map(nodes.map((n) => [n.id, (n.data as NodeData).name])), [nodes]);
  const statusEdges = useMemo(
    () => edges.map((e) => ({ from: nameOf.get(e.source) ?? e.source, to: nameOf.get(e.target) ?? e.target, type: (e.data as EdgeData).type })),
    [edges, nameOf],
  );
  const statusQ = useQuery({
    queryKey: ["dataflow-status", namespace, name, JSON.stringify(statusEdges)],
    queryFn: () => getDataFlowStatus(namespace, name, statusEdges),
    enabled: editing && statusEdges.length > 0,
    refetchInterval: 4000,
  });
  const legBy = useMemo(() => {
    const m = new Map<string, DataFlowDirection>();
    for (const d of statusQ.data?.directions ?? []) m.set(`${d.from}->${d.to}`, d);
    return m;
  }, [statusQ.data]);
  const displayEdges = useMemo(
    () =>
      edges.map((e) => {
        const d = e.data as EdgeData;
        const sFrom = nameOf.get(e.source) ?? e.source;
        const sTo = nameOf.get(e.target) ?? e.target;
        let stroke = EDGE_COLOR[d.type];
        let label = `${EDGE_GLYPH[d.type]} ${EDGE_LABEL[d.type]}${d.type === "replication" && d.bootstrap ? " +seed" : ""}`;
        if (editing && (d.type === "replication" || d.type === "migration")) {
          const legs = (d.type === "migration"
            ? [legBy.get(`${sFrom}->${sTo}`)]
            : [legBy.get(`${sFrom}->${sTo}`), legBy.get(`${sTo}->${sFrom}`)]
          ).filter(Boolean) as DataFlowDirection[];
          if (legs.length) {
            const lag = Math.max(...legs.map((l) => l.lag));
            const dead = legs.reduce((s, l) => s + l.deadLetter, 0);
            const found = legs.every((l) => l.found);
            const st: EdgeState = !found ? "pending" : dead > 0 ? "dead" : lag > 0 ? "lag" : "synced";
            const s = EDGE_STATE[st];
            const detail = st === "dead" ? `dead ${dead}${lag ? ` · lag ${lag}` : ""}` : st === "lag" ? `lag ${lag}` : s.word;
            // pattern + shape glyph + word carry the state; color is the third (redundant) cue
            // NOT animated: React Flow animates by forcing a moving dash, which would
            // override our solid "in sync" pattern (a synced edge would look dashed, like
            // "lagging"). Static strokeDasharray keeps the pattern exact + matching the legend.
            return {
              ...e,
              label: `${EDGE_GLYPH[d.type]} ${s.glyph} ${detail}`,
              animated: false,
              style: { stroke: s.color, strokeWidth: s.width, strokeDasharray: s.dash ?? "none" },
              labelStyle: { fontSize: 11 },
            };
          }
        }
        return { ...e, label, animated: false, style: { stroke, strokeWidth: 2, strokeDasharray: "none" }, labelStyle: { fontSize: 11 } };
      }),
    [edges, legBy, nameOf, editing],
  );

  function patchNode(p: Partial<NodeData>) {
    setNodes((ns) => ns.map((n) => (n.id === selNode ? { ...n, data: { ...(n.data as NodeData), ...p } } : n)));
  }
  function patchEdge(p: Partial<EdgeData>) {
    setEdges((es) => es.map((e) => (e.id === selEdge ? { ...e, data: { ...(e.data as EdgeData), ...p } } : e)));
  }
  function deleteSelected() {
    if (selNode) deleteNode(selNode);
    else if (selEdge) {
      setEdges((es) => es.filter((e) => e.id !== selEdge));
      setSelEdge(null);
    }
  }
  function deleteNode(id: string) {
    setNodes((ns) => ns.filter((n) => n.id !== id));
    setEdges((es) => es.filter((e) => e.source !== id && e.target !== id));
    if (selNode === id) setSelNode(null);
  }

  async function deploy() {
    setErr(null);
    setSaving(true);
    try {
      const idToName = new Map(nodes.map((n) => [n.id, (n.data as NodeData).name]));
      const specNodes = nodes.map((n) => {
        const d = n.data as NodeData;
        const pos = { x: Math.round(n.position.x), y: Math.round(n.position.y) };
        if (d.role === "function")
          return { name: d.name, role: "function", ...(d.functionUrl ? { functionUrl: d.functionUrl } : {}), ...(d.functionRef ? { functionRef: d.functionRef } : {}), ...pos };
        if (d.role === "bucket")
          return { name: d.name, role: "bucket", bucket: d.bucket, ...(d.prefix ? { prefix: d.prefix } : {}), ...pos };
        if (d.role === "topic") return { name: d.name, role: "topic", ...pos };
        return {
          name: d.name,
          role: "database",
          engine: d.engine,
          host: d.host,
          port: Number(d.port) || 5432,
          database: d.database,
          username: d.username,
          passwordSecretRef: { name: `${name}-creds`, key: `${d.name}-password` },
          schema: d.schema,
          ssl: d.ssl,
          ...pos,
        };
      });
      const specEdges = edges.map((e) => {
        const d = e.data as EdgeData;
        return {
          from: idToName.get(e.source) ?? e.source,
          to: idToName.get(e.target) ?? e.target,
          type: d.type,
          ...(d.type === "migration" ? { mode: d.mode } : {}),
          ...(d.type === "replication" && d.bootstrap ? { bootstrap: true } : {}),
        };
      });
      const stringData: Record<string, string> = {};
      for (const n of nodes) {
        const d = n.data as NodeData;
        if (d.role === "database" && d.password) stringData[`${d.name}-password`] = d.password;
      }
      if (Object.keys(stringData).length) {
        await k8sCreate(corePaths.secrets(namespace), {
          apiVersion: "v1",
          kind: "Secret",
          metadata: { name: `${name}-creds`, namespace },
          stringData,
        }).catch(() => {});
      }
      await k8sCreate(openinfraPaths.dataflows(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "DataFlow",
        metadata: { name, namespace },
        spec: { nodes: specNodes, edges: specEdges, tables: tables.split(",").map((t) => t.trim()).filter(Boolean) },
      });
      navigate({ to: "/dataflows" });
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to deploy the data flow.");
    } finally {
      setSaving(false);
    }
  }

  const RFNODES = useMemo(() => nodeTypes, []);
  const ed = edge?.data as EdgeData | undefined;
  const nd = node?.data as NodeData | undefined;
  const edgeTypes = edge ? allowedTypes(roleOf(edge.source), roleOf(edge.target)) : [];

  // ── Peek: live metrics for one node step ───────────────────────────────────
  const peekNode = nodes.find((n) => n.id === peek);
  const peekData = peekNode?.data as NodeData | undefined;
  const peekName = peekData?.name ?? "";
  const allDirs = statusQ.data?.directions ?? [];
  const peekOut = allDirs.filter((d) => d.from === peekName); // this node's output stream + its consumers
  const peekIn = allDirs.filter((d) => d.to === peekName); // legs writing INTO this node (sink view)
  const peekStream = peekOut.find((d) => d.found);
  // live database-engine internals for a peeked database node (issue #56)
  const dbStatsQ = useQuery({
    queryKey: ["db-stats", namespace, name, peekName],
    queryFn: () => getDbStats(namespace, name, peekName),
    enabled: Boolean(peek) && editing && peekData?.role === "database",
    refetchInterval: 5000,
  });
  const dbs = dbStatsQ.data;

  return (
    <div className="flex h-[calc(100vh-9rem)] gap-3">
      <div className="relative flex-1 rounded-md border">
        {/* palette */}
        <div className="absolute left-2 top-2 z-10 flex flex-col gap-0.5 rounded-md border bg-card/90 p-1 backdrop-blur">
          <span className="px-1 pt-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">Databases</span>
          {ENGINES.map((e) => (
            <PaletteBtn key={e} icon={Database} accent={ROLE_META.database.accent} label={ENGINE_LABEL[e] ?? e} onClick={() => addNode("database", e)} />
          ))}
          <span className="px-1 pt-1 text-[10px] uppercase tracking-wide text-muted-foreground">Pipeline</span>
          <PaletteBtn icon={Radio} accent={ROLE_META.topic.accent} label="Topic" onClick={() => addNode("topic")} />
          <PaletteBtn icon={Zap} accent={ROLE_META.function.accent} label="Function" onClick={() => addNode("function")} />
          <PaletteBtn icon={Archive} accent={ROLE_META.bucket.accent} label="Bucket" onClick={() => addNode("bucket")} />
        </div>
        {editing ? (
          <div className="absolute right-2 top-2 z-10 flex flex-col gap-0.5 rounded-md border bg-card/90 p-2 text-[10px] backdrop-blur">
            <span className="font-medium text-muted-foreground">Edge status {statusQ.isFetching ? "• live" : ""}</span>
            <Legend color={EDGE_STATE.synced.color} width={EDGE_STATE.synced.width} label="✓ in sync (solid)" />
            <Legend color={EDGE_STATE.lag.color} dash={EDGE_STATE.lag.dash} width={EDGE_STATE.lag.width} label="▲ lagging (dashed)" />
            <Legend color={EDGE_STATE.dead.color} dash={EDGE_STATE.dead.dash} width={EDGE_STATE.dead.width} label="✕ dead-letters (dotted)" />
            <Legend color={EDGE_STATE.pending.color} dash={EDGE_STATE.pending.dash} width={EDGE_STATE.pending.width} label="○ not provisioned" />
          </div>
        ) : null}
        <ReactFlow
          nodes={nodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          connectionMode={ConnectionMode.Loose}
          nodeTypes={RFNODES}
          onNodeClick={(_, n) => { setSelNode(n.id); setSelEdge(null); setMenu(null); }}
          onNodeContextMenu={(e, n) => { e.preventDefault(); setMenu({ x: e.clientX, y: e.clientY, id: n.id }); }}
          onEdgeClick={(_, e) => { setSelEdge(e.id); setSelNode(null); setMenu(null); }}
          onPaneClick={() => { setSelNode(null); setSelEdge(null); setMenu(null); }}
          fitView
        >
          <Background />
          <Controls />
          <MiniMap pannable zoomable />
        </ReactFlow>
        {menu ? (
          <>
            <div className="fixed inset-0 z-20" onClick={() => setMenu(null)} onContextMenu={(e) => { e.preventDefault(); setMenu(null); }} />
            <div className="fixed z-30 min-w-40 overflow-hidden rounded-md border bg-popover py-1 text-sm shadow-md" style={{ left: menu.x, top: menu.y }}>
              <button className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent" onClick={() => { setPeek(menu.id); setMenu(null); }}>
                <Activity className="size-3.5" /> Peek metrics
              </button>
              <button className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent" onClick={() => { setSelNode(menu.id); setSelEdge(null); setMenu(null); }}>
                <SlidersHorizontal className="size-3.5" /> Configure properties
              </button>
              <button className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-destructive hover:bg-accent" onClick={() => { deleteNode(menu.id); setMenu(null); }}>
                <Trash2 className="size-3.5" /> Delete node
              </button>
            </div>
          </>
        ) : null}
      </div>

      {/* inspector */}
      <div className="w-80 space-y-3 overflow-y-auto rounded-md border p-3">
        {!editing ? (
          <div className="space-y-1">
            <Label className="text-xs">Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="customers-pipeline" />
          </div>
        ) : (
          <div className="text-sm font-medium">{name}</div>
        )}
        <div className="space-y-1">
          <Label className="text-xs">Namespace</Label>
          <Select value={namespace} onValueChange={setNamespace} disabled={editing}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{namespaces.map((ns) => <SelectItem key={ns} value={ns}>{ns}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Tables (comma-separated)</Label>
          <Input value={tables} onChange={(e) => setTables(e.target.value)} placeholder="customers, orders" />
        </div>

        <hr className="border-border" />

        {nd ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                {(() => { const I = ROLE_META[nd.role].icon; return <I className="size-4" style={{ color: ROLE_META[nd.role].accent }} />; })()}
                {ROLE_META[nd.role].label}
              </span>
              <Button size="sm" variant="ghost" onClick={deleteSelected}><Trash2 className="size-3.5" /></Button>
            </div>
            <Field label="Name / id"><Input value={nd.name} onChange={(e) => patchNode({ name: e.target.value })} /></Field>

            {nd.role === "database" ? (
              <>
                <Field label="Engine">
                  <Select value={nd.engine} onValueChange={(v) => patchNode({ engine: v, port: PORTS[v] ?? "5432", schema: v === "sqlserver" ? "dbo" : "public" })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{ENGINES.map((e) => <SelectItem key={e} value={e}>{ENGINE_LABEL[e]}</SelectItem>)}</SelectContent>
                  </Select>
                </Field>
                <Field label="Host"><Input value={nd.host} onChange={(e) => patchNode({ host: e.target.value })} placeholder="pg.ns.svc" /></Field>
                <Field label="Port"><Input value={nd.port} onChange={(e) => patchNode({ port: e.target.value })} /></Field>
                <Field label="Database"><Input value={nd.database} onChange={(e) => patchNode({ database: e.target.value })} /></Field>
                <Field label="Username"><Input value={nd.username} onChange={(e) => patchNode({ username: e.target.value })} /></Field>
                <Field label={editing ? "Password (blank = unchanged)" : "Password"}>
                  <Input type="password" value={nd.password} onChange={(e) => patchNode({ password: e.target.value })} />
                </Field>
              </>
            ) : null}

            {nd.role === "function" ? (
              <>
                <Field label="Function URL"><Input value={nd.functionUrl} onChange={(e) => patchNode({ functionUrl: e.target.value })} placeholder="http://fn.ns.svc.cluster.local:8080" /></Field>
                <Field label="…or Function name (kind: Function)"><Input value={nd.functionRef} onChange={(e) => patchNode({ functionRef: e.target.value })} placeholder="my-transform" /></Field>
                <p className="text-[11px] text-muted-foreground">Receives each change event as JSON, returns the transformed event. 204/empty drops it (a filter).</p>
              </>
            ) : null}

            {nd.role === "bucket" ? (
              <>
                <Field label="Bucket"><Input value={nd.bucket} onChange={(e) => patchNode({ bucket: e.target.value })} placeholder="cdc-archive" /></Field>
                <Field label="Key prefix (optional)"><Input value={nd.prefix} onChange={(e) => patchNode({ prefix: e.target.value })} placeholder="orders/" /></Field>
              </>
            ) : null}

            {nd.role === "topic" ? (
              <p className="text-[11px] text-muted-foreground">A message stream other apps (or DB nodes) can subscribe to — fans out to many consumers independently.</p>
            ) : null}
          </div>
        ) : ed ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Edge</span>
              <Button size="sm" variant="ghost" onClick={deleteSelected}><Trash2 className="size-3.5" /></Button>
            </div>
            <Field label="Type">
              <Select value={ed.type} onValueChange={(v) => patchEdge({ type: v as EdgeType })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {edgeTypes.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t === "replication" ? "Replication (two-way)" : t === "migration" ? "Migration (one-way)" : t === "stream" ? "Stream (to topic)" : "Pipe (ETL flow)"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            {ed.type === "replication" ? (
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={ed.bootstrap} onChange={(e) => patchEdge({ bootstrap: e.target.checked })} />
                Seed an empty target (create schema + copy data, then sync)
              </label>
            ) : null}
            {ed.type === "migration" ? (
              <Field label="Mode">
                <Select value={ed.mode || "full-load-and-cdc"} onValueChange={(v) => patchEdge({ mode: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="full-load">Full load</SelectItem>
                    <SelectItem value="cdc">CDC</SelectItem>
                    <SelectItem value="full-load-and-cdc">Full load + CDC</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
            ) : null}
          </div>
        ) : (
          <div className="space-y-2 text-xs text-muted-foreground">
            <p>Add resources from the palette, drag between them to connect, then click a node or edge to configure it.</p>
            <p>Edges adapt to what you connect: <strong>database↔database</strong> = replication or migration; <strong>database→topic</strong> = stream (fan-out); <strong>anything→function/bucket/db</strong> = a pipe (ETL transform / load). Connect one source to several targets to fan-out.</p>
          </div>
        )}

        {err ? <p className="text-sm text-destructive">{err}</p> : null}
        <Button className="w-full" onClick={deploy} disabled={!name || !namespace || saving || nodes.length === 0}>
          <Save className="size-4" /> {saving ? "Deploying…" : editing ? "Update flow" : "Deploy flow"}
        </Button>
      </div>

      {/* Peek: live per-node metrics */}
      <Dialog open={Boolean(peek)} onOpenChange={(o) => !o && setPeek(null)}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Activity className="size-4" /> {peekName}
              {peekData ? <span className="text-xs font-normal text-muted-foreground">· {ROLE_META[peekData.role].label}</span> : null}
            </DialogTitle>
            <DialogDescription>Live monitoring for this step {statusQ.isFetching ? "· refreshing" : ""}</DialogDescription>
          </DialogHeader>
          {!editing ? (
            <p className="text-sm text-muted-foreground">Deploy the flow to see live metrics.</p>
          ) : !peekStream && !peekIn.length ? (
            <p className="text-sm text-muted-foreground">No live metrics yet — this step may still be provisioning, or it isn't connected.</p>
          ) : (
            <div className="space-y-4 text-sm">
              {/* INBOUND — what this step is applying (the sink view: targets, buckets) */}
              {peekIn.length ? (
                <div>
                  <div className="mb-1 text-xs font-medium text-muted-foreground">Incoming — applied into this step</div>
                  <div className="space-y-1">
                    {peekIn.map((d) => (
                      <div key={`in-${d.from}-${d.to}-${d.type}`} className="flex items-center justify-between rounded border px-2 py-1 text-xs">
                        <span><strong>{d.from}</strong> → <span className="text-muted-foreground">({d.type})</span></span>
                        <span className="flex gap-3">
                          <span className={d.deadLetter > 0 ? "text-destructive" : d.lag > 0 ? "text-amber-600" : "text-emerald-600"}>{d.deadLetter > 0 ? "✕" : d.lag > 0 ? "▲" : "✓"} backlog {d.lag.toLocaleString()}</span>
                          <span className="text-muted-foreground">applying {d.ackPending}</span>
                          <span className="text-muted-foreground">retries {d.redelivered}</span>
                          {d.deadLetter > 0 ? <span className="text-destructive">✕ dead {d.deadLetter}</span> : null}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {/* OUTBOUND — this step's own change stream (the source view: dbs, functions) */}
              {peekStream ? (
                <>
                  <div className="grid grid-cols-3 gap-2">
                    <Metric label="Captured" value={peekStream.captured.toLocaleString()} />
                    <Metric label="Buffered" value={formatBytes(peekStream.bytes)} />
                    <Metric label="Tables" value={String((peekStream.tables ?? []).length)} />
                  </div>
                  {peekStream.tables && peekStream.tables.length ? (
                    <div>
                      <div className="mb-1 text-xs font-medium text-muted-foreground">Per-table throughput</div>
                      <div className="max-h-28 space-y-0.5 overflow-y-auto">
                        {peekStream.tables.slice(0, 8).map((t) => (
                          <div key={t.subject} className="flex justify-between rounded bg-muted/40 px-2 py-0.5 text-xs">
                            <code>{t.table}</code><span className="text-muted-foreground">{t.count.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  <div>
                    <div className="mb-1 text-xs font-medium text-muted-foreground">Outgoing — downstream consumers</div>
                    <div className="space-y-1">
                      {peekOut.map((d) => (
                        <div key={`out-${d.from}-${d.to}-${d.type}`} className="flex items-center justify-between rounded border px-2 py-1 text-xs">
                          <span>→ <strong>{d.to}</strong> <span className="text-muted-foreground">({d.type})</span></span>
                          <span className="flex gap-3">
                            <span className={d.lag > 0 ? "text-amber-600" : "text-emerald-600"}>{d.deadLetter > 0 ? "✕" : d.lag > 0 ? "▲" : "✓"} lag {d.lag.toLocaleString()}</span>
                            <span className="text-muted-foreground">in-flight {d.ackPending}</span>
                            {d.deadLetter > 0 ? <span className="text-destructive">✕ dead {d.deadLetter}</span> : null}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-xs text-muted-foreground">This step is a sink — it consumes upstream data and doesn't publish its own change stream.</p>
              )}
            </div>
          )}

          {/* Database engine internals (database nodes only) — issue #56 */}
          {editing && peekData?.role === "database" ? (
            <div className="mt-3 space-y-3 border-t pt-3 text-sm">
              <div className="text-xs font-medium text-muted-foreground">Database engine {dbStatsQ.isFetching ? "· live" : ""}</div>
              {!dbs ? (
                <p className="text-xs text-muted-foreground">{dbStatsQ.isError ? "Couldn't reach the database." : "Loading engine stats…"}</p>
              ) : (
                <>
                  <div className="grid grid-cols-4 gap-2">
                    <Metric label="Connections" value={`${dbs.connections.total}${dbs.connections.max ? `/${dbs.connections.max}` : ""}`} />
                    <Metric label="Active" value={String(dbs.connections.active)} />
                    <Metric label="Idle" value={String(dbs.connections.idle)} />
                    <Metric label="Idle in txn" value={String(dbs.connections.idleInTx)} />
                  </div>
                  {dbs.replication && dbs.replication.length ? (
                    <div>
                      <div className="mb-1 text-xs font-medium text-muted-foreground">Replication slots (CDC lag)</div>
                      <div className="space-y-0.5">
                        {dbs.replication.map((s) => (
                          <div key={s.slot} className="flex items-center justify-between rounded bg-muted/40 px-2 py-0.5 text-xs">
                            <code>{s.slot}</code>
                            <span className="flex gap-2">
                              <span className={s.active ? "text-emerald-600" : "text-muted-foreground"}>{s.active ? "active" : "inactive"}</span>
                              <span className={s.lagBytes > 50_000_000 ? "text-amber-600" : "text-muted-foreground"}>{formatBytes(s.lagBytes)} behind</span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {dbs.topQueries && dbs.topQueries.length ? (
                    <div>
                      <div className="mb-1 text-xs font-medium text-muted-foreground">Top queries</div>
                      <div className="max-h-40 space-y-1 overflow-y-auto">
                        {dbs.topQueries.map((q, i) => (
                          <div key={i} className="rounded border px-2 py-1 text-[11px]">
                            <div className="flex justify-between text-muted-foreground">
                              <span>{q.calls ? `${q.calls.toLocaleString()} calls` : "active"}</span>
                              <span>{q.meanMs ? `${q.meanMs.toFixed(1)} ms avg` : ""}{q.totalMs ? ` · ${(q.totalMs / 1000).toFixed(1)}s total` : ""}</span>
                            </div>
                            <code className="mt-0.5 block truncate font-mono" title={q.query}>{q.query}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {dbs.note ? <p className="text-[11px] italic text-muted-foreground">{dbs.note}</p> : null}
                </>
              )}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function PaletteBtn({ icon: Icon, accent, label, onClick }: { icon: LucideIcon; accent: string; label: string; onClick: () => void }) {
  return (
    <Button size="sm" variant="ghost" className="h-7 justify-start gap-2 px-1.5" onClick={onClick}>
      <Plus className="size-3 text-muted-foreground" />
      <Icon className="size-3.5" style={{ color: accent }} />
      {label}
    </Button>
  );
}

function Legend({ color, dash, width = 2, label }: { color: string; dash?: string; width?: number; label: string }) {
  // Mirror the real edge: an SVG line so the dash PATTERN shows (not just the color), and a
  // shape glyph in the label — so the state is legible without relying on color.
  return (
    <span className="flex items-center gap-1.5">
      <svg width="20" height="6" aria-hidden="true" className="shrink-0">
        <line x1="0" y1="3" x2="20" y2="3" stroke={color} strokeWidth={width} strokeDasharray={dash} strokeLinecap="round" />
      </svg>
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      {children}
    </div>
  );
}

export function DataFlowCanvasPage() {
  return (
    <DetailShell backTo="/dataflows" backLabel="Data Flows" icon={<Workflow className="size-5" />} title="Data flow canvas" subtitle="Chain databases, topics, functions and buckets into a pipeline">
      <ReactFlowProvider>
        <CanvasInner />
      </ReactFlowProvider>
    </DetailShell>
  );
}
