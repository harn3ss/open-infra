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
import { Database, Plus, Trash2, Save, SlidersHorizontal } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
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
import { ApiError, k8sGet, k8sCreate, getDataFlowStatus, type DataFlowDirection } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION } from "@/types/k8s";
import type { DataFlow, K8sObject } from "@/types/k8s";

const ENGINES = ["postgres", "mysql", "mariadb", "sqlserver"];
const PORTS: Record<string, string> = { postgres: "5432", mysql: "3306", mariadb: "3306", sqlserver: "1433" };
const ENGINE_LABEL: Record<string, string> = { postgres: "PostgreSQL", mysql: "MySQL", mariadb: "MariaDB", sqlserver: "SQL Server" };

interface NodeData extends Record<string, unknown> {
  site: string;
  engine: string;
  host: string;
  port: string;
  database: string;
  username: string;
  password: string; // only used at deploy; never read back
  schema: string;
  ssl: boolean;
}
interface EdgeData extends Record<string, unknown> {
  type: "replication" | "migration";
  mode: string;
}

const emptyNode = (engine: string): NodeData => ({
  site: "",
  engine,
  host: "",
  port: PORTS[engine] ?? "5432",
  database: "app",
  username: engine === "sqlserver" ? "sa" : "postgres",
  password: "",
  schema: engine === "sqlserver" ? "dbo" : "public",
  ssl: false,
});

// ── custom DB node ──────────────────────────────────────────────────────────
function DbNode({ data, selected }: NodeProps) {
  const d = data as NodeData;
  return (
    <div
      className={`rounded-md border bg-card px-3 py-2 shadow-sm ${selected ? "ring-2 ring-primary" : ""}`}
      style={{ minWidth: 160 }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-2">
        <Database className="size-4 text-muted-foreground" />
        <span className="font-medium">{d.site || "unnamed"}</span>
      </div>
      <div className="mt-0.5 text-xs text-muted-foreground">{ENGINE_LABEL[d.engine] ?? d.engine}</div>
      {d.host ? <div className="text-[11px] text-muted-foreground">{d.host}</div> : null}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { db: DbNode };

function CanvasInner() {
  const params = useParams({ strict: false }) as { namespace?: string; name?: string };
  const navigate = useNavigate();
  const editing = Boolean(params.name);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<EdgeData>>([]);
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number; id: string } | null>(null);
  const [name, setName] = useState(params.name ?? "");
  const [namespace, setNamespace] = useState(params.namespace ?? "default");
  const [tables, setTables] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [seq, setSeq] = useState(1);

  // namespaces for the picker
  const nsWatch = useQuery({
    queryKey: ["namespaces-list"],
    queryFn: () => k8sGet<{ items: K8sObject[] }>(corePaths.namespaces()),
  });
  const namespaces = (nsWatch.data?.items ?? [])
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  // load an existing DataFlow into the canvas
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
        type: "db",
        position: { x: n.x ?? 0, y: n.y ?? 0 },
        data: {
          site: n.name ?? "",
          engine: n.engine ?? "postgres",
          host: n.host ?? "",
          port: String(n.port ?? 5432),
          database: n.database ?? "",
          username: n.username ?? "",
          password: "",
          schema: n.schema ?? "public",
          ssl: Boolean(n.ssl),
        },
      })),
    );
    setEdges(
      (df.spec?.edges ?? []).map((e, i) => ({
        id: `e${i}`,
        source: e.from ?? "",
        target: e.to ?? "",
        label: e.type === "migration" ? "→ migration" : "⇄ replication",
        animated: true,
        data: { type: (e.type as EdgeData["type"]) ?? "replication", mode: e.mode ?? "full-load-and-cdc" },
      })),
    );
  }, [df, setNodes, setEdges]);

  const onConnect = useCallback(
    (c: Connection) =>
      setEdges((eds) =>
        addEdge(
          { ...c, id: `e-${c.source}-${c.target}`, label: "⇄ replication", animated: true, data: { type: "replication", mode: "full-load-and-cdc" } },
          eds,
        ),
      ),
    [setEdges],
  );

  function addNode(engine: string) {
    const id = `node-${seq}`;
    setSeq((s) => s + 1);
    setNodes((ns) => [
      ...ns,
      { id, type: "db", position: { x: 80 + ns.length * 40, y: 80 + ns.length * 30 }, data: { ...emptyNode(engine), site: `${engine}-${seq}` } },
    ]);
    setSelNode(id);
    setSelEdge(null);
  }

  const node = nodes.find((n) => n.id === selNode);
  const edge = edges.find((e) => e.id === selEdge);

  // ── live per-edge status overlay (only for a deployed flow) ────────────────
  const siteOf = useMemo(() => new Map(nodes.map((n) => [n.id, (n.data as NodeData).site])), [nodes]);
  const statusEdges = useMemo(
    () => edges.map((e) => ({ from: siteOf.get(e.source) ?? e.source, to: siteOf.get(e.target) ?? e.target, type: (e.data as EdgeData).type })),
    [edges, siteOf],
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
        const sFrom = siteOf.get(e.source) ?? e.source;
        const sTo = siteOf.get(e.target) ?? e.target;
        const legs = (d.type === "migration"
          ? [legBy.get(`${sFrom}->${sTo}`)]
          : [legBy.get(`${sFrom}->${sTo}`), legBy.get(`${sTo}->${sFrom}`)]
        ).filter(Boolean) as DataFlowDirection[];
        let stroke = "#94a3b8"; // slate = unknown / not yet provisioned
        let label = d.type === "migration" ? "→ migration" : "⇄ replication";
        if (editing && legs.length) {
          const lag = Math.max(...legs.map((l) => l.lag));
          const dead = legs.reduce((s, l) => s + l.deadLetter, 0);
          const found = legs.every((l) => l.found);
          stroke = !found ? "#94a3b8" : dead > 0 ? "#ef4444" : lag > 0 ? "#f59e0b" : "#22c55e";
          label = `${d.type === "migration" ? "→" : "⇄"} lag ${lag}${dead ? ` ⚠${dead}` : ""}`;
        }
        return { ...e, label, animated: true, style: { stroke, strokeWidth: 2 }, labelStyle: { fontSize: 11 } };
      }),
    [edges, legBy, siteOf, editing],
  );

  function patchNode(p: Partial<NodeData>) {
    setNodes((ns) => ns.map((n) => (n.id === selNode ? { ...n, data: { ...(n.data as NodeData), ...p } } : n)));
  }
  function patchEdge(p: Partial<EdgeData>) {
    setEdges((es) =>
      es.map((e) =>
        e.id === selEdge
          ? { ...e, data: { ...(e.data as EdgeData), ...p }, label: ((p.type ?? (e.data as EdgeData).type) === "migration") ? "→ migration" : "⇄ replication" }
          : e,
      ),
    );
  }
  function deleteSelected() {
    if (selNode) {
      setNodes((ns) => ns.filter((n) => n.id !== selNode));
      setEdges((es) => es.filter((e) => e.source !== selNode && e.target !== selNode));
      setSelNode(null);
    } else if (selEdge) {
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
      const idToSite = new Map(nodes.map((n) => [n.id, (n.data as NodeData).site]));
      const specNodes = nodes.map((n) => {
        const d = n.data as NodeData;
        return {
          name: d.site,
          engine: d.engine,
          host: d.host,
          port: Number(d.port) || 5432,
          database: d.database,
          username: d.username,
          passwordSecretRef: { name: `${name}-creds`, key: `${d.site}-password` },
          schema: d.schema,
          ssl: d.ssl,
          x: Math.round(n.position.x),
          y: Math.round(n.position.y),
        };
      });
      const specEdges = edges.map((e) => {
        const d = e.data as EdgeData;
        return {
          from: idToSite.get(e.source) ?? e.source,
          to: idToSite.get(e.target) ?? e.target,
          type: d.type,
          ...(d.type === "migration" ? { mode: d.mode } : {}),
        };
      });
      // creds secret: one key per node that has a password entered
      const stringData: Record<string, string> = {};
      for (const n of nodes) {
        const d = n.data as NodeData;
        if (d.password) stringData[`${d.site}-password`] = d.password;
      }
      if (Object.keys(stringData).length) {
        await k8sCreate(corePaths.secrets(namespace), {
          apiVersion: "v1",
          kind: "Secret",
          metadata: { name: `${name}-creds`, namespace },
          stringData,
        } as K8sObject).catch(() => {});
      }
      await k8sCreate(openinfraPaths.dataflows(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "DataFlow",
        metadata: { name, namespace },
        spec: {
          nodes: specNodes,
          edges: specEdges,
          tables: tables.split(",").map((t) => t.trim()).filter(Boolean),
        },
      } as K8sObject);
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

  return (
    <div className="flex h-[calc(100vh-9rem)] gap-3">
      {/* canvas */}
      <div className="relative flex-1 rounded-md border">
        {/* palette */}
        <div className="absolute left-2 top-2 z-10 flex flex-col gap-1 rounded-md border bg-card/90 p-1 backdrop-blur">
          <span className="px-1 text-[10px] uppercase tracking-wide text-muted-foreground">Add</span>
          {ENGINES.map((e) => (
            <Button key={e} size="sm" variant="ghost" className="justify-start" onClick={() => addNode(e)}>
              <Plus className="size-3" /> {ENGINE_LABEL[e]}
            </Button>
          ))}
        </div>
        {editing ? (
          <div className="absolute right-2 top-2 z-10 flex flex-col gap-0.5 rounded-md border bg-card/90 p-2 text-[10px] backdrop-blur">
            <span className="font-medium text-muted-foreground">Edge status {statusQ.isFetching ? "• live" : ""}</span>
            <Legend color="#22c55e" label="in sync" />
            <Legend color="#f59e0b" label="lagging" />
            <Legend color="#ef4444" label="dead-letters" />
            <Legend color="#94a3b8" label="not provisioned" />
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
            <div
              className="fixed z-30 min-w-36 overflow-hidden rounded-md border bg-popover py-1 text-sm shadow-md"
              style={{ left: menu.x, top: menu.y }}
            >
              <button
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent"
                onClick={() => { setSelNode(menu.id); setSelEdge(null); setMenu(null); }}
              >
                <SlidersHorizontal className="size-3.5" /> Configure properties
              </button>
              <button
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-destructive hover:bg-accent"
                onClick={() => { deleteNode(menu.id); setMenu(null); }}
              >
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
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="east-west-south" />
          </div>
        ) : (
          <div className="text-sm font-medium">{name}</div>
        )}
        <div className="space-y-1">
          <Label className="text-xs">Namespace</Label>
          <Select value={namespace} onValueChange={setNamespace} disabled={editing}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {namespaces.map((ns) => <SelectItem key={ns} value={ns}>{ns}</SelectItem>)}
            </SelectContent>
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
              <span className="text-sm font-medium">Node</span>
              <Button size="sm" variant="ghost" onClick={deleteSelected}><Trash2 className="size-3.5" /></Button>
            </div>
            <Field label="Site id"><Input value={nd.site} onChange={(e) => patchNode({ site: e.target.value })} /></Field>
            <Field label="Engine">
              <Select value={nd.engine} onValueChange={(v) => patchNode({ engine: v, port: PORTS[v] ?? "5432", schema: v === "sqlserver" ? "dbo" : "public" })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{ENGINES.map((e) => <SelectItem key={e} value={e}>{ENGINE_LABEL[e]}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
            <Field label="Host"><Input value={nd.host} onChange={(e) => patchNode({ host: e.target.value })} /></Field>
            <Field label="Port"><Input value={nd.port} onChange={(e) => patchNode({ port: e.target.value })} /></Field>
            <Field label="Database"><Input value={nd.database} onChange={(e) => patchNode({ database: e.target.value })} /></Field>
            <Field label="Username"><Input value={nd.username} onChange={(e) => patchNode({ username: e.target.value })} /></Field>
            <Field label={editing ? "Password (blank = unchanged)" : "Password"}>
              <Input type="password" value={nd.password} onChange={(e) => patchNode({ password: e.target.value })} />
            </Field>
          </div>
        ) : ed ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Edge</span>
              <Button size="sm" variant="ghost" onClick={deleteSelected}><Trash2 className="size-3.5" /></Button>
            </div>
            <Field label="Type">
              <Select value={ed.type} onValueChange={(v) => patchEdge({ type: v as EdgeData["type"] })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="replication">Replication (two-way)</SelectItem>
                  <SelectItem value="migration">Migration (one-way →)</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            {ed.type === "migration" ? (
              <Field label="Mode">
                <Select value={ed.mode} onValueChange={(v) => patchEdge({ mode: v })}>
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
          <p className="text-xs text-muted-foreground">
            Add database engines from the palette, drag to connect them, then click a node or edge to
            configure it. Replication edges are two-way (multi-master); migration edges are one-way.
          </p>
        )}

        {err ? <p className="text-sm text-destructive">{err}</p> : null}
        <Button className="w-full" onClick={deploy} disabled={!name || !namespace || saving || nodes.length === 0}>
          <Save className="size-4" /> {saving ? "Deploying…" : editing ? "Update flow" : "Deploy flow"}
        </Button>
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="inline-block h-0.5 w-4 rounded" style={{ backgroundColor: color }} />
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
    <DetailShell backTo="/dataflows" backLabel="Data Flows" icon={<Database className="size-5" />} title="Data flow canvas" subtitle="Drag database engines, connect them, deploy a topology">
      <ReactFlowProvider>
        <CanvasInner />
      </ReactFlowProvider>
    </DetailShell>
  );
}
