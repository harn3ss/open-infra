import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Database,
  Download,
  FileText,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import {
  k8sCreate,
  listBucketObjects,
  listBuckets,
  queryResult,
  type QueryResult,
} from "@/lib/api";
import type { StatusTone } from "@/lib/format";
import { age } from "@/lib/format";
import type { Query } from "@/types/k8s";
import { SqlEditor, type SqlEditorHandle } from "./sql-editor";

const DEFAULT_SQL =
  "SELECT *\nFROM read_parquet('s3://query-data/sales.parquet')\nLIMIT 100";

function toneFor(state?: string): StatusTone {
  if (state === "SUCCEEDED") return "success";
  if (state === "FAILED") return "destructive";
  return "warning";
}

type Engine = "duckdb" | "trino";

// Capability-labeled, not raw engine names — users pick by what they want to do.
const ENGINES: { value: Engine; label: string; hint: string }[] = [
  { value: "duckdb", label: "Lake files — serverless", hint: "read_parquet('s3://…') · $0 idle" },
  { value: "trino", label: "Catalog & federation", hint: "database.table · joins across sources" },
];

interface QueryTab {
  id: number;
  name: string;
  sql: string;
  engine: Engine;
  crName: string | null; // the kind: Query created for this tab's last run
}

let tabSeq = 2;

export function QueriesPage() {
  const { scoped } = useNamespace();
  const ns = scoped || "default";

  const [tabs, setTabs] = useState<QueryTab[]>([
    { id: 1, name: "Query 1", sql: DEFAULT_SQL, engine: "duckdb", crName: null },
  ]);
  const [activeId, setActiveId] = useState(1);
  const active = tabs.find((t) => t.id === activeId) ?? tabs[0]!;
  const editorRef = useRef<SqlEditorHandle>(null);

  const patchActive = (p: Partial<QueryTab>) =>
    setTabs((ts) => ts.map((t) => (t.id === activeId ? { ...t, ...p } : t)));

  const addTab = () => {
    const id = ++tabSeq;
    setTabs((ts) => [...ts, { id, name: `Query ${id}`, sql: "", engine: "duckdb", crName: null }]);
    setActiveId(id);
  };
  const closeTab = (id: number) => {
    setTabs((ts) => {
      const next = ts.filter((t) => t.id !== id);
      if (id === activeId && next[0]) setActiveId(next[0].id);
      return next.length ? next : [{ id: 1, name: "Query 1", sql: "", engine: "duckdb", crName: null }];
    });
  };

  // history (kind: Query CRs)
  const history = useK8sWatch<Query>(openinfraPaths.queries(scoped));
  const recent = useMemo(
    () =>
      [...history.items].sort((a, b) =>
        (b.metadata.creationTimestamp ?? "").localeCompare(
          a.metadata.creationTimestamp ?? "",
        ),
      ),
    [history.items],
  );

  const run = useMutation({
    mutationFn: async (sql: string) => {
      const name = `q-${Date.now().toString(36)}`;
      await k8sCreate(openinfraPaths.queries(ns), {
        apiVersion: "openinfra.dev/v1",
        kind: "Query",
        metadata: { name, namespace: ns },
        spec: { sql, engine: active.engine },
      });
      return name;
    },
    onSuccess: (name) => patchActive({ crName: name }),
  });

  const result = useQuery({
    queryKey: ["query-result", ns, active?.crName],
    enabled: Boolean(active?.crName),
    queryFn: () => queryResult(ns, active!.crName as string),
    refetchInterval: (q) =>
      q.state.data && q.state.data.state !== "RUNNING" ? false : 1500,
  });
  const res = result.data;

  const openInTab = (sql: string, crName: string, engine: Engine) => {
    const id = ++tabSeq;
    setTabs((ts) => [...ts, { id, name: `Query ${id}`, sql, engine, crName }]);
    setActiveId(id);
  };

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4">
      <PageHeader
        title="Query"
        description="Serverless SQL over your data lake — no database to load into."
        icon={<Search />}
      />

      <Tabs defaultValue="editor" className="flex min-h-0 flex-1 flex-col">
        <TabsList className="w-fit">
          <TabsTrigger value="editor">Editor</TabsTrigger>
          <TabsTrigger value="recent">Recent queries</TabsTrigger>
        </TabsList>

        {/* ── Editor: three-pane IDE ── */}
        <TabsContent value="editor" className="min-h-0 flex-1">
          <div className="flex h-full min-h-0 overflow-hidden rounded-lg border border-border bg-background">
            <DataPanel onInsert={(s) => editorRef.current?.insert(s)} />
            <div className="flex min-w-0 flex-1 flex-col">
              <QueryTabBar
                tabs={tabs}
                activeId={activeId}
                onSelect={setActiveId}
                onAdd={addTab}
                onClose={closeTab}
              />
              <EditorAndResults
                key={active.id}
                tab={active}
                res={res}
                running={run.isPending}
                editorRef={editorRef}
                onChange={(sql) => patchActive({ sql })}
                onRun={(sql) => run.mutate(sql)}
                onClear={() => patchActive({ sql: "" })}
                onEngineChange={(engine) => patchActive({ engine })}
              />
            </div>
          </div>
        </TabsContent>

        {/* ── Recent queries ── */}
        <TabsContent value="recent" className="min-h-0 flex-1">
          <RecentQueries queries={recent} ns={ns} onOpen={openInTab} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ------------------------------- Data panel ------------------------------- */

function DataPanel({ onInsert }: { onInsert: (snippet: string) => void }) {
  const [bucket, setBucket] = useState<string>("");
  const [filter, setFilter] = useState("");

  const buckets = useQuery({ queryKey: ["buckets"], queryFn: listBuckets });
  const objects = useQuery({
    queryKey: ["bucket-objects", bucket],
    enabled: Boolean(bucket),
    queryFn: () => listBucketObjects(bucket),
  });

  const files = (objects.data ?? []).filter(
    (o) =>
      !o.isPrefix &&
      /\.(parquet|csv|json)$/i.test(o.key) &&
      o.key.toLowerCase().includes(filter.toLowerCase()),
  );

  const snippetFor = (key: string) => {
    const uri = `s3://${bucket}/${key}`;
    if (/\.csv$/i.test(key)) return `read_csv_auto('${uri}')`;
    if (/\.json$/i.test(key)) return `read_json_auto('${uri}')`;
    return `read_parquet('${uri}')`;
  };

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-muted/20">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-xs font-medium text-muted-foreground">
        <Database className="size-3.5" /> Data
      </div>
      <div className="space-y-2 p-2">
        <select
          value={bucket}
          onChange={(e) => setBucket(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">Select a bucket…</option>
          {(buckets.data ?? []).map((b) => (
            <option key={b.name} value={b.name}>
              {b.name}
            </option>
          ))}
        </select>
        {bucket ? (
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1.5 size-3.5 text-muted-foreground" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter tables…"
              className="w-full rounded-md border border-border bg-background py-1 pl-7 pr-2 text-xs outline-none focus:ring-1 focus:ring-ring"
            />
          </div>
        ) : null}
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-1 pb-2">
        {bucket && files.length === 0 ? (
          <div className="p-2 text-xs text-muted-foreground">
            {objects.isLoading ? "Loading…" : "No queryable files."}
          </div>
        ) : (
          files.map((o) => (
            <button
              key={o.key}
              onClick={() => onInsert(snippetFor(o.key))}
              title={`Insert ${snippetFor(o.key)}`}
              className="flex w-full items-center gap-2 truncate rounded px-2 py-1 text-left text-xs hover:bg-muted"
            >
              <FileText className="size-3.5 shrink-0 text-muted-foreground" />
              <span className="truncate">{o.key}</span>
            </button>
          ))
        )}
      </div>
    </aside>
  );
}

/* ------------------------------ Query tab bar ----------------------------- */

function QueryTabBar({
  tabs,
  activeId,
  onSelect,
  onAdd,
  onClose,
}: {
  tabs: QueryTab[];
  activeId: number;
  onSelect: (id: number) => void;
  onAdd: () => void;
  onClose: (id: number) => void;
}) {
  return (
    <div className="flex items-center gap-1 border-b border-border px-2">
      {tabs.map((t) => (
        <div
          key={t.id}
          className={`group flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs ${
            t.id === activeId
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <button onClick={() => onSelect(t.id)}>{t.name}</button>
          <button
            onClick={() => onClose(t.id)}
            className="opacity-0 group-hover:opacity-100"
            aria-label="Close tab"
          >
            <X className="size-3" />
          </button>
        </div>
      ))}
      <button
        onClick={onAdd}
        className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
        aria-label="New query"
      >
        <Plus className="size-3.5" />
      </button>
    </div>
  );
}

/* -------------------------- Editor + results split ------------------------ */

function EditorAndResults({
  tab,
  res,
  running,
  editorRef,
  onChange,
  onRun,
  onClear,
  onEngineChange,
}: {
  tab: QueryTab;
  res?: QueryResult;
  running: boolean;
  editorRef: React.RefObject<SqlEditorHandle | null>;
  onChange: (sql: string) => void;
  onRun: (sql: string) => void;
  onClear: () => void;
  onEngineChange: (engine: Engine) => void;
}) {
  const [topPct, setTopPct] = useState(58);
  const containerRef = useRef<HTMLDivElement>(null);

  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: MouseEvent) =>
      setTopPct(
        Math.min(85, Math.max(20, ((ev.clientY - rect.top) / rect.height) * 100)),
      );
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  return (
    <div ref={containerRef} className="flex min-h-0 flex-1 flex-col">
      {/* editor (top pane) */}
      <div style={{ height: `${topPct}%` }} className="min-h-0 overflow-hidden">
        <SqlEditor
          ref={editorRef}
          value={tab.sql}
          onChange={onChange}
          onRun={onRun}
        />
      </div>

      {/* action bar */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border bg-muted/20 px-3 py-1.5">
        <Button
          size="sm"
          onClick={() => editorRef.current?.run()}
          disabled={running || !tab.sql.trim()}
        >
          {running ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <Play className="size-4" />
          )}
          Run
        </Button>
        <Button size="sm" variant="ghost" onClick={onClear}>
          Clear
        </Button>
        <span className="text-[11px] text-muted-foreground">⌘⏎ to run</span>
        <select
          value={tab.engine}
          onChange={(e) => onEngineChange(e.target.value as Engine)}
          title={ENGINES.find((x) => x.value === tab.engine)?.hint}
          className="rounded-md border border-border bg-background px-2 py-1 text-[11px] outline-none focus:ring-1 focus:ring-ring"
        >
          {ENGINES.map((x) => (
            <option key={x.value} value={x.value}>
              {x.label}
            </option>
          ))}
        </select>
        <div className="flex-1" />
        {res?.state === "SUCCEEDED" && res.rows?.length ? (
          <Button size="sm" variant="ghost" onClick={() => downloadCsv(tab.name, res)}>
            <Download className="size-4" /> CSV
          </Button>
        ) : null}
      </div>

      {/* draggable splitter */}
      <div
        onMouseDown={startDrag}
        className="h-1.5 shrink-0 cursor-row-resize border-y border-border bg-muted/30 hover:bg-primary/40"
        aria-hidden
      />

      {/* results (fills the rest) */}
      <div className="flex min-h-0 flex-1 flex-col">
        <ResultsPanel res={res} hasRun={Boolean(tab.crName)} />
      </div>
    </div>
  );
}

function ResultsPanel({ res, hasRun }: { res?: QueryResult; hasRun: boolean }) {
  if (!hasRun) {
    return (
      <div className="flex flex-1 items-center justify-center text-xs text-muted-foreground">
        Run a query to see results.
      </div>
    );
  }
  const state = res?.state ?? "RUNNING";
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-3 py-1.5 text-[11px] text-muted-foreground">
        <StatusBadge status={state} tone={toneFor(state)} />
        {state === "SUCCEEDED" ? (
          <>
            <span>
              <span className="text-muted-foreground/70">Run time:</span>{" "}
              {(res!.executionTimeMs / 1000).toFixed(2)} s
            </span>
            <span>
              <span className="text-muted-foreground/70">Rows:</span> {res!.rowCount}
              {res!.truncated ? ` (showing ${res!.rows?.length})` : ""}
            </span>
          </>
        ) : state === "RUNNING" ? (
          <span>running…</span>
        ) : null}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {state === "FAILED" ? (
          <pre className="whitespace-pre-wrap p-3 text-xs text-destructive">
            {res?.error}
          </pre>
        ) : res?.columns?.length ? (
          <table className="w-full border-collapse text-sm">
            <thead className="sticky top-0 bg-background">
              <tr>
                {res.columns.map((c) => (
                  <th
                    key={c}
                    className="border-b border-border p-2 text-left text-xs font-semibold"
                  >
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(res.rows ?? []).map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td
                      key={j}
                      className="border-b border-border p-2 font-mono text-xs tabular-nums"
                    >
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        ) : state === "RUNNING" ? (
          <div className="flex items-center gap-2 p-3 text-xs text-muted-foreground">
            <Loader2 className="size-4 animate-spin" /> Running query…
          </div>
        ) : (
          <div className="p-3 text-xs text-muted-foreground">No results.</div>
        )}
      </div>
    </>
  );
}

/* ------------------------------ Recent queries ---------------------------- */

function RecentQueries({
  queries,
  ns,
  onOpen,
}: {
  queries: Query[];
  ns: string;
  onOpen: (sql: string, crName: string, engine: Engine) => void;
}) {
  return (
    <div className="h-full overflow-auto rounded-lg border border-border bg-background">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-medium text-muted-foreground">
          Recent queries ({queries.length})
        </span>
        <RefreshCw className="size-3.5 text-muted-foreground" />
      </div>
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background">
          <tr className="text-left text-xs text-muted-foreground">
            <th className="border-b border-border p-2 font-medium">Query</th>
            <th className="w-24 border-b border-border p-2 font-medium">Namespace</th>
            <th className="w-24 border-b border-border p-2 font-medium">Age</th>
          </tr>
        </thead>
        <tbody>
          {queries.length === 0 ? (
            <tr>
              <td colSpan={3} className="p-3 text-xs text-muted-foreground">
                No queries yet.
              </td>
            </tr>
          ) : (
            queries.map((q) => (
              <tr key={`${q.metadata.namespace}/${q.metadata.name}`}>
                <td className="border-b border-border p-2">
                  <button
                    onClick={() =>
                      onOpen(q.spec?.sql ?? "", q.metadata.name ?? "", (q.spec?.engine ?? "duckdb") as Engine)
                    }
                    title={q.spec?.sql}
                    className="max-w-[560px] truncate font-mono text-xs text-primary hover:underline"
                  >
                    {q.spec?.sql}
                  </button>
                </td>
                <td className="border-b border-border p-2 text-xs text-muted-foreground">
                  {q.metadata.namespace ?? ns}
                </td>
                <td className="border-b border-border p-2 text-xs text-muted-foreground">
                  {age(q.metadata.creationTimestamp)}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

/* --------------------------------- CSV ----------------------------------- */

function downloadCsv(name: string, res: QueryResult) {
  const esc = (v: string) =>
    /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  const lines = [
    (res.columns ?? []).map(esc).join(","),
    ...(res.rows ?? []).map((r) => r.map(esc).join(",")),
  ];
  const url = URL.createObjectURL(
    new Blob([lines.join("\n")], { type: "text/csv" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
