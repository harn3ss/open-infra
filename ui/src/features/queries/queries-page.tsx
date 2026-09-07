import { useMemo, useRef, useState } from "react";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Bookmark,
  ChevronRight,
  Database,
  Download,
  FileText,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Search,
  Table2,
  Trash2,
  X,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import {
  k8sCreate,
  listBucketObjects,
  listBuckets,
  listCatalogTables,
  queryResult,
  type QueryResult,
} from "@/lib/api";
import type { StatusTone } from "@/lib/format";
import { age, formatTimestamp } from "@/lib/format";
import type { Query } from "@/types/k8s";
import { SqlEditor, type SqlEditorHandle } from "./sql-editor";

const DEFAULT_SQL =
  "SELECT *\nFROM read_parquet('s3://query-data/sales.parquet')\nLIMIT 100";

function toneFor(state?: string): StatusTone {
  const s = (state ?? "").toUpperCase();
  if (s === "SUCCEEDED") return "success";
  if (s === "FAILED") return "destructive";
  if (s === "RUNNING") return "warning";
  return "muted";
}

/** executionTimeMs → a human runtime like Athena's ("842 ms", "1.24 s", "2m 3s"). */
function formatRuntime(ms?: number): string {
  if (ms == null || ms <= 0) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(2)} s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s % 60)}s`;
}

type Engine = "duckdb" | "trino";

// Capability-labeled, not raw engine names — users pick by what they want to do.
const ENGINES: { value: Engine; label: string; hint: string }[] = [
  { value: "duckdb", label: "Lake files — serverless", hint: "read_parquet('s3://…') · $0 idle" },
  { value: "trino", label: "Catalog & federation", hint: "database.table · joins across sources" },
];

const engineLabel = (e?: string) =>
  ENGINES.find((x) => x.value === e)?.label ?? e ?? "duckdb";

/* --------------------------- Saved queries (v1) --------------------------- */
// Honest v1: named queries persisted to this browser's localStorage only — no
// backend, so they are NOT synced across devices or users. Labeled as such in UI.

interface SavedQuery {
  id: string;
  name: string;
  sql: string;
  engine: Engine;
  savedAt: string; // ISO
}

const SAVED_KEY = "openinfra:saved-queries";

function readSaved(): SavedQuery[] {
  try {
    const raw = localStorage.getItem(SAVED_KEY);
    const v = raw ? JSON.parse(raw) : [];
    return Array.isArray(v) ? (v as SavedQuery[]) : [];
  } catch {
    return [];
  }
}

function useSavedQueries() {
  const [saved, setSaved] = useState<SavedQuery[]>(readSaved);

  const persist = (next: SavedQuery[]) => {
    setSaved(next);
    try {
      localStorage.setItem(SAVED_KEY, JSON.stringify(next));
    } catch {
      /* ignore — private mode / disabled storage */
    }
  };

  const save = (name: string, sql: string, engine: Engine) =>
    persist([
      {
        id: `sq-${Date.now().toString(36)}`,
        name,
        sql,
        engine,
        savedAt: new Date().toISOString(),
      },
      ...saved,
    ]);

  const remove = (id: string) => persist(saved.filter((s) => s.id !== id));

  return { saved, save, remove };
}

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

  const [view, setView] = useState<"editor" | "recent" | "saved">("editor");
  const saved = useSavedQueries();

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

  const openInTab = (sql: string, crName: string | null, engine: Engine) => {
    const id = ++tabSeq;
    setTabs((ts) => [...ts, { id, name: `Query ${id}`, sql, engine, crName }]);
    setActiveId(id);
    setView("editor"); // jump to the editor so the re-opened query is visible
  };

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4">
      <PageHeader
        title="Query"
        description="Serverless SQL over your data lake — no database to load into."
        icon={<Search />}
      />

      <Tabs
        value={view}
        onValueChange={(v) => setView(v as "editor" | "recent" | "saved")}
        className="flex min-h-0 flex-1 flex-col"
      >
        <TabsList className="w-fit">
          <TabsTrigger value="editor">Editor</TabsTrigger>
          <TabsTrigger value="recent">Recent queries</TabsTrigger>
          <TabsTrigger value="saved">Saved queries</TabsTrigger>
        </TabsList>

        {/* ── Editor: three-pane IDE ── */}
        <TabsContent value="editor" className="min-h-0 flex-1">
          <div className="flex h-full min-h-0 overflow-hidden rounded-lg border border-border bg-background">
            <DataPanel
              engine={active.engine}
              onInsert={(s) => editorRef.current?.insert(s)}
            />
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
                onSaveQuery={saved.save}
              />
            </div>
          </div>
        </TabsContent>

        {/* ── Recent queries (Athena-style history) ── */}
        <TabsContent value="recent" className="min-h-0 flex-1">
          <RecentQueries
            queries={recent}
            ns={ns}
            showNamespace={!scoped}
            onOpenEditor={openInTab}
          />
        </TabsContent>

        {/* ── Saved queries ── */}
        <TabsContent value="saved" className="min-h-0 flex-1">
          <SavedQueries
            saved={saved.saved}
            onOpen={(sql, engine) => openInTab(sql, null, engine)}
            onRemove={saved.remove}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ------------------------------- Data panel ------------------------------- */

function DataPanel({
  engine,
  onInsert,
}: {
  engine: Engine;
  onInsert: (snippet: string) => void;
}) {
  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-muted/20">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-xs font-medium text-muted-foreground">
        <Database className="size-3.5" /> {engine === "trino" ? "Catalog" : "Data"}
      </div>
      {engine === "trino" ? (
        <CatalogTree onInsert={onInsert} />
      ) : (
        <BucketTree onInsert={onInsert} />
      )}
    </aside>
  );
}

// DuckDB: browse buckets → queryable files; click to insert read_parquet('s3://…').
function BucketTree({ onInsert }: { onInsert: (snippet: string) => void }) {
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
    <>
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
              placeholder="Filter files…"
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
    </>
  );
}

// Trino: browse the Iceberg catalog (schemas → tables) from the always-on REST
// catalog; click a table to insert iceberg.<schema>.<table>.
function CatalogTree({ onInsert }: { onInsert: (snippet: string) => void }) {
  const cat = useQuery({
    queryKey: ["catalog-tables"],
    queryFn: listCatalogTables,
    refetchInterval: 15000,
  });
  const [open, setOpen] = useState<Record<string, boolean>>({ demo: true });
  const schemas = cat.data ?? [];

  return (
    <div className="min-h-0 flex-1 overflow-auto p-1">
      {schemas.length === 0 ? (
        <div className="p-2 text-xs text-muted-foreground">
          {cat.isLoading
            ? "Loading…"
            : "No tables yet — create one with a Trino CREATE TABLE."}
        </div>
      ) : (
        schemas.map((s) => (
          <div key={s.schema}>
            <button
              onClick={() =>
                setOpen((o) => ({ ...o, [s.schema]: !o[s.schema] }))
              }
              className="flex w-full items-center gap-1 rounded px-2 py-1 text-left text-xs hover:bg-muted"
            >
              <ChevronRight
                className={`size-3 shrink-0 transition-transform ${open[s.schema] ? "rotate-90" : ""}`}
              />
              <Database className="size-3.5 shrink-0 text-muted-foreground" />
              <span className="truncate">{s.schema}</span>
            </button>
            {open[s.schema]
              ? s.tables.map((t) => (
                  <button
                    key={t}
                    onClick={() => onInsert(`iceberg.${s.schema}.${t}`)}
                    title={`Insert iceberg.${s.schema}.${t}`}
                    className="flex w-full items-center gap-2 truncate rounded px-2 py-1 pl-8 text-left text-xs hover:bg-muted"
                  >
                    <Table2 className="size-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate">{t}</span>
                  </button>
                ))
              : null}
          </div>
        ))
      )}
    </div>
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
  onSaveQuery,
}: {
  tab: QueryTab;
  res?: QueryResult;
  running: boolean;
  editorRef: React.RefObject<SqlEditorHandle | null>;
  onChange: (sql: string) => void;
  onRun: (sql: string) => void;
  onClear: () => void;
  onEngineChange: (engine: Engine) => void;
  onSaveQuery: (name: string, sql: string, engine: Engine) => void;
}) {
  const [topPct, setTopPct] = useState(58);
  const containerRef = useRef<HTMLDivElement>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState("");

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
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            setSaveName(tab.name);
            setSaveOpen(true);
          }}
          disabled={!tab.sql.trim()}
        >
          <Bookmark className="size-4" /> Save
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

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save query</DialogTitle>
            <DialogDescription>
              Saved in this browser only (localStorage) — an honest v1, not
              synced across devices or users.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5 py-2">
            <label className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <Input
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="e.g. Daily sales rollup"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter" && saveName.trim() && tab.sql.trim()) {
                  onSaveQuery(saveName.trim(), tab.sql, tab.engine);
                  setSaveOpen(false);
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setSaveOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!saveName.trim() || !tab.sql.trim()}
              onClick={() => {
                onSaveQuery(saveName.trim(), tab.sql, tab.engine);
                setSaveOpen(false);
              }}
            >
              <Bookmark className="size-4" /> Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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

// Athena-style query history: each past run's state / runtime / rows, click a
// row to re-open its RESULTS. NB: there is deliberately no "Data scanned" column
// — no bytes-scanned metric is measured by the Query engine or the result API, so
// showing one would be fabricated. Runtime/state/rows come from the per-run result
// endpoint (the CR status only carries a coarse phase).
function RecentQueries({
  queries,
  ns,
  showNamespace,
  onOpenEditor,
}: {
  queries: Query[];
  ns: string;
  showNamespace: boolean;
  onOpenEditor: (sql: string, crName: string, engine: Engine) => void;
}) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Query | null>(null);

  // Cap the number of runs we fan out result-fetches for (each is a BFF/MinIO
  // read); the list is already newest-first.
  const rows = queries.slice(0, 250);

  const results = useQueries({
    queries: rows.map((q) => {
      const rns = q.metadata.namespace ?? ns;
      const name = q.metadata.name ?? "";
      return {
        queryKey: ["query-result", rns, name],
        queryFn: () => queryResult(rns, name),
        enabled: Boolean(name),
        staleTime: 15_000,
        retry: 0,
        // Keep polling only while a run is still RUNNING; finished runs are stable.
        refetchInterval: (query: { state: { data?: QueryResult } }) =>
          query.state.data && query.state.data.state !== "RUNNING"
            ? false
            : 5000,
      };
    }),
  });

  const colCount = showNamespace ? 6 : 5;

  return (
    <div className="h-full overflow-auto rounded-lg border border-border bg-background">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-medium text-muted-foreground">
          Recent queries ({queries.length})
        </span>
        <button
          onClick={() => qc.invalidateQueries({ queryKey: ["query-result"] })}
          title="Refresh run stats"
          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="size-3.5" />
        </button>
      </div>
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background">
          <tr className="text-left text-xs text-muted-foreground">
            <th className="border-b border-border p-2 font-medium">Query</th>
            <th className="w-28 border-b border-border p-2 font-medium">State</th>
            <th className="w-24 border-b border-border p-2 font-medium">Runtime</th>
            <th className="w-20 border-b border-border p-2 font-medium">Rows</th>
            {showNamespace ? (
              <th className="w-24 border-b border-border p-2 font-medium">
                Namespace
              </th>
            ) : null}
            <th className="w-28 border-b border-border p-2 font-medium">Time</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={colCount} className="p-3 text-xs text-muted-foreground">
                No queries yet.
              </td>
            </tr>
          ) : (
            rows.map((q, i) => {
              const r = results[i];
              const res = r?.data;
              const loading = r?.isLoading ?? false;
              const phase = q.status?.phase;
              return (
                <tr
                  key={`${q.metadata.namespace}/${q.metadata.name}`}
                  onClick={() => setSelected(q)}
                  className="group cursor-pointer hover:bg-muted/50"
                >
                  {/* Query preview → view results */}
                  <td className="border-b border-border p-2">
                    <div className="flex items-center gap-2">
                      <span
                        title={q.spec?.sql}
                        className="block max-w-[460px] truncate font-mono text-xs text-primary"
                      >
                        {q.spec?.sql}
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenEditor(
                            q.spec?.sql ?? "",
                            q.metadata.name ?? "",
                            (q.spec?.engine ?? "duckdb") as Engine,
                          );
                        }}
                        title="Re-open in editor"
                        aria-label="Re-open in editor"
                        className="shrink-0 rounded p-1 text-muted-foreground opacity-0 hover:bg-muted hover:text-foreground group-hover:opacity-100"
                      >
                        <Pencil className="size-3.5" />
                      </button>
                    </div>
                  </td>
                  {/* State */}
                  <td className="border-b border-border p-2">
                    {res?.state ? (
                      <StatusBadge status={res.state} tone={toneFor(res.state)} />
                    ) : loading ? (
                      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                        <Loader2 className="size-3 animate-spin" /> checking…
                      </span>
                    ) : phase ? (
                      <StatusBadge
                        status={phase.toUpperCase()}
                        tone={toneFor(phase)}
                      />
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  {/* Runtime */}
                  <td className="border-b border-border p-2 text-xs tabular-nums text-muted-foreground">
                    {res && res.state !== "RUNNING"
                      ? formatRuntime(res.executionTimeMs)
                      : "—"}
                  </td>
                  {/* Rows */}
                  <td className="border-b border-border p-2 text-xs tabular-nums text-muted-foreground">
                    {res?.state === "SUCCEEDED"
                      ? res.rowCount.toLocaleString()
                      : "—"}
                  </td>
                  {showNamespace ? (
                    <td className="border-b border-border p-2 text-xs text-muted-foreground">
                      {q.metadata.namespace ?? ns}
                    </td>
                  ) : null}
                  {/* Time */}
                  <td
                    className="border-b border-border p-2 text-xs text-muted-foreground"
                    title={formatTimestamp(q.metadata.creationTimestamp)}
                  >
                    {age(q.metadata.creationTimestamp)}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>

      {selected ? (
        <ResultsSheet
          query={selected}
          ns={ns}
          onClose={() => setSelected(null)}
          onOpenEditor={onOpenEditor}
        />
      ) : null}
    </div>
  );
}

/* ---------------------- Past-run results (view results) ------------------- */

// Row-click on a history entry lands here: re-fetch that run's result via the
// existing result endpoint (shared React-Query cache — same key as the list, so
// no double fetch) and render the results grid, matching Athena's "view results".
function ResultsSheet({
  query,
  ns,
  onClose,
  onOpenEditor,
}: {
  query: Query;
  ns: string;
  onClose: () => void;
  onOpenEditor: (sql: string, crName: string, engine: Engine) => void;
}) {
  const rns = query.metadata.namespace ?? ns;
  const name = query.metadata.name ?? "";
  const sql = query.spec?.sql ?? "";
  const engine = (query.spec?.engine ?? "duckdb") as Engine;

  const result = useQuery({
    queryKey: ["query-result", rns, name],
    queryFn: () => queryResult(rns, name),
    refetchInterval: (q) =>
      q.state.data && q.state.data.state !== "RUNNING" ? false : 1500,
  });
  const res = result.data;

  return (
    <Sheet open onOpenChange={(o) => (o ? null : onClose())}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 p-0 sm:max-w-2xl"
      >
        <SheetHeader className="gap-2 pr-12">
          <div>
            <SheetTitle className="text-base">Query results</SheetTitle>
            <SheetDescription>
              {name} · {engineLabel(engine)} ·{" "}
              {age(query.metadata.creationTimestamp)} ago
            </SheetDescription>
          </div>
          <pre className="max-h-28 overflow-auto rounded-md border border-border bg-muted/30 p-2 font-mono text-xs">
            {sql}
          </pre>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                onOpenEditor(sql, name, engine);
                onClose();
              }}
            >
              <Pencil className="size-3.5" /> Open in editor
            </Button>
            {res?.state === "SUCCEEDED" && res.rows?.length ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => downloadCsv(name, res)}
              >
                <Download className="size-4" /> CSV
              </Button>
            ) : null}
          </div>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col">
          <ResultsPanel res={res} hasRun />
        </div>
      </SheetContent>
    </Sheet>
  );
}

/* ------------------------------ Saved queries ----------------------------- */

function SavedQueries({
  saved,
  onOpen,
  onRemove,
}: {
  saved: SavedQuery[];
  onOpen: (sql: string, engine: Engine) => void;
  onRemove: (id: string) => void;
}) {
  return (
    <div className="h-full overflow-auto rounded-lg border border-border bg-background">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-medium text-muted-foreground">
          Saved queries ({saved.length})
        </span>
      </div>
      <p className="border-b border-border bg-muted/20 px-3 py-1.5 text-[11px] text-muted-foreground">
        Saved in this browser only (localStorage) — an honest v1, not synced
        across devices or users.
      </p>
      {saved.length === 0 ? (
        <div className="p-3 text-xs text-muted-foreground">
          No saved queries yet. Write a query in the editor and choose{" "}
          <span className="font-medium">Save</span>.
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-background">
            <tr className="text-left text-xs text-muted-foreground">
              <th className="w-48 border-b border-border p-2 font-medium">
                Name
              </th>
              <th className="border-b border-border p-2 font-medium">Query</th>
              <th className="w-40 border-b border-border p-2 font-medium">
                Engine
              </th>
              <th className="w-24 border-b border-border p-2 font-medium">
                Saved
              </th>
              <th className="w-16 border-b border-border p-2" />
            </tr>
          </thead>
          <tbody>
            {saved.map((s) => (
              <tr key={s.id} className="hover:bg-muted/50">
                <td className="border-b border-border p-2 align-top text-xs font-medium">
                  {s.name}
                </td>
                <td className="border-b border-border p-2 align-top">
                  <button
                    onClick={() => onOpen(s.sql, s.engine)}
                    title={s.sql}
                    className="block max-w-[520px] truncate text-left font-mono text-xs text-primary hover:underline"
                  >
                    {s.sql}
                  </button>
                </td>
                <td className="border-b border-border p-2 align-top text-xs text-muted-foreground">
                  {engineLabel(s.engine)}
                </td>
                <td
                  className="border-b border-border p-2 align-top text-xs text-muted-foreground"
                  title={formatTimestamp(s.savedAt)}
                >
                  {age(s.savedAt)}
                </td>
                <td className="border-b border-border p-2 align-top">
                  <div className="flex items-center gap-1">
                    <Button
                      size="icon-sm"
                      variant="ghost"
                      title="Open in editor"
                      aria-label="Open in editor"
                      onClick={() => onOpen(s.sql, s.engine)}
                    >
                      <Pencil className="size-3.5" />
                    </Button>
                    <Button
                      size="icon-sm"
                      variant="ghost"
                      title="Delete saved query"
                      aria-label="Delete saved query"
                      onClick={() => onRemove(s.id)}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
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
