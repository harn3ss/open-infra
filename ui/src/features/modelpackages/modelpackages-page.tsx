import { type ReactNode, useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Package, Plus, ChevronLeft, ArrowLeftRight, RefreshCw } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/common/page-header";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useListFilter } from "@/hooks/use-list-filter";
import { useNamespace } from "@/lib/namespace-context";
import { kindDocsUrl } from "@/lib/kind-docs";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ModelPackage } from "@/types/k8s";

/** Approval status → badge tone. */
export function approvalTone(s?: string): "success" | "destructive" | "warning" | "muted" {
  switch (s) {
    case "Approved":
      return "success";
    case "Rejected":
      return "destructive";
    case "PendingManualApproval":
      return "warning";
    default:
      return "muted";
  }
}

/** Leading-numeric value of a version string, for sorting (v2 < v10). */
function versionNum(v?: string): number {
  if (!v) return 0;
  const n = Number.parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

/** Highest version first, then newest first, so [0] is the "latest" package. */
function byLatest(a: ModelPackage, b: ModelPackage): number {
  const dv = versionNum(b.spec?.version) - versionNum(a.spec?.version);
  if (dv !== 0) return dv;
  return (b.metadata.creationTimestamp ?? "").localeCompare(
    a.metadata.creationTimestamp ?? "",
  );
}

/** A model-package group: all versions that share a `spec.modelName`. */
interface ModelGroup {
  name: string;
  /** Versions, latest first. */
  packages: ModelPackage[];
  latest: ModelPackage;
}

/** kind: ModelPackage — the model registry (SageMaker Model Registry). AWS's
 *  defining hierarchy is Model Package *Groups* → versioned collections, so the
 *  page you land on lists groups (grouped by `spec.modelName`); drilling into a
 *  group reveals its versions, and a version opens the existing package detail
 *  (the approve → deploy view). */
export function ModelPackagesPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const { items, isLoading, isError, error, live, refetch } = useK8sWatch<ModelPackage>(
    openinfraPaths.modelpackages(scoped),
  );

  // Topbar global search filters at the version (package) level; groups reflect
  // the filtered set, matching every other list view.
  const { filtered } = useListFilter(items, (p) => [
    p.metadata.name,
    p.spec?.modelName,
    p.spec?.version,
    p.spec?.framework,
  ]);

  const groups = useMemo<ModelGroup[]>(() => {
    const map = new Map<string, ModelPackage[]>();
    for (const p of filtered) {
      const key = p.spec?.modelName ?? p.metadata.name ?? "—";
      const arr = map.get(key);
      if (arr) arr.push(p);
      else map.set(key, [p]);
    }
    return [...map.entries()]
      .map(([name, pkgs]) => {
        const sorted = [...pkgs].sort(byLatest);
        return { name, packages: sorted, latest: sorted[0] } as ModelGroup;
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [filtered]);

  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const activeGroup = selectedGroup
    ? groups.find((g) => g.name === selectedGroup) ?? null
    : null;

  const [groupSorting, setGroupSorting] = useState<SortingState>([
    { id: "group", desc: false },
  ]);
  const [versionSorting, setVersionSorting] = useState<SortingState>([
    { id: "version", desc: true },
  ]);

  const groupColumns = useMemo<ColumnDef<ModelGroup, unknown>[]>(
    () => [
      {
        id: "group",
        header: "Model group",
        accessorFn: (g) => g.name,
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-2 font-medium">
            <Package className="size-4 text-muted-foreground" />
            {row.original.name}
          </span>
        ),
        size: 260,
      },
      {
        id: "latestVersion",
        header: "Latest version",
        accessorFn: (g) => versionNum(g.latest.spec?.version),
        cell: ({ row }) => (
          <Badge variant="secondary">v{row.original.latest.spec?.version ?? "1"}</Badge>
        ),
        size: 130,
      },
      {
        id: "versions",
        header: "Versions",
        accessorFn: (g) => g.packages.length,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.packages.length}
          </span>
        ),
        size: 100,
      },
      {
        id: "approval",
        header: "Latest approval",
        accessorFn: (g) => g.latest.spec?.approvalStatus ?? "PendingManualApproval",
        cell: ({ row }) => {
          const s = row.original.latest.spec?.approvalStatus ?? "PendingManualApproval";
          return <StatusBadge status={s} tone={approvalTone(s)} />;
        },
        size: 190,
      },
      {
        id: "age",
        header: "Updated",
        accessorFn: (g) => g.latest.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {age(row.original.latest.metadata.creationTimestamp)}
          </span>
        ),
        size: 100,
      },
    ],
    [],
  );

  const versionColumns = useMemo<ColumnDef<ModelPackage, unknown>[]>(
    () => [
      {
        id: "version",
        header: "Version",
        accessorFn: (p) => versionNum(p.spec?.version),
        cell: ({ row }) => (
          <span className="font-medium">v{row.original.spec?.version ?? "1"}</span>
        ),
        size: 110,
      },
      {
        id: "name",
        header: "Package",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">{row.original.metadata.name}</code>
        ),
        size: 240,
      },
      {
        id: "approval",
        header: "Approval",
        accessorFn: (p) => p.spec?.approvalStatus ?? "PendingManualApproval",
        cell: ({ row }) => {
          const s = row.original.spec?.approvalStatus ?? "PendingManualApproval";
          return <StatusBadge status={s} tone={approvalTone(s)} />;
        },
        size: 190,
      },
      {
        id: "framework",
        header: "Framework",
        accessorFn: (p) => p.spec?.framework ?? "—",
        cell: ({ row }) =>
          row.original.spec?.framework ? (
            <Badge variant="secondary">{row.original.spec.framework}</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (p) => p.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  const registerButton = (
    <Button onClick={() => navigate({ to: "/model-registry/new" })}>
      <Plus className="size-4" />
      Register model
    </Button>
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Package />}
        title="Model Registry"
        description="Versioned, approvable records of trained models — open-infra's SageMaker Model Registry. Models are grouped into versioned collections; approve a version, then promote it to a served Model."
        actions={
          <>
            <LiveIndicator live={live} />
            <Button variant="outline" size="icon" onClick={refetch} aria-label="Refresh">
              <RefreshCw className="size-4" />
            </Button>
            {registerButton}
          </>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading model registry…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<Package />}
          title="No model packages yet"
          description="Register a trained model artifact (from a Training Job's output) to version and approve it. Packages that share a model name form a versioned group."
          action={registerButton}
          learnMore={kindDocsUrl("ModelPackage")}
        />
      ) : activeGroup ? (
        <VersionsView
          group={activeGroup}
          sorting={versionSorting}
          onSortingChange={setVersionSorting}
          columns={versionColumns}
          onBack={() => setSelectedGroup(null)}
          onOpenVersion={(p) =>
            navigate({
              to: "/model-registry/$namespace/$name",
              params: {
                namespace: p.metadata.namespace ?? "default",
                name: p.metadata.name ?? "",
              },
            })
          }
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {groups.length} {groups.length === 1 ? "group" : "groups"} · {filtered.length}{" "}
            {filtered.length === 1 ? "version" : "versions"}
          </p>
          <VirtualDataTable
            data={groups}
            columns={groupColumns}
            getRowId={(g) => g.name}
            sorting={groupSorting}
            onSortingChange={setGroupSorting}
            onRowClick={(g) => setSelectedGroup(g.name)}
            emptyState={
              <EmptyState title="No matches" description="No model groups match the current filter." />
            }
          />
        </>
      )}
    </div>
  );
}

/** The drill-in for one model group: its versions, plus an optional side-by-side
 *  version comparison. Rows open the existing package detail (the version view). */
function VersionsView({
  group,
  sorting,
  onSortingChange,
  columns,
  onBack,
  onOpenVersion,
}: {
  group: ModelGroup;
  sorting: SortingState;
  onSortingChange: React.Dispatch<React.SetStateAction<SortingState>>;
  columns: ColumnDef<ModelPackage, unknown>[];
  onBack: () => void;
  onOpenVersion: (p: ModelPackage) => void;
}) {
  const [comparing, setComparing] = useState(false);
  const canCompare = group.packages.length >= 2;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack} className="-ml-2">
          <ChevronLeft className="size-4" />
          Model Registry
        </Button>
        <div className="flex items-center gap-2">
          <Package className="size-4 text-muted-foreground" />
          <h2 className="text-lg font-semibold tracking-tight">{group.name}</h2>
          <Badge variant="secondary">
            {group.packages.length} {group.packages.length === 1 ? "version" : "versions"}
          </Badge>
        </div>
        {canCompare ? (
          <Button
            variant={comparing ? "secondary" : "outline"}
            size="sm"
            className="ml-auto"
            onClick={() => setComparing((c) => !c)}
          >
            <ArrowLeftRight className="size-4" />
            Compare versions
          </Button>
        ) : null}
      </div>

      <VirtualDataTable
        data={group.packages}
        columns={columns}
        getRowId={(p) => p.metadata.uid ?? `${p.metadata.namespace}/${p.metadata.name}`}
        sorting={sorting}
        onSortingChange={onSortingChange}
        heightClassName="max-h-[calc(100vh-24rem)]"
        onRowClick={onOpenVersion}
        emptyState={<EmptyState title="No versions" description="This group has no versions." />}
      />

      {comparing && canCompare ? <CompareVersions group={group} /> : null}
    </div>
  );
}

/** Side-by-side metadata/metrics comparison of two versions in a group. Rows
 *  whose values differ are highlighted. No backend — reads the two CRs. */
function CompareVersions({ group }: { group: ModelGroup }) {
  const [aName, setAName] = useState(group.packages[0]?.metadata.name ?? "");
  const [bName, setBName] = useState(group.packages[1]?.metadata.name ?? "");

  const a =
    group.packages.find((p) => p.metadata.name === aName) ?? group.packages[0];
  const b =
    group.packages.find((p) => p.metadata.name === bName) ??
    group.packages[1] ??
    group.packages[0];

  if (!a || !b) return null;

  const fields: {
    label: string;
    raw: (p: ModelPackage) => string;
    render: (p: ModelPackage) => ReactNode;
  }[] = [
    {
      label: "Version",
      raw: (p) => p.spec?.version ?? "1",
      render: (p) => <span className="font-medium">v{p.spec?.version ?? "1"}</span>,
    },
    {
      label: "Approval",
      raw: (p) => p.spec?.approvalStatus ?? "PendingManualApproval",
      render: (p) => {
        const s = p.spec?.approvalStatus ?? "PendingManualApproval";
        return <StatusBadge status={s} tone={approvalTone(s)} />;
      },
    },
    {
      label: "Framework",
      raw: (p) => p.spec?.framework ?? "",
      render: (p) =>
        p.spec?.framework ? (
          <Badge variant="secondary">{p.spec.framework}</Badge>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      label: "Artifact",
      raw: (p) => `s3://${p.spec?.artifact?.bucket ?? ""}/${p.spec?.artifact?.key ?? ""}`,
      render: (p) => (
        <code className="text-xs">
          s3://{p.spec?.artifact?.bucket}/{p.spec?.artifact?.key ?? ""}
        </code>
      ),
    },
    {
      label: "Serving image",
      raw: (p) => p.spec?.image ?? "",
      render: (p) => <code className="text-xs">{p.spec?.image}</code>,
    },
    {
      label: "Port",
      raw: (p) => String(p.spec?.port ?? 8000),
      render: (p) => <span>{p.spec?.port ?? 8000}</span>,
    },
    {
      label: "Metrics",
      raw: (p) => p.spec?.metrics ?? "",
      render: (p) =>
        p.spec?.metrics ? (
          <code className="text-xs">{p.spec.metrics}</code>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      label: "Created",
      raw: (p) => p.metadata.creationTimestamp ?? "",
      render: (p) => (
        <span className="text-muted-foreground">{age(p.metadata.creationTimestamp)}</span>
      ),
    },
  ];

  const options = group.packages;

  return (
    <Card>
      <CardContent className="space-y-4 p-4">
        <div className="grid grid-cols-[7rem_1fr_1fr] items-center gap-3">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Field
          </span>
          <VersionPicker value={aName} onChange={setAName} options={options} />
          <VersionPicker value={bName} onChange={setBName} options={options} />
        </div>
        <div className="divide-y divide-border rounded-lg border border-border">
          {fields.map((f) => {
            const differs = f.raw(a) !== f.raw(b);
            return (
              <div
                key={f.label}
                className={cn(
                  "grid grid-cols-[7rem_1fr_1fr] items-center gap-3 px-3 py-2 text-sm",
                  differs && "bg-warning/5",
                )}
              >
                <span className="text-xs font-medium text-muted-foreground">{f.label}</span>
                <div className="min-w-0">{f.render(a)}</div>
                <div className="min-w-0">{f.render(b)}</div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function VersionPicker({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: ModelPackage[];
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-8">
        <SelectValue placeholder="Select a version" />
      </SelectTrigger>
      <SelectContent>
        {options.map((p) => (
          <SelectItem key={p.metadata.name} value={p.metadata.name ?? ""}>
            v{p.spec?.version ?? "1"} · {p.metadata.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
