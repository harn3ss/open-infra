import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { Boxes, Plus, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/common/status-badge";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { ApplicationDetail } from "@/features/applications/application-detail";
import { NewApplicationDialog } from "@/features/applications/new-application-dialog";
import { applicationHealth } from "@/features/applications/application-status";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useDeleteResource } from "@/hooks/use-delete-resource";
import { useListFilter } from "@/hooks/use-list-filter";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import { age } from "@/lib/format";
import { ApiError } from "@/lib/api";
import type { Application, K8sObject } from "@/types/k8s";

export function ApplicationsPage() {
  const { scoped } = useNamespace();
  const listPath = openinfraPaths.applications(scoped);

  const { items, isLoading, isError, error, live, refetch } =
    useK8sWatch<Application>(listPath);

  // Namespaces for the "New Application" dialog selector.
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () =>
      nsWatch.items
        .map((n) => n.metadata.name)
        .filter((n): n is string => Boolean(n))
        .sort((a, b) => a.localeCompare(b)),
    [nsWatch.items],
  );

  const { filtered } = useListFilter(items, (a) => [
    a.metadata.name,
    a.metadata.namespace,
    a.spec?.image,
    a.spec?.domain,
  ]);

  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);
  const [selected, setSelected] = useState<Application | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [toDelete, setToDelete] = useState<Application | null>(null);

  const deleteMutation = useDeleteResource(listPath);

  const columns = useMemo<ColumnDef<Application, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (a) => a.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (a) => a.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 140,
      },
      {
        id: "image",
        header: "Image",
        accessorFn: (a) => a.spec?.image ?? "",
        cell: ({ row }) => (
          <code className="block max-w-[22rem] truncate text-xs">
            {row.original.spec?.image ?? "—"}
          </code>
        ),
        size: 320,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (a) => applicationHealth(a).label,
        cell: ({ row }) => {
          const h = applicationHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (a) => a.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {age(row.original.metadata.creationTimestamp)}
          </span>
        ),
        size: 90,
      },
    ],
    [],
  );

  const openDetail = (app: Application) => {
    setSelected(app);
    setDetailOpen(true);
  };

  const confirmDelete = () => {
    if (!toDelete) return;
    const path = openinfraPaths.application(
      toDelete.metadata.namespace ?? "default",
      toDelete.metadata.name,
    );
    deleteMutation.mutate(path, {
      onSuccess: () => {
        setToDelete(null);
        setDetailOpen(false);
      },
    });
  };

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Boxes />}
        title="Applications"
        description="The open-infra flagship resource. Declare intent; the platform provisions the rest."
        actions={
          <>
            <LiveIndicator live={live} />
            <Button variant="outline" size="icon" onClick={refetch} aria-label="Refresh">
              <RefreshCw className="size-4" />
            </Button>
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" />
              New Application
            </Button>
          </>
        }
      />

      {isLoading ? (
        <LoadingState label="Loading Applications…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={<Boxes className="size-6" />}
          title="No Applications yet"
          description="Create your first Application to spin up an autoscaling, HTTPS service with optional database, buckets, and queues."
          action={
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" />
              New Application
            </Button>
          }
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {items.length}{" "}
            {items.length === 1 ? "Application" : "Applications"}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(a) =>
              a.metadata.uid ?? `${a.metadata.namespace}/${a.metadata.name}`
            }
            sorting={sorting}
            onSortingChange={setSorting}
            onRowClick={openDetail}
            emptyState={
              <EmptyState
                title="No matches"
                description="No Applications match the current filter."
              />
            }
          />
        </>
      )}

      <ApplicationDetail
        app={selected}
        open={detailOpen}
        onOpenChange={setDetailOpen}
        onDelete={(app) => setToDelete(app)}
      />

      <NewApplicationDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        defaultNamespace={scoped}
        namespaces={namespaces}
        listPath={listPath}
      />

      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(o) => (o ? null : setToDelete(null))}
        title="Delete Application?"
        description={
          toDelete ? (
            <>
              This permanently deletes{" "}
              <span className="font-medium text-foreground">
                {toDelete.metadata.name}
              </span>{" "}
              and the infrastructure it provisioned (hosting, and any attached
              database, buckets, and queues). This cannot be undone.
            </>
          ) : null
        }
        confirmLabel="Delete"
        loading={deleteMutation.isPending}
        onConfirm={confirmDelete}
      />

      {deleteMutation.isError ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {deleteMutation.error instanceof ApiError
            ? deleteMutation.error.message
            : "Failed to delete the Application."}
        </div>
      ) : null}
    </div>
  );
}
