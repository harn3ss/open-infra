import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import { ResourceYamlSheet } from "@/components/common/resource-yaml-sheet";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { RowActions } from "@/components/common/row-actions";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useDeleteResource } from "@/hooks/use-delete-resource";
import { useListFilter } from "@/hooks/use-list-filter";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { K8sObject } from "@/types/k8s";

export interface ResourceTableConfig<T extends K8sObject> {
  /** Display name, singular (e.g. "Pod"). */
  kind: string;
  /** Live list path (without /api/k8s prefix). */
  listPath: string;
  /** Columns (excluding the trailing actions column, which is added here). */
  columns: ColumnDef<T, unknown>[];
  /** Build the single-object path for delete, or omit to disable delete. */
  deletePath?: (item: T) => string;
  /** Strings used for the global search filter. */
  searchFields: (item: T) => Array<string | undefined>;
  /** Optional predicate to narrow the list (e.g. only LoadBalancer Services). */
  filter?: (item: T) => boolean;
  /** Default sort. */
  defaultSort?: SortingState;
  emptyTitle?: string;
  emptyDescription?: string;
}

/**
 * Generic, live, virtualized resource table driven by useK8sWatch. Provides a
 * row actions menu (View YAML, Delete-with-confirm) and a YAML drawer. Used for
 * Pods, Deployments, Services, Nodes, and any other list-able kind.
 */
export function ResourceTable<T extends K8sObject>({
  config,
  className,
}: {
  config: ResourceTableConfig<T>;
  className?: string;
}) {
  const { items: allItems, isLoading, isError, error, live, refetch } =
    useK8sWatch<T>(config.listPath);
  const items = useMemo(
    () => (config.filter ? allItems.filter(config.filter) : allItems),
    [allItems, config],
  );
  const { filtered } = useListFilter(items, config.searchFields);

  const [sorting, setSorting] = useState<SortingState>(
    config.defaultSort ?? [{ id: "name", desc: false }],
  );
  const [yamlResource, setYamlResource] = useState<T | null>(null);
  const [yamlOpen, setYamlOpen] = useState(false);
  const [toDelete, setToDelete] = useState<T | null>(null);

  const deleteMutation = useDeleteResource(config.listPath);

  const columns = useMemo<ColumnDef<T, unknown>[]>(() => {
    const actions: ColumnDef<T, unknown> = {
      id: "actions",
      header: "",
      enableSorting: false,
      size: 56,
      cell: ({ row }) => (
        <div className="flex justify-end">
          <RowActions
            onViewYaml={() => {
              setYamlResource(row.original);
              setYamlOpen(true);
            }}
            onDelete={() => setToDelete(row.original)}
            disableDelete={!config.deletePath}
          />
        </div>
      ),
    };
    return [...config.columns, actions];
  }, [config]);

  const confirmDelete = () => {
    if (!toDelete || !config.deletePath) return;
    deleteMutation.mutate(config.deletePath(toDelete), {
      onSuccess: () => setToDelete(null),
    });
  };

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {isLoading
            ? "Loading…"
            : `${filtered.length} of ${items.length} ${
                items.length === 1 ? config.kind : `${config.kind}s`
              }`}
        </p>
        <div className="flex items-center gap-2">
          <LiveIndicator live={live} />
          <Button
            variant="outline"
            size="icon-sm"
            onClick={refetch}
            aria-label="Refresh"
          >
            <RefreshCw className="size-4" />
          </Button>
        </div>
      </div>

      {isLoading ? (
        <LoadingState label={`Loading ${config.kind}s…`} />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState
          title={config.emptyTitle ?? `No ${config.kind}s`}
          description={
            config.emptyDescription ??
            `There are no ${config.kind}s in this scope.`
          }
        />
      ) : (
        <VirtualDataTable
          data={filtered}
          columns={columns}
          getRowId={(item) =>
            item.metadata.uid ??
            `${item.metadata.namespace ?? ""}/${item.metadata.name}`
          }
          sorting={sorting}
          onSortingChange={setSorting}
          onRowClick={(item) => {
            setYamlResource(item);
            setYamlOpen(true);
          }}
          emptyState={
            <EmptyState
              title="No matches"
              description={`No ${config.kind}s match the current filter.`}
            />
          }
        />
      )}

      <ResourceYamlSheet
        resource={yamlResource}
        open={yamlOpen}
        onOpenChange={setYamlOpen}
      />

      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(o) => (o ? null : setToDelete(null))}
        title={`Delete ${config.kind}?`}
        description={
          toDelete ? (
            <>
              This permanently deletes{" "}
              <span className="font-medium text-foreground">
                {toDelete.metadata.name}
              </span>
              {toDelete.metadata.namespace
                ? ` in ${toDelete.metadata.namespace}`
                : ""}
              . This cannot be undone.
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
            : `Failed to delete the ${config.kind}.`}
        </div>
      ) : null}
    </div>
  );
}
