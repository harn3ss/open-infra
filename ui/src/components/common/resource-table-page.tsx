import { type ReactNode, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import { ResourceYamlSheet } from "@/components/common/resource-yaml-sheet";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useListFilter } from "@/hooks/use-list-filter";
import { useNamespace } from "@/lib/namespace-context";
import type { K8sObject } from "@/types/k8s";

export interface ResourceTablePageProps<T extends K8sObject> {
  icon: ReactNode;
  title: string;
  description: string;
  /** List-path builder (namespace-scoped when a namespace is selected). */
  listPath: (ns?: string) => string;
  columns: ColumnDef<T, unknown>[];
  search: (item: T) => (string | undefined)[];
  singular: string;
  plural: string;
  emptyTitle: string;
  emptyDescription: string;
  /** If set, a row click runs this (e.g. navigate to a detail page) instead of
   *  opening the YAML drawer. */
  onRowClick?: (item: T) => void;
}

/**
 * A read-only, live, filterable table for a resource kind. Rows open a YAML
 * drawer. Shared by the Functions / Models / Databases views so they stay
 * consistent with the Applications page without duplicating the scaffolding.
 */
export function ResourceTablePage<T extends K8sObject>({
  icon,
  title,
  description,
  listPath,
  columns,
  search,
  singular,
  plural,
  emptyTitle,
  emptyDescription,
  onRowClick,
}: ResourceTablePageProps<T>) {
  const { scoped } = useNamespace();
  const { items, isLoading, isError, error, live, refetch } = useK8sWatch<T>(
    listPath(scoped),
  );
  const { filtered } = useListFilter(items, search);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);
  const [yamlObj, setYamlObj] = useState<T | null>(null);
  const [yamlOpen, setYamlOpen] = useState(false);

  return (
    <div className="space-y-5">
      <PageHeader
        icon={icon}
        title={title}
        description={description}
        actions={
          <>
            <LiveIndicator live={live} />
            <Button
              variant="outline"
              size="icon"
              onClick={refetch}
              aria-label="Refresh"
            >
              <RefreshCw className="size-4" />
            </Button>
          </>
        }
      />

      {isLoading ? (
        <LoadingState label={`Loading ${plural}…`} />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState icon={icon} title={emptyTitle} description={emptyDescription} />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {items.length}{" "}
            {items.length === 1 ? singular : plural}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(o) =>
              o.metadata.uid ?? `${o.metadata.namespace}/${o.metadata.name}`
            }
            sorting={sorting}
            onSortingChange={setSorting}
            onRowClick={(o) => {
              if (onRowClick) {
                onRowClick(o);
              } else {
                setYamlObj(o);
                setYamlOpen(true);
              }
            }}
            emptyState={
              <EmptyState
                title="No matches"
                description={`No ${plural} match the current filter.`}
              />
            }
          />
        </>
      )}

      <ResourceYamlSheet
        resource={yamlObj}
        open={yamlOpen}
        onOpenChange={setYamlOpen}
      />
    </div>
  );
}
