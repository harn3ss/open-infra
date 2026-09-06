import { type ReactNode, useMemo, useState } from "react";
import {
  type ColumnDef,
  type SortingState,
  type VisibilityState,
} from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import { ResourceYamlSheet } from "@/components/common/resource-yaml-sheet";
import {
  PropertyFilter,
  applyFilterTokens,
  type FilterOperation,
  type FilterPropertyDef,
  type FilterToken,
} from "@/components/common/property-filter";
import {
  CollectionPreferences,
  useCollectionPreferences,
} from "@/components/common/collection-preferences";
import { Pagination, usePagination } from "@/components/common/pagination";
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
  /** Optional predicate to narrow the list (e.g. only Apps with a database). */
  filter?: (item: T) => boolean;
  singular: string;
  plural: string;
  emptyTitle: string;
  emptyDescription: string;
  /** If set, a row click runs this (e.g. navigate to a detail page) instead of
   *  opening the YAML drawer. */
  onRowClick?: (item: T) => void;
  /** Extra header actions (e.g. a "New" button), rendered left of refresh. Also
   *  reused as the primary call-to-action in the empty state. */
  headerActions?: ReactNode;
  /** Optional docs URL — surfaces a "Learn more" link in the empty state. */
  docsHref?: string;

  // ── AWS Table fidelity (all optional, off by default; existing callers unaffected) ──

  /**
   * Enables the Cloudscape-style tokenized property filter above the table (in
   * addition to the global text search). Each def declares a filterable property
   * and how to read its value off an item.
   */
  filterProperties?: FilterPropertyDef<T>[];
  /** Shows the ⚙ preferences gear (page size, column visibility, density). */
  enablePreferences?: boolean;
  /** Switch from full virtualization to discrete AWS-style pagination. */
  enablePagination?: boolean;
  /** Initial page size when pagination/preferences are on. Default 25. */
  defaultPageSize?: number;
  /** localStorage key for persisted preferences. Defaults to `plural`. */
  preferencesStorageKey?: string;
  /** Human labels for columns (by column id) in the preferences dialog. */
  columnLabels?: Record<string, string>;
}

/**
 * A read-only, live, filterable table for a resource kind. Rows open a YAML
 * drawer (or a detail page via `onRowClick`). Shared by most resource list views
 * so they stay consistent without duplicating the scaffolding.
 *
 * Opt into higher AWS fidelity per page via `filterProperties` (property filter),
 * `enablePreferences` (column/page-size gear), and `enablePagination` — all
 * backward-compatible; omit them for the original text-filter + virtualized list.
 */
export function ResourceTablePage<T extends K8sObject>({
  icon,
  title,
  description,
  listPath,
  columns,
  search,
  filter,
  singular,
  plural,
  emptyTitle,
  emptyDescription,
  onRowClick,
  headerActions,
  docsHref,
  filterProperties,
  enablePreferences = false,
  enablePagination = false,
  defaultPageSize = 25,
  preferencesStorageKey,
  columnLabels,
}: ResourceTablePageProps<T>) {
  const { scoped } = useNamespace();
  const { items: allItems, isLoading, isError, error, live, refetch } =
    useK8sWatch<T>(listPath(scoped));
  const items = filter ? allItems.filter(filter) : allItems;

  // Global text search (topbar) → property-filter tokens.
  const { filtered: textFiltered } = useListFilter(items, search);
  const [tokens, setTokens] = useState<FilterToken[]>([]);
  const [operation, setOperation] = useState<FilterOperation>("and");
  const filtered = useMemo(
    () =>
      filterProperties && filterProperties.length && tokens.length
        ? applyFilterTokens(textFiltered, tokens, filterProperties, operation)
        : textFiltered,
    [textFiltered, tokens, operation, filterProperties],
  );

  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);
  const [yamlObj, setYamlObj] = useState<T | null>(null);
  const [yamlOpen, setYamlOpen] = useState(false);

  // Column metadata for the preferences dialog + visibility state.
  const columnMeta = useMemo(
    () =>
      columns.map((c, idx) => {
        const id = (c.id ??
          (c as { accessorKey?: string }).accessorKey ??
          String(idx)) as string;
        const label =
          columnLabels?.[id] ??
          (typeof c.header === "string" ? c.header : id);
        return { id, label, alwaysVisible: id === "name" };
      }),
    [columns, columnLabels],
  );

  const [prefs, setPrefs] = useCollectionPreferences(
    preferencesStorageKey ?? plural,
    {
      pageSize: defaultPageSize,
      visibleColumns: columnMeta.map((m) => m.id),
      wrapLines: false,
    },
  );

  const columnVisibility = useMemo<VisibilityState | undefined>(() => {
    if (!enablePreferences) return undefined;
    const vis: VisibilityState = {};
    for (const m of columnMeta) {
      vis[m.id] = m.alwaysVisible || prefs.visibleColumns.includes(m.id);
    }
    return vis;
  }, [enablePreferences, columnMeta, prefs.visibleColumns]);

  const pg = usePagination(filtered, prefs.pageSize);
  const rows = enablePagination ? pg.pageItems : filtered;

  const showControls = enablePreferences || enablePagination;

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
            {headerActions}
          </>
        }
      />

      {isLoading ? (
        <LoadingState label={`Loading ${plural}…`} />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={icon}
          title={emptyTitle}
          description={emptyDescription}
          action={headerActions}
          learnMore={docsHref}
        />
      ) : (
        <>
          {filterProperties && filterProperties.length ? (
            <PropertyFilter
              properties={filterProperties}
              tokens={tokens}
              onChange={setTokens}
              operation={operation}
              onOperationChange={setOperation}
            />
          ) : null}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              {filtered.length} of {items.length}{" "}
              {items.length === 1 ? singular : plural}
            </p>
            {showControls ? (
              <div className="flex items-center gap-2">
                {enablePagination ? (
                  <Pagination
                    currentPage={pg.page}
                    pageCount={pg.pageCount}
                    onPageChange={pg.setPage}
                  />
                ) : null}
                {enablePreferences ? (
                  <CollectionPreferences
                    value={prefs}
                    onChange={setPrefs}
                    columnOptions={columnMeta}
                    pageSizeOptions={[10, 25, 50, 100]}
                    showDensity
                  />
                ) : null}
              </div>
            ) : null}
          </div>

          <VirtualDataTable
            data={rows}
            columns={columns}
            getRowId={(o) =>
              o.metadata.uid ?? `${o.metadata.namespace}/${o.metadata.name}`
            }
            sorting={sorting}
            onSortingChange={setSorting}
            columnVisibility={columnVisibility}
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
