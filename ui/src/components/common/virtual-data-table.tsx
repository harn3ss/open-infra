import { useRef } from "react";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface VirtualDataTableProps<TData> {
  data: TData[];
  columns: ColumnDef<TData, unknown>[];
  /** Stable row id (e.g. uid) for keys + virtualization. */
  getRowId: (row: TData) => string;
  sorting: SortingState;
  onSortingChange: React.Dispatch<React.SetStateAction<SortingState>>;
  onRowClick?: (row: TData) => void;
  /** Approx row height in px for the virtualizer. */
  estimateRowHeight?: number;
  /** Tailwind height/maxHeight for the scroll container. */
  heightClassName?: string;
  emptyState?: React.ReactNode;
}

/**
 * A sortable, virtualized table. Renders only the visible rows, so it stays
 * smooth with thousands of pods. The scroll container owns the height; rows are
 * absolutely positioned by the virtualizer.
 */
export function VirtualDataTable<TData>({
  data,
  columns,
  getRowId,
  sorting,
  onSortingChange,
  onRowClick,
  estimateRowHeight = 44,
  heightClassName = "h-[calc(100vh-19rem)]",
  emptyState,
}: VirtualDataTableProps<TData>) {
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;
  const scrollRef = useRef<HTMLDivElement>(null);

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => estimateRowHeight,
    overscan: 12,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();
  const paddingTop = virtualRows.length > 0 ? (virtualRows[0]?.start ?? 0) : 0;
  const paddingBottom =
    virtualRows.length > 0
      ? totalSize - (virtualRows[virtualRows.length - 1]?.end ?? 0)
      : 0;

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <div ref={scrollRef} className={cn("overflow-auto", heightClassName)}>
        <table className="w-full caption-bottom text-sm">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-border">
                {headerGroup.headers.map((header) => {
                  const canSort = header.column.getCanSort();
                  const sorted = header.column.getIsSorted();
                  return (
                    <th
                      key={header.id}
                      style={{ width: header.getSize() }}
                      className="h-10 px-3 text-left align-middle text-xs font-semibold uppercase tracking-wide text-muted-foreground"
                    >
                      {header.isPlaceholder ? null : canSort ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 hover:text-foreground"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                          {sorted === "asc" ? (
                            <ArrowUp className="size-3" />
                          ) : sorted === "desc" ? (
                            <ArrowDown className="size-3" />
                          ) : (
                            <ChevronsUpDown className="size-3 opacity-40" />
                          )}
                        </button>
                      ) : (
                        flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>{emptyState}</td>
              </tr>
            ) : (
              <>
                {paddingTop > 0 ? (
                  <tr style={{ height: paddingTop }} aria-hidden />
                ) : null}
                {virtualRows.map((virtualRow) => {
                  const row = rows[virtualRow.index] as Row<TData>;
                  return (
                    <tr
                      key={row.id}
                      data-index={virtualRow.index}
                      ref={(node) => rowVirtualizer.measureElement(node)}
                      onClick={
                        onRowClick
                          ? (e) => {
                              // Don't fire the row action (YAML drawer) when the
                              // click came from an interactive control in the row —
                              // action buttons, copy buttons, and links have their
                              // own handlers and shouldn't also open the drawer.
                              if (
                                (e.target as HTMLElement).closest(
                                  "button, a, input, select, textarea, [role='button'], [role='menuitem']",
                                )
                              )
                                return;
                              onRowClick(row.original);
                            }
                          : undefined
                      }
                      className={cn(
                        "border-b border-border transition-colors hover:bg-secondary/50",
                        onRowClick && "cursor-pointer",
                      )}
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td
                          key={cell.id}
                          className="px-3 py-2 align-middle"
                          style={{ width: cell.column.getSize() }}
                        >
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext(),
                          )}
                        </td>
                      ))}
                    </tr>
                  );
                })}
                {paddingBottom > 0 ? (
                  <tr style={{ height: paddingBottom }} aria-hidden />
                ) : null}
              </>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
