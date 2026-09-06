import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

/** A page number, or an ellipsis gap. */
type PageItem = number | "…";

function pageItems(current: number, total: number, siblings: number): PageItem[] {
  if (total <= 1) return [1];
  const first = 1;
  const last = total;
  const start = Math.max(first + 1, current - siblings);
  const end = Math.min(last - 1, current + siblings);
  const items: PageItem[] = [first];
  if (start > first + 1) items.push("…");
  for (let p = start; p <= end; p++) items.push(p);
  if (end < last - 1) items.push("…");
  if (last > first) items.push(last);
  return items;
}

/**
 * Discrete page control (Cloudscape `Pagination`): `‹ 1 2 … 9 ›`. Presentational
 * and fully controlled — pair it with {@link usePagination} (or drive it from
 * `ResourceTablePage`'s built-in pagination) to window a list.
 *
 * @example
 * const pg = usePagination(rows, 25);
 * <Pagination currentPage={pg.page} pageCount={pg.pageCount} onPageChange={pg.setPage} />
 */
export function Pagination({
  currentPage,
  pageCount,
  onPageChange,
  siblingCount = 1,
  disabled = false,
  className,
}: {
  /** 1-based current page. */
  currentPage: number;
  /** Total number of pages. */
  pageCount: number;
  onPageChange: (page: number) => void;
  /** Pages shown either side of the current one. Default 1. */
  siblingCount?: number;
  disabled?: boolean;
  className?: string;
}) {
  const items = pageItems(currentPage, Math.max(1, pageCount), siblingCount);
  const go = (p: number) => {
    if (disabled) return;
    const next = Math.min(Math.max(1, p), Math.max(1, pageCount));
    if (next !== currentPage) onPageChange(next);
  };
  const btn =
    "inline-flex h-8 min-w-8 items-center justify-center rounded-md px-2 text-sm transition-colors disabled:pointer-events-none disabled:opacity-40";
  return (
    <nav
      className={cn("flex items-center gap-1", className)}
      aria-label="Pagination"
    >
      <button
        type="button"
        className={cn(btn, "hover:bg-secondary")}
        onClick={() => go(currentPage - 1)}
        disabled={disabled || currentPage <= 1}
        aria-label="Previous page"
      >
        <ChevronLeft className="size-4" />
      </button>
      {items.map((it, i) =>
        it === "…" ? (
          <span
            key={`gap-${i}`}
            className="px-1 text-sm text-muted-foreground"
            aria-hidden
          >
            …
          </span>
        ) : (
          <button
            key={it}
            type="button"
            className={cn(
              btn,
              it === currentPage
                ? "bg-primary text-primary-foreground"
                : "hover:bg-secondary",
            )}
            onClick={() => go(it)}
            disabled={disabled}
            aria-current={it === currentPage ? "page" : undefined}
            aria-label={`Page ${it}`}
          >
            {it}
          </button>
        ),
      )}
      <button
        type="button"
        className={cn(btn, "hover:bg-secondary")}
        onClick={() => go(currentPage + 1)}
        disabled={disabled || currentPage >= pageCount}
        aria-label="Next page"
      >
        <ChevronRight className="size-4" />
      </button>
    </nav>
  );
}

export interface UsePaginationResult<T> {
  page: number;
  setPage: (page: number) => void;
  pageCount: number;
  /** The current page's slice of items. */
  pageItems: T[];
  pageSize: number;
}

/**
 * Windows a list into pages. Clamps the current page when `items`/`pageSize`
 * shrink (e.g. after filtering) so you never land on an empty out-of-range page.
 */
export function usePagination<T>(
  items: T[],
  pageSize: number,
): UsePaginationResult<T> {
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(items.length / Math.max(1, pageSize)));
  const clamped = Math.min(page, pageCount);
  const slice = useMemo(() => {
    const start = (clamped - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, clamped, pageSize]);
  return {
    page: clamped,
    setPage,
    pageCount,
    pageItems: slice,
    pageSize,
  };
}
