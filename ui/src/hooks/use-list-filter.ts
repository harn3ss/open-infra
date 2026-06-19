import { useMemo } from "react";
import { useSearch } from "@/lib/search-context";

/**
 * Filters a list by the global search query against caller-provided haystacks.
 * The match is a case-insensitive substring across all returned strings.
 */
export function useListFilter<T>(
  items: T[],
  getHaystacks: (item: T) => Array<string | undefined>,
): { filtered: T[]; query: string } {
  const { query } = useSearch();
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) =>
      getHaystacks(item).some((h) => h?.toLowerCase().includes(q)),
    );
    // getHaystacks is assumed stable enough for list rendering.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, query]);
  return { filtered, query };
}
