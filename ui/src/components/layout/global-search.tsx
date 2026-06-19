import { Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useSearch } from "@/lib/search-context";
import { cn } from "@/lib/utils";

/** Top-bar search box that filters the current list view. */
export function GlobalSearch({ className }: { className?: string }) {
  const { query, setQuery } = useSearch();
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Filter current view…"
        className="h-9 pl-9 pr-9"
        aria-label="Filter current view"
      />
      {query ? (
        <button
          type="button"
          onClick={() => setQuery("")}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-1 text-muted-foreground hover:text-foreground"
          aria-label="Clear filter"
        >
          <X className="size-3.5" />
        </button>
      ) : null}
    </div>
  );
}
