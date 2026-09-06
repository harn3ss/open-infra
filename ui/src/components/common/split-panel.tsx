import { type ReactNode } from "react";
import { ChevronDown, ChevronUp, X } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The AWS/Cloudscape `SplitPanel`: a collapsible panel that shows the details of
 * the currently selected list row without leaving the list ("split view"). This
 * is a self-contained, controlled, in-flow panel — place it at the bottom (or
 * side) of a list page and drive `open`/selection yourself. When collapsed it
 * shows just the header bar.
 *
 * @example
 * const [sel, setSel] = useState<Vpc | null>(null);
 * <SplitPanel open={!!sel} onOpenChange={(o) => !o && setSel(null)} header={sel?.name}>
 *   {sel ? <KeyValuePairs items={overviewOf(sel)} /> : null}
 * </SplitPanel>
 */
export function SplitPanel({
  open,
  onOpenChange,
  header,
  children,
  position = "bottom",
  emptyText = "Select an item to see its details.",
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Header content (e.g. the selected resource name). */
  header?: ReactNode;
  children?: ReactNode;
  /** `"bottom"` (default) docks below the list; `"side"` fills a right column. */
  position?: "bottom" | "side";
  emptyText?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-xl border border-border bg-card shadow-sm",
        position === "side" && "h-full",
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <button
          type="button"
          onClick={() => onOpenChange(!open)}
          aria-label={open ? "Collapse panel" : "Expand panel"}
          aria-expanded={open}
          className="rounded-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          {position === "bottom" ? (
            open ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronUp className="size-4" />
            )
          ) : (
            <ChevronDown className={cn("size-4 transition-transform", !open && "-rotate-90")} />
          )}
        </button>
        <div className="min-w-0 flex-1 truncate text-sm font-semibold">
          {header ?? "Details"}
        </div>
        {open ? (
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            aria-label="Close panel"
            className="rounded-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        ) : null}
      </div>

      {open ? (
        <div
          className={cn(
            "overflow-auto p-4",
            position === "bottom" ? "max-h-[45vh]" : "flex-1",
          )}
        >
          {children ?? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              {emptyText}
            </p>
          )}
        </div>
      ) : null}
    </div>
  );
}
