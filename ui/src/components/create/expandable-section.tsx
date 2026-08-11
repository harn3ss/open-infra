import { type ReactNode, useState } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Progressive-disclosure section (Cloudscape "Additional settings" pattern): a collapsed-by-default
 * region that holds fields with safe defaults, so the primary form stays short. Label it with a noun,
 * not a verb.
 */
export function ExpandableSection({
  title,
  description,
  defaultExpanded = false,
  count,
  children,
}: {
  title: string;
  description?: string;
  defaultExpanded?: boolean;
  count?: number;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultExpanded);
  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 p-4 text-left"
        aria-expanded={open}
      >
        <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
        <span className="font-medium">{title}</span>
        {count != null && count > 0 ? (
          <span className="text-xs text-muted-foreground">({count})</span>
        ) : null}
        {description ? <span className="ml-2 truncate text-xs text-muted-foreground">{description}</span> : null}
      </button>
      {open ? <div className="space-y-4 border-t border-border p-4">{children}</div> : null}
    </div>
  );
}
