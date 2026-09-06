import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

/** One attribute in a {@link KeyValuePairs} grid. */
export interface KeyValuePair {
  /** Muted label shown above the value. */
  label: ReactNode;
  /** The value. Falsy values render as an em-dash unless `value` is `0`/`false`. */
  value: ReactNode;
  /** Optional trailing node next to the label (e.g. an `<InfoLink />`). */
  info?: ReactNode;
}

const COLS: Record<number, string> = {
  1: "sm:grid-cols-1",
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-2 lg:grid-cols-3",
  4: "sm:grid-cols-2 lg:grid-cols-4",
};

/**
 * The AWS/Cloudscape `KeyValuePairs` / `ColumnLayout variant="text-grid"` detail
 * grid: attribute pairs laid out in 1–4 responsive columns, each a muted label
 * above an emphasized value. Use it for a detail page's Overview container (drop
 * it inside a `Card`/`CardContent` with a section header) instead of the
 * single-column {@link DetailRow} `dl` when a resource has several attributes.
 *
 * @example
 * <Card><CardContent>
 *   <KeyValuePairs columns={3} items={[
 *     { label: "VPC ID", value: <span className="inline-flex items-center gap-1">{id}<CopyButton value={id} /></span> },
 *     { label: "CIDR", value: "10.0.0.0/16" },
 *     { label: "Status", value: <StatusBadge status="Available" tone="success" /> },
 *   ]} />
 * </CardContent></Card>
 */
export function KeyValuePairs({
  items,
  columns = 3,
  className,
}: {
  items: KeyValuePair[];
  /** Column count on wide viewports (collapses to 1 on narrow). Default 3. */
  columns?: 1 | 2 | 3 | 4;
  className?: string;
}) {
  return (
    <dl className={cn("grid grid-cols-1 gap-x-8 gap-y-4", COLS[columns], className)}>
      {items.map((item, i) => (
        <div key={i} className="min-w-0 space-y-1">
          <dt className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            {item.label}
            {item.info}
          </dt>
          <dd className="min-w-0 break-words text-sm font-medium text-foreground">
            {isEmpty(item.value) ? (
              <span className="text-muted-foreground">—</span>
            ) : (
              item.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function isEmpty(v: ReactNode): boolean {
  return v === null || v === undefined || v === "";
}
