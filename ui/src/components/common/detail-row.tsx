import { cn } from "@/lib/utils";

/** A label/value row used in detail panels. */
export function DetailRow({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("grid grid-cols-3 gap-3 py-1.5 text-sm", className)}>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="col-span-2 min-w-0 break-words font-medium">{children}</dd>
    </div>
  );
}

/** Renders a key/value map (labels, annotations) as small pills. */
export function KeyValueList({
  data,
  emptyLabel = "None",
}: {
  data?: Record<string, string>;
  emptyLabel?: string;
}) {
  const entries = data ? Object.entries(data) : [];
  if (entries.length === 0) {
    return <span className="text-muted-foreground">{emptyLabel}</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([k, v]) => (
        <span
          key={k}
          className="inline-flex max-w-full items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs"
          title={`${k}: ${v}`}
        >
          <span className="text-muted-foreground">{k}</span>
          {v ? <span className="truncate font-medium">{v}</span> : null}
        </span>
      ))}
    </div>
  );
}
