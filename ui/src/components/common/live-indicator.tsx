import { cn } from "@/lib/utils";

/** A small "LIVE" pill indicating an active SSE watch stream. */
export function LiveIndicator({
  live,
  className,
}: {
  live: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium",
        live
          ? "bg-success/15 text-success"
          : "bg-muted text-muted-foreground",
        className,
      )}
      title={live ? "Live updates via watch stream" : "Reconnecting…"}
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          live ? "bg-success animate-pulse" : "bg-muted-foreground",
        )}
      />
      {live ? "Live" : "Offline"}
    </span>
  );
}
