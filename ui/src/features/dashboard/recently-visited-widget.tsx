import { Link } from "@tanstack/react-router";
import { History } from "lucide-react";
import { Widget } from "@/features/dashboard/widget";
import { useRecentlyVisited } from "@/features/dashboard/use-recently-visited";

/**
 * Recently visited — the most-recognized AWS Console Home widget. Renders the
 * services the user has opened most recently as clickable tiles. Empty until the
 * user has navigated somewhere (a fresh login shows the empty state).
 */
export function RecentlyVisitedWidget({ className }: { className?: string }) {
  const services = useRecentlyVisited(6);

  return (
    <Widget title="Recently visited" icon={History} className={className}>
      {services.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-1 py-6 text-center">
          <p className="text-sm font-medium">No history yet</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            Services you open will show up here for quick access. Pick one from{" "}
            <span className="font-medium">Services</span> below to get started.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {services.map((svc) => (
            <Link
              key={svc.to}
              to={svc.to}
              className="group flex items-center gap-3 rounded-lg border border-border p-3 transition-colors hover:border-primary/40 hover:bg-secondary/50"
            >
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <svc.icon className="size-5" />
              </div>
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{svc.label}</div>
                <div className="truncate text-xs text-muted-foreground">
                  {svc.category}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </Widget>
  );
}
