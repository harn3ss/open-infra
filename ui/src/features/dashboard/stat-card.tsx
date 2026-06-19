import { Link } from "@tanstack/react-router";
import { ArrowUpRight, type LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

/** A clickable summary tile for a resource count, with a small sub-stat. */
export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  to,
  loading,
  error,
  accent = "primary",
}: {
  label: string;
  value: number;
  sub?: string;
  icon: LucideIcon;
  to: string;
  loading?: boolean;
  error?: boolean;
  accent?: "primary" | "accent" | "success" | "warning";
}) {
  const accentClasses: Record<string, string> = {
    primary: "bg-primary/10 text-primary",
    accent: "bg-accent/10 text-accent",
    success: "bg-success/10 text-success",
    warning: "bg-warning/10 text-warning",
  };

  return (
    <Card className="group relative overflow-hidden transition-colors hover:border-primary/40">
      <Link to={to} className="block p-5">
        <div className="flex items-start justify-between">
          <div
            className={cn(
              "flex size-10 items-center justify-center rounded-lg",
              accentClasses[accent],
            )}
          >
            <Icon className="size-5" />
          </div>
          <ArrowUpRight className="size-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
        </div>
        <div className="mt-4">
          {loading ? (
            <Skeleton className="h-8 w-16" />
          ) : error ? (
            <div className="text-2xl font-semibold text-muted-foreground">—</div>
          ) : (
            <div className="text-3xl font-semibold tracking-tight tabular-nums">
              {value}
            </div>
          )}
          <div className="mt-1 text-sm font-medium text-muted-foreground">
            {label}
          </div>
          {sub && !loading && !error ? (
            <div className="mt-0.5 text-xs text-muted-foreground/80">{sub}</div>
          ) : null}
          {error ? (
            <div className="mt-0.5 text-xs text-destructive">Unavailable</div>
          ) : null}
        </div>
      </Link>
    </Card>
  );
}
