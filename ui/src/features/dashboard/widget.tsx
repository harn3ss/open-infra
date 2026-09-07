import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowRight, type LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * A Console-Home widget card: a titled, bordered container with an optional
 * right-side header slot (e.g. a live pill or count) and an optional footer link
 * to the full view — the shape every AWS Console Home widget shares. Colors and
 * fonts are ours; the layout grammar is AWS's.
 */
export function Widget({
  title,
  icon: Icon,
  headerAction,
  footerHref,
  footerLabel,
  className,
  bodyClassName,
  children,
}: {
  title: string;
  icon?: LucideIcon;
  /** Right-aligned header content (LiveIndicator, a count pill, etc.). */
  headerAction?: ReactNode;
  /** When set, renders a "View all"-style footer link to this route. */
  footerHref?: string;
  footerLabel?: string;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  return (
    <Card className={cn("flex h-full flex-col overflow-hidden", className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border px-5 py-3">
        <div className="flex min-w-0 items-center gap-2 text-sm font-semibold">
          {Icon ? (
            <Icon className="size-4 shrink-0 text-muted-foreground" />
          ) : null}
          <span className="truncate">{title}</span>
        </div>
        {headerAction}
      </div>
      <div className={cn("flex flex-1 flex-col p-5", bodyClassName)}>
        {children}
      </div>
      {footerHref ? (
        <Link
          to={footerHref}
          className="flex items-center gap-1 border-t border-border px-5 py-2.5 text-sm font-medium text-primary transition-colors hover:bg-secondary/50"
        >
          {footerLabel ?? "View all"}
          <ArrowRight className="size-3.5" />
        </Link>
      ) : null}
    </Card>
  );
}
