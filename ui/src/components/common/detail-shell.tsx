import { type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import type { StatusTone } from "@/lib/format";

/**
 * Full-page resource detail header: a back link to the list, an icon + title +
 * status, and an actions slot — the top of every per-resource detail view.
 */
export function DetailShell({
  backTo,
  backLabel,
  icon,
  title,
  subtitle,
  status,
  actions,
  children,
}: {
  backTo: string;
  backLabel: string;
  icon: ReactNode;
  title: string;
  subtitle?: ReactNode;
  status?: { label: string; tone: StatusTone } | null;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="space-y-5">
      <Link
        to={backTo}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ChevronLeft className="size-4" /> {backLabel}
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
            {icon}
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="truncate text-xl font-semibold">{title}</h1>
              {status ? (
                <StatusBadge status={status.label} tone={status.tone} />
              ) : null}
            </div>
            {subtitle ? (
              <div className="text-sm text-muted-foreground">{subtitle}</div>
            ) : null}
          </div>
        </div>
        {actions ? (
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        ) : null}
      </div>

      {children}
    </div>
  );
}
