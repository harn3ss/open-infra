import { Fragment } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

const SEGMENT_LABELS: Record<string, string> = {
  "": "Dashboard",
  applications: "Applications",
  workloads: "Workloads",
  nodes: "Nodes",
  network: "Network",
  monitoring: "Monitoring",
};

function labelFor(segment: string): string {
  return SEGMENT_LABELS[segment] ?? decodeURIComponent(segment);
}

/** Path-derived breadcrumbs. The last crumb is the current page (not a link). */
export function Breadcrumbs() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const parts = pathname.split("/").filter(Boolean);

  const crumbs = [
    { label: "Dashboard", href: "/" },
    ...parts.map((part, i) => ({
      label: labelFor(part),
      href: `/${parts.slice(0, i + 1).join("/")}`,
    })),
  ];

  return (
    <nav aria-label="Breadcrumb" className="flex items-center text-sm">
      <ol className="flex items-center gap-1">
        {crumbs.map((crumb, i) => {
          const isLast = i === crumbs.length - 1;
          return (
            <Fragment key={crumb.href}>
              {i > 0 ? (
                <ChevronRight className="size-3.5 text-muted-foreground/60" />
              ) : null}
              <li>
                {isLast ? (
                  <span className="font-medium text-foreground" aria-current="page">
                    {crumb.label}
                  </span>
                ) : (
                  <Link
                    to={crumb.href}
                    className={cn(
                      "text-muted-foreground transition-colors hover:text-foreground",
                    )}
                  >
                    {crumb.label}
                  </Link>
                )}
              </li>
            </Fragment>
          );
        })}
      </ol>
    </nav>
  );
}
