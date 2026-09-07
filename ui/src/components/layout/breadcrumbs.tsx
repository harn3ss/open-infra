import { Fragment } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronRight } from "lucide-react";
import {
  leafForPath,
  matchLen,
  serviceForPath,
} from "@/components/layout/nav-items";
import { cn } from "@/lib/utils";

const SEGMENT_LABELS: Record<string, string> = {
  "": "Dashboard",
  new: "Create",
  map: "Resource map",
  images: "Images",
  managed: "Managed",
};

function labelFor(segment: string): string {
  return SEGMENT_LABELS[segment] ?? decodeURIComponent(segment);
}

interface Crumb {
  label: string;
  href: string;
}

/**
 * Path-derived breadcrumbs reflecting AWS's `Service › Type › Name`. The service
 * level is resolved from the nav tree (route → service), the type from the active
 * sub-nav leaf, and the name from the trailing path segment. The last crumb is
 * the current page (not a link).
 */
export function Breadcrumbs() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const parts = pathname.split("/").filter(Boolean);

  const service = serviceForPath(pathname);
  const leaf = leafForPath(pathname);

  let crumbs: Crumb[];

  if (!service) {
    // Home, or a route not owned by any service — fall back to raw path segments.
    crumbs = [
      { label: "Dashboard", href: "/" },
      ...parts.map((part, i) => ({
        label: labelFor(part),
        href: `/${parts.slice(0, i + 1).join("/")}`,
      })),
    ];
  } else {
    crumbs = [{ label: "Dashboard", href: "/" }];
    if (service.to !== "/") {
      crumbs.push({ label: service.label, href: service.to });
    }
    // Type crumb: the sub-nav leaf, when it differs from the service landing.
    if (leaf && leaf.to !== service.to) {
      crumbs.push({ label: leaf.label, href: leaf.to });
    }

    // Name crumb: the trailing segment(s) beyond the deepest matched anchor.
    const anchors = [leaf?.to, service.to, ...(service.routePrefixes ?? [])].filter(
      (a): a is string => Boolean(a),
    );
    let consumed = "";
    let consumedLen = -1;
    for (const a of anchors) {
      const len = matchLen(pathname, a);
      if (len > consumedLen) {
        consumedLen = len;
        consumed = a;
      }
    }
    const consumedCount = consumed ? consumed.split("/").filter(Boolean).length : 0;
    const remaining = parts.slice(consumedCount);
    const name = remaining.at(-1);
    if (name !== undefined) {
      crumbs.push({ label: labelFor(name), href: pathname });
    }
  }

  return (
    <nav aria-label="Breadcrumb" className="flex items-center text-sm">
      <ol className="flex items-center gap-1">
        {crumbs.map((crumb, i) => {
          const isLast = i === crumbs.length - 1;
          return (
            <Fragment key={`${crumb.href}-${i}`}>
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
