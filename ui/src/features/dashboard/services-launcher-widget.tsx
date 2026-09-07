import { Link } from "@tanstack/react-router";
import { LayoutGrid } from "lucide-react";
import { Widget } from "@/features/dashboard/widget";
import {
  CATEGORIES,
  SERVICES,
  serviceVisible,
} from "@/components/layout/nav-items";
import { useConfig } from "@/lib/config-context";

/**
 * Services launcher — AWS Console Home's "View all services". Every service,
 * grouped by category (same two-level model as the nav), so the home doubles as
 * a launcher. Flag-gated services (e.g. Chaos) appear only when enabled.
 */
export function ServicesLauncherWidget({ className }: { className?: string }) {
  const config = useConfig();
  const groups = CATEGORIES.map((category) => ({
    category,
    services: SERVICES.filter(
      (s) => s.category === category && serviceVisible(s, config),
    ),
  })).filter((g) => g.services.length > 0);

  return (
    <Widget title="Services" icon={LayoutGrid} className={className}>
      <div className="gap-x-8 sm:columns-2 lg:columns-3 xl:columns-4">
        {groups.map((group) => (
          <div key={group.category} className="mb-6 break-inside-avoid">
            <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {group.category}
            </div>
            <ul className="space-y-0.5">
              {group.services.map((svc) => (
                <li key={svc.to}>
                  <Link
                    to={svc.to}
                    className="group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-secondary"
                  >
                    <svc.icon className="size-4 shrink-0 text-muted-foreground transition-colors group-hover:text-primary" />
                    <span className="truncate">{svc.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Widget>
  );
}
