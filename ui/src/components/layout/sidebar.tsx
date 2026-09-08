import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  Star,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { BrandWordmark } from "@/components/layout/brand";
import {
  CATEGORIES,
  NAV_ITEMS,
  SERVICES,
  isActive,
  isMultiService,
  leafForPath,
  matchLen,
  navItemVisible,
  serviceForPath,
  serviceVisible,
  type NavItem,
  type Service,
} from "@/components/layout/nav-items";
import { useNavPrefs } from "@/lib/use-nav-prefs";
import { useConfig } from "@/lib/config-context";
import { cn } from "@/lib/utils";

const STORE_KEY = "openinfra:nav:expanded";

function loadExpanded(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? (JSON.parse(raw) as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}

const BY_PATH: Record<string, NavItem> = Object.fromEntries(
  NAV_ITEMS.map((i) => [i.to, i]),
);

export function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const config = useConfig();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { pins, recents, togglePin, isPinned, recordVisit } = useNavPrefs();

  // Which service owns the current route (drives the launcher/service-mode swap).
  const activeService = useMemo(() => serviceForPath(pathname), [pathname]);
  const activeCategory = activeService?.category ?? "";

  // The active leaf (longest-matching flat/child route) — for pin/recent + highlight.
  const activeLeaf = useMemo(() => {
    let best: NavItem | undefined;
    let bestLen = -1;
    for (const it of NAV_ITEMS) {
      const len = matchLen(pathname, it.to);
      if (len > bestLen) {
        bestLen = len;
        best = it;
      }
    }
    return bestLen >= 0 ? best : undefined;
  }, [pathname]);
  useEffect(() => {
    if (activeLeaf) recordVisit(activeLeaf.to);
  }, [activeLeaf, recordVisit]);

  // "‹ All services" override: shows the launcher even while inside a multi
  // service. It survives an in-place All-services click (no route change), and a
  // real navigation clears it so entering a service reveals that service's sub-nav.
  const [showAllServices, setShowAllServices] = useState(false);
  useEffect(() => {
    setShowAllServices(false);
  }, [pathname]);

  const inServiceMode = !showAllServices && isMultiService(activeService);

  // Visible services + which categories are non-empty (config-gated, e.g. Chaos).
  const servicesByCategory = useMemo(() => {
    const visible = SERVICES.filter((s) => serviceVisible(s, config));
    return CATEGORIES.map((name) => ({
      name,
      services: visible.filter((s) => s.category === name),
    })).filter((c) => c.services.length > 0);
  }, [config]);

  const activeChildLeaf = useMemo(() => leafForPath(pathname), [pathname]);

  const pinnedItems = useMemo(
    () =>
      pins
        .map((p) => BY_PATH[p])
        .filter((i): i is NavItem => i != null && navItemVisible(i, config)),
    [pins, config],
  );
  const recentItems = useMemo(
    () =>
      recents
        .map((p) => BY_PATH[p])
        .filter(
          (i): i is NavItem =>
            i != null && i.to !== activeLeaf?.to && navItemVisible(i, config),
        )
        .slice(0, 5),
    [recents, activeLeaf, config],
  );

  const [expanded, setExpanded] = useState<Record<string, boolean>>(loadExpanded);
  useEffect(() => {
    if (!activeCategory) return;
    setExpanded((prev) => (prev[activeCategory] ? prev : { ...prev, [activeCategory]: true }));
  }, [activeCategory]);

  const toggleCategory = useCallback((name: string) => {
    setExpanded((prev) => {
      const next = { ...prev, [name]: !prev[name] };
      try {
        localStorage.setItem(STORE_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  // A leaf link (multi-service child, flat-service list, or a pin/recent entry).
  function navLink(
    item: NavItem,
    opts?: { indent?: boolean; canPin?: boolean; active?: boolean },
  ) {
    const active = opts?.active ?? isActive(pathname, item.to);
    const link = (
      <Link
        to={item.to}
        className={cn(
          "flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
          collapsed && "justify-center px-0",
          !collapsed && opts?.indent && "pl-9",
          !collapsed && "pr-8",
          active
            ? "bg-primary/15 text-primary"
            : "text-sidebar-foreground hover:bg-secondary hover:text-foreground",
        )}
        aria-current={active ? "page" : undefined}
      >
        <item.icon className="size-[1.15rem] shrink-0" />
        {!collapsed ? <span className="truncate">{item.label}</span> : null}
      </Link>
    );

    if (collapsed) {
      return (
        <Tooltip key={item.to}>
          <TooltipTrigger asChild>{link}</TooltipTrigger>
          <TooltipContent side="right">{item.label}</TooltipContent>
        </Tooltip>
      );
    }

    const pinned = isPinned(item.to);
    return (
      <div key={item.to} className="group/nav relative">
        {link}
        {opts?.canPin !== false ? (
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              togglePin(item.to);
            }}
            aria-label={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
            title={pinned ? "Unpin" : "Pin to top"}
            className={cn(
              "absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 transition-opacity",
              pinned
                ? "text-primary opacity-100"
                : "text-muted-foreground opacity-0 hover:text-foreground group-hover/nav:opacity-100",
            )}
          >
            <Star className={cn("size-3.5", pinned && "fill-current")} />
          </button>
        ) : null}
      </div>
    );
  }

  // A launcher row for a whole service. Multi services show a ▸ to signal you
  // *enter* them; clicking navigates to the landing and (via the pathname change)
  // the rail swaps to that service's sub-nav.
  function serviceRow(svc: Service) {
    const active = serviceForPath(pathname)?.label === svc.label;
    const multi = isMultiService(svc);
    const link = (
      <Link
        to={svc.to}
        onClick={() => setShowAllServices(false)}
        className={cn(
          "flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
          collapsed ? "justify-center px-0" : "pl-9 pr-8",
          active
            ? "bg-primary/15 text-primary"
            : "text-sidebar-foreground hover:bg-secondary hover:text-foreground",
        )}
        aria-current={active ? "page" : undefined}
      >
        <svc.icon className="size-[1.15rem] shrink-0" />
        {!collapsed ? (
          <>
            <span className="truncate">{svc.label}</span>
            {multi ? (
              <ChevronRight className="ml-auto size-3.5 shrink-0 opacity-40" />
            ) : null}
          </>
        ) : null}
      </Link>
    );

    if (collapsed) {
      return (
        <Tooltip key={svc.to}>
          <TooltipTrigger asChild>{link}</TooltipTrigger>
          <TooltipContent side="right">{svc.label}</TooltipContent>
        </Tooltip>
      );
    }

    const pinned = isPinned(svc.to);
    return (
      <div key={svc.to} className="group/nav relative">
        {link}
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            togglePin(svc.to);
          }}
          aria-label={pinned ? `Unpin ${svc.label}` : `Pin ${svc.label}`}
          title={pinned ? "Unpin" : "Pin to top"}
          className={cn(
            "absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 transition-opacity",
            pinned
              ? "text-primary opacity-100"
              : "text-muted-foreground opacity-0 hover:text-foreground group-hover/nav:opacity-100",
          )}
        >
          <Star className={cn("size-3.5", pinned && "fill-current")} />
        </button>
      </div>
    );
  }

  function cluster(label: string, icon: ReactNode, items: NavItem[]) {
    if (collapsed || items.length === 0) return null;
    return (
      <div className="pb-1">
        <div className="flex items-center gap-1.5 px-3 pb-0.5 pt-1 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground/70">
          {icon}
          {label}
        </div>
        {items.map((item) => navLink(item))}
      </div>
    );
  }

  // ── Service mode: the rail is that service's own sub-nav ──────────────────────
  function renderServiceMode(svc: Service) {
    const children = (svc.children ?? []).filter((c) => navItemVisible(c, config));
    if (collapsed) {
      return (
        <>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                onClick={() => setShowAllServices(true)}
                aria-label="All services"
                className="flex w-full items-center justify-center rounded-lg py-1.5 text-muted-foreground hover:bg-secondary hover:text-foreground"
              >
                <ChevronLeft className="size-[1.15rem]" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="right">All services</TooltipContent>
          </Tooltip>
          {children.map((child) =>
            navLink(child, { active: activeChildLeaf?.to === child.to }),
          )}
        </>
      );
    }
    return (
      <>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setShowAllServices(true);
          }}
          className="mb-1 flex w-full items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
        >
          <ChevronLeft className="size-3.5 shrink-0" />
          All services
        </button>
        <div className="flex items-center gap-2 px-3 pb-1 pt-0.5">
          <svc.icon className="size-4 shrink-0 text-primary" />
          <span className="truncate text-sm font-semibold text-foreground">{svc.label}</span>
        </div>
        <div className="space-y-0.5">
          {children.map((child) =>
            navLink(child, { active: activeChildLeaf?.to === child.to }),
          )}
        </div>
      </>
    );
  }

  // ── Launcher mode: all services grouped by category ──────────────────────────
  function renderLauncher() {
    if (collapsed) {
      return SERVICES.filter((s) => serviceVisible(s, config)).map((svc) =>
        serviceRow(svc),
      );
    }
    return servicesByCategory.map((cat) => {
      const open = expanded[cat.name] !== false; // default: expanded
      const hasActive = cat.name === activeCategory;
      return (
        <div key={cat.name} className="pt-1">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              toggleCategory(cat.name);
            }}
            aria-expanded={open}
            className={cn(
              "flex w-full items-center justify-between gap-2 rounded-md px-3 py-1.5 text-left text-[0.65rem] font-semibold uppercase tracking-wider transition-colors",
              hasActive
                ? "text-foreground/80"
                : "text-muted-foreground/70 hover:text-foreground",
            )}
          >
            <span className="min-w-0 flex-1 text-left">{cat.name}</span>
            <ChevronDown
              className={cn(
                "size-3.5 shrink-0 transition-transform duration-200",
                open ? "" : "-rotate-90",
              )}
            />
          </button>
          {open ? (
            <div className="mt-0.5 space-y-0.5">
              {cat.services.map((svc) => serviceRow(svc))}
            </div>
          ) : null}
        </div>
      );
    });
  }

  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200",
        collapsed ? "w-[4.25rem]" : "w-60",
      )}
    >
      <div
        className={cn(
          "flex h-14 items-center border-b border-sidebar-border px-3",
          collapsed ? "justify-center" : "justify-between",
        )}
      >
        {!collapsed ? <BrandWordmark /> : <BrandWordmark collapsed />}
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
        <TooltipProvider delayDuration={0}>
          {inServiceMode && activeService ? (
            renderServiceMode(activeService)
          ) : (
            <>
              {navLink({ label: "Dashboard", to: "/", icon: LayoutDashboard }, { canPin: false })}
              {cluster("Pinned", <Star className="size-3" />, pinnedItems)}
              {cluster("Recent", <Clock className="size-3" />, recentItems)}
              {renderLauncher()}
            </>
          )}
        </TooltipProvider>
      </nav>

      <div className="border-t border-sidebar-border p-2">
        {!collapsed ? (
          <div className="px-2 pb-2 text-[0.7rem] text-muted-foreground">
            <div className="truncate" title={config.clusterName}>
              {config.clusterName || "cluster"}
            </div>
            <div className="opacity-70">v{config.version || "dev"}</div>
          </div>
        ) : null}
        <Button
          variant="ghost"
          size={collapsed ? "icon" : "sm"}
          onClick={onToggle}
          className={cn("w-full", collapsed && "justify-center")}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <PanelLeftOpen className="size-4" />
          ) : (
            <>
              <PanelLeftClose className="size-4" />
              <span>Collapse</span>
            </>
          )}
        </Button>
      </div>
    </aside>
  );
}
