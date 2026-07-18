import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronDown, Clock, PanelLeftClose, PanelLeftOpen, Star } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { BrandWordmark } from "@/components/layout/brand";
import { NAV_ITEMS, NAV_SECTIONS, type NavItem } from "@/components/layout/nav-items";
import { useNavPrefs } from "@/lib/use-nav-prefs";
import { useConfig } from "@/lib/config-context";
import { cn } from "@/lib/utils";

function isActive(pathname: string, to: string, matchPrefix?: boolean): boolean {
  if (to === "/") return pathname === "/";
  if (matchPrefix) return pathname === to || pathname.startsWith(`${to}/`);
  return pathname === to;
}

function activeSectionFor(pathname: string): string {
  const hit = NAV_ITEMS.find((i) => isActive(pathname, i.to, i.matchPrefix));
  return hit?.section ?? "";
}

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
  const activeSection = activeSectionFor(pathname);
  const { pins, recents, togglePin, isPinned, recordVisit } = useNavPrefs();

  const activeItem = useMemo(
    () => NAV_ITEMS.find((i) => isActive(pathname, i.to, i.matchPrefix)),
    [pathname],
  );
  useEffect(() => {
    if (activeItem) recordVisit(activeItem.to);
  }, [activeItem, recordVisit]);

  const { ungrouped, sections } = useMemo(() => {
    const ungrouped: NavItem[] = NAV_ITEMS.filter((i) => !i.section);
    const sections = NAV_SECTIONS.map((name) => ({
      name,
      items: NAV_ITEMS.filter((i) => i.section === name),
    }));
    return { ungrouped, sections };
  }, []);

  const pinnedItems = useMemo(
    () => pins.map((p) => BY_PATH[p]).filter((i): i is NavItem => Boolean(i)),
    [pins],
  );
  const recentItems = useMemo(
    () =>
      recents
        .map((p) => BY_PATH[p])
        .filter((i): i is NavItem => i != null && i.to !== activeItem?.to)
        .slice(0, 5),
    [recents, activeItem],
  );

  const [expanded, setExpanded] = useState<Record<string, boolean>>(loadExpanded);
  useEffect(() => {
    if (!activeSection) return;
    setExpanded((prev) => (prev[activeSection] ? prev : { ...prev, [activeSection]: true }));
  }, [activeSection]);

  const toggleSection = useCallback((name: string) => {
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

  function navLink(item: NavItem, opts?: { indent?: boolean; canPin?: boolean }) {
    const active = isActive(pathname, item.to, item.matchPrefix);
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
          {ungrouped.map((item) => navLink(item, { canPin: false }))}

          {cluster("Pinned", <Star className="size-3" />, pinnedItems)}
          {cluster("Recent", <Clock className="size-3" />, recentItems)}

          {collapsed
            ? NAV_ITEMS.filter((i) => i.section).map((item) => navLink(item))
            : sections.map((section) => {
                const open = Boolean(expanded[section.name]);
                const hasActive = section.name === activeSection;
                return (
                  <div key={section.name} className="pt-1">
                    <button
                      type="button"
                      onClick={() => toggleSection(section.name)}
                      aria-expanded={open}
                      className={cn(
                        "flex w-full items-center justify-between rounded-md px-3 py-1.5 text-[0.65rem] font-semibold uppercase tracking-wider transition-colors",
                        hasActive
                          ? "text-foreground/80"
                          : "text-muted-foreground/70 hover:text-foreground",
                      )}
                    >
                      <span>{section.name}</span>
                      <ChevronDown
                        className={cn(
                          "size-3.5 shrink-0 transition-transform duration-200",
                          open ? "" : "-rotate-90",
                        )}
                      />
                    </button>
                    {open ? (
                      <div className="mt-0.5 space-y-0.5">
                        {section.items.map((item) => navLink(item, { indent: true }))}
                      </div>
                    ) : null}
                  </div>
                );
              })}
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
