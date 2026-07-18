import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronDown, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { BrandWordmark } from "@/components/layout/brand";
import { NAV_ITEMS, NAV_SECTIONS, type NavItem } from "@/components/layout/nav-items";
import { useConfig } from "@/lib/config-context";
import { cn } from "@/lib/utils";

function isActive(pathname: string, to: string, matchPrefix?: boolean): boolean {
  if (to === "/") return pathname === "/";
  if (matchPrefix) return pathname === to || pathname.startsWith(`${to}/`);
  return pathname === to;
}

/** The section that owns the current route (or "" for ungrouped/Dashboard). */
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

  // Ungrouped items (Dashboard) first, then items bucketed by section in order.
  const { ungrouped, sections } = useMemo(() => {
    const ungrouped: NavItem[] = NAV_ITEMS.filter((i) => !i.section);
    const sections = NAV_SECTIONS.map((name) => ({
      name,
      items: NAV_ITEMS.filter((i) => i.section === name),
    }));
    return { ungrouped, sections };
  }, []);

  // Expand/collapse state, persisted. Default collapsed; the section owning the
  // current route auto-expands (Cloudscape heuristic). User toggles are remembered.
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

  function navLink(item: NavItem, indent = false) {
    const active = isActive(pathname, item.to, item.matchPrefix);
    const link = (
      <Link
        to={item.to}
        className={cn(
          "flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
          collapsed && "justify-center px-0",
          !collapsed && indent && "pl-9",
          active
            ? "bg-primary/15 text-primary"
            : "text-sidebar-foreground hover:bg-secondary hover:text-foreground",
        )}
        aria-current={active ? "page" : undefined}
      >
        <item.icon className="size-[1.15rem] shrink-0" />
        {!collapsed ? <span>{item.label}</span> : null}
      </Link>
    );
    return collapsed ? (
      <Tooltip key={item.to}>
        <TooltipTrigger asChild>{link}</TooltipTrigger>
        <TooltipContent side="right">{item.label}</TooltipContent>
      </Tooltip>
    ) : (
      <Fragment key={item.to}>{link}</Fragment>
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
          {ungrouped.map((item) => navLink(item))}

          {collapsed
            ? // Icon rail: sections don't apply — flat icon list with tooltips.
              NAV_ITEMS.filter((i) => i.section).map((item) => navLink(item))
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
                        {section.items.map((item) => navLink(item, true))}
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
