import { Fragment } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { BrandWordmark } from "@/components/layout/brand";
import { NAV_ITEMS } from "@/components/layout/nav-items";
import { useConfig } from "@/lib/config-context";
import { cn } from "@/lib/utils";

function isActive(pathname: string, to: string, matchPrefix?: boolean): boolean {
  if (to === "/") return pathname === "/";
  if (matchPrefix) return pathname === to || pathname.startsWith(`${to}/`);
  return pathname === to;
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

      <nav className="flex-1 space-y-1 overflow-y-auto p-2">
        <TooltipProvider delayDuration={0}>
          {NAV_ITEMS.map((item, i) => {
            const active = isActive(pathname, item.to, item.matchPrefix);
            const showSection =
              !collapsed &&
              item.section &&
              item.section !== NAV_ITEMS[i - 1]?.section;
            const link = (
              <Link
                to={item.to}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  collapsed && "justify-center px-0",
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
            return (
              <Fragment key={item.to}>
                {showSection ? (
                  <div className="px-3 pb-1 pt-3 text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground/70">
                    {item.section}
                  </div>
                ) : null}
                {collapsed ? (
                  <Tooltip>
                    <TooltipTrigger asChild>{link}</TooltipTrigger>
                    <TooltipContent side="right">{item.label}</TooltipContent>
                  </Tooltip>
                ) : (
                  link
                )}
              </Fragment>
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
