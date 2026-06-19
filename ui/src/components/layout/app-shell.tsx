import { useState } from "react";
import { Outlet } from "@tanstack/react-router";
import { Menu } from "lucide-react";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { BrandWordmark } from "@/components/layout/brand";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

/**
 * The console frame: a fixed sidebar (collapsible on desktop, a drawer on
 * mobile), a sticky top bar, and a scrolling content area where routes render.
 */
export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex h-screen w-full overflow-hidden oi-aurora">
      {/* Desktop sidebar */}
      <div className="hidden md:block">
        <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      </div>

      {/* Mobile sidebar drawer */}
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-64 p-0">
          <SheetHeader className="border-b border-border">
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <BrandWordmark />
          </SheetHeader>
          <div className="flex-1 overflow-y-auto" onClick={() => setMobileOpen(false)}>
            <Sidebar collapsed={false} onToggle={() => undefined} />
          </div>
        </SheetContent>
      </Sheet>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center md:hidden">
          <Button
            variant="ghost"
            size="icon"
            className="ml-2 mt-2"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="size-5" />
          </Button>
        </div>
        <Topbar />
        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
