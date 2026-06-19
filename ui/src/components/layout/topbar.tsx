import { CircleDot } from "lucide-react";
import { Breadcrumbs } from "@/components/layout/breadcrumbs";
import { GlobalSearch } from "@/components/layout/global-search";
import { NamespaceSwitcher } from "@/components/layout/namespace-switcher";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { Separator } from "@/components/ui/separator";
import { useConfig } from "@/lib/config-context";

export function Topbar() {
  const config = useConfig();
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur">
      <div className="flex min-w-0 items-center gap-3">
        <div
          className="flex items-center gap-2 rounded-md bg-secondary px-2.5 py-1 text-sm font-medium"
          title="Connected cluster"
        >
          <CircleDot className="size-3.5 text-accent" />
          <span className="max-w-[12rem] truncate">
            {config.clusterName || "cluster"}
          </span>
        </div>
        <Separator orientation="vertical" className="h-6" />
        <div className="hidden md:block">
          <Breadcrumbs />
        </div>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <GlobalSearch className="hidden w-64 sm:block" />
        <NamespaceSwitcher />
        <Separator orientation="vertical" className="h-6" />
        <ThemeToggle />
      </div>
    </header>
  );
}
