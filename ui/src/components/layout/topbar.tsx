import { CircleDot, Search } from "lucide-react";
import { Breadcrumbs } from "@/components/layout/breadcrumbs";
import { GlobalSearch } from "@/components/layout/global-search";
import { openCommandPalette } from "@/components/layout/command-palette";
import { NamespaceSwitcher } from "@/components/layout/namespace-switcher";
import { SettingsMenu } from "@/components/layout/settings-menu";
import { Separator } from "@/components/ui/separator";
import { useConfig } from "@/lib/config-context";

const IS_MAC =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

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
        <button
          type="button"
          onClick={openCommandPalette}
          className="hidden h-9 w-56 items-center gap-2 rounded-md border border-border bg-secondary/50 px-3 text-sm text-muted-foreground transition-colors hover:bg-secondary lg:flex"
          aria-label="Jump to a page"
        >
          <Search className="size-4 shrink-0" />
          <span>Jump to…</span>
          <kbd className="ml-auto rounded border border-border bg-background px-1.5 py-0.5 text-[0.65rem]">
            {IS_MAC ? "⌘" : "Ctrl"} K
          </kbd>
        </button>
        <GlobalSearch className="hidden w-56 sm:block lg:w-48" />
        <NamespaceSwitcher />
        <Separator orientation="vertical" className="h-6" />
        <SettingsMenu />
      </div>
    </header>
  );
}
