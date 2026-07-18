import { useEffect, useMemo, useRef, useState } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Link } from "@tanstack/react-router";
import { CornerDownLeft, Search } from "lucide-react";
import { NAV_ITEMS, type NavItem } from "@/components/layout/nav-items";
import { cn } from "@/lib/utils";

// Global command palette — jump to any destination by keyboard (⌘K / Ctrl+K).
// Decoupled trigger: any component can dispatch this event to open it.
export const COMMAND_PALETTE_EVENT = "openinfra:command-palette";
export function openCommandPalette() {
  window.dispatchEvent(new Event(COMMAND_PALETTE_EVENT));
}

function score(item: NavItem, q: string): boolean {
  if (!q) return true;
  const hay = `${item.label} ${item.section ?? ""}`.toLowerCase();
  return q.split(/\s+/).every((w) => hay.includes(w));
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const rowRefs = useRef<Array<HTMLAnchorElement | null>>([]);

  // ⌘K / Ctrl+K toggles; the custom event opens (for the top-bar button).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    function onOpen() {
      setOpen(true);
    }
    window.addEventListener("keydown", onKey);
    window.addEventListener(COMMAND_PALETTE_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(COMMAND_PALETTE_EVENT, onOpen);
    };
  }, []);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    return NAV_ITEMS.filter((i) => score(i, q));
  }, [query]);

  // reset selection as results change; clear query when closed
  useEffect(() => setIndex(0), [query, open]);
  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);
  useEffect(() => {
    rowRefs.current[index]?.scrollIntoView({ block: "nearest" });
  }, [index]);

  function onInputKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      rowRefs.current[index]?.click();
    }
  }

  return (
    <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <DialogPrimitive.Content
          className="fixed left-1/2 top-[15vh] z-50 w-full max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border border-border bg-popover shadow-2xl duration-150 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95"
          onOpenAutoFocus={(e) => {
            // focus our input, not the first row
            e.preventDefault();
            (e.currentTarget as HTMLElement)
              .querySelector<HTMLInputElement>("input")
              ?.focus();
          }}
        >
          <DialogPrimitive.Title className="sr-only">
            Jump to a page
          </DialogPrimitive.Title>

          <div className="flex items-center gap-3 border-b border-border px-4">
            <Search className="size-4 shrink-0 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder="Jump to a page…"
              className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              aria-label="Jump to a page"
            />
            <kbd className="hidden rounded border border-border px-1.5 py-0.5 text-[0.65rem] text-muted-foreground sm:inline">
              Esc
            </kbd>
          </div>

          <div className="max-h-[min(24rem,60vh)] overflow-y-auto p-2">
            {results.length === 0 ? (
              <div className="px-3 py-8 text-center text-sm text-muted-foreground">
                No matches for “{query}”.
              </div>
            ) : (
              results.map((item, i) => {
                const active = i === index;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    onClick={() => setOpen(false)}
                    onMouseMove={() => setIndex(i)}
                    className={cn(
                      "flex items-center gap-3 rounded-lg px-3 py-2 text-sm",
                      active
                        ? "bg-primary/15 text-primary"
                        : "text-foreground hover:bg-secondary",
                    )}
                  >
                    <item.icon className="size-4 shrink-0 opacity-80" />
                    <span className="font-medium">{item.label}</span>
                    {item.section ? (
                      <span className="ml-auto text-xs text-muted-foreground">
                        {item.section}
                      </span>
                    ) : null}
                  </Link>
                );
              })
            )}
          </div>

          <div className="flex items-center gap-4 border-t border-border px-4 py-2 text-[0.7rem] text-muted-foreground">
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-border px-1">↑</kbd>
              <kbd className="rounded border border-border px-1">↓</kbd>
              to navigate
            </span>
            <span className="flex items-center gap-1">
              <CornerDownLeft className="size-3" /> to open
            </span>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
