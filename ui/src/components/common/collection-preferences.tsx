import { useEffect, useState } from "react";
import { Settings2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useDensity, type Density } from "@/lib/use-density";
import { cn } from "@/lib/utils";

/** Persisted table display preferences (Cloudscape `CollectionPreferences`). */
export interface CollectionPreferencesValue {
  /** Rows per page. */
  pageSize: number;
  /** Column ids currently visible. */
  visibleColumns: string[];
  /** Wrap long cell text instead of truncating. */
  wrapLines: boolean;
}

/** A column offered in the visibility list. */
export interface ColumnOption {
  id: string;
  label: string;
  /** Cannot be hidden (e.g. the Name column). */
  alwaysVisible?: boolean;
}

/**
 * Persist table preferences to `localStorage` per resource kind. Mirrors
 * `useDensity`'s storage pattern; returns a `[value, setValue]` tuple.
 */
export function useCollectionPreferences(
  storageKey: string,
  defaults: CollectionPreferencesValue,
): [CollectionPreferencesValue, (v: CollectionPreferencesValue) => void] {
  const key = `openinfra:prefs:${storageKey}`;
  const [value, setValue] = useState<CollectionPreferencesValue>(() => {
    try {
      const raw = localStorage.getItem(key);
      if (raw) return { ...defaults, ...JSON.parse(raw) };
    } catch {
      /* ignore */
    }
    return defaults;
  });
  const update = (v: CollectionPreferencesValue) => {
    setValue(v);
    try {
      localStorage.setItem(key, JSON.stringify(v));
    } catch {
      /* ignore */
    }
  };
  return [value, update];
}

/**
 * The ⚙ gear that opens a preferences modal: page size, column visibility, and
 * (optionally) wrap-lines and content density. Applies on Confirm (AWS behavior);
 * Cancel discards. Pair with {@link useCollectionPreferences} to persist.
 *
 * @example
 * const [prefs, setPrefs] = useCollectionPreferences("vpcs", {
 *   pageSize: 25, visibleColumns: ["name", "cidr"], wrapLines: false,
 * });
 * <CollectionPreferences value={prefs} onChange={setPrefs}
 *   columnOptions={[{ id: "name", label: "Name", alwaysVisible: true }, { id: "cidr", label: "CIDR" }]}
 *   showDensity />
 */
export function CollectionPreferences({
  value,
  onChange,
  columnOptions,
  pageSizeOptions = [10, 25, 50, 100],
  showWrapLines = false,
  showDensity = false,
  title = "Preferences",
  triggerClassName,
}: {
  value: CollectionPreferencesValue;
  onChange: (v: CollectionPreferencesValue) => void;
  columnOptions: ColumnOption[];
  pageSizeOptions?: number[];
  showWrapLines?: boolean;
  showDensity?: boolean;
  title?: string;
  triggerClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const { density, setDensity } = useDensity();
  const [draft, setDraft] = useState<CollectionPreferencesValue>(value);
  const [draftDensity, setDraftDensity] = useState<Density>(density);

  // Re-seed the draft each time the modal opens.
  useEffect(() => {
    if (open) {
      setDraft(value);
      setDraftDensity(density);
    }
  }, [open, value, density]);

  const toggleColumn = (id: string, on: boolean) => {
    setDraft((d) => ({
      ...d,
      visibleColumns: on
        ? [...new Set([...d.visibleColumns, id])]
        : d.visibleColumns.filter((c) => c !== id),
    }));
  };

  const confirm = () => {
    onChange(draft);
    if (showDensity) setDensity(draftDensity);
    setOpen(false);
  };

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="icon-sm"
        onClick={() => setOpen(true)}
        aria-label="Preferences"
        className={triggerClassName}
      >
        <Settings2 className="size-4" />
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
          </DialogHeader>

          <div className="space-y-5">
            {/* Page size */}
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">Page size</legend>
              <div className="flex flex-wrap gap-2">
                {pageSizeOptions.map((n) => (
                  <button
                    key={n}
                    type="button"
                    onClick={() => setDraft((d) => ({ ...d, pageSize: n }))}
                    className={cn(
                      "h-8 min-w-12 rounded-md border px-3 text-sm transition-colors",
                      draft.pageSize === n
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-input hover:bg-secondary",
                    )}
                    aria-pressed={draft.pageSize === n}
                  >
                    {n}
                  </button>
                ))}
              </div>
            </fieldset>

            {/* Visible columns */}
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">Visible columns</legend>
              <div className="space-y-1.5">
                {columnOptions.map((col) => {
                  const checked =
                    col.alwaysVisible || draft.visibleColumns.includes(col.id);
                  return (
                    <label
                      key={col.id}
                      className={cn(
                        "flex items-center gap-2 text-sm",
                        col.alwaysVisible && "text-muted-foreground",
                      )}
                    >
                      <input
                        type="checkbox"
                        className="size-4 accent-primary"
                        checked={checked}
                        disabled={col.alwaysVisible}
                        onChange={(e) => toggleColumn(col.id, e.target.checked)}
                      />
                      {col.label}
                    </label>
                  );
                })}
              </div>
            </fieldset>

            {showWrapLines ? (
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-primary"
                  checked={draft.wrapLines}
                  onChange={(e) =>
                    setDraft((d) => ({ ...d, wrapLines: e.target.checked }))
                  }
                />
                Wrap lines
              </label>
            ) : null}

            {showDensity ? (
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Density</legend>
                <div className="flex gap-2">
                  {(["comfortable", "compact"] as Density[]).map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => setDraftDensity(d)}
                      className={cn(
                        "h-8 rounded-md border px-3 text-sm capitalize transition-colors",
                        draftDensity === d
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-input hover:bg-secondary",
                      )}
                      aria-pressed={draftDensity === d}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </fieldset>
            ) : null}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={confirm}>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
