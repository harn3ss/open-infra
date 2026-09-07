import { useEffect, useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Check } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TagsEditor, type Tag } from "@/components/common/tags-editor";
import { Spinner } from "@/components/common/states";

/** AWS's per-resource tag limit — hide "Add" past it (the BFF enforces the real bound). */
const MAX_TAGS = 50;

/**
 * The AWS "Tags" tab, shared by the User / Role / Policy detail pages. Tags are free-form
 * key/value pairs; this stages edits in the `TagsEditor` and Save PUTs the whole set to the BFF
 * (add/change/remove in one call), which stores them as openinfra.dev/tag-* annotations on the CR.
 * The annotation prefix never reaches the UI — keys shown here are clean.
 *
 * `tags` is the current set from the resource view; `save` performs the PUT; `onSaved` invalidates
 * the resource query so the tab reflects the stored set. Fully controlled and self-contained so a
 * detail page just drops it in place of the old PendingTab.
 */
export function TagsTab({
  tags,
  save,
  onSaved,
  resourceLabel,
}: {
  tags: Record<string, string>;
  save: (tags: Record<string, string>) => Promise<unknown>;
  onSaved: () => void;
  /** e.g. "user", "role", "policy" — used only in the helper copy. */
  resourceLabel: string;
}) {
  const original = useMemo(
    () => Object.entries(tags).map(([key, value]) => ({ key, value })),
    [tags],
  );

  const [rows, setRows] = useState<Tag[]>(original);
  // Re-seed from the server whenever the stored set changes (e.g. after a save, or a background
  // refetch that actually changed the data — React Query's structural sharing keeps the reference
  // stable when it did not, so this does not clobber in-progress edits on a plain poll).
  useEffect(() => {
    setRows(original);
  }, [original]);

  // Duplicate non-empty keys can't round-trip (a map keeps one) — flag before the user saves.
  const trimmedKeys = rows.map((r) => r.key.trim()).filter((k) => k !== "");
  const duplicateKey = trimmedKeys.find((k, i) => trimmedKeys.indexOf(k) !== i);

  const toMap = (): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const r of rows) {
      const k = r.key.trim();
      if (k) out[k] = r.value;
    }
    return out;
  };

  // Dirty when the cleaned set differs from the stored set (keys or values).
  const dirty = useMemo(() => {
    const next = toMap();
    const nextKeys = Object.keys(next);
    const curKeys = Object.keys(tags);
    if (nextKeys.length !== curKeys.length) return true;
    return nextKeys.some((k) => !(k in tags) || tags[k] !== next[k]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, tags]);

  const mut = useMutation({
    mutationFn: () => save(toMap()),
    onSuccess: () => onSaved(),
  });

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">Tags</h3>
          <p className="text-sm text-muted-foreground">
            Tags are key/value labels you attach to this {resourceLabel} to organize, search, and
            report on it. Keys are unique; a value may be empty.
          </p>
        </div>

        <TagsEditor value={rows} onChange={setRows} maxTags={MAX_TAGS} addLabel="Add new tag" />

        <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
          <Button
            disabled={!dirty || !!duplicateKey || mut.isPending}
            onClick={() => mut.mutate()}
          >
            {mut.isPending ? <Spinner className="size-4" /> : null}
            Save changes
          </Button>
          {dirty ? (
            <Button variant="ghost" onClick={() => setRows(original)}>
              Reset
            </Button>
          ) : null}
          {duplicateKey ? (
            <span className="text-sm text-destructive">
              Duplicate key <code className="text-xs">{duplicateKey}</code> — keys must be unique.
            </span>
          ) : null}
          {mut.isError ? (
            <span className="text-sm text-destructive">{(mut.error as Error).message}</span>
          ) : null}
          {mut.isSuccess && !dirty ? (
            <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <Check className="size-4 text-success" /> Saved
            </span>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
