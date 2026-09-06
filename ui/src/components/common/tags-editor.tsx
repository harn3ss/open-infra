import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

/** A single key/value tag. */
export interface Tag {
  key: string;
  value: string;
}

/**
 * The AWS/Cloudscape tag editor: add/remove key–value rows. Fully controlled —
 * hold the `Tag[]` in the parent form and persist it however the resource
 * expects (labels, annotations, a `tags` map). Empty rows are the user's to fill;
 * strip blank keys on submit.
 *
 * @example
 * const [tags, setTags] = useState<Tag[]>([]);
 * <TagsEditor value={tags} onChange={setTags} />
 * // on submit: Object.fromEntries(tags.filter(t => t.key).map(t => [t.key, t.value]))
 */
export function TagsEditor({
  value,
  onChange,
  keyPlaceholder = "Key",
  valuePlaceholder = "Value",
  addLabel = "Add new tag",
  maxTags,
  className,
}: {
  value: Tag[];
  onChange: (tags: Tag[]) => void;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  addLabel?: string;
  /** Cap the number of rows (hides "Add" at the limit). */
  maxTags?: number;
  className?: string;
}) {
  const update = (i: number, patch: Partial<Tag>) =>
    onChange(value.map((t, idx) => (idx === i ? { ...t, ...patch } : t)));
  const remove = (i: number) => onChange(value.filter((_, idx) => idx !== i));
  const add = () => onChange([...value, { key: "", value: "" }]);

  const atLimit = maxTags != null && value.length >= maxTags;

  return (
    <div className={cn("space-y-3", className)}>
      {value.length > 0 ? (
        <div className="space-y-2">
          {/* Column labels */}
          <div className="grid grid-cols-[1fr_1fr_auto] gap-2 text-xs font-medium text-muted-foreground">
            <span>Key</span>
            <span>Value</span>
            <span className="sr-only">Actions</span>
          </div>
          {value.map((tag, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_auto] items-center gap-2">
              <Input
                value={tag.key}
                onChange={(e) => update(i, { key: e.target.value })}
                placeholder={keyPlaceholder}
                aria-label={`Tag ${i + 1} key`}
              />
              <Input
                value={tag.value}
                onChange={(e) => update(i, { value: e.target.value })}
                placeholder={valuePlaceholder}
                aria-label={`Tag ${i + 1} value`}
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={() => remove(i)}
                aria-label={`Remove tag ${i + 1}`}
                className="text-muted-foreground hover:text-destructive"
              >
                <Trash2 className="size-4" />
              </Button>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">No tags.</p>
      )}

      {!atLimit ? (
        <Button type="button" variant="outline" size="sm" onClick={add}>
          <Plus className="size-4" /> {addLabel}
        </Button>
      ) : null}
    </div>
  );
}
