import type {
  ArrayFieldTemplateProps,
  FieldTemplateProps,
  ObjectFieldTemplateProps,
} from "@rjsf/utils";
import { Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ExpandableSection } from "@/components/create/expandable-section";
import { cn } from "@/lib/utils";

// Custom RJSF templates that give schema-driven forms the AWS/Cloudscape semantics the console was
// missing: mark OPTIONAL (not required), turn each CRD `description` into inline help, group nested
// objects into titled sections, split a resource's spec into an essential set + a collapsed
// "Advanced settings" section, and render arrays as a clean add/remove list.

interface FormCtx {
  /** idSchema.$id of the root object — used to detect "this is the top-level spec". */
  rootId?: string;
  /** Spec property names shown up-front; everything else goes under "Advanced settings". */
  essential?: string[];
}

/** One field: label (with "- optional" for non-required), help from description, control, error. */
export function FieldTemplate(props: FieldTemplateProps) {
  const { id, classNames, style, label, required, rawDescription, rawErrors, children, hidden, displayLabel } = props;

  if (hidden) return <div className="hidden">{children}</div>;

  // Objects/arrays render their own titles via their templates; only leaf fields draw a label here.
  if (!displayLabel) {
    return (
      <div className={cn("space-y-2", classNames)} style={style}>
        {children}
      </div>
    );
  }

  return (
    <div className={cn("space-y-1.5", classNames)} style={style}>
      {label ? (
        <label htmlFor={id} className="text-sm font-medium">
          {label}
          {!required ? <span className="ml-1 font-normal text-muted-foreground">- optional</span> : null}
        </label>
      ) : null}
      {rawDescription ? <p className="text-xs text-muted-foreground">{rawDescription}</p> : null}
      {children}
      {rawErrors && rawErrors.length > 0 ? (
        <p className="text-xs text-destructive">{rawErrors[0]}</p>
      ) : null}
    </div>
  );
}

function Section({ title, description, children }: { title?: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-4 rounded-lg border border-border p-4">
      {title ? (
        <div>
          <h3 className="text-sm font-semibold">{title}</h3>
          {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
        </div>
      ) : null}
      <div className="space-y-4">{children}</div>
    </div>
  );
}

/** Objects: the ROOT spec splits into essential fields + a collapsed "Advanced settings"; nested
 *  objects render as titled sections (Cloudscape Containers). */
export function ObjectFieldTemplate(props: ObjectFieldTemplateProps) {
  const { idSchema, properties, title, description, formContext } = props;
  const ctx = (formContext ?? {}) as FormCtx;
  const isRoot = !!ctx.rootId && idSchema?.$id === ctx.rootId;

  if (isRoot && ctx.essential && ctx.essential.length > 0) {
    const essential = new Set(ctx.essential);
    const primary = properties.filter((p) => essential.has(p.name));
    const advanced = properties.filter((p) => !essential.has(p.name) && !p.hidden);
    return (
      <div className="space-y-4">
        {primary.map((p) => (
          <div key={p.name}>{p.content}</div>
        ))}
        {advanced.length > 0 ? (
          <ExpandableSection
            title="Advanced settings"
            description="Everything else has a sensible default"
            count={advanced.length}
          >
            {advanced.map((p) => (
              <div key={p.name}>{p.content}</div>
            ))}
          </ExpandableSection>
        ) : null}
      </div>
    );
  }

  // Nested object → a titled section. (No title on the bare root when un-tiered → just stack.)
  if (!title) {
    return (
      <div className="space-y-4">
        {properties.map((p) => (
          <div key={p.name}>{p.content}</div>
        ))}
      </div>
    );
  }
  return (
    <Section title={title} description={description}>
      {properties.map((p) => (
        <div key={p.name}>{p.content}</div>
      ))}
    </Section>
  );
}

/** Arrays: a clean labelled list with per-item remove + an Add button (RJSF's default is clunky). */
export function ArrayFieldTemplate(props: ArrayFieldTemplateProps) {
  const { title, items, canAdd, onAddClick, schema } = props;
  const itemLabel =
    (typeof schema.items === "object" && schema.items && "title" in schema.items && (schema.items as { title?: string }).title) ||
    "item";
  return (
    <div className="space-y-2">
      {title ? <span className="text-sm font-medium">{title}</span> : null}
      {items && items.length > 0 ? (
        <div className="space-y-3">
          {items.map((item) => (
            <div key={item.key} className="flex items-start gap-2 rounded-md border border-border p-3">
              <div className="min-w-0 flex-1">{item.children}</div>
              {item.hasRemove ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="mt-1 shrink-0 text-muted-foreground hover:text-destructive"
                  onClick={item.onDropIndexClick(item.index)}
                  aria-label="Remove"
                >
                  <X className="size-4" />
                </Button>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">None yet.</p>
      )}
      {canAdd ? (
        <Button type="button" variant="outline" size="sm" onClick={onAddClick}>
          <Plus className="size-4" /> Add {String(itemLabel).toLowerCase()}
        </Button>
      ) : null}
    </div>
  );
}

export const createTemplates = { FieldTemplate, ObjectFieldTemplate, ArrayFieldTemplate };
