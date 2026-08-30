import type { ReactNode } from "react";
import { ArrowLeft, Rocket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/common/states";
import { ApiError } from "@/lib/api";

/**
 * The AWS/Cloudscape "single-page create" chrome (issue #96) for kinds whose editor is BESPOKE and does
 * not fit the schema-driven CreatePage (Security Group rule tables, IAM policy statement rows, …). Gives
 * them the SAME shell as the schema-driven pages: a Back link + "Create [resource]" H1, the caller's form
 * body as children, an error box, and a sticky footer with Cancel + a primary that follows the AWS rules —
 * it is NEVER disabled for validity (only while submitting); the caller validates on submit and shows
 * inline errors. Exiting with unsaved changes prompts a confirm, per the pattern.
 */
export function CreateShell({
  icon,
  title,
  description,
  onCancel,
  onSubmit,
  submitLabel,
  pending,
  error,
  dirty = false,
  children,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel: string;
  pending: boolean;
  error?: unknown;
  /** When true, a Cancel/Back click confirms before discarding the in-progress form. */
  dirty?: boolean;
  children: ReactNode;
}) {
  const cancel = () => {
    if (pending) return;
    if (dirty && !window.confirm("Discard this resource? Your changes will be lost.")) return;
    onCancel();
  };
  return (
    <div className="mx-auto max-w-3xl space-y-6 pb-24">
      <div>
        <Button variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground" onClick={cancel}>
          <ArrowLeft className="size-4" /> Back
        </Button>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          {icon} {title}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{description}</p>
      </div>

      {children}

      {error ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error instanceof ApiError ? error.message : "Failed to create the resource."}
        </div>
      ) : null}

      {/* Sticky actions — Cancel + a primary that is never disabled for validity (AWS rule). */}
      <div className="fixed inset-x-0 bottom-0 z-10 border-t border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-3xl items-center justify-end gap-3 p-4">
          <Button variant="outline" onClick={cancel} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={pending}>
            {pending ? <Spinner className="text-current" /> : <Rocket className="size-4" />}
            {submitLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
