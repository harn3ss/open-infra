import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Download, FileText } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/common/states";
import { getIamPolicy, listIamPolicies } from "@/lib/api";
import { PermissionsSummary } from "./permissions-summary";
import { parseDoc, type PolicyDoc } from "./model";

/**
 * AWS's "Actions ▾ → Import policy" flow, adapted to open-infra. It APPENDS an existing policy's
 * statements into the draft the user is authoring (it never replaces). Two sources:
 *
 *   • From an existing policy — pick one of the account's Policies; its control- and data-plane
 *     statements are previewed, then merged in. (Wired to the read-only /iam/policies endpoints.)
 *   • Paste a policy document — paste a Policy document (the same shape the JSON tab shows) and merge
 *     its statements. Best-effort: anything the document can express, the merge accepts.
 *
 * This is import-only and additive; nothing here mutates the imported source policy.
 */
export function ImportPolicyDialog({
  open,
  onOpenChange,
  onImport,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onImport: (doc: PolicyDoc) => void;
}) {
  const [mode, setMode] = useState<"existing" | "paste">("existing");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="size-4" /> Import policy
          </DialogTitle>
          <DialogDescription>
            Add the permissions from an existing policy to the one you are authoring. Import{" "}
            <span className="font-medium">appends</span> — it never replaces your draft.
          </DialogDescription>
        </DialogHeader>

        {/* Source toggle */}
        <div className="inline-flex overflow-hidden rounded-md border border-border text-xs">
          {(
            [
              ["existing", "From an existing policy"],
              ["paste", "Paste a policy document"],
            ] as const
          ).map(([m, label]) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={[
                "px-3 py-1.5 font-medium transition-colors",
                mode === m ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-muted",
              ].join(" ")}
            >
              {label}
            </button>
          ))}
        </div>

        {mode === "existing" ? (
          <ExistingSource onImport={onImport} onClose={() => onOpenChange(false)} />
        ) : (
          <PasteSource onImport={onImport} onClose={() => onOpenChange(false)} />
        )}
      </DialogContent>
    </Dialog>
  );
}

/** Import from one of the account's stored Policies. */
function ExistingSource({
  onImport,
  onClose,
}: {
  onImport: (doc: PolicyDoc) => void;
  onClose: () => void;
}) {
  const [selected, setSelected] = useState<string>("");

  const list = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const detail = useQuery({
    queryKey: ["iam", "policy", selected],
    queryFn: () => getIamPolicy(selected),
    enabled: Boolean(selected),
  });

  const doc: PolicyDoc | null = useMemo(() => {
    if (!detail.data) return null;
    return {
      description: detail.data.description,
      statements: detail.data.statements,
      dataPlane: detail.data.dataPlane,
      controlPlane: detail.data.controlPlane,
    };
  }, [detail.data]);

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <label className="text-xs font-medium">Policy</label>
        {list.isLoading ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Spinner /> Loading policies…
          </div>
        ) : list.isError ? (
          <p className="text-xs text-destructive">Couldn't load policies.</p>
        ) : (list.data ?? []).length === 0 ? (
          <p className="text-xs text-muted-foreground">No existing policies to import from.</p>
        ) : (
          <Select value={selected || undefined} onValueChange={setSelected}>
            <SelectTrigger className="h-9 w-full text-sm">
              <SelectValue placeholder="Choose a policy to import" />
            </SelectTrigger>
            <SelectContent>
              {(list.data ?? []).map((p) => (
                <SelectItem key={p.name} value={p.name}>
                  {p.name}
                  {p.description ? ` — ${p.description}` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {selected && detail.isLoading ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Spinner /> Loading {selected}…
        </div>
      ) : null}

      {doc ? (
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <FileText className="size-3.5" /> These permissions will be added:
          </div>
          <div className="max-h-64 overflow-auto rounded-md border border-border">
            <PermissionsSummary doc={doc} />
          </div>
        </div>
      ) : null}

      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={!doc}
          onClick={() => {
            if (doc) {
              onImport(doc);
              onClose();
            }
          }}
        >
          <Download className="size-4" /> Import
        </Button>
      </DialogFooter>
    </div>
  );
}

/** Import by pasting a Policy document (the JSON-tab shape). */
function PasteSource({
  onImport,
  onClose,
}: {
  onImport: (doc: PolicyDoc) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState("");

  const parsed = useMemo<{ doc: PolicyDoc | null; error: string | null }>(() => {
    if (!text.trim()) return { doc: null, error: null };
    try {
      return { doc: parseDoc(text), error: null };
    } catch (e) {
      return { doc: null, error: (e as Error).message };
    }
  }, [text]);

  return (
    <div className="space-y-3">
      <textarea
        className="h-48 w-full resize-y rounded-md border border-border bg-background p-2.5 font-mono text-xs outline-none focus:ring-2 focus:ring-ring"
        placeholder={'{\n  "description": "...",\n  "statements": [ { "actions": ["applications:*"] } ],\n  "dataPlane": { "appliesTo": ["*"], "statements": [] }\n}'}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
      />

      {parsed.error ? (
        <p className="flex items-start gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
          <AlertTriangle className="mt-px size-3.5 shrink-0" /> {parsed.error}
        </p>
      ) : null}

      {parsed.doc ? (
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <FileText className="size-3.5" /> These permissions will be added:
          </div>
          <div className="max-h-56 overflow-auto rounded-md border border-border">
            <PermissionsSummary doc={parsed.doc} />
          </div>
        </div>
      ) : null}

      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          disabled={!parsed.doc}
          onClick={() => {
            if (parsed.doc) {
              onImport(parsed.doc);
              onClose();
            }
          }}
        >
          <Download className="size-4" /> Import
        </Button>
      </DialogFooter>
    </div>
  );
}
