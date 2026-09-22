import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, Copy, Download, FileText, ShieldAlert } from "lucide-react";
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
import { getIamPolicy, importAwsPolicy, listIamPolicies } from "@/lib/api";
import type { ImportAwsResult, ImportedStatement } from "@/lib/api";
import { PermissionsSummary } from "./permissions-summary";
import { parseDoc, type PolicyDoc } from "./model";

/**
 * AWS's "Actions ▾ → Import policy" flow, adapted to open-infra. It APPENDS statements into the draft
 * the user is authoring (it never replaces). Three sources:
 *
 *   • From an existing policy — pick one of the account's Policies; merge its statements.
 *   • Paste a policy document — paste an open-infra Policy document (the JSON-tab shape) and merge it.
 *   • AWS IAM policy — paste an AWS IAM policy JSON; a DRY-RUN preview (BFF /iam/import) shows what
 *     translates, what is refused (with the reason — never silently dropped), and what is broad, then
 *     the translated data-plane statements can be added to the draft.
 *
 * This is import-only and additive; nothing here mutates the imported source.
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
  const [mode, setMode] = useState<"existing" | "paste" | "aws">("existing");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="size-4" /> Import policy
          </DialogTitle>
          <DialogDescription>
            Add permissions to the policy you are authoring. Import{" "}
            <span className="font-medium">appends</span> — it never replaces your draft.
          </DialogDescription>
        </DialogHeader>

        {/* Source toggle */}
        <div className="inline-flex overflow-hidden rounded-md border border-border text-xs">
          {(
            [
              ["existing", "From an existing policy"],
              ["paste", "Paste a policy document"],
              ["aws", "AWS IAM policy"],
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
        ) : mode === "paste" ? (
          <PasteSource onImport={onImport} onClose={() => onOpenChange(false)} />
        ) : (
          <AwsSource onImport={onImport} onClose={() => onOpenChange(false)} />
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

/** Render one translated data-plane statement, with badges for conditions / IP conditions / breadth. */
function StatementLine({ s }: { s: ImportedStatement }) {
  return (
    <div className="border-b border-border px-2 py-1.5 text-xs last:border-b-0">
      <div className="font-mono">
        <span className={s.effect === "Deny" ? "text-destructive" : "text-foreground"}>{s.effect}</span>{" "}
        {s.actions.join(", ")} <span className="text-muted-foreground">on</span>{" "}
        {(s.resources ?? ["*"]).join(", ")}
      </div>
      <div className="mt-0.5 flex flex-wrap gap-1">
        {s.condition
          ? Object.entries(s.condition).map(([k, v]) => (
              <span key={k} className="rounded bg-muted px-1 text-[10px] text-muted-foreground">
                {k}={v}
              </span>
            ))
          : null}
        {(s.ipConditions ?? []).map((c, i) => (
          <span key={i} className="rounded bg-muted px-1 text-[10px] text-muted-foreground">
            {c.negate ? "sourceIp∉" : "sourceIp∈"} {c.cidr}
          </span>
        ))}
        {s.broad ? (
          <span className="rounded bg-amber-500/15 px-1 text-[10px] font-medium text-amber-600 dark:text-amber-400">
            wildcard
          </span>
        ) : null}
      </div>
    </div>
  );
}

/** Import by pasting an AWS IAM policy — a dry-run preview via the BFF, then add the translated part. */
function AwsSource({
  onImport,
  onClose,
}: {
  onImport: (doc: PolicyDoc) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState("");
  const [copied, setCopied] = useState(false);
  const preview = useMutation<ImportAwsResult, Error, string>({ mutationFn: (doc) => importAwsPolicy(doc) });
  const result = preview.data;

  const hasIp = (result?.translated ?? []).some((s) => (s.ipConditions?.length ?? 0) > 0);

  // The data-plane block an operator would author — lossless, keeps IP conditions. For pasting into the
  // JSON tab (the visual editor can't carry IP conditions, so that is the faithful path for those).
  const dataPlaneJson = useMemo(() => {
    if (!result || result.translated.length === 0) return "";
    const statements = result.translated.map(({ broad: _broad, ...s }) => s);
    return JSON.stringify({ dataPlane: { appliesTo: ["*"], statements } }, null, 2);
  }, [result]);

  const addToDraft = () => {
    if (!result || result.translated.length === 0 || hasIp) return;
    // Merge only the fully model-representable statements (no IP conditions here, guarded by hasIp).
    // The engine only ever emits Allow/Deny, so narrowing effect to the union is safe.
    const statements = result.translated.map((t) => ({
      effect: t.effect === "Deny" ? ("Deny" as const) : ("Allow" as const),
      actions: t.actions,
      resources: t.resources,
      condition: t.condition,
    }));
    onImport({ description: "", statements: [], dataPlane: { appliesTo: ["*"], statements } });
    onClose();
  };

  return (
    <div className="space-y-3">
      <textarea
        className="h-40 w-full resize-y rounded-md border border-border bg-background p-2.5 font-mono text-xs outline-none focus:ring-2 focus:ring-ring"
        placeholder={'{\n  "Version": "2012-10-17",\n  "Statement": [\n    { "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::assets/*" }\n  ]\n}'}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
      />

      <div className="flex items-center gap-2">
        <Button
          size="sm"
          disabled={!text.trim() || preview.isPending}
          onClick={() => preview.mutate(text)}
        >
          {preview.isPending ? <Spinner /> : <FileText className="size-4" />} Preview import
        </Button>
        <span className="text-[11px] text-muted-foreground">
          Dry run — translates and reports only; nothing is created.
        </span>
      </div>

      {preview.isError ? (
        <p className="flex items-start gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
          <AlertTriangle className="mt-px size-3.5 shrink-0" /> {preview.error.message}
        </p>
      ) : null}

      {result ? (
        <div className="space-y-2">
          {/* Faithfulness banner */}
          {result.faithful ? (
            <p className="flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 p-2 text-xs text-emerald-700 dark:text-emerald-400">
              <Check className="size-3.5" /> Every statement maps onto the data plane.
            </p>
          ) : (
            <p className="flex items-start gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
              <ShieldAlert className="mt-px size-3.5 shrink-0" /> {result.summary.refused} part(s) refused —
              they are not imported. Author them natively on kind: Policy dataPlane.
            </p>
          )}

          {/* Translated */}
          {result.translated.length > 0 ? (
            <div>
              <div className="mb-1 text-xs font-medium text-muted-foreground">
                Translated ({result.summary.translated})
              </div>
              <div className="max-h-48 overflow-auto rounded-md border border-border">
                {result.translated.map((s, i) => (
                  <StatementLine key={i} s={s} />
                ))}
              </div>
            </div>
          ) : null}

          {/* Needs review */}
          {result.needsReview.length > 0 ? (
            <div>
              <div className="mb-1 text-xs font-medium text-amber-600 dark:text-amber-400">
                Needs review ({result.needsReview.length})
              </div>
              <ul className="space-y-0.5 rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-[11px] text-muted-foreground">
                {result.needsReview.map((n, i) => (
                  <li key={i}>• {n}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {/* Refused */}
          {result.refused.length > 0 ? (
            <div>
              <div className="mb-1 text-xs font-medium text-destructive">
                Refused — not imported ({result.refused.length})
              </div>
              <ul className="space-y-0.5 rounded-md border border-destructive/30 bg-destructive/5 p-2 text-[11px] text-destructive">
                {result.refused.map((n, i) => (
                  <li key={i}>• {n}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {hasIp ? (
            <p className="flex items-start gap-1.5 rounded-md border border-border bg-muted/40 p-2 text-[11px] text-muted-foreground">
              <AlertTriangle className="mt-px size-3.5 shrink-0" /> Some statements use an IP condition,
              which the visual editor can't carry. Use <span className="font-medium">Copy dataPlane JSON</span>{" "}
              and paste it into the JSON tab so the condition is preserved.
            </p>
          ) : null}
        </div>
      ) : null}

      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        {result && result.translated.length > 0 ? (
          <Button
            variant="outline"
            onClick={() => {
              void navigator.clipboard?.writeText(dataPlaneJson);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? <Check className="size-4" /> : <Copy className="size-4" />} Copy dataPlane JSON
          </Button>
        ) : null}
        <Button
          disabled={!result || result.translated.length === 0 || hasIp}
          onClick={addToDraft}
        >
          <Download className="size-4" /> Add translated to draft
        </Button>
      </DialogFooter>
    </div>
  );
}
