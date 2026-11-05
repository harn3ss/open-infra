import { useState } from "react";
import { FileJson, Pencil, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { JsonEditor } from "./policy-editor/json-editor";
import type { IamPolicy, InlinePolicy } from "@/lib/api";
import { EMPTY_POLICY_DOCUMENT, checkPolicyDocument, statementCount } from "@/lib/policy-document";

/**
 * An identity's inline policies — the AWS "Add inline policy" surface on a user, group or role. Each is
 * a name and an AWS JSON document; onSave receives the full new set (the caller PATCHes it).
 */
export function InlinePoliciesPanel({
  policies,
  onSave,
  subjectLabel,
  saving = false,
}: {
  policies: InlinePolicy[];
  onSave: (next: InlinePolicy[]) => void;
  subjectLabel: string;
  saving?: boolean;
}) {
  const [editing, setEditing] = useState<{ index: number; name: string; document: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  function save() {
    if (!editing) return;
    const name = editing.name.trim();
    if (!/^[\w+=,.@-]{1,128}$/.test(name)) {
      setError("A policy name is 1–128 letters, digits or +=,.@-_.");
      return;
    }
    if (policies.some((p, i) => p.name === name && i !== editing.index)) {
      setError(`${subjectLabel} already has an inline policy named ${name}.`);
      return;
    }
    const msg = checkPolicyDocument(editing.document);
    if (msg) {
      setError(msg);
      return;
    }
    const next = [...policies];
    if (editing.index < 0) next.push({ name, document: editing.document });
    else next[editing.index] = { name, document: editing.document };
    onSave(next);
    setEditing(null);
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="flex items-center justify-between border-b p-4">
          <div>
            <div className="text-sm font-medium">Inline policies ({policies.length})</div>
            <p className="text-xs text-muted-foreground">
              Policies embedded in {subjectLabel} only — they are deleted with it.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={saving}
            onClick={() => {
              setError(null);
              setEditing({ index: -1, name: "", document: EMPTY_POLICY_DOCUMENT });
            }}
          >
            <Plus className="size-4" /> Add inline policy
          </Button>
        </div>
        {policies.length === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">No inline policies.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="p-3 font-medium">Policy name</th>
                <th className="p-3 font-medium">Statements</th>
                <th className="p-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p, i) => (
                <tr key={p.name} className="border-b last:border-0">
                  <td className="p-3">
                    <span className="inline-flex items-center gap-1.5 font-medium">
                      <FileJson className="size-3.5 text-muted-foreground" />
                      {p.name}
                    </span>
                  </td>
                  <td className="p-3 text-muted-foreground">{statementCount(p.document)}</td>
                  <td className="p-3 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={saving}
                      onClick={() => {
                        setError(null);
                        setEditing({ index: i, name: p.name, document: p.document });
                      }}
                    >
                      <Pencil className="size-4" /> Edit
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-muted-foreground hover:text-destructive"
                      disabled={saving}
                      onClick={() => onSave(policies.filter((_, j) => j !== i))}
                    >
                      <Trash2 className="size-4" /> Remove
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>

      <Dialog open={editing !== null} onOpenChange={(v) => !v && setEditing(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{editing && editing.index >= 0 ? "Edit inline policy" : "Add inline policy"}</DialogTitle>
            <DialogDescription>An AWS IAM policy document (JSON), embedded in {subjectLabel}.</DialogDescription>
          </DialogHeader>
          {editing ? (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="inline-name">Policy name</Label>
                <Input
                  id="inline-name"
                  value={editing.name}
                  onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                />
              </div>
              <JsonEditor
                value={editing.document}
                onChange={(v) => setEditing({ ...editing, document: v })}
                error={error}
              />
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button onClick={save}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

const NONE = "__none__";

/**
 * The permissions boundary card: the managed or customer policy that caps what the identity's policies
 * can grant (AWS "Permissions boundary"). Selecting one sets it; "No boundary" removes it.
 */
export function PermissionBoundaryCard({
  boundary,
  policies,
  onSave,
  saving = false,
}: {
  boundary?: string;
  policies: IamPolicy[];
  onSave: (policy: string) => void;
  saving?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
        <div className="flex items-start gap-2">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          <div>
            <div className="text-sm font-medium">Permissions boundary</div>
            <p className="text-xs text-muted-foreground">
              {boundary
                ? `Capped by ${boundary}: its policies grant only what this boundary also allows.`
                : "Not set. The identity's policies grant their full permissions."}
            </p>
          </div>
        </div>
        <Select value={boundary || NONE} onValueChange={(v) => onSave(v === NONE ? "" : v)} disabled={saving}>
          <SelectTrigger className="w-64">
            <SelectValue placeholder="No boundary" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NONE}>No boundary</SelectItem>
            {policies.map((p) => (
              <SelectItem key={p.name} value={p.name}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </CardContent>
    </Card>
  );
}
