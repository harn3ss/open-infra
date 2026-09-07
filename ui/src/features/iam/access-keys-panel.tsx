import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  KeyRound,
  Plus,
  Trash2,
  Ban,
  CircleCheck,
  AlertTriangle,
  Download,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/common/copy-button";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { Spinner } from "@/components/common/states";
import { useFlash } from "@/components/common/flashbar";
import {
  createAccessKey,
  deleteAccessKey,
  listAccessKeys,
  updateAccessKey,
  type AccessKey,
  type AccessKeyCreated,
} from "@/lib/api";

const MAX_KEYS = 2;

/**
 * The access-keys section of a User's "Security credentials" tab — the AWS signature surface.
 * Lists the user's aws-shim SigV4 keys (ID, created, last used, Active/Inactive), mints a new one
 * with a ONE-TIME secret reveal, and deactivates/activates/deletes existing keys. The secret is
 * shown exactly once (in the create response); after that only metadata is ever available, so a
 * lost key is replaced, never recovered — the same contract as AWS.
 */
export function AccessKeysPanel({ user }: { user: string }) {
  const qc = useQueryClient();
  const flash = useFlash();

  const keysQuery = useQuery({
    queryKey: ["iam", "accessKeys", user],
    queryFn: () => listAccessKeys(user),
  });
  const keys = keysQuery.data ?? [];

  const invalidate = () => qc.invalidateQueries({ queryKey: ["iam", "accessKeys", user] });

  // The freshly-minted key, held only long enough to show its secret once.
  const [revealed, setRevealed] = useState<AccessKeyCreated | null>(null);
  // Pending destructive/deactivate confirmation.
  const [confirm, setConfirm] = useState<{ kind: "deactivate" | "delete"; id: string } | null>(
    null,
  );

  const create = useMutation({
    mutationFn: () => createAccessKey(user),
    onSuccess: (res) => {
      setRevealed(res);
      void invalidate();
    },
    onError: (e) => flash.error((e as Error).message),
  });

  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "Active" | "Inactive" }) =>
      updateAccessKey(user, id, status),
    onSuccess: (_res, { status }) => {
      void invalidate();
      setConfirm(null);
      flash.success(`Access key ${status === "Active" ? "activated" : "deactivated"}.`);
    },
    onError: (e) => flash.error((e as Error).message),
  });

  const del = useMutation({
    mutationFn: (id: string) => deleteAccessKey(user, id),
    onSuccess: () => {
      void invalidate();
      setConfirm(null);
      flash.success("Access key deleted.");
    },
    onError: (e) => flash.error((e as Error).message),
  });

  const atLimit = keys.length >= MAX_KEYS;

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <h3 className="flex items-center gap-1.5 text-sm font-semibold">
              <KeyRound className="size-4" /> Access keys
            </h3>
            <p className="text-sm text-muted-foreground">
              Long-term credentials for the AWS-compatible endpoint (aws-shim). Sign requests with
              SigV4 using an unmodified AWS SDK or the AWS CLI. A key acts with this user's current
              permissions — nothing more.
            </p>
          </div>
          <Button
            onClick={() => create.mutate()}
            disabled={atLimit || create.isPending}
            title={atLimit ? `A user may have at most ${MAX_KEYS} access keys` : undefined}
          >
            {create.isPending ? <Spinner className="size-4" /> : <Plus className="size-4" />}
            Create access key
          </Button>
        </div>

        {atLimit ? (
          <p className="text-xs text-muted-foreground">
            This user has the maximum of {MAX_KEYS} access keys. Delete one to create another — the
            two-key limit exists so you can rotate (create the new key, cut over, then delete the
            old).
          </p>
        ) : null}

        {keysQuery.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner className="size-4" /> Loading access keys…
          </div>
        ) : keysQuery.isError ? (
          <p className="text-sm text-destructive">
            {(keysQuery.error as Error).message || "Could not load access keys."}
          </p>
        ) : keys.length === 0 ? (
          <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
            No access keys. Create one to use this user with the AWS CLI or SDKs against the shim.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Access key ID</th>
                  <th className="py-2 pr-4 font-medium">Created</th>
                  <th className="py-2 pr-4 font-medium">Last used</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-0 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <AccessKeyRow
                    key={k.accessKeyId}
                    k={k}
                    busy={setStatus.isPending || del.isPending}
                    onActivate={() => setStatus.mutate({ id: k.accessKeyId, status: "Active" })}
                    onDeactivate={() => setConfirm({ kind: "deactivate", id: k.accessKeyId })}
                    onDelete={() => setConfirm({ kind: "delete", id: k.accessKeyId })}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>

      {/* One-time secret reveal — the ONLY moment the secret is ever shown. */}
      <SecretRevealDialog created={revealed} onClose={() => setRevealed(null)} />

      {/* Deactivate confirm (reversible) */}
      <ConfirmDialog
        open={confirm?.kind === "deactivate"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Deactivate access key?"
        destructive={false}
        confirmLabel="Deactivate"
        loading={setStatus.isPending}
        onConfirm={() =>
          confirm && setStatus.mutate({ id: confirm.id, status: "Inactive" })
        }
        description={
          <>
            Requests signed with{" "}
            <code className="font-mono text-xs">{confirm?.id}</code> will start failing immediately.
            You can re-activate it later.
          </>
        }
      />

      {/* Delete confirm (permanent) */}
      <ConfirmDialog
        open={confirm?.kind === "delete"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Delete access key?"
        confirmLabel="Delete"
        loading={del.isPending}
        onConfirm={() => confirm && del.mutate(confirm.id)}
        description={
          <>
            Permanently delete access key{" "}
            <code className="font-mono text-xs">{confirm?.id}</code>. This cannot be undone, and any
            client still using it will stop working.
          </>
        }
      />
    </Card>
  );
}

function AccessKeyRow({
  k,
  busy,
  onActivate,
  onDeactivate,
  onDelete,
}: {
  k: AccessKey;
  busy: boolean;
  onActivate: () => void;
  onDeactivate: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="border-b last:border-0">
      <td className="py-2 pr-4">
        <span className="inline-flex items-center gap-1">
          <code className="font-mono text-xs">{k.accessKeyId}</code>
          <CopyButton value={k.accessKeyId} label="Copy access key ID" />
        </span>
      </td>
      <td className="py-2 pr-4 text-muted-foreground">{formatDate(k.created)}</td>
      <td className="py-2 pr-4 text-muted-foreground">{k.lastUsed ? formatDate(k.lastUsed) : "—"}</td>
      <td className="py-2 pr-4">
        {k.status === "Active" ? (
          <Badge variant="success">Active</Badge>
        ) : (
          <Badge variant="muted">Inactive</Badge>
        )}
      </td>
      <td className="py-2 pr-0">
        <div className="flex items-center justify-end gap-1">
          {k.status === "Active" ? (
            <Button variant="ghost" size="sm" disabled={busy} onClick={onDeactivate}>
              <Ban className="size-4" /> Deactivate
            </Button>
          ) : (
            <Button variant="ghost" size="sm" disabled={busy} onClick={onActivate}>
              <CircleCheck className="size-4" /> Activate
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            disabled={busy}
            onClick={onDelete}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="size-4" /> Delete
          </Button>
        </div>
      </td>
    </tr>
  );
}

function SecretRevealDialog({
  created,
  onClose,
}: {
  created: AccessKeyCreated | null;
  onClose: () => void;
}) {
  return (
    <Dialog open={created !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CircleCheck className="size-5 text-success" /> Access key created
          </DialogTitle>
          <DialogDescription asChild>
            <div>
              Copy your secret access key now. This is the only time it is shown — it cannot be
              retrieved afterwards. If you lose it, delete this key and create a new one.
            </div>
          </DialogDescription>
        </DialogHeader>

        {created ? (
          <div className="space-y-3">
            <SecretField label="Access key ID" value={created.accessKeyId} />
            <SecretField label="Secret access key" value={created.secretAccessKey} mono />

            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>
                Store this secret somewhere safe (a secrets manager). Anyone with it can act as{" "}
                <span className="font-medium">{created.owner}</span> against the AWS-compatible
                endpoint.
              </span>
            </div>
          </div>
        ) : null}

        <DialogFooter>
          {created ? (
            <Button variant="outline" onClick={() => downloadCsv(created)}>
              <Download className="size-4" /> Download .csv
            </Button>
          ) : null}
          <Button onClick={onClose}>I have saved my key</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SecretField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-1.5">
        <code className={mono ? "flex-1 break-all font-mono text-xs" : "flex-1 break-all text-sm"}>
          {value}
        </code>
        <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />
      </div>
    </div>
  );
}

function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

/** AWS offers the credentials as a .csv download; mirror it. The console SPA is not sandboxed, so
 *  a Blob download works normally. */
function downloadCsv(created: AccessKeyCreated) {
  const csv = `Access key ID,Secret access key\n${created.accessKeyId},${created.secretAccessKey}\n`;
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${created.owner}_accessKeys.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
