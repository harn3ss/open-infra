import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, Database, RotateCcw, Trash2 } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { age } from "@/lib/format";
import {
  deleteDbSnapshot,
  listDbSnapshots,
  restoreDbSnapshot,
  type DbSnapshot,
} from "@/lib/api";

const fmtBytes = (n: number) => {
  if (!n) return "—";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};

function RestoreDialog({
  snap,
  onClose,
}: {
  snap: DbSnapshot;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [target, setTarget] = useState(snap.sourceName);
  const restore = useMutation({
    mutationFn: () => restoreDbSnapshot(snap.id, snap.namespace, target.trim()),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["db-snapshots"] });
      onClose();
    },
  });
  return (
    <ConfirmDialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Restore snapshot"
      confirmLabel="Restore"
      destructive={false}
      loading={restore.isPending}
      onConfirm={() => target.trim() && restore.mutate()}
      description={
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Streams <span className="font-medium">{snap.id}</span> into an{" "}
            <b>existing, empty</b> Postgres database in{" "}
            <span className="font-mono">{snap.namespace}</span>. Create the target
            database first (New Database), then restore into it — the restore
            replaces its contents.
          </p>
          <label className="block text-sm">
            <span className="text-muted-foreground">Target database name</span>
            <input
              className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="my-db"
            />
          </label>
          {restore.isError ? (
            <p className="text-sm text-destructive">
              {(restore.error as Error).message}
            </p>
          ) : null}
        </div>
      }
    />
  );
}

export function SnapshotsPage() {
  const qc = useQueryClient();
  const [restoring, setRestoring] = useState<DbSnapshot | null>(null);
  const { data = [], isLoading, isError, error, isFetching } = useQuery({
    queryKey: ["db-snapshots"],
    queryFn: listDbSnapshots,
    refetchInterval: 10000,
  });
  const del = useMutation({
    mutationFn: (s: DbSnapshot) =>
      deleteDbSnapshot(s.namespace, s.sourceName, s.id, s.kind),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["db-snapshots"] }),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Camera />}
        title="Snapshots"
        description="Final snapshots of databases — Postgres as a pg_dump, managed engines as a Longhorn backup — kept in object storage. Survives the database's deletion; restore into a new one."
        actions={<LiveIndicator live={isFetching} />}
      />

      <p className="text-xs text-muted-foreground">
        In-cluster snapshots (stored in MinIO) — they survive resource deletion, but are
        not off-cluster disaster recovery.
      </p>

      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data.length === 0 ? (
        <EmptyState
          title="No snapshots yet"
          description="Take one from a database's Danger Zone before you deprovision it, or from its detail page."
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="p-3 font-medium">Source</th>
                  <th className="p-3 font-medium">Engine</th>
                  <th className="p-3 text-right font-medium">Size</th>
                  <th className="p-3 font-medium">Taken</th>
                  <th className="p-3 font-medium">Status</th>
                  <th className="p-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.map((s) => (
                  <tr key={`${s.namespace}/${s.id}`} className="border-b last:border-0">
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <Database className="size-4 text-muted-foreground" />
                        <span className="font-medium">{s.sourceName}</span>
                        <span className="text-muted-foreground">· {s.namespace}</span>
                      </div>
                    </td>
                    <td className="p-3">
                      <Badge variant="secondary">{s.engine}</Badge>
                    </td>
                    <td className="p-3 text-right tabular-nums">{fmtBytes(s.sizeBytes)}</td>
                    <td className="p-3 text-muted-foreground">
                      {s.createdAt ? age(s.createdAt) : "—"}
                    </td>
                    <td className="p-3">
                      <Badge
                        variant={s.status === "ready" ? "default" : "secondary"}
                        className={s.status === "failed" ? "bg-destructive" : ""}
                      >
                        {s.status}
                      </Badge>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={s.status !== "ready"}
                          onClick={() => setRestoring(s)}
                        >
                          <RotateCcw className="size-3.5" /> Restore
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-destructive"
                          disabled={del.isPending}
                          onClick={() => del.mutate(s)}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {restoring ? (
        <RestoreDialog snap={restoring} onClose={() => setRestoring(null)} />
      ) : null}
    </div>
  );
}
