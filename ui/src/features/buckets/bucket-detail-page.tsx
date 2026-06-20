import { useRef, useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronRight,
  Download,
  FileText,
  Folder,
  HardDrive,
  RefreshCw,
  Trash2,
  Upload,
} from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DangerZone } from "@/components/common/danger-zone";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import {
  deleteBucket,
  deleteObject,
  listBucketObjects,
  listBuckets,
  objectDownloadUrl,
  uploadObject,
} from "@/lib/api";
import { age, formatBytes } from "@/lib/format";

function basename(key: string): string {
  const k = key.endsWith("/") ? key.slice(0, -1) : key;
  const i = k.lastIndexOf("/");
  return i >= 0 ? k.slice(i + 1) : k;
}

function ObjectsTab({ bucket }: { bucket: string }) {
  const qc = useQueryClient();
  const [prefix, setPrefix] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const [confirmKey, setConfirmKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["bucket-objects", bucket, prefix],
    queryFn: () => listBucketObjects(bucket, prefix),
  });
  const parts = prefix.split("/").filter(Boolean);
  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["bucket-objects", bucket, prefix] });

  const onUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    try {
      for (const f of Array.from(files)) {
        await uploadObject(bucket, prefix + f.name, f);
      }
      await invalidate();
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const delMutation = useMutation({
    mutationFn: (key: string) => deleteObject(bucket, key),
    onSuccess: () => {
      setConfirmKey(null);
      invalidate();
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-1 flex-wrap items-center gap-1 text-sm">
          <button
            className="font-medium text-primary hover:underline"
            onClick={() => setPrefix("")}
          >
            {bucket}
          </button>
          {parts.map((p, i) => (
            <span key={i} className="flex items-center gap-1">
              <ChevronRight className="size-3 text-muted-foreground" />
              <button
                className="text-primary hover:underline"
                onClick={() => setPrefix(parts.slice(0, i + 1).join("/") + "/")}
              >
                {p}
              </button>
            </span>
          ))}
        </div>
        <input
          ref={fileRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => onUpload(e.target.files)}
        />
        <Button
          variant="outline"
          size="icon"
          onClick={() => refetch()}
          aria-label="Refresh"
          disabled={isFetching}
        >
          <RefreshCw className="size-4" />
        </Button>
        <Button onClick={() => fileRef.current?.click()} disabled={busy}>
          <Upload className="size-4" />
          {busy ? "Uploading…" : "Upload"}
        </Button>
      </div>

      {isLoading ? (
        <LoadingState label="Loading objects…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data || data.length === 0 ? (
        <EmptyState
          title="Empty"
          description="No objects under this path. Use Upload to add files."
        />
      ) : (
        <ul className="divide-y divide-border overflow-hidden rounded-md border">
          {data.map((o) =>
            o.isPrefix ? (
              <li key={o.key}>
                <button
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-secondary"
                  onClick={() => setPrefix(o.key)}
                >
                  <Folder className="size-4 text-muted-foreground" />
                  <span className="font-medium">{basename(o.key)}/</span>
                </button>
              </li>
            ) : (
              <li
                key={o.key}
                className="group flex items-center gap-2 px-3 py-2 text-sm"
              >
                <FileText className="size-4 shrink-0 text-muted-foreground" />
                <span className="truncate">{basename(o.key)}</span>
                <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                  {formatBytes(o.size)}
                </span>
                <span className="w-16 shrink-0 text-right text-xs text-muted-foreground">
                  {age(o.lastModified)}
                </span>
                <a
                  href={objectDownloadUrl(bucket, o.key)}
                  className="shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label={`Download ${basename(o.key)}`}
                >
                  <Download className="size-4" />
                </a>
                <button
                  className="shrink-0 text-muted-foreground hover:text-destructive"
                  onClick={() => setConfirmKey(o.key)}
                  aria-label={`Delete ${basename(o.key)}`}
                >
                  <Trash2 className="size-4" />
                </button>
              </li>
            ),
          )}
        </ul>
      )}

      <ConfirmDialog
        open={Boolean(confirmKey)}
        onOpenChange={(o) => (o ? null : setConfirmKey(null))}
        title="Delete object?"
        description={
          confirmKey ? (
            <>
              Permanently delete{" "}
              <span className="font-medium text-foreground">{confirmKey}</span>?
            </>
          ) : null
        }
        confirmLabel="Delete"
        loading={delMutation.isPending}
        onConfirm={() => confirmKey && delMutation.mutate(confirmKey)}
      />
    </div>
  );
}

export function BucketDetailPage() {
  const { bucket } = useParams({ strict: false }) as { bucket: string };
  const navigate = useNavigate();

  const { data: buckets } = useQuery({ queryKey: ["buckets"], queryFn: listBuckets });
  const meta = buckets?.find((b) => b.name === bucket);

  const deleteMutation = useMutation({
    mutationFn: () => deleteBucket(bucket),
    onSuccess: () => navigate({ to: "/buckets" }),
  });

  return (
    <DetailShell
      backTo="/buckets"
      backLabel="Buckets"
      icon={<HardDrive className="size-5" />}
      title={bucket}
      subtitle="Object storage bucket (MinIO / S3)"
    >
      <Tabs defaultValue="objects">
        <TabsList>
          <TabsTrigger value="objects">Objects</TabsTrigger>
          <TabsTrigger value="properties">Properties</TabsTrigger>
        </TabsList>
        <TabsContent value="objects" className="pt-4">
          <ObjectsTab bucket={bucket} />
        </TabsContent>
        <TabsContent value="properties" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="bucket" name={bucket} />
              <DetailRow label="Name">{bucket}</DetailRow>
              <DetailRow label="Created">
                {meta ? age(meta.createdAt) + " ago" : "—"}
              </DetailRow>
              <DetailRow label="Endpoint">
                {`s3://${bucket} (minio.minio.svc.cluster.local:9000)`}
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <DangerZone
        resourceLabel="Bucket"
        resourceName={bucket}
        deleting={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
        confirmDescription={
          <>
            Permanently delete bucket{" "}
            <span className="font-medium text-foreground">{bucket}</span> and all
            its objects. This cannot be undone.
          </>
        }
      />
    </DetailShell>
  );
}
