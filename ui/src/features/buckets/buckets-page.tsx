import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { HardDrive, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useListFilter } from "@/hooks/use-list-filter";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Application } from "@/types/k8s";

interface BucketRow {
  id: string;
  bucket: string;
  app: string;
  namespace: string;
}

// Buckets are object storage provisioned by Applications (spec.storage.buckets);
// we surface them aggregated across Applications with their owning app.
export function BucketsPage() {
  const { scoped } = useNamespace();
  const { items, isLoading, isError, error, live, refetch } =
    useK8sWatch<Application>(openinfraPaths.applications(scoped));

  const rows = useMemo<BucketRow[]>(
    () =>
      items.flatMap((a) =>
        (a.spec?.storage?.buckets ?? []).map((b) => ({
          id: `${a.metadata.namespace}/${a.metadata.name}/${b}`,
          bucket: b,
          app: a.metadata.name ?? "",
          namespace: a.metadata.namespace ?? "",
        })),
      ),
    [items],
  );

  const { filtered } = useListFilter(rows, (r) => [
    r.bucket,
    r.app,
    r.namespace,
  ]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "bucket", desc: false },
  ]);

  const columns = useMemo<ColumnDef<BucketRow, unknown>[]>(
    () => [
      {
        id: "bucket",
        header: "Bucket",
        accessorFn: (r) => r.bucket,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.bucket}</span>
        ),
        size: 280,
      },
      {
        id: "app",
        header: "Application",
        accessorFn: (r) => r.app,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.app}</span>
        ),
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (r) => r.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.namespace}
          </span>
        ),
        size: 160,
      },
    ],
    [],
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<HardDrive />}
        title="Buckets"
        description="Object storage — open-infra's S3 (MinIO). Declared by Applications via `storage.buckets`; the platform creates the bucket and injects credentials."
        actions={
          <>
            <LiveIndicator live={live} />
            <Button
              variant="outline"
              size="icon"
              onClick={refetch}
              aria-label="Refresh"
            >
              <RefreshCw className="size-4" />
            </Button>
          </>
        }
      />
      {isLoading ? (
        <LoadingState label="Loading buckets…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<HardDrive className="size-6" />}
          title="No buckets yet"
          description="Add `storage: { buckets: [uploads] }` to an Application — the platform creates the bucket and injects MINIO_* credentials."
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {rows.length}{" "}
            {rows.length === 1 ? "bucket" : "buckets"}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(r) => r.id}
            sorting={sorting}
            onSortingChange={setSorting}
            emptyState={
              <EmptyState
                title="No matches"
                description="No buckets match the current filter."
              />
            }
          />
        </>
      )}
    </div>
  );
}
