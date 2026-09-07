import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ChevronRight, HardDrive, Plus, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useListFilter } from "@/hooks/use-list-filter";
import { listBuckets, type BucketInfo } from "@/lib/api";
import { age } from "@/lib/format";

export function BucketsPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["buckets"],
    queryFn: listBuckets,
  });
  const buckets = data ?? [];
  const { filtered } = useListFilter(buckets, (b) => [b.name]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);

  const columns = useMemo<ColumnDef<BucketInfo, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Bucket",
        accessorFn: (b) => b.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.name}</span>
        ),
        size: 360,
      },
      {
        id: "created",
        header: "Created",
        accessorFn: (b) => b.createdAt,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {age(row.original.createdAt)}
          </span>
        ),
        size: 160,
      },
      {
        id: "browse",
        header: "",
        accessorFn: () => "",
        enableSorting: false,
        cell: () => (
          <span className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
            browse <ChevronRight className="size-3" />
          </span>
        ),
        size: 120,
      },
    ],
    [],
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<HardDrive />}
        title="Buckets"
        description="Object storage — open-infra's S3 (MinIO). Live from the cluster; click a bucket to browse and manage objects."
        actions={
          <>
            <Button
              variant="outline"
              size="icon"
              onClick={() => refetch()}
              aria-label="Refresh"
              disabled={isFetching}
            >
              <RefreshCw className="size-4" />
            </Button>
            <Button onClick={() => navigate({ to: "/buckets/new" })}>
              <Plus className="size-4" />
              Create bucket
            </Button>
          </>
        }
      />
      {isLoading ? (
        <LoadingState label="Loading buckets…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : buckets.length === 0 ? (
        <EmptyState
          icon={<HardDrive className="size-6" />}
          title="No buckets yet"
          description="Create a bucket, or declare `storage: { buckets: [uploads] }` on an Application."
          action={
            <Button onClick={() => navigate({ to: "/buckets/new" })}>
              <Plus className="size-4" />
              Create bucket
            </Button>
          }
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {buckets.length}{" "}
            {buckets.length === 1 ? "bucket" : "buckets"}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(b) => b.name}
            sorting={sorting}
            onSortingChange={setSorting}
            onRowClick={(b) =>
              navigate({ to: "/buckets/$bucket", params: { bucket: b.name } })
            }
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
