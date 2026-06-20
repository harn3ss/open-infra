import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronRight,
  FileText,
  Folder,
  HardDrive,
  RefreshCw,
} from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useListFilter } from "@/hooks/use-list-filter";
import { listBucketObjects, listBuckets, type BucketInfo } from "@/lib/api";
import { age, formatBytes } from "@/lib/format";

function basename(key: string): string {
  const k = key.endsWith("/") ? key.slice(0, -1) : key;
  const i = k.lastIndexOf("/");
  return i >= 0 ? k.slice(i + 1) : k;
}

/** Browse a bucket's objects with prefix ("folder") navigation. */
function ObjectBrowser({ bucket }: { bucket: string }) {
  const [prefix, setPrefix] = useState("");
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["bucket-objects", bucket, prefix],
    queryFn: () => listBucketObjects(bucket, prefix),
  });
  const parts = prefix.split("/").filter(Boolean);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1 text-sm">
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

      {isLoading ? (
        <LoadingState label="Loading objects…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : !data || data.length === 0 ? (
        <EmptyState title="Empty" description="No objects under this path." />
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
                className="flex items-center gap-2 px-3 py-2 text-sm"
              >
                <FileText className="size-4 shrink-0 text-muted-foreground" />
                <span className="truncate">{basename(o.key)}</span>
                <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                  {formatBytes(o.size)}
                </span>
                <span className="w-16 shrink-0 text-right text-xs text-muted-foreground">
                  {age(o.lastModified)}
                </span>
              </li>
            ),
          )}
        </ul>
      )}
    </div>
  );
}

export function BucketsPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["buckets"],
    queryFn: listBuckets,
  });
  const buckets = data ?? [];
  const { filtered } = useListFilter(buckets, (b) => [b.name]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);
  const [selected, setSelected] = useState<string | null>(null);

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
        description="Object storage — open-infra's S3 (MinIO). Live from the cluster's MinIO; click a bucket to browse objects."
        actions={
          <Button
            variant="outline"
            size="icon"
            onClick={() => refetch()}
            aria-label="Refresh"
            disabled={isFetching}
          >
            <RefreshCw className="size-4" />
          </Button>
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
          description="Declare `storage: { buckets: [uploads] }` on an Application — the MinIO bucket appears here."
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
            onRowClick={(b) => setSelected(b.name)}
            emptyState={
              <EmptyState
                title="No matches"
                description="No buckets match the current filter."
              />
            }
          />
        </>
      )}

      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <HardDrive className="size-4" /> {selected}
            </SheetTitle>
          </SheetHeader>
          <div className="mt-4">
            {selected ? <ObjectBrowser bucket={selected} /> : null}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
