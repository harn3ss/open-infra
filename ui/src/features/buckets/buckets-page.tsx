import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ChevronRight, HardDrive, Plus, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
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
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useListFilter } from "@/hooks/use-list-filter";
import { ApiError, createBucket, listBuckets, type BucketInfo } from "@/lib/api";
import { age } from "@/lib/format";

export function BucketsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["buckets"],
    queryFn: listBuckets,
  });
  const buckets = data ?? [];
  const { filtered } = useListFilter(buckets, (b) => [b.name]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);
  const [newOpen, setNewOpen] = useState(false);
  const [newName, setNewName] = useState("");

  const createMutation = useMutation({
    mutationFn: () => createBucket(newName.trim()),
    onSuccess: () => {
      setNewOpen(false);
      setNewName("");
      qc.invalidateQueries({ queryKey: ["buckets"] });
    },
  });

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
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" />
              New bucket
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
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" />
              New bucket
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

      <Dialog open={newOpen} onOpenChange={setNewOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New bucket</DialogTitle>
            <DialogDescription>
              Bucket names are lowercase, 3–63 chars, no spaces.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="bucket-name">Name</Label>
            <Input
              id="bucket-name"
              value={newName}
              autoFocus
              placeholder="my-bucket"
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newName.trim()) createMutation.mutate();
              }}
            />
            {createMutation.isError ? (
              <p className="text-sm text-destructive">
                {createMutation.error instanceof ApiError
                  ? createMutation.error.message
                  : "Failed to create bucket."}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setNewOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={!newName.trim() || createMutation.isPending}
            >
              {createMutation.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
