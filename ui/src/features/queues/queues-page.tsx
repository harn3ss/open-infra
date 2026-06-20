import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { RefreshCw, Send } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useListFilter } from "@/hooks/use-list-filter";
import { listQueues, type StreamInfo } from "@/lib/api";
import { formatBytes } from "@/lib/format";

export function QueuesPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["queues"],
    queryFn: listQueues,
    refetchInterval: 10_000,
  });
  const streams = data ?? [];
  const { filtered } = useListFilter(streams, (s) => [
    s.name,
    s.account,
    ...(s.subjects ?? []),
  ]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "name", desc: false },
  ]);

  const columns = useMemo<ColumnDef<StreamInfo, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Stream",
        accessorFn: (s) => s.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.name}</span>
        ),
        size: 220,
      },
      {
        id: "subjects",
        header: "Subjects",
        accessorFn: (s) => (s.subjects ?? []).join(", "),
        cell: ({ row }) => (
          <code className="block max-w-[20rem] truncate text-xs">
            {(row.original.subjects ?? []).join(", ") || "—"}
          </code>
        ),
        size: 280,
      },
      {
        id: "messages",
        header: "Messages",
        accessorFn: (s) => s.messages,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.messages.toLocaleString()}
          </span>
        ),
        size: 120,
      },
      {
        id: "bytes",
        header: "Size",
        accessorFn: (s) => s.bytes,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {formatBytes(row.original.bytes)}
          </span>
        ),
        size: 110,
      },
      {
        id: "consumers",
        header: "Consumers",
        accessorFn: (s) => s.consumers,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.consumers}
          </span>
        ),
        size: 110,
      },
    ],
    [],
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Send />}
        title="Queues"
        description="Messaging — open-infra's SQS/SNS (NATS JetStream). Live stream stats from the cluster's NATS."
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
        <LoadingState label="Loading streams…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : streams.length === 0 ? (
        <EmptyState
          icon={<Send className="size-6" />}
          title="No JetStream streams"
          description="An Application declares queues with `queues: [jobs]`; the stream appears here once the app (or you) creates it in JetStream."
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {streams.length}{" "}
            {streams.length === 1 ? "stream" : "streams"}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(s) => `${s.account}/${s.name}`}
            sorting={sorting}
            onSortingChange={setSorting}
            onRowClick={(s) =>
              navigate({ to: "/queues/$stream", params: { stream: s.name } })
            }
            emptyState={
              <EmptyState
                title="No matches"
                description="No streams match the current filter."
              />
            }
          />
        </>
      )}
    </div>
  );
}
