import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Radio, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Stream } from "@/types/k8s";

function streamStatus(s: Stream): { label: string; tone: StatusTone } {
  const conds = s.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function StreamsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Stream, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (s) => s.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (s) => s.spec?.source?.engine ?? "",
        cell: ({ row }) => {
          const src = row.original.spec?.source;
          return (
            <span className="text-xs">
              <code>{src?.engine}</code>{" "}
              <span className="text-muted-foreground">{src?.host}</span>
            </span>
          );
        },
        size: 240,
      },
      {
        id: "subjects",
        header: "Subjects (JetStream)",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">cdc.{row.original.metadata.name}.&gt;</code>
        ),
        size: 200,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => streamStatus(s).label,
        cell: ({ row }) => {
          const s = streamStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Stream>
      icon={<Radio />}
      title="Streams"
      description="Change-data-capture streams — open-infra's 'Kinesis'. A Stream taps a source database's change log (Debezium) and publishes every row change as a real-time event onto NATS JetStream (subjects cdc.<name>.<schema>.<table>), where apps, Functions, and sinks subscribe."
      listPath={openinfraPaths.streams}
      columns={columns}
      onRowClick={(s) =>
        navigate({
          to: "/streams/$namespace/$name",
          params: {
            namespace: s.metadata.namespace ?? "default",
            name: s.metadata.name ?? "",
          },
        })
      }
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.source?.engine, s.spec?.source?.host]}
      singular="Stream"
      plural="Streams"
      emptyTitle="No streams yet"
      emptyDescription="Create one to publish a database's changes onto JetStream in real time."
      docsHref={kindDocsUrl("Stream")}
      headerActions={
        <Button onClick={() => navigate({ to: "/streams/new" })}>
          <Plus className="size-4" /> New Stream
        </Button>
      }
    />
  );
}
