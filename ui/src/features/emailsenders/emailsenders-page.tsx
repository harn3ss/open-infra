import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Mail, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import type { Condition, EmailSender } from "@/types/k8s";

/** Ready when the Ready condition is True (or status.ready is set); else provisioning. */
function senderStatus(s: EmailSender): { label: string; tone: StatusTone } {
  const ready = s.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True" || s.status?.ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function EmailSendersPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<EmailSender, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/emailsenders/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 200,
      },
      {
        id: "fromAddress",
        header: "From address",
        accessorFn: (s) => s.spec?.fromAddress ?? s.status?.fromAddress ?? "",
        cell: ({ row }) => {
          const from = row.original.spec?.fromAddress ?? row.original.status?.fromAddress;
          return from ? (
            <code className="text-xs">{from}</code>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
        size: 260,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => senderStatus(s).label,
        cell: ({ row }) => {
          const st = senderStatus(row.original);
          return <StatusBadge status={st.label} tone={st.tone} />;
        },
        size: 130,
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

  const filterProperties = useMemo<FilterPropertyDef<EmailSender>[]>(
    () => [
      { key: "name", label: "Name", getValue: (s) => s.metadata.name },
      { key: "fromAddress", label: "From address", getValue: (s) => s.spec?.fromAddress },
      {
        key: "status",
        label: "Status",
        getValue: (s) => senderStatus(s).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<EmailSender>
      icon={<Mail />}
      title="Email Senders"
      description="A transactional sending identity (AWS SES). Each sender is a From address plus an SMTP connection secret that apps use to send mail through an in-cluster relay."
      listPath={openinfraPaths.emailsenders}
      columns={columns}
      onRowClick={(s) =>
        navigate({
          to: "/emailsenders/$namespace/$name",
          params: {
            namespace: s.metadata.namespace ?? "default",
            name: s.metadata.name ?? "",
          },
        })
      }
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.fromAddress, s.spec?.fromName]}
      singular="email sender"
      plural="email senders"
      emptyTitle="No email senders yet"
      emptyDescription="Create an email sender to give an application a From address and an SMTP connection secret for transactional mail."
      docsHref={kindDocsUrl("EmailSender")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{ fromAddress: "From address" }}
      headerActions={
        <Button onClick={() => navigate({ to: "/emailsenders/new" })}>
          <Plus className="size-4" /> Create email sender
        </Button>
      }
    />
  );
}
