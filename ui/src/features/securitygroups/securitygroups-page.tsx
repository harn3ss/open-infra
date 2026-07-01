import { useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Shield, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { NewSecurityGroupDialog } from "./new-security-group-dialog";
import { Button } from "@/components/ui/button";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  type Condition,
  type K8sObject,
  type SecurityGroup,
} from "@/types/k8s";

// One peer rendered compactly: 192.0.2.0/24 · sg:web · ns:kube-system
function peerLabel(p: { cidr?: string; securityGroup?: string; namespace?: string }): string {
  if (p.cidr) return p.cidr;
  if (p.securityGroup) return `sg:${p.securityGroup}`;
  if (p.namespace) return `ns:${p.namespace}`;
  return "?";
}

function summarize(
  rules: { protocol?: string; ports?: number[]; from?: unknown[]; to?: unknown[] }[] | undefined,
  dir: "from" | "to",
): string {
  if (!rules || rules.length === 0) return "—";
  return rules
    .map((r) => {
      const ports = r.ports && r.ports.length ? r.ports.join(",") : "all";
      const peers = ((r[dir] as { cidr?: string; securityGroup?: string; namespace?: string }[]) ?? [])
        .map(peerLabel)
        .join(", ");
      return `${r.protocol ?? "TCP"} ${ports}${peers ? ` ${dir === "from" ? "←" : "→"} ${peers}` : ""}`;
    })
    .join("  •  ");
}

function sgStatus(sg: SecurityGroup): { label: string; tone: StatusTone } {
  const ready = (sg.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function SecurityGroupsPage() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);
  const [editing, setEditing] = useState<SecurityGroup | null>(null);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const columns = useMemo<ColumnDef<SecurityGroup, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (sg) => sg.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/security-groups/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (sg) => sg.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "ingress",
        header: "Inbound",
        enableSorting: false,
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">
            {summarize(row.original.spec?.ingress, "from")}
          </code>
        ),
        size: 260,
      },
      {
        id: "egress",
        header: "Outbound",
        enableSorting: false,
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">
            {summarize(row.original.spec?.egress, "to")}
          </code>
        ),
        size: 240,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (sg) => sgStatus(sg).label,
        cell: ({ row }) => {
          const s = sgStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (sg) => sg.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <>
      <ResourceTablePage<SecurityGroup>
        icon={<Shield />}
        title="Security Groups"
        description="Reusable firewall rule sets — open-infra's Security Groups. Attach one to an Application, Function, or Virtual Machine (securityGroups: [...]) to control its inbound/outbound traffic. Enforced by Cilium."
        listPath={openinfraPaths.securitygroups}
        columns={columns}
        onRowClick={(sg) =>
          navigate({
            to: "/security-groups/$namespace/$name",
            params: {
              namespace: sg.metadata.namespace ?? "default",
              name: sg.metadata.name ?? "",
            },
          })
        }
        search={(sg) => [sg.metadata.name, sg.metadata.namespace]}
        singular="Security Group"
        plural="Security Groups"
        emptyTitle="No security groups yet"
        emptyDescription="Create a rule set, then attach it to a resource."
        headerActions={
          <Button
            onClick={() => {
              setEditing(null);
              setNewOpen(true);
            }}
          >
            <Plus className="size-4" /> New Security Group
          </Button>
        }
      />
      <NewSecurityGroupDialog
        open={newOpen}
        onOpenChange={(o) => {
          setNewOpen(o);
          if (!o) setEditing(null);
        }}
        namespaces={namespaces}
        defaultNamespace={scoped}
        editing={editing}
      />
    </>
  );
}
