import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MonitorSmartphone } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { LiveIndicator } from "@/components/common/live-indicator";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatTimestamp } from "@/lib/format";
import {
  cancelRemoteDesktopConnection,
  getRemoteDesktopConnection,
  listRemoteDesktopConnections,
  type RemoteDesktopConnection,
} from "@/lib/api";

/*
 * Fleet Manager → Account management → Connect with Remote Desktop: the account's Remote Desktop
 * connections, active and past (ssm-guiconnect:ListConnections). A connection's details are
 * ssm-guiconnect:GetConnection; ending an active one, ssm-guiconnect:CancelConnection. Connections are
 * started from an instance: Connect → RDP client → Connect using Fleet Manager.
 */

function StatusBadgeFor({ status }: { status: string }) {
  const tone =
    status === "Active"
      ? "bg-emerald-600 text-white"
      : status === "Failed"
        ? "bg-destructive text-white"
        : "";
  return (
    <Badge variant="secondary" className={tone}>
      {status}
    </Badge>
  );
}

function ConnectionsTable({
  rows,
  onOpen,
  ended,
}: {
  rows: RemoteDesktopConnection[];
  onOpen: (c: RemoteDesktopConnection) => void;
  ended: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-muted-foreground">
              <th className="p-3 font-medium">Connection ID</th>
              <th className="p-3 font-medium">Node</th>
              <th className="p-3 font-medium">Windows user</th>
              <th className="p-3 font-medium">Connected by</th>
              <th className="p-3 font-medium">Status</th>
              <th className="p-3 font-medium">Start time</th>
              <th className="p-3 font-medium">{ended ? "End time" : "Ends"}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.connectionId} className="border-b last:border-0">
                <td className="p-3">
                  <button className="font-mono text-xs text-primary hover:underline" onClick={() => onOpen(c)}>
                    {c.connectionId}
                  </button>
                </td>
                <td className="p-3">
                  <Link
                    to="/vms/$namespace/$name"
                    params={{ namespace: c.namespace, name: c.instance }}
                    className="text-primary hover:underline"
                  >
                    {c.instanceId}
                  </Link>{" "}
                  <span className="text-muted-foreground">({c.instance})</span>
                </td>
                <td className="p-3">{c.username}</td>
                <td className="max-w-[18rem] truncate p-3 text-muted-foreground" title={c.principal}>
                  {c.principal || "—"}
                </td>
                <td className="p-3">
                  <StatusBadgeFor status={c.status} />
                </td>
                <td className="p-3 text-muted-foreground">{formatTimestamp(c.startedAt)}</td>
                <td className="p-3 text-muted-foreground">
                  {formatTimestamp(ended ? c.endedAt : c.expiresAt) || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

function ConnectionSheet({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["remote-desktop-connection", id],
    queryFn: () => getRemoteDesktopConnection(id),
  });
  const end = useMutation({
    mutationFn: () => cancelRemoteDesktopConnection(id),
    onSuccess: () => {
      setConfirm(false);
      void qc.invalidateQueries({ queryKey: ["remote-desktop-connections"] });
      void qc.invalidateQueries({ queryKey: ["remote-desktop-connection", id] });
    },
  });
  const rows: [string, React.ReactNode][] = data
    ? [
        ["Connection ID", <span className="font-mono text-xs">{data.connectionId}</span>],
        ["Node", `${data.instanceId} (${data.instance})`],
        ["Windows user", data.username],
        ["Connected by", data.principal || "—"],
        ["Status", <StatusBadgeFor status={data.status} />],
        ["Start time", formatTimestamp(data.startedAt)],
        [data.endedAt ? "End time" : "Ends", formatTimestamp(data.endedAt ?? data.expiresAt) || "—"],
        ...(data.reason ? ([["Reason", data.reason]] as [string, React.ReactNode][]) : []),
      ]
    : [];
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Remote Desktop connection</SheetTitle>
          <SheetDescription>{id}</SheetDescription>
        </SheetHeader>
        <div className="space-y-4 p-4">
          {isLoading ? (
            <LoadingState />
          ) : isError ? (
            <ErrorState error={error} />
          ) : (
            <dl className="grid grid-cols-[9rem_1fr] gap-y-2 text-sm">
              {rows.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all">{v}</dd>
                </div>
              ))}
            </dl>
          )}
          {data?.status === "Active" ? (
            <div className="space-y-2 rounded-md border border-destructive/40 p-3">
              <div className="text-sm font-medium text-destructive">End connection</div>
              <p className="text-sm text-muted-foreground">
                Ends this Remote Desktop session for whoever is connected. Their Windows session stays signed in.
              </p>
              <Button variant="destructive" size="sm" onClick={() => setConfirm(true)}>
                End connection
              </Button>
              {end.isError ? <ErrorState error={end.error} /> : null}
            </div>
          ) : null}
        </div>
        <ConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title="End this connection?"
          confirmLabel="End connection"
          destructive
          loading={end.isPending}
          onConfirm={() => end.mutate()}
          description={<p className="text-sm">The person connected is disconnected within a few seconds.</p>}
        />
      </SheetContent>
    </Sheet>
  );
}

export function FleetManagerPage() {
  const [open, setOpen] = useState<string | null>(null);
  const { data, isLoading, isError, error, isFetching } = useQuery({
    queryKey: ["remote-desktop-connections"],
    queryFn: listRemoteDesktopConnections,
    refetchInterval: 10000,
  });
  return (
    <div className="space-y-6">
      <PageHeader
        icon={<MonitorSmartphone />}
        title="Fleet Manager"
        description="Remote Desktop connections to your Windows instances. Connect from an instance: Connect → RDP client → Connect using Fleet Manager."
        actions={<LiveIndicator live={isFetching} />}
      />
      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState error={error} />
      ) : (
        <Tabs defaultValue="active">
          <TabsList>
            <TabsTrigger value="active">Active connections ({data?.active.length ?? 0})</TabsTrigger>
            <TabsTrigger value="history">Connection history</TabsTrigger>
          </TabsList>
          <TabsContent value="active" className="pt-3">
            {data && data.active.length > 0 ? (
              <ConnectionsTable rows={data.active} onOpen={(c) => setOpen(c.connectionId)} ended={false} />
            ) : (
              <EmptyState
                title="No active connections"
                description="Remote Desktop connections in this account appear here while they're open."
              />
            )}
          </TabsContent>
          <TabsContent value="history" className="pt-3">
            {data && data.history.length > 0 ? (
              <ConnectionsTable rows={data.history} onOpen={(c) => setOpen(c.connectionId)} ended />
            ) : (
              <EmptyState title="No past connections" description="Ended Remote Desktop connections appear here." />
            )}
          </TabsContent>
        </Tabs>
      )}
      {open ? <ConnectionSheet id={open} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}
