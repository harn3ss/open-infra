import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Table2, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { tableStatus, billingLabel } from "@/features/tables/tables-page";
import type { Table, TableKey, TableKeyType } from "@/types/k8s";

const KEY_TYPE_NAME: Record<TableKeyType, string> = { S: "String", N: "Number", B: "Binary" };

/** Render a DynamoDB key as `attrName (String · S)`. */
function keyValue(keyDef?: TableKey) {
  if (!keyDef?.name) return null;
  return (
    <span className="inline-flex items-center gap-1">
      <code className="text-xs">{keyDef.name}</code>
      <span className="text-muted-foreground">
        ({KEY_TYPE_NAME[keyDef.type]} · {keyDef.type})
      </span>
    </span>
  );
}

export function TableDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.table(namespace, name);

  const { data: tbl, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["table", namespace, name],
    queryFn: () => k8sGet<Table>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/tables" }),
  });

  if (isLoading) return <LoadingState label="Loading table…" />;
  if (isError || !tbl) return <ErrorState error={error} onRetry={refetch} />;

  const status = tableStatus(tbl);
  const spec = tbl.spec;
  const tableName = spec?.tableName ?? tbl.metadata.name ?? name;
  const gsis = spec?.globalSecondaryIndexes ?? [];

  return (
    <DetailShell
      backTo="/tables"
      backLabel="Tables"
      icon={<Table2 className="size-5" />}
      title={tableName}
      subtitle={`Table · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="indexes">Indexes ({gsis.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Table name",
                    value: (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{tableName}</code>
                        <CopyButton value={tableName} />
                      </span>
                    ),
                  },
                  { label: "Partition key", value: keyValue(spec?.hashKey) },
                  { label: "Sort key", value: keyValue(spec?.rangeKey) },
                  { label: "Capacity mode", value: billingLabel(spec?.billingMode) },
                  {
                    label: "Time to Live (TTL) attribute",
                    value: spec?.ttlAttribute ? (
                      <code className="text-xs">{spec.ttlAttribute}</code>
                    ) : (
                      <span className="text-muted-foreground">Disabled</span>
                    ),
                  },
                  {
                    label: "Status",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {/* Honest data-plane note: items live behind the aws-shim DynamoDB API, not this console. */}
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              Items are accessed via the <span className="font-medium text-foreground">DynamoDB data API</span> (the
              aws-shim front door, opt-in) — use the AWS SDK or CLI (<code className="text-xs">GetItem</code>,{" "}
              <code className="text-xs">PutItem</code>, <code className="text-xs">Query</code>,{" "}
              <code className="text-xs">Scan</code>) against the shim endpoint. This console manages the table's
              schema (keys, indexes, TTL); it does not browse items. The key schema is immutable, as in DynamoDB.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="indexes" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Global secondary indexes</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {gsis.length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">
                  No global secondary indexes. A GSI lets you query the table on a different partition/sort key —
                  add one in the table spec (each has its own key schema).
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-left text-xs font-medium text-muted-foreground">
                        <th className="px-4 py-2">Index name</th>
                        <th className="px-4 py-2">Partition key</th>
                        <th className="px-4 py-2">Sort key</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {gsis.map((g) => (
                        <tr key={g.name}>
                          <td className="px-4 py-2 font-medium">{g.name}</td>
                          <td className="px-4 py-2">{keyValue(g.hashKey)}</td>
                          <td className="px-4 py-2">
                            {keyValue(g.rangeKey) ?? <span className="text-muted-foreground">—</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={tbl} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Table"
            resourceName={tableName}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete table{" "}
                <span className="font-medium text-foreground">{tableName}</span> and all of its items. This cannot
                be undone.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
