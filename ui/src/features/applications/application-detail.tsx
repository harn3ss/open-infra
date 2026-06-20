import { ExternalLink, Trash2 } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { StatusBadge } from "@/components/common/status-badge";
import { DetailRow, KeyValueList } from "@/components/common/detail-row";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { age, formatTimestamp } from "@/lib/format";
import {
  applicationHealth,
  conditionTone,
} from "@/features/applications/application-status";
import type { Application } from "@/types/k8s";

export function ApplicationDetail({
  app,
  open,
  onOpenChange,
  onDelete,
}: {
  app: Application | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDelete: (app: Application) => void;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-xl">
        {app ? (
          <>
            <SheetHeader>
              <div className="flex items-center justify-between gap-2 pr-8">
                <div className="min-w-0">
                  <SheetTitle className="truncate">
                    {app.metadata.name}
                  </SheetTitle>
                  <SheetDescription>
                    Application · {app.metadata.namespace}
                  </SheetDescription>
                </div>
                <StatusBadge
                  status={applicationHealth(app).label}
                  tone={applicationHealth(app).tone}
                />
              </div>
            </SheetHeader>

            <div className="flex-1 overflow-auto p-5">
              <Tabs defaultValue="overview">
                <TabsList>
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="conditions">Conditions</TabsTrigger>
                  <TabsTrigger value="yaml">YAML</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-5">
                  {app.status?.url ? (
                    <a
                      href={app.status.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline"
                    >
                      {app.status.url}
                      <ExternalLink className="size-3.5" />
                    </a>
                  ) : null}

                  <dl className="divide-y divide-border">
                    <ResourceNameRow
                      kind="application"
                      name={app.metadata.name}
                      namespace={app.metadata.namespace}
                    />
                    <DetailRow label="Image">
                      <span className="flex items-center gap-1.5">
                        <code className="break-all text-xs">
                          {app.spec?.image}
                        </code>
                        {app.spec?.image ? (
                          <CopyButton value={app.spec.image} />
                        ) : null}
                      </span>
                    </DetailRow>
                    <DetailRow label="Port">{app.spec?.port ?? "—"}</DetailRow>
                    <DetailRow label="Domain">
                      {app.spec?.domain ?? "—"}
                    </DetailRow>
                    <DetailRow label="Created">
                      <span title={formatTimestamp(app.metadata.creationTimestamp)}>
                        {age(app.metadata.creationTimestamp)} ago
                      </span>
                    </DetailRow>
                  </dl>

                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold">Scaling</h3>
                    <dl className="divide-y divide-border">
                      <DetailRow label="Min replicas">
                        {app.spec?.scaling?.min ?? 1}
                      </DetailRow>
                      <DetailRow label="Max replicas">
                        {app.spec?.scaling?.max ?? 5}
                      </DetailRow>
                      <DetailRow label="Target CPU %">
                        {app.spec?.scaling?.targetCPUPercent ?? 70}
                      </DetailRow>
                    </dl>
                  </div>

                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold">Attached resources</h3>
                    <dl className="divide-y divide-border">
                      <DetailRow label="Database">
                        {app.spec?.database?.name ? (
                          <Badge variant="accent">
                            {app.spec.database.engine ?? "postgres"} ·{" "}
                            {app.spec.database.name}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </DetailRow>
                      <DetailRow label="Buckets">
                        {app.spec?.storage?.buckets?.length ? (
                          <div className="flex flex-wrap gap-1.5">
                            {app.spec.storage.buckets.map((b) => (
                              <Badge key={b} variant="secondary">
                                {b}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </DetailRow>
                      <DetailRow label="Queues">
                        {app.spec?.queues?.length ? (
                          <div className="flex flex-wrap gap-1.5">
                            {app.spec.queues.map((q) => (
                              <Badge key={q} variant="secondary">
                                {q}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </DetailRow>
                      <DetailRow label="Secrets">
                        {app.spec?.secrets?.length ? (
                          <div className="flex flex-wrap gap-1.5">
                            {app.spec.secrets.map((s) => (
                              <Badge key={s} variant="muted">
                                {s}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </DetailRow>
                    </dl>
                  </div>

                  {app.spec?.env?.length ? (
                    <div className="space-y-3">
                      <h3 className="text-sm font-semibold">Environment</h3>
                      <div className="rounded-lg border border-border">
                        {app.spec.env.map((e, i) => (
                          <div
                            key={`${e.name}-${i}`}
                            className="flex items-center justify-between gap-3 border-b border-border px-3 py-1.5 text-sm last:border-0"
                          >
                            <code className="text-xs text-muted-foreground">
                              {e.name}
                            </code>
                            <code className="truncate text-xs">{e.value}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="space-y-2">
                    <h3 className="text-sm font-semibold">Labels</h3>
                    <KeyValueList data={app.metadata.labels} />
                  </div>
                </TabsContent>

                <TabsContent value="conditions" className="space-y-2">
                  {app.status?.conditions?.length ? (
                    app.status.conditions.map((c, i) => (
                      <div
                        key={`${c.type}-${i}`}
                        className="rounded-lg border border-border p-3"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{c.type}</span>
                          <StatusBadge status={c.status} tone={conditionTone(c)} />
                        </div>
                        {c.reason ? (
                          <p className="mt-1 text-xs text-muted-foreground">
                            {c.reason}
                          </p>
                        ) : null}
                        {c.message ? (
                          <p className="mt-1 text-xs text-muted-foreground">
                            {c.message}
                          </p>
                        ) : null}
                        {c.lastTransitionTime ? (
                          <p className="mt-1 text-[0.7rem] text-muted-foreground/70">
                            {formatTimestamp(c.lastTransitionTime)}
                          </p>
                        ) : null}
                      </div>
                    ))
                  ) : (
                    <p className="py-6 text-center text-sm text-muted-foreground">
                      No conditions reported yet.
                    </p>
                  )}
                </TabsContent>

                <TabsContent value="yaml">
                  <YamlViewer value={app} maxHeightClassName="max-h-[65vh]" />
                </TabsContent>
              </Tabs>
            </div>

            <Separator />
            <div className="flex items-center justify-between gap-2 p-4">
              <span className="text-sm font-semibold text-destructive">
                Danger Zone
              </span>
              <Button variant="destructive" onClick={() => onDelete(app)}>
                <Trash2 className="size-4" />
                Delete
              </Button>
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
