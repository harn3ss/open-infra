import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Mail, TriangleAlert } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { AdvancedYaml } from "@/components/common/advanced-yaml";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { EmailSender } from "@/types/k8s";
import { awsState } from "@/lib/aws-states";

function senderStatus(s: EmailSender): { label: string; tone: StatusTone } {
  // An identity the account has not verified yet is SES's "Pending", whatever else is ready: its
  // credentials sign in, but every send is refused until the operator verifies it.
  if (s.status?.verificationStatus === "PENDING") return { label: "Pending verification", tone: "warning" };
  // The resource's state in AWS's words (lib/aws-states).
  return awsState(s, "emailsender");
}

export function EmailSenderDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.emailsender(namespace, name);

  const { data: sender, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["emailsender", namespace, name],
    queryFn: () => k8sGet<EmailSender>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/emailsenders" }),
  });

  if (isLoading) return <LoadingState label="Loading email sender…" />;
  if (isError || !sender) return <ErrorState error={error} onRetry={refetch} />;

  const status = senderStatus(sender);
  const spec = sender.spec;
  const fromAddress = spec?.fromAddress ?? sender.status?.fromAddress;
  const connectionSecret = sender.status?.connectionSecret;
  const smtpUsername = sender.status?.smtpUsername;
  const iamUser = sender.status?.iamUser;
  const verification = sender.status?.verificationStatus;

  return (
    <DetailShell
      backTo="/emailsenders"
      backLabel="Email Senders"
      icon={<Mail className="size-5" />}
      title={name}
      subtitle="Email sender"
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">Advanced</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "From address",
                    value: fromAddress ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{fromAddress}</code>
                        <CopyButton value={fromAddress} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "From name",
                    value: spec?.fromName ? spec.fromName : null,
                  },
                  {
                    label: "Connection secret",
                    value: connectionSecret ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{connectionSecret}</code>
                        <CopyButton value={connectionSecret} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">provisioning…</span>
                    ),
                  },
                  {
                    label: "Identity status",
                    value: verification ? (
                      <StatusBadge
                        status={verification === "SUCCESS" ? "Verified" : "Pending"}
                        tone={verification === "SUCCESS" ? "success" : "warning"}
                      />
                    ) : null,
                  },
                  {
                    label: "SMTP user name",
                    value: smtpUsername ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{smtpUsername}</code>
                        <CopyButton value={smtpUsername} />
                      </span>
                    ) : null,
                  },
                  {
                    label: "IAM user",
                    value: iamUser ? <code className="text-xs">{iamUser}</code> : null,
                  },
                  {
                    label: "Ready",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {connectionSecret ? (
            <div className="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
              Reference the SMTP credentials in an Application or Function via{" "}
              <code className="text-xs">spec.secrets</code> — open-infra injects the{" "}
              <span className="font-medium text-foreground">{connectionSecret}</span> secret (host, port, username,
              password) into the workload's environment. Send through the SES SMTP interface with STARTTLS, as this
              From address only.
            </div>
          ) : null}

          {/* Honest maturity note — deliverability is operator-owned, not console-claimed. */}
          <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-sm text-warning">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span>
              <span className="font-medium">Experimental.</span> Mail is sent through the SES SMTP interface to the
              platform relay. Internet deliverability is <span className="font-medium">not guaranteed out of the box</span> — reaching
              real inboxes needs a smarthost (an authenticated upstream relay) plus SPF, DKIM, and DMARC DNS records for
              your domain. Those are operator-configured; the console does not verify them.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <AdvancedYaml value={sender} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Email Sender"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete email sender <span className="font-medium text-foreground">{name}</span>. Any
                application referencing its connection secret{" "}
                {connectionSecret ? (
                  <span className="font-medium text-foreground">{connectionSecret}</span>
                ) : (
                  "secret"
                )}{" "}
                will no longer be able to send mail.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
