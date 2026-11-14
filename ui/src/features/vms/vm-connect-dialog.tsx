import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CopyButton } from "@/components/common/copy-button";
import { ErrorState } from "@/components/common/states";
import {
  ApiError,
  checkSerialConsole,
  getSerialConsoleAccess,
  setSerialConsoleAccess,
} from "@/lib/api";
import { SerialTerminal } from "./serial-terminal";

/*
 * The EC2 console's "Connect to instance": SSH client (or RDP client for Windows) and EC2 serial console.
 * The serial console is the instance's serial port (ttyS0), for when the network can't reach it: allowed
 * per account (Manage access, ec2:EnableSerialConsoleAccess), one session per instance, opened in the
 * browser here or with `aws ec2-instance-connect send-serial-console-ssh-public-key` and ssh.
 */

function Cmd({ value }: { value: string }) {
  return (
    <div className="flex items-start gap-1 rounded-md border bg-muted/40 p-2">
      <code className="flex-1 whitespace-pre-wrap break-all text-xs">{value}</code>
      <CopyButton value={value} />
    </div>
  );
}

export function VmConnectDialog({
  namespace,
  name,
  instanceId,
  isWindows,
  connectCmd,
  open,
  onOpenChange,
}: {
  namespace: string;
  name: string;
  instanceId?: string;
  isWindows: boolean;
  connectCmd: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [terminal, setTerminal] = useState(false);
  const [manage, setManage] = useState(false);
  const [tab, setTab] = useState("client");
  const access = useQuery({
    queryKey: ["serial-console-access"],
    queryFn: getSerialConsoleAccess,
    enabled: open,
  });
  const setAccess = useMutation({
    mutationFn: (allow: boolean) => setSerialConsoleAccess(allow),
    onSuccess: () => {
      setManage(false);
      qc.invalidateQueries({ queryKey: ["serial-console-access"] });
    },
  });
  const check = useMutation({
    mutationFn: () => checkSerialConsole(namespace, name),
    onSuccess: () => setTerminal(true),
  });
  const allowed = access.data?.serialConsoleAccessEnabled ?? false;
  const id = instanceId ?? "<instance-id>";
  const endpoint = access.data?.endpoint || "<serial-console-endpoint>";

  return (
    <>
      <Dialog open={open && !terminal} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Connect to instance</DialogTitle>
            <DialogDescription>
              Connect to your instance <span className="font-medium text-foreground">{id}</span> ({name}).
            </DialogDescription>
          </DialogHeader>
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="client">{isWindows ? "RDP client" : "SSH client"}</TabsTrigger>
              <TabsTrigger value="serial">EC2 serial console</TabsTrigger>
            </TabsList>
            <TabsContent value="client" className="space-y-3 pt-3">
              <p className="text-sm text-muted-foreground">
                {isWindows
                  ? "Connect with a Remote Desktop client to the instance's address, as Administrator with the password on its Access tab."
                  : "Connect with an SSH client, with your key or the password on the instance's Access tab."}
              </p>
              <Cmd value={connectCmd} />
            </TabsContent>
            <TabsContent value="serial" className="space-y-3 pt-3">
              {access.isError ? (
                <ErrorState error={access.error} onRetry={() => access.refetch()} />
              ) : (
                <>
                  <dl className="grid grid-cols-[10rem_1fr] gap-y-1 text-sm">
                    <dt className="text-muted-foreground">Instance ID</dt>
                    <dd>{id}</dd>
                    <dt className="text-muted-foreground">Serial port</dt>
                    <dd>ttyS0</dd>
                    <dt className="text-muted-foreground">Serial console access</dt>
                    <dd>{access.isLoading ? "…" : allowed ? "Allowed" : "Not allowed"}</dd>
                  </dl>
                  {!access.isLoading && !allowed ? (
                    <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
                      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-600" />
                      <span>
                        EC2 serial console access is not allowed for this account. An administrator can allow
                        it under Manage access.
                      </span>
                    </div>
                  ) : null}
                  {manage ? (
                    <div className="space-y-2 rounded-md border p-3 text-sm">
                      <div className="font-medium">EC2 serial console access</div>
                      <p className="text-muted-foreground">
                        Allowing access lets principals with ec2-instance-connect:SendSerialConsoleSSHPublicKey
                        connect to the serial console of any instance in this account.
                      </p>
                      <div className="flex gap-2">
                        <Button size="sm" onClick={() => setAccess.mutate(!allowed)} disabled={setAccess.isPending}>
                          {allowed ? "Disallow" : "Allow"}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setManage(false)}>
                          Cancel
                        </Button>
                      </div>
                      {setAccess.isError ? <ErrorState error={setAccess.error} /> : null}
                    </div>
                  ) : null}
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">Connect with an SSH client</summary>
                    <div className="space-y-2 pt-2">
                      <p className="text-muted-foreground">
                        Push a public key, then connect within 60 seconds:
                      </p>
                      <Cmd
                        value={`aws ec2-instance-connect send-serial-console-ssh-public-key --instance-id ${id} --serial-port 0 --ssh-public-key file://my_key.pub`}
                      />
                      <Cmd value={`ssh -i my_key ${id}.port0@${endpoint}`} />
                    </div>
                  </details>
                  {check.isError ? (
                    <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
                      {check.error instanceof ApiError ? check.error.message : String(check.error)}
                    </p>
                  ) : null}
                </>
              )}
            </TabsContent>
          </Tabs>
          <DialogFooter className="gap-2">
            {tab === "serial" ? (
              <>
                <Button variant="outline" onClick={() => setManage((m) => !m)}>
                  Manage access
                </Button>
                <Button variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button onClick={() => check.mutate()} disabled={check.isPending || !allowed}>
                  Connect
                </Button>
              </>
            ) : (
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        open={open && terminal}
        onOpenChange={(o) => {
          if (!o) {
            setTerminal(false);
            onOpenChange(false);
          }
        }}
      >
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <DialogTitle>EC2 serial console — {id}</DialogTitle>
            <DialogDescription>ttyS0 of {name}. Closing this window ends the session.</DialogDescription>
          </DialogHeader>
          {terminal ? <SerialTerminal namespace={namespace} name={name} /> : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
