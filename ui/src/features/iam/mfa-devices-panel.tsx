import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, Eye, EyeOff, Plus, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CopyButton } from "@/components/common/copy-button";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { Spinner } from "@/components/common/states";
import { useFlash } from "@/components/common/flashbar";
import {
  cancelMfaDevice,
  createVirtualMfaDevice,
  enableMfaDevice,
  listMfaDevices,
  removeMfaDevice,
  type MfaDevice,
  type VirtualMfaDeviceCreated,
} from "@/lib/api";

const MAX_DEVICES = 8;

/**
 * The "Multi-factor authentication (MFA)" section of a user's Security credentials tab, as the AWS console
 * has it: the user's MFA devices, "Assign MFA device" (a virtual device — an authenticator app — set up
 * from its QR code and two consecutive codes) and "Remove". A user with a device signs in to the console
 * with its code, and its sessions carry MFA for IAM policy's aws:MultiFactorAuthPresent.
 */
export function MfaDevicesPanel({ user }: { user: string }) {
  const qc = useQueryClient();
  const flash = useFlash();
  const devicesQuery = useQuery({
    queryKey: ["iam", "mfaDevices", user],
    queryFn: () => listMfaDevices(user),
  });
  const devices = devicesQuery.data ?? [];
  const invalidate = () => qc.invalidateQueries({ queryKey: ["iam", "mfaDevices", user] });

  const [assigning, setAssigning] = useState(false);
  const [removing, setRemoving] = useState<MfaDevice | null>(null);

  const remove = useMutation({
    mutationFn: (serial: string) => removeMfaDevice(user, serial),
    onSuccess: () => {
      void invalidate();
      setRemoving(null);
      flash.success("MFA device removed.");
    },
    onError: (e) => flash.error((e as Error).message),
  });

  const atLimit = devices.length >= MAX_DEVICES;

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <h3 className="flex items-center gap-1.5 text-sm font-semibold">
              <ShieldCheck className="size-4" /> Multi-factor authentication (MFA)
            </h3>
            <p className="text-sm text-muted-foreground">
              Use MFA to increase the security of this user's sign-in. With an MFA device assigned, the
              console asks for its code after the password, and policies can require MFA
              (<code className="text-xs">aws:MultiFactorAuthPresent</code>). A user can have up to{" "}
              {MAX_DEVICES} MFA devices.
            </p>
          </div>
          <Button
            variant="outline"
            onClick={() => setAssigning(true)}
            disabled={atLimit}
            title={atLimit ? `A user may have at most ${MAX_DEVICES} MFA devices` : undefined}
          >
            <Plus className="size-4" /> Assign MFA device
          </Button>
        </div>

        {devicesQuery.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner className="size-4" /> Loading MFA devices…
          </div>
        ) : devicesQuery.isError ? (
          <p className="text-sm text-destructive">
            {(devicesQuery.error as Error).message || "Could not load MFA devices."}
          </p>
        ) : devices.length === 0 ? (
          <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
            No MFA devices. Assign an MFA device to improve the security of this user's sign-in.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Type</th>
                  <th className="py-2 pr-4 font-medium">Identifier</th>
                  <th className="py-2 pr-4 font-medium">Created on</th>
                  <th className="py-2 pr-0 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.serialNumber} className="border-b last:border-0">
                    <td className="py-2 pr-4">
                      <Badge variant="secondary">
                        <Smartphone className="size-3" /> Virtual
                      </Badge>
                    </td>
                    <td className="py-2 pr-4">
                      <span className="inline-flex items-center gap-1 break-all">
                        <code className="font-mono text-xs">{d.serialNumber}</code>
                        <CopyButton value={d.serialNumber} label="Copy identifier" />
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-muted-foreground">{formatDate(d.enableDate ?? d.created)}</td>
                    <td className="py-2 pr-0">
                      <div className="flex justify-end">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={remove.isPending}
                          onClick={() => setRemoving(d)}
                          className="text-destructive hover:text-destructive"
                        >
                          <Trash2 className="size-4" /> Remove
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>

      <AssignMfaDialog
        user={user}
        open={assigning}
        onClose={() => setAssigning(false)}
        onAssigned={() => {
          setAssigning(false);
          void invalidate();
          flash.success("MFA device assigned. The next sign-in asks for its code.");
        }}
      />

      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove MFA device?"
        confirmLabel="Remove"
        loading={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.serialNumber)}
        description={
          <>
            Remove <code className="font-mono text-xs">{removing?.serialNumber}</code> from{" "}
            <span className="font-medium">{user}</span>. The device is deactivated and deleted; the user's
            next sign-in no longer asks for its code, and policies that require MFA deny its sessions until
            another device is assigned.
          </>
        }
      />
    </Card>
  );
}

/**
 * "Assign MFA device": name the device (an authenticator app), scan its QR code (or type its secret key),
 * then enter two consecutive codes. Cancelling after the QR code is shown deletes the device, which no one
 * else holds the secret of.
 */
function AssignMfaDialog({
  user,
  open,
  onClose,
  onAssigned,
}: {
  user: string;
  open: boolean;
  onClose: () => void;
  onAssigned: () => void;
}) {
  const [name, setName] = useState("");
  const [created, setCreated] = useState<VirtualMfaDeviceCreated | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [code1, setCode1] = useState("");
  const [code2, setCode2] = useState("");
  const [error, setError] = useState<string | null>(null);

  const nameValid = /^[\w+=,.@-]{1,128}$/.test(name);

  function reset() {
    setName("");
    setCreated(null);
    setShowSecret(false);
    setCode1("");
    setCode2("");
    setError(null);
  }

  const create = useMutation({
    mutationFn: () => createVirtualMfaDevice(user, name),
    onSuccess: (res) => {
      setCreated(res);
      setError(null);
    },
    onError: (e) => setError((e as Error).message),
  });

  const enable = useMutation({
    mutationFn: () => enableMfaDevice(user, created?.serialNumber ?? "", code1, code2),
    onSuccess: () => {
      reset();
      onAssigned();
    },
    onError: (e) => setError((e as Error).message),
  });

  function cancel() {
    // A device set up but not enabled is deleted: its secret was shown only here.
    if (created) void cancelMfaDevice(user, created.serialNumber).catch(() => undefined);
    reset();
    onClose();
  }

  const codeInput = (id: string, value: string, set: (v: string) => void) => (
    <Input
      id={id}
      value={value}
      onChange={(e) => set(e.target.value.replace(/\D/g, "").slice(0, 6))}
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      className="font-mono"
    />
  );

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !create.isPending && !enable.isPending && cancel()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Smartphone className="size-5" /> {created ? "Set up device" : "Select MFA device"}
          </DialogTitle>
          <DialogDescription asChild>
            <div>
              {created
                ? "Set up an authenticator app on a phone or computer for this user."
                : "Name the MFA device and choose its type. The name is part of its identifier and must be unique in the account."}
            </div>
          </DialogDescription>
        </DialogHeader>

        {!created ? (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="mfa-name">Device name</Label>
              <Input id="mfa-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={`${user}-phone`} autoFocus />
              <p className="text-xs text-muted-foreground">
                Letters, digits and + = , . @ _ - (no spaces). Up to 128 characters.
              </p>
            </div>
            <div className="space-y-1.5">
              <div className="text-sm font-medium">MFA device</div>
              <div className="flex items-start gap-3 rounded-md border border-primary/50 bg-primary/5 p-3">
                <CircleCheck className="mt-0.5 size-4 shrink-0 text-primary" />
                <div className="space-y-0.5 text-sm">
                  <div className="font-medium">Authenticator app</div>
                  <div className="text-muted-foreground">
                    Authenticate using a code generated by an app installed on a mobile device or computer.
                  </div>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Passkeys, security keys and hardware TOTP tokens are not supported.
              </p>
            </div>
          </div>
        ) : (
          <ol className="list-decimal space-y-4 pl-5 text-sm">
            <li>Install a compatible authenticator app on a mobile device or computer.</li>
            <li className="space-y-2">
              <div>Open your authenticator app, then scan this QR code with it.</div>
              <img
                src={`data:image/png;base64,${created.qrCodePng}`}
                alt="QR code of the virtual MFA device"
                className="size-48 rounded-md border bg-white p-1"
              />
              <div className="space-y-1">
                <button
                  type="button"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                  onClick={() => setShowSecret((s) => !s)}
                >
                  {showSecret ? <EyeOff className="size-3" /> : <Eye className="size-3" />}
                  {showSecret ? "Hide secret key" : "Alternatively, show the secret key"}
                </button>
                {showSecret ? (
                  <div className="flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-1.5">
                    <code className="flex-1 break-all font-mono text-xs">{created.base32StringSeed}</code>
                    <CopyButton value={created.base32StringSeed} label="Copy secret key" />
                  </div>
                ) : null}
              </div>
            </li>
            <li className="space-y-2">
              <div>Type two consecutive MFA codes below.</div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="mfa-code-1">MFA code 1</Label>
                  {codeInput("mfa-code-1", code1, setCode1)}
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="mfa-code-2">MFA code 2</Label>
                  {codeInput("mfa-code-2", code2, setCode2)}
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Enter the code the app shows, wait for it to change, then enter the next one.
              </p>
            </li>
          </ol>
        )}

        {error ? <p className="text-sm text-destructive">{error}</p> : null}

        <DialogFooter>
          <Button variant="outline" onClick={cancel} disabled={create.isPending || enable.isPending}>
            Cancel
          </Button>
          {!created ? (
            <Button disabled={!nameValid || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? <Spinner className="size-4" /> : null}
              Next
            </Button>
          ) : (
            <Button
              disabled={code1.length !== 6 || code2.length !== 6 || enable.isPending}
              onClick={() => enable.mutate()}
            >
              {enable.isPending ? <Spinner className="size-4" /> : null}
              Add MFA
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
