import { useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Disc, Loader2, Plus, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/common/status-badge";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { corePaths, kubevirtPaths, openinfraPaths } from "@/lib/k8s-paths";
import { ApiError, k8sCreate, k8sDelete } from "@/lib/api";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
  type KubevirtVm,
  type VmImage,
} from "@/types/k8s";
import {
  IMAGES_NAMESPACE,
  WINDOWS_CATALOG,
  goldenPvcName,
} from "./vm-shared";

type Pvc = K8sObject<unknown, { phase?: string }>;

function buildState(
  claim: VmImage | undefined,
  installer: KubevirtVm | undefined,
  golden: Pvc | undefined,
): { label: string; tone: StatusTone; state: "none" | "building" | "ready" } {
  const ps = installer?.status?.printableStatus;
  const built = ps === "Stopped" || (!installer && golden?.status?.phase === "Bound");
  if (built) return { label: "Ready", tone: "success", state: "ready" };
  if (claim || installer)
    return {
      label: ps && ps !== "Stopped" ? `Building · ${ps}` : "Building…",
      tone: "warning",
      state: "building",
    };
  return { label: "Not built", tone: "muted", state: "none" };
}

export function VmImagesPage() {
  const queryClient = useQueryClient();
  const images = useK8sWatch<VmImage>(openinfraPaths.vmimages(IMAGES_NAMESPACE));
  const installers = useK8sWatch<KubevirtVm>(kubevirtPaths.vms(IMAGES_NAMESPACE));
  const goldens = useK8sWatch<Pvc>(corePaths.pvcs(IMAGES_NAMESPACE));

  const byName = useMemo(() => {
    const im = new Map(images.items.map((i) => [i.metadata.name, i]));
    const inst = new Map(installers.items.map((i) => [i.metadata.name, i]));
    const gold = new Map(goldens.items.map((p) => [p.metadata.name, p]));
    return { im, inst, gold };
  }, [images.items, installers.items, goldens.items]);

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: watchQueryKey(openinfraPaths.vmimages(IMAGES_NAMESPACE)),
    });

  const build = useMutation({
    mutationFn: (os: string) =>
      k8sCreate(openinfraPaths.vmimages(IMAGES_NAMESPACE), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "VmImage",
        metadata: { name: os, namespace: IMAGES_NAMESPACE },
        spec: { os },
      } as K8sObject),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (os: string) =>
      k8sDelete(openinfraPaths.vmimage(IMAGES_NAMESPACE, os)),
    onSuccess: invalidate,
  });

  return (
    <DetailShell
      backTo="/vms"
      backLabel="Virtual Machines"
      icon={<Disc className="size-5" />}
      title="VM Images"
      subtitle="Windows golden images — built once from Microsoft eval ISOs, then cloned by Windows VMs"
    >
      <div className="rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
        Windows evaluation editions are free for <strong>non-production testing
        only</strong> (180 days). A build downloads a ~5&nbsp;GB ISO and runs an
        unattended install — expect 20–40 minutes.
      </div>
      {build.error || remove.error ? (
        <div className="mt-3 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {(() => {
            const e = build.error ?? remove.error;
            return e instanceof ApiError ? e.message : "Action failed.";
          })()}
        </div>
      ) : null}

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {WINDOWS_CATALOG.map((os) => {
          const claim = byName.im.get(os.value);
          const installer = byName.inst.get(`${os.value}-installer`);
          const golden = byName.gold.get(goldenPvcName(os.value));
          const st = buildState(claim, installer, golden);
          return (
            <Card key={os.value}>
              <CardContent className="space-y-3 p-4">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{os.label}</span>
                  <StatusBadge status={st.label} tone={st.tone} />
                </div>
                <p className="text-xs text-muted-foreground">
                  {st.state === "ready"
                    ? `Available as os: ${os.value} when you create a VM.`
                    : st.state === "building"
                      ? "Importing the ISO + running the unattended install…"
                      : "Not built yet."}
                </p>
                {st.state === "none" ? (
                  <Button
                    size="sm"
                    onClick={() => build.mutate(os.value)}
                    disabled={build.isPending}
                  >
                    <Plus className="size-4" /> Build
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => remove.mutate(os.value)}
                    disabled={remove.isPending}
                  >
                    {st.state === "building" ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Trash2 className="size-4" />
                    )}
                    {st.state === "building" ? "Cancel" : "Remove"}
                  </Button>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </DetailShell>
  );
}
