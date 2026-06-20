import { Card, CardContent } from "@/components/ui/card";
import { CopyButton } from "@/components/common/copy-button";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import type { Service } from "@/types/k8s";

/**
 * How to reach a database from outside the cluster. Always shows a
 * `kubectl port-forward` command (works anywhere with kubeconfig). If the DB is
 * exposed (`database.expose: true` → a `<app>-db-lan` MetalLB LoadBalancer), it
 * also shows the LAN-reachable host:port.
 */
export function DbConnectivity({
  namespace,
  internalSvc,
  lanSvc,
  port,
  scheme,
}: {
  namespace: string;
  internalSvc: string;
  lanSvc: string;
  port: number;
  scheme: string;
}) {
  const { items } = useK8sWatch<Service>(corePaths.services(namespace));
  const lan = items.find((s) => s.metadata.name === lanSvc);
  const lanIp = lan?.status?.loadBalancer?.ingress?.[0]?.ip;
  const pf = `kubectl port-forward -n ${namespace} svc/${internalSvc} ${port}:${port}`;

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="space-y-1">
          <p className="text-sm font-medium">From your machine (port-forward)</p>
          <span className="flex items-center gap-1">
            <code className="block max-w-full truncate rounded bg-secondary px-2 py-1 text-xs">
              {pf}
            </code>
            <CopyButton value={pf} />
          </span>
          <p className="text-xs text-muted-foreground">
            then connect to{" "}
            <code className="text-xs">{`${scheme}://…@localhost:${port}`}</code>{" "}
            — works from any host with kubeconfig access.
          </p>
        </div>

        <div className="space-y-1">
          <p className="text-sm font-medium">LAN endpoint</p>
          {lanIp ? (
            <span className="flex items-center gap-1">
              <code className="rounded bg-secondary px-2 py-1 text-xs text-primary">
                {lanIp}:{port}
              </code>
              <CopyButton value={`${lanIp}:${port}`} />
            </span>
          ) : (
            <p className="text-xs text-muted-foreground">
              Not exposed. Set <code className="text-xs">database.expose: true</code>{" "}
              for a LAN IP (MetalLB LoadBalancer) reachable from workstations.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
