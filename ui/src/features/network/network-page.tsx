import { Globe } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResourceTable,
  type ResourceTableConfig,
} from "@/components/common/resource-table";
import {
  ingressColumns,
  loadBalancerColumns,
  networkPolicyColumns,
} from "@/features/network/columns";
import { corePaths, networkingPaths } from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import type { Ingress, NetworkPolicy, Service } from "@/types/k8s";

export function NetworkPage() {
  const { scoped } = useNamespace();

  const lbConfig: ResourceTableConfig<Service> = {
    kind: "Load Balancer",
    listPath: corePaths.services(scoped),
    columns: loadBalancerColumns,
    filter: (s) => s.spec?.type === "LoadBalancer",
    searchFields: (s) => [s.metadata.name, s.metadata.namespace],
    emptyTitle: "No Load Balancers",
    emptyDescription:
      "No LoadBalancer Services in this scope. MetalLB assigns an external IP to each one.",
  };

  const ingressConfig: ResourceTableConfig<Ingress> = {
    kind: "Ingress",
    listPath: networkingPaths.ingresses(scoped),
    columns: ingressColumns,
    searchFields: (i) => [
      i.metadata.name,
      i.metadata.namespace,
      ...(i.spec?.rules?.map((r) => r.host) ?? []),
    ],
    emptyTitle: "No Ingresses",
    emptyDescription: "No Ingress routes (Traefik) in this scope.",
  };

  const netpolConfig: ResourceTableConfig<NetworkPolicy> = {
    kind: "Network Policy",
    listPath: networkingPaths.networkPolicies(scoped),
    columns: networkPolicyColumns,
    searchFields: (np) => [np.metadata.name, np.metadata.namespace],
    emptyTitle: "No Network Policies",
    emptyDescription:
      "No NetworkPolicies in this scope. Each app namespace gets one for tenant isolation.",
  };

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Globe />}
        title="Network"
        description="Load balancers (MetalLB), ingress routes (Traefik + TLS), and network policies."
      />

      <Tabs defaultValue="loadbalancers">
        <TabsList>
          <TabsTrigger value="loadbalancers">Load Balancers</TabsTrigger>
          <TabsTrigger value="ingresses">Ingresses</TabsTrigger>
          <TabsTrigger value="policies">Network Policies</TabsTrigger>
        </TabsList>
        <TabsContent value="loadbalancers">
          <ResourceTable config={lbConfig} />
        </TabsContent>
        <TabsContent value="ingresses">
          <ResourceTable config={ingressConfig} />
        </TabsContent>
        <TabsContent value="policies">
          <ResourceTable config={netpolConfig} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
