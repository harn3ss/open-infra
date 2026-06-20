import { Network } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResourceTable,
  type ResourceTableConfig,
} from "@/components/common/resource-table";
import {
  deploymentColumns,
  podColumns,
  serviceColumns,
} from "@/features/workloads/columns";
import { appsPaths, corePaths, resourcePaths } from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import { useNodeHealth } from "@/hooks/use-node-health";
import type { Deployment, Pod, Service } from "@/types/k8s";

export function WorkloadsPage() {
  const { scoped } = useNamespace();
  const { offlineNodes } = useNodeHealth();

  const podsConfig: ResourceTableConfig<Pod> = {
    kind: "Pod",
    listPath: corePaths.pods(scoped),
    columns: podColumns(offlineNodes),
    searchFields: (p) => [
      p.metadata.name,
      p.metadata.namespace,
      p.spec?.nodeName,
      p.status?.phase,
    ],
    deletePath: (p) =>
      resourcePaths.pod(p.metadata.namespace ?? "default", p.metadata.name),
    emptyTitle: "No Pods",
    emptyDescription: "No Pods are running in this scope.",
  };

  const deploymentsConfig: ResourceTableConfig<Deployment> = {
    kind: "Deployment",
    listPath: appsPaths.deployments(scoped),
    columns: deploymentColumns,
    searchFields: (d) => [d.metadata.name, d.metadata.namespace],
    deletePath: (d) =>
      resourcePaths.deployment(
        d.metadata.namespace ?? "default",
        d.metadata.name,
      ),
    emptyTitle: "No Deployments",
    emptyDescription: "No Deployments exist in this scope.",
  };

  const servicesConfig: ResourceTableConfig<Service> = {
    kind: "Service",
    listPath: corePaths.services(scoped),
    columns: serviceColumns,
    searchFields: (s) => [
      s.metadata.name,
      s.metadata.namespace,
      s.spec?.type,
      s.spec?.clusterIP,
    ],
    deletePath: (s) =>
      resourcePaths.service(s.metadata.namespace ?? "default", s.metadata.name),
    emptyTitle: "No Services",
    emptyDescription: "No Services exist in this scope.",
  };

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Network />}
        title="Workloads"
        description="Live view of the core Kubernetes objects backing your apps."
      />

      <Tabs defaultValue="pods">
        <TabsList>
          <TabsTrigger value="pods">Pods</TabsTrigger>
          <TabsTrigger value="deployments">Deployments</TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
        </TabsList>
        <TabsContent value="pods">
          <ResourceTable config={podsConfig} />
        </TabsContent>
        <TabsContent value="deployments">
          <ResourceTable config={deploymentsConfig} />
        </TabsContent>
        <TabsContent value="services">
          <ResourceTable config={servicesConfig} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
