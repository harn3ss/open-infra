import { useNavigate } from "@tanstack/react-router";
import { Globe } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { ELASTICIP_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: ElasticIp (Unit B, kube-ovn). */
export function CreateElasticIpPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={ELASTICIP_CREATE.kind}
      crdName={ELASTICIP_CREATE.crdName}
      icon={<Globe className="size-6 text-primary" />}
      title={`Create ${ELASTICIP_CREATE.kind}`}
      description={ELASTICIP_CREATE.description}
      sections={ELASTICIP_CREATE.sections}
      uiSchema={ELASTICIP_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.elasticips(ns)}
      listPath={openinfraPaths.elasticips()}
      onCancel={() => navigate({ to: "/elastic-ips" })}
      onCreated={(namespace, name) => navigate({ to: "/elastic-ips/$namespace/$name", params: { namespace, name } })}
    />
  );
}
