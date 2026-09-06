import { useNavigate } from "@tanstack/react-router";
import { Waypoints } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { NATGATEWAY_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: NatGateway (Unit B, kube-ovn). */
export function CreateNatGatewayPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={NATGATEWAY_CREATE.kind}
      crdName={NATGATEWAY_CREATE.crdName}
      icon={<Waypoints className="size-6 text-primary" />}
      title={`Create ${NATGATEWAY_CREATE.kind}`}
      description={NATGATEWAY_CREATE.description}
      sections={NATGATEWAY_CREATE.sections}
      uiSchema={NATGATEWAY_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.natgateways(ns)}
      listPath={openinfraPaths.natgateways()}
      onCancel={() => navigate({ to: "/nat-gateways" })}
      onCreated={(namespace, name) => navigate({ to: "/nat-gateways/$namespace/$name", params: { namespace, name } })}
    />
  );
}
