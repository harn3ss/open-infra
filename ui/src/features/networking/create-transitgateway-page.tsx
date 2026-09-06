import { useNavigate } from "@tanstack/react-router";
import { Share2 } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { TRANSITGATEWAY_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: TransitGateway (pattern A — attachments render via RJSF). */
export function CreateTransitGatewayPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={TRANSITGATEWAY_CREATE.kind}
      crdName={TRANSITGATEWAY_CREATE.crdName}
      icon={<Share2 className="size-6 text-primary" />}
      title={`Create ${TRANSITGATEWAY_CREATE.kind}`}
      description={TRANSITGATEWAY_CREATE.description}
      sections={TRANSITGATEWAY_CREATE.sections}
      uiSchema={TRANSITGATEWAY_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.transitgateways(ns)}
      listPath={openinfraPaths.transitgateways()}
      onCancel={() => navigate({ to: "/transit-gateways" })}
      onCreated={(namespace, name) => navigate({ to: "/transit-gateways/$namespace/$name", params: { namespace, name } })}
    />
  );
}
