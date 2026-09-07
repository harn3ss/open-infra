import { useNavigate } from "@tanstack/react-router";
import { Webhook } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { HTTPAPI_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: HttpApi (API Gateway HTTP API). */
export function CreateHttpApiPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={HTTPAPI_CREATE.kind}
      crdName={HTTPAPI_CREATE.crdName}
      icon={<Webhook className="size-6 text-primary" />}
      title={`Create ${HTTPAPI_CREATE.kind}`}
      description={HTTPAPI_CREATE.description}
      sections={HTTPAPI_CREATE.sections}
      uiSchema={HTTPAPI_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.httpapis(ns)}
      listPath={openinfraPaths.httpapis()}
      onCancel={() => navigate({ to: "/http-apis" })}
      onCreated={(namespace, name) => navigate({ to: "/http-apis/$namespace/$name", params: { namespace, name } })}
    />
  );
}
