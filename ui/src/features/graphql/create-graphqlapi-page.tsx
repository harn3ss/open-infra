import { useNavigate } from "@tanstack/react-router";
import { Waypoints } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { GRAPHQLAPI_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: GRAPHQLAPI (issue #96). */
export function CreateGraphqlApiPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={GRAPHQLAPI_CREATE.kind}
      crdName={GRAPHQLAPI_CREATE.crdName}
      icon={<Waypoints className="size-6 text-primary" />}
      title={`Create ${GRAPHQLAPI_CREATE.kind}`}
      description={GRAPHQLAPI_CREATE.description}
      sections={GRAPHQLAPI_CREATE.sections}
      uiSchema={GRAPHQLAPI_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.graphqlapis(ns)}
      listPath={openinfraPaths.graphqlapis()}
      onCancel={() => navigate({ to: "/graphql" })}
      onCreated={(namespace, name) => navigate({ to: "/graphql/$namespace/$name", params: { namespace, name } })}
    />
  );
}
