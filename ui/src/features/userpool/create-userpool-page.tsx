import { useNavigate } from "@tanstack/react-router";
import { IdCard } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { USERPOOL_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: UserPool (Keycloak realm / Cognito analog). */
export function CreateUserPoolPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={USERPOOL_CREATE.kind}
      crdName={USERPOOL_CREATE.crdName}
      icon={<IdCard className="size-6 text-primary" />}
      title={`Create ${USERPOOL_CREATE.kind}`}
      description={USERPOOL_CREATE.description}
      sections={USERPOOL_CREATE.sections}
      uiSchema={USERPOOL_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.userpools(ns)}
      listPath={openinfraPaths.userpools()}
      onCancel={() => navigate({ to: "/user-pools" })}
      onCreated={(namespace, name) =>
        navigate({ to: "/user-pools/$namespace/$name", params: { namespace, name } })
      }
    />
  );
}
