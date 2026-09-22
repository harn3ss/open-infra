import { useNavigate } from "@tanstack/react-router";
import { Fingerprint } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { IDENTITYPROVIDER_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: IdentityProvider (external OIDC IdP registry). */
export function CreateIdentityProviderPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={IDENTITYPROVIDER_CREATE.kind}
      crdName={IDENTITYPROVIDER_CREATE.crdName}
      icon={<Fingerprint className="size-6 text-primary" />}
      title={`Create ${IDENTITYPROVIDER_CREATE.kind}`}
      description={IDENTITYPROVIDER_CREATE.description}
      sections={IDENTITYPROVIDER_CREATE.sections}
      uiSchema={IDENTITYPROVIDER_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.identityproviders(ns)}
      listPath={openinfraPaths.identityproviders()}
      onCancel={() => navigate({ to: "/identity-providers" })}
      onCreated={(namespace, name) =>
        navigate({ to: "/identity-providers/$namespace/$name", params: { namespace, name } })
      }
    />
  );
}
