import { useNavigate } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { CERTIFICATEAUTHORITY_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: CertificateAuthority (managed PKI). */
export function CreateCaPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={CERTIFICATEAUTHORITY_CREATE.kind}
      crdName={CERTIFICATEAUTHORITY_CREATE.crdName}
      icon={<ShieldCheck className="size-6 text-primary" />}
      title={`Create ${CERTIFICATEAUTHORITY_CREATE.kind}`}
      description={CERTIFICATEAUTHORITY_CREATE.description}
      sections={CERTIFICATEAUTHORITY_CREATE.sections}
      uiSchema={CERTIFICATEAUTHORITY_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.certificateauthorities(ns)}
      listPath={openinfraPaths.certificateauthorities()}
      onCancel={() => navigate({ to: "/pki" })}
      onCreated={(namespace, name) =>
        navigate({ to: "/pki/$namespace/$name", params: { namespace, name } })
      }
    />
  );
}
