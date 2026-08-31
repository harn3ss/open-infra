import { useNavigate } from "@tanstack/react-router";
import { Package } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { MODELPACKAGE_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: ModelPackage (#27). */
export function CreateModelPackagePage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={MODELPACKAGE_CREATE.kind}
      crdName={MODELPACKAGE_CREATE.crdName}
      icon={<Package className="size-6 text-primary" />}
      title={`Create ${MODELPACKAGE_CREATE.kind}`}
      description={MODELPACKAGE_CREATE.description}
      sections={MODELPACKAGE_CREATE.sections}
      uiSchema={MODELPACKAGE_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.modelpackages(ns)}
      listPath={openinfraPaths.modelpackages()}
      onCancel={() => navigate({ to: "/model-registry" })}
      onCreated={(namespace, name) => navigate({ to: "/model-registry/$namespace/$name", params: { namespace, name } })}
    />
  );
}
