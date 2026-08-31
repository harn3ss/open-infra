import { useNavigate } from "@tanstack/react-router";
import { Table2 } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { FEATUREGROUP_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: FeatureGroup (#27). */
export function CreateFeatureGroupPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={FEATUREGROUP_CREATE.kind}
      crdName={FEATUREGROUP_CREATE.crdName}
      icon={<Table2 className="size-6 text-primary" />}
      title={`Create ${FEATUREGROUP_CREATE.kind}`}
      description={FEATUREGROUP_CREATE.description}
      sections={FEATUREGROUP_CREATE.sections}
      uiSchema={FEATUREGROUP_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.featuregroups(ns)}
      listPath={openinfraPaths.featuregroups()}
      onCancel={() => navigate({ to: "/feature-store" })}
      onCreated={(namespace, name) => navigate({ to: "/feature-store/$namespace/$name", params: { namespace, name } })}
    />
  );
}
