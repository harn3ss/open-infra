import { useNavigate } from "@tanstack/react-router";
import { Layers } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { BATCHTRANSFORM_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: BatchTransform (#27). */
export function CreateBatchTransformPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={BATCHTRANSFORM_CREATE.kind}
      crdName={BATCHTRANSFORM_CREATE.crdName}
      icon={<Layers className="size-6 text-primary" />}
      title={`Create ${BATCHTRANSFORM_CREATE.kind}`}
      description={BATCHTRANSFORM_CREATE.description}
      sections={BATCHTRANSFORM_CREATE.sections}
      uiSchema={BATCHTRANSFORM_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.batchtransforms(ns)}
      listPath={openinfraPaths.batchtransforms()}
      onCancel={() => navigate({ to: "/batch-transform" })}
      onCreated={(namespace, name) => navigate({ to: "/batch-transform/$namespace/$name", params: { namespace, name } })}
    />
  );
}
