import { useNavigate } from "@tanstack/react-router";
import { BrainCircuit } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { MODEL_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: MODEL (issue #96). */
export function CreateModelPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={MODEL_CREATE.kind}
      crdName={MODEL_CREATE.crdName}
      icon={<BrainCircuit className="size-6 text-primary" />}
      title={`Create ${MODEL_CREATE.kind}`}
      description={MODEL_CREATE.description}
      sections={MODEL_CREATE.sections}
      uiSchema={MODEL_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.models(ns)}
      listPath={openinfraPaths.models()}
      onCancel={() => navigate({ to: "/models" })}
      onCreated={(namespace, name) => navigate({ to: "/models/$namespace/$name", params: { namespace, name } })}
    />
  );
}
