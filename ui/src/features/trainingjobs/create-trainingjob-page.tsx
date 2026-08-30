import { useNavigate } from "@tanstack/react-router";
import { BrainCog } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { TRAININGJOB_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: TrainingJob (#27). */
export function CreateTrainingJobPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={TRAININGJOB_CREATE.kind}
      crdName={TRAININGJOB_CREATE.crdName}
      icon={<BrainCog className="size-6 text-primary" />}
      title={`Create ${TRAININGJOB_CREATE.kind}`}
      description={TRAININGJOB_CREATE.description}
      sections={TRAININGJOB_CREATE.sections}
      uiSchema={TRAININGJOB_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.trainingjobs(ns)}
      listPath={openinfraPaths.trainingjobs()}
      onCancel={() => navigate({ to: "/trainingjobs" })}
      onCreated={(namespace, name) => navigate({ to: "/trainingjobs/$namespace/$name", params: { namespace, name } })}
    />
  );
}
