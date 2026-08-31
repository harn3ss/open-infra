import { useNavigate } from "@tanstack/react-router";
import { FlaskConical } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { PROCESSINGJOB_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: ProcessingJob (#27). */
export function CreateProcessingJobPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={PROCESSINGJOB_CREATE.kind}
      crdName={PROCESSINGJOB_CREATE.crdName}
      icon={<FlaskConical className="size-6 text-primary" />}
      title={`Create ${PROCESSINGJOB_CREATE.kind}`}
      description={PROCESSINGJOB_CREATE.description}
      sections={PROCESSINGJOB_CREATE.sections}
      uiSchema={PROCESSINGJOB_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.processingjobs(ns)}
      listPath={openinfraPaths.processingjobs()}
      onCancel={() => navigate({ to: "/processing" })}
      onCreated={(namespace, name) => navigate({ to: "/processing/$namespace/$name", params: { namespace, name } })}
    />
  );
}
