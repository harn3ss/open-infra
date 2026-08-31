import { useNavigate } from "@tanstack/react-router";
import { Target } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { TUNINGJOB_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: TuningJob (#27). */
export function CreateTuningJobPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={TUNINGJOB_CREATE.kind}
      crdName={TUNINGJOB_CREATE.crdName}
      icon={<Target className="size-6 text-primary" />}
      title={`Create ${TUNINGJOB_CREATE.kind}`}
      description={TUNINGJOB_CREATE.description}
      sections={TUNINGJOB_CREATE.sections}
      uiSchema={TUNINGJOB_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.tuningjobs(ns)}
      listPath={openinfraPaths.tuningjobs()}
      onCancel={() => navigate({ to: "/tuning" })}
      onCreated={(namespace, name) => navigate({ to: "/tuning/$namespace/$name", params: { namespace, name } })}
    />
  );
}
