import { useNavigate } from "@tanstack/react-router";
import { Gauge } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { MODELMONITOR_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: ModelMonitor (#27). */
export function CreateModelMonitorPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={MODELMONITOR_CREATE.kind}
      crdName={MODELMONITOR_CREATE.crdName}
      icon={<Gauge className="size-6 text-primary" />}
      title={`Create ${MODELMONITOR_CREATE.kind}`}
      description={MODELMONITOR_CREATE.description}
      sections={MODELMONITOR_CREATE.sections}
      uiSchema={MODELMONITOR_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.modelmonitors(ns)}
      listPath={openinfraPaths.modelmonitors()}
      onCancel={() => navigate({ to: "/model-monitor" })}
      onCreated={(namespace, name) => navigate({ to: "/model-monitor/$namespace/$name", params: { namespace, name } })}
    />
  );
}
