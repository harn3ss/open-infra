import { useNavigate } from "@tanstack/react-router";
import { ScrollText } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { FLOWLOG_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: FlowLog (VPC Flow Logs). */
export function CreateFlowLogPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={FLOWLOG_CREATE.kind}
      crdName={FLOWLOG_CREATE.crdName}
      icon={<ScrollText className="size-6 text-primary" />}
      title={`Create ${FLOWLOG_CREATE.kind}`}
      description={FLOWLOG_CREATE.description}
      sections={FLOWLOG_CREATE.sections}
      uiSchema={FLOWLOG_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.flowlogs(ns)}
      listPath={openinfraPaths.flowlogs()}
      onCancel={() => navigate({ to: "/flow-logs" })}
      onCreated={(namespace, name) => navigate({ to: "/flow-logs/$namespace/$name", params: { namespace, name } })}
    />
  );
}
