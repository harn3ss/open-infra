import { useNavigate } from "@tanstack/react-router";
import { Zap } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { FUNCTION_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: FUNCTION (issue #96). */
export function CreateFunctionPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={FUNCTION_CREATE.kind}
      crdName={FUNCTION_CREATE.crdName}
      icon={<Zap className="size-6 text-primary" />}
      title={`Create ${FUNCTION_CREATE.kind}`}
      description={FUNCTION_CREATE.description}
      sections={FUNCTION_CREATE.sections}
      uiSchema={FUNCTION_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.functions(ns)}
      listPath={openinfraPaths.functions()}
      onCancel={() => navigate({ to: "/functions" })}
      onCreated={(namespace, name) => navigate({ to: "/functions/$namespace/$name", params: { namespace, name } })}
    />
  );
}
