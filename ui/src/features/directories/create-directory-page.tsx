import { useNavigate } from "@tanstack/react-router";
import { Building2 } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { DIRECTORY_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: DIRECTORY (issue #96). */
export function CreateDirectoryPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={DIRECTORY_CREATE.kind}
      crdName={DIRECTORY_CREATE.crdName}
      icon={<Building2 className="size-6 text-primary" />}
      title={`Create ${DIRECTORY_CREATE.kind}`}
      description={DIRECTORY_CREATE.description}
      sections={DIRECTORY_CREATE.sections}
      uiSchema={DIRECTORY_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.directories(ns)}
      listPath={openinfraPaths.directories()}
      onCancel={() => navigate({ to: "/directories" })}
      onCreated={(namespace, name) => navigate({ to: "/directories/$namespace/$name", params: { namespace, name } })}
    />
  );
}
