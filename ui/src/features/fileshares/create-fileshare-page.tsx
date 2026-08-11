import { useNavigate } from "@tanstack/react-router";
import { FolderTree } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { FILESHARE_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: FILESHARE (issue #96). */
export function CreateFileSharePage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={FILESHARE_CREATE.kind}
      crdName={FILESHARE_CREATE.crdName}
      icon={<FolderTree className="size-6 text-primary" />}
      title={`Create ${FILESHARE_CREATE.kind}`}
      description={FILESHARE_CREATE.description}
      sections={FILESHARE_CREATE.sections}
      uiSchema={FILESHARE_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.fileshares(ns)}
      listPath={openinfraPaths.fileshares()}
      onCancel={() => navigate({ to: "/fileshares" })}
      onCreated={(namespace, name) => navigate({ to: "/fileshares/$namespace/$name", params: { namespace, name } })}
    />
  );
}
