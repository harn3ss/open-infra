import { useNavigate } from "@tanstack/react-router";
import { Disc3 } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { VOLUME_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: VOLUME (issue #96). */
export function CreateVolumePage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={VOLUME_CREATE.kind}
      crdName={VOLUME_CREATE.crdName}
      icon={<Disc3 className="size-6 text-primary" />}
      title={`Create ${VOLUME_CREATE.kind}`}
      description={VOLUME_CREATE.description}
      sections={VOLUME_CREATE.sections}
      uiSchema={VOLUME_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.volumes(ns)}
      listPath={openinfraPaths.volumes()}
      onCancel={() => navigate({ to: "/volumes" })}
      onCreated={(namespace, name) => navigate({ to: "/volumes/$namespace/$name", params: { namespace, name } })}
    />
  );
}
