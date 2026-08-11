import { useNavigate } from "@tanstack/react-router";
import { Radio } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { STREAM_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create with a credential (password → Secret) section (issue #96). */
export function CreateStreamPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={STREAM_CREATE.kind}
      crdName={STREAM_CREATE.crdName}
      icon={<Radio className="size-6 text-primary" />}
      title={`Create ${STREAM_CREATE.kind}`}
      description={STREAM_CREATE.description}
      sections={STREAM_CREATE.sections}
      credentials={STREAM_CREATE.credentials}
      uiSchema={STREAM_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.streams(ns)}
      listPath={openinfraPaths.streams()}
      onCancel={() => navigate({ to: "/streams" })}
      onCreated={(namespace, name) => navigate({ to: "/streams/$namespace/$name", params: { namespace, name } })}
    />
  );
}
