import { useNavigate } from "@tanstack/react-router";
import { Repeat } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { REPLICATION_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create with a credential (password → Secret) section (issue #96). */
export function CreateReplicationPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={REPLICATION_CREATE.kind}
      crdName={REPLICATION_CREATE.crdName}
      icon={<Repeat className="size-6 text-primary" />}
      title={`Create ${REPLICATION_CREATE.kind}`}
      description={REPLICATION_CREATE.description}
      sections={REPLICATION_CREATE.sections}
      credentials={REPLICATION_CREATE.credentials}
      uiSchema={REPLICATION_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.replications(ns)}
      listPath={openinfraPaths.replications()}
      onCancel={() => navigate({ to: "/replications" })}
      onCreated={(namespace, name) => navigate({ to: "/replications/$namespace/$name", params: { namespace, name } })}
    />
  );
}
