import { useNavigate } from "@tanstack/react-router";
import { ArrowRightLeft } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { MIGRATION_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create with a credential (password → Secret) section (issue #96). */
export function CreateMigrationPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={MIGRATION_CREATE.kind}
      crdName={MIGRATION_CREATE.crdName}
      icon={<ArrowRightLeft className="size-6 text-primary" />}
      title={`Create ${MIGRATION_CREATE.kind}`}
      description={MIGRATION_CREATE.description}
      sections={MIGRATION_CREATE.sections}
      credentials={MIGRATION_CREATE.credentials}
      uiSchema={MIGRATION_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.migrations(ns)}
      listPath={openinfraPaths.migrations()}
      onCancel={() => navigate({ to: "/migrations" })}
      onCreated={(namespace, name) => navigate({ to: "/migrations/$namespace/$name", params: { namespace, name } })}
    />
  );
}
