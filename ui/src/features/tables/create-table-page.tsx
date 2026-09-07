import { useNavigate } from "@tanstack/react-router";
import { Table2 } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { TABLE_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: Table (DynamoDB front door). */
export function CreateTablePage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={TABLE_CREATE.kind}
      crdName={TABLE_CREATE.crdName}
      icon={<Table2 className="size-6 text-primary" />}
      title={`Create ${TABLE_CREATE.kind}`}
      description={TABLE_CREATE.description}
      sections={TABLE_CREATE.sections}
      uiSchema={TABLE_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.tables(ns)}
      listPath={openinfraPaths.tables()}
      onCancel={() => navigate({ to: "/tables" })}
      onCreated={(namespace, name) => navigate({ to: "/tables/$namespace/$name", params: { namespace, name } })}
    />
  );
}
