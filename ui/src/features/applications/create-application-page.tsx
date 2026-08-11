import { useNavigate } from "@tanstack/react-router";
import { Boxes } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { APPLICATION_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/**
 * Full-page create for kind: Application — the reference for the issue-#96 create rewrite. Owns the
 * typed router navigation (Cancel → list, success → the new resource's detail page); everything else
 * comes from the shared schema-driven CreatePage.
 */
export function CreateApplicationPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={APPLICATION_CREATE.kind}
      crdName={APPLICATION_CREATE.crdName}
      icon={<Boxes className="size-6 text-primary" />}
      title="Create Application"
      description={APPLICATION_CREATE.description}
      sections={APPLICATION_CREATE.sections}
      uiSchema={APPLICATION_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.applications(ns)}
      listPath={openinfraPaths.applications()}
      onCancel={() => navigate({ to: "/applications" })}
      onCreated={(namespace, name) =>
        navigate({ to: "/applications/$namespace/$name", params: { namespace, name } })
      }
    />
  );
}
