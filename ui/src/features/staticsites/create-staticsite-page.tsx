import { useNavigate } from "@tanstack/react-router";
import { AppWindow } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { STATICSITE_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: StaticSite (AWS Amplify / S3 static website). */
export function CreateStaticSitePage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={STATICSITE_CREATE.kind}
      crdName={STATICSITE_CREATE.crdName}
      icon={<AppWindow className="size-6 text-primary" />}
      title={`Create ${STATICSITE_CREATE.kind}`}
      description={STATICSITE_CREATE.description}
      sections={STATICSITE_CREATE.sections}
      uiSchema={STATICSITE_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.staticsites(ns)}
      listPath={openinfraPaths.staticsites()}
      onCancel={() => navigate({ to: "/staticsites" })}
      onCreated={(namespace, name) => navigate({ to: "/staticsites/$namespace/$name", params: { namespace, name } })}
    />
  );
}
