import { useNavigate } from "@tanstack/react-router";
import { Mail } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import { EMAILSENDER_CREATE } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";

/** Full-page, schema-driven create for kind: EmailSender (AWS SES-style sending identity). */
export function CreateEmailSenderPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={EMAILSENDER_CREATE.kind}
      crdName={EMAILSENDER_CREATE.crdName}
      icon={<Mail className="size-6 text-primary" />}
      title={`Create ${EMAILSENDER_CREATE.kind}`}
      description={EMAILSENDER_CREATE.description}
      sections={EMAILSENDER_CREATE.sections}
      uiSchema={EMAILSENDER_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.emailsenders(ns)}
      listPath={openinfraPaths.emailsenders()}
      onCancel={() => navigate({ to: "/emailsenders" })}
      onCreated={(namespace, name) => navigate({ to: "/emailsenders/$namespace/$name", params: { namespace, name } })}
    />
  );
}
