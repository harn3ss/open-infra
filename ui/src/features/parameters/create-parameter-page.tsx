import { useNavigate } from "@tanstack/react-router";
import { SlidersHorizontal } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import type { CreateKindSpec } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";
import { PARAMETERS_CRD_NAME } from "@/types/k8s";

/**
 * Per-kind create configuration for kind: Parameter (SSM Parameter Store). Co-located here so the
 * feature owns its own files; mirror it into `components/create/create-registry.ts` (as
 * `PARAMETER_CREATE`) if the console centralizes create specs, then import from there and drop this.
 *
 * Note: `value` is entered here (the CRD collects it directly — it is not a passwordSecretRef
 * credential), so the create form and its YAML preview reflect what the user just typed. The
 * never-show-SecureString rule applies to the DETAIL page, which redacts stored SecureString values.
 */
export const PARAMETER_CREATE: CreateKindSpec = {
  kind: "Parameter",
  crdName: PARAMETERS_CRD_NAME,
  description:
    "A hierarchical configuration value or secret stored by path (AWS SSM Parameter Store) — choose String for plain config or SecureString for an encrypted, Vault-backed secret.",
  sections: [
    { title: "Parameter", fields: ["path", "value", "type"] },
    { title: "Advanced", fields: ["tier", "expiresAt"], advanced: true },
  ],
  uiSchema: {
    path: { "ui:placeholder": "/app/db/host" },
    value: { "ui:placeholder": "the value to store" },
    expiresAt: { "ui:placeholder": "2026-12-31T00:00:00Z (RFC3339, optional)" },
  },
};

/** Full-page, schema-driven create for kind: Parameter (SSM Parameter Store). */
export function CreateParameterPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={PARAMETER_CREATE.kind}
      crdName={PARAMETER_CREATE.crdName}
      icon={<SlidersHorizontal className="size-6 text-primary" />}
      title={`Create ${PARAMETER_CREATE.kind}`}
      description={PARAMETER_CREATE.description}
      sections={PARAMETER_CREATE.sections}
      uiSchema={PARAMETER_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.parameters(ns)}
      listPath={openinfraPaths.parameters()}
      onCancel={() => navigate({ to: "/parameters" })}
      onCreated={(namespace, name) => navigate({ to: "/parameters/$namespace/$name", params: { namespace, name } })}
    />
  );
}
