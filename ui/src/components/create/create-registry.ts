import type { UiSchema } from "@rjsf/utils";

/**
 * Per-kind create configuration — the data that steers the unified schema-driven create page
 * (issue #96). Adding a resource to the new create experience is (mostly) a matter of adding an
 * entry here: which spec fields are "essential" (shown up-front; everything else collapses under
 * "Advanced settings"), plus RJSF layout hints. Fields, defaults, enums, help text and validation
 * all come from the CRD schema — this only supplies the editorial "which 20% to hide" judgment the
 * schema can't encode, per the AWS/Cloudscape research.
 */
export interface CreateKindSpec {
  kind: string;
  crdName: string;
  description: string;
  /** Spec property names shown up-front (the Quick-create set). */
  essential: string[];
  uiSchema?: UiSchema;
}

export const APPLICATION_CREATE: CreateKindSpec = {
  kind: "Application",
  crdName: "applications.openinfra.dev",
  description:
    "Declare intent — open-infra provisions hosting, scaling, and any attached database, buckets, or queues from this spec.",
  // Deploy-my-thing essentials up front; scaling/database/storage/queues/env/secrets/SGs collapse.
  essential: ["image", "port", "expose"],
  uiSchema: {
    "ui:order": [
      "image",
      "port",
      "expose",
      "domain",
      "scaling",
      "database",
      "storage",
      "queues",
      "env",
      "secrets",
      "securityGroups",
      "*",
    ],
    image: { "ui:placeholder": "ghcr.io/me/my-api:latest" },
    domain: { "ui:placeholder": "my-api.example.com" },
  },
};
