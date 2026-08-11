import type { UiSchema } from "@rjsf/utils";

/**
 * Per-kind create configuration — the data that steers the unified schema-driven create page
 * (issue #96). Fields, defaults, enums, help text and validation all come from the CRD schema; this
 * supplies the editorial layer the schema can't encode: how to GROUP fields into named sections and
 * which sections are advanced (collapsed). Per the AWS/Cloudscape research, the advanced area is not
 * one flat blob — it's several titled, separately-collapsible sub-sections ("Network settings",
 * "Storage", …), each holding a few related fields.
 */
export interface SectionSpec {
  /** Section heading. */
  title: string;
  /** Spec property names in this section, in display order. */
  fields: string[];
  /** Advanced sections render collapsed (progressive disclosure); primary sections are always shown. */
  advanced?: boolean;
}

export interface CreateKindSpec {
  kind: string;
  crdName: string;
  description: string;
  /** Ordered sections. The first (non-advanced) is the primary/essential group. */
  sections: SectionSpec[];
  uiSchema?: UiSchema;
}

export const VIRTUALMACHINE_CREATE: CreateKindSpec = {
  kind: "VirtualMachine",
  crdName: "virtualmachines.openinfra.dev",
  description:
    "A full virtual machine — pick an OS image and a size; open-infra clones the golden image, wires networking, and boots it.",
  sections: [
    { title: "Machine", fields: ["os", "cpu", "memory", "diskSize"] },
    { title: "Networking", fields: ["network", "expose", "ports", "securityGroups"], advanced: true },
    { title: "Access", fields: ["sshKey"], advanced: true },
    {
      title: "Placement & lifecycle",
      fields: ["running", "highAvailability", "cpuModel", "existingRootClaim"],
      advanced: true,
    },
  ],
  uiSchema: {
    memory: { "ui:placeholder": "2Gi" },
    diskSize: { "ui:placeholder": "20Gi" },
    sshKey: { "ui:placeholder": "ssh-ed25519 AAAA… (injected via cloud-init on Linux)" },
    cpuModel: { "ui:placeholder": "host-passthrough (or e.g. Broadwell-noTSX for live migration)" },
  },
};

export const APPLICATION_CREATE: CreateKindSpec = {
  kind: "Application",
  crdName: "applications.openinfra.dev",
  description:
    "Declare intent — open-infra provisions hosting, scaling, and any attached database, buckets, or queues from this spec.",
  sections: [
    { title: "Container", fields: ["image", "port", "expose", "domain"] },
    { title: "Autoscaling", fields: ["scaling"], advanced: true },
    { title: "Database", fields: ["database"], advanced: true },
    { title: "Storage & queues", fields: ["storage", "queues"], advanced: true },
    { title: "Environment", fields: ["env", "secrets"], advanced: true },
    { title: "Network security", fields: ["securityGroups"], advanced: true },
  ],
  uiSchema: {
    image: { "ui:placeholder": "ghcr.io/me/my-api:latest" },
    domain: { "ui:placeholder": "my-api.example.com" },
  },
};
