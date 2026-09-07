import { useNavigate } from "@tanstack/react-router";
import { DatabaseZap } from "lucide-react";
import { CreatePage } from "@/components/create/create-page";
import type { CreateKindSpec } from "@/components/create/create-registry";
import { openinfraPaths } from "@/lib/k8s-paths";
import { DATABASEPROXIES_CRD_NAME } from "@/types/k8s";

/**
 * Per-kind create configuration for kind: DatabaseProxy (RDS Proxy). Co-located here so the feature
 * owns its own files; mirror it into `components/create/create-registry.ts` (as `DATABASEPROXY_CREATE`)
 * if the console centralizes create specs, then import from there and drop this const.
 */
export const DATABASEPROXY_CREATE: CreateKindSpec = {
  kind: "DatabaseProxy",
  crdName: DATABASEPROXIES_CRD_NAME,
  description:
    "A pooled, connection-bounded endpoint in front of a managed SQL Server / Babelfish database (AWS RDS Proxy) — it terminates client logins, reuses warm backend connections, and caps concurrency.",
  sections: [
    { title: "Proxy", fields: ["targetDatabase", "engineFamily"] },
    { title: "Connection pooling", fields: ["poolMax", "acquireTimeoutMs", "replicas"], advanced: true },
    { title: "Client TLS", fields: ["tls"], advanced: true },
  ],
  uiSchema: {
    targetDatabase: { "ui:placeholder": "my-managed-db" },
    poolMax: { "ui:placeholder": "20" },
    acquireTimeoutMs: { "ui:placeholder": "10000" },
    replicas: { "ui:placeholder": "1" },
  },
};

/** Full-page, schema-driven create for kind: DatabaseProxy (RDS Proxy). */
export function CreateDatabaseProxyPage() {
  const navigate = useNavigate();
  return (
    <CreatePage
      kind={DATABASEPROXY_CREATE.kind}
      crdName={DATABASEPROXY_CREATE.crdName}
      icon={<DatabaseZap className="size-6 text-primary" />}
      title={`Create ${DATABASEPROXY_CREATE.kind}`}
      description={DATABASEPROXY_CREATE.description}
      sections={DATABASEPROXY_CREATE.sections}
      uiSchema={DATABASEPROXY_CREATE.uiSchema}
      createPath={(ns) => openinfraPaths.databaseproxies(ns)}
      listPath={openinfraPaths.databaseproxies()}
      onCancel={() => navigate({ to: "/database-proxies" })}
      onCreated={(namespace, name) => navigate({ to: "/database-proxies/$namespace/$name", params: { namespace, name } })}
    />
  );
}
