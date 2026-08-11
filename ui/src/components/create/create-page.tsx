import { type ReactNode, useMemo, useRef, useState } from "react";
import Form from "@rjsf/core";
import type { IChangeEvent } from "@rjsf/core";
import type { RJSFSchema, UiSchema } from "@rjsf/utils";
import validator from "@rjsf/validator-ajv8";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Rocket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ErrorState, LoadingState, Spinner } from "@/components/common/states";
import { ExpandableSection } from "@/components/create/expandable-section";
import { InfoLink } from "@/components/help/info-link";
import { LearnMore } from "@/components/help/learn-more";
import { kindDocsUrl } from "@/lib/kind-docs";
import { createTemplates } from "@/components/create/rjsf-templates";
import type { CredentialSpec, SectionSpec } from "@/components/create/create-registry";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, getCrdSchema, k8sCreate } from "@/lib/api";
import { isValidName, rfc1123Error } from "@/lib/rfc1123";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";

const ROOT_ID = "oi-create";

export interface CreatePageConfig {
  kind: string;
  crdName: string;
  icon: ReactNode;
  title: string;
  description: string;
  /** Named field groups; the first (non-advanced) shows up-front, advanced ones collapse. */
  sections: SectionSpec[];
  /** RJSF layout hints (ui:order, ui:widget, ui:placeholder, …). */
  uiSchema?: UiSchema;
  /**
   * Endpoint objects that carry a `passwordSecretRef` (e.g. "source", "target", "siteA"). For each,
   * the page collects a password, creates a Kubernetes Secret, and fills the ref — so the plaintext
   * lives only in the Secret, never in the resource spec.
   */
  credentials?: CredentialSpec[];
  /** k8s create path for a namespace, e.g. openinfraPaths.applications. */
  createPath: (ns: string) => string;
  /** list path (k8s) to invalidate after create. */
  listPath: string;
  /** Called on Back/Cancel — the wrapper does the typed router navigation. */
  onCancel: () => void;
  /** Called after a successful create — the wrapper lands the user on the new resource. */
  onCreated: (namespace: string, name: string) => void;
}

/**
 * The unified, full-page, schema-driven "create a resource" experience (issue #96). Replaces the
 * per-resource modals: identity header + the CRD spec rendered from its OpenAPI schema with
 * Cloudscape semantics (OPTIONAL-marked fields, help from `description`, an essential set with the
 * rest under "Advanced settings"), a live YAML preview escape hatch, inline validation that goes
 * live after the first submit, a never-disabled Create button, and landing on the new resource.
 */
export function CreatePage(cfg: CreatePageConfig) {
  const queryClient = useQueryClient();
  const formRef = useRef<Form<unknown, RJSFSchema> | null>(null);

  const { scoped } = useNamespace();
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => (nsWatch.items ?? []).map((n) => n.metadata?.name ?? "").filter(Boolean).sort(),
    [nsWatch.items],
  );

  const creds = cfg.credentials ?? [];

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [nameTouched, setNameTouched] = useState(false);
  const [formData, setFormData] = useState<Record<string, unknown>>({});
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [credTouched, setCredTouched] = useState(false);
  const [liveValidate, setLiveValidate] = useState(false);

  const schemaQuery = useQuery({
    queryKey: ["crd-schema", cfg.crdName],
    queryFn: () => getCrdSchema(cfg.crdName),
    staleTime: 5 * 60_000,
  });

  const specSchema = useMemo<RJSFSchema | null>(() => {
    const raw = schemaQuery.data as Record<string, unknown> | undefined;
    if (!raw) return null;
    const props = raw["properties"] as Record<string, unknown> | undefined;
    const spec = (props && "spec" in props ? props["spec"] : raw) as RJSFSchema;
    if (creds.length === 0) return spec;
    // Hide passwordSecretRef from the endpoint forms — the Credentials section handles it, and we
    // fill the ref on submit. Clone so we never mutate the cached query data.
    const clone = JSON.parse(JSON.stringify(spec)) as RJSFSchema;
    const cprops = (clone.properties ?? {}) as Record<string, { properties?: Record<string, unknown>; required?: string[] }>;
    for (const c of creds) {
      const ep = cprops[c.path];
      if (ep?.properties) delete ep.properties.passwordSecretRef;
      if (ep && Array.isArray(ep.required)) ep.required = ep.required.filter((r) => r !== "passwordSecretRef");
    }
    return clone;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schemaQuery.data]);

  const secretNameFor = (path: string) => `${name || "resource"}-${path.replace(/\./g, "-")}-creds`;

  // Overlay the passwordSecretRef into each credentialed endpoint (for both the YAML preview and the
  // actual create) — the ref, never the plaintext.
  const specWithRefs = (base: Record<string, unknown>): Record<string, unknown> => {
    if (creds.length === 0) return base;
    const s = { ...base } as Record<string, unknown>;
    for (const c of creds) {
      const ep = s[c.path];
      if (ep && typeof ep === "object") {
        s[c.path] = { ...(ep as object), passwordSecretRef: { name: secretNameFor(c.path), key: "password" } };
      }
    }
    return s;
  };

  const manifest = useMemo(
    (): K8sObject => ({
      apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
      kind: cfg.kind,
      metadata: { name: name || `my-${cfg.kind.toLowerCase()}`, namespace },
      spec: specWithRefs(formData),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [cfg.kind, name, namespace, formData],
  );

  const createMutation = useMutation({
    mutationFn: async (fd: Record<string, unknown>) => {
      // 1. Create a Secret per credential (so the password never lands in the CR spec).
      for (const c of creds) {
        const pw = passwords[c.path];
        if (!pw) continue;
        await k8sCreate<K8sObject>(corePaths.secrets(namespace), {
          apiVersion: "v1",
          kind: "Secret",
          metadata: { name: secretNameFor(c.path), namespace },
          stringData: { password: pw },
        });
      }
      // 2. Create the resource, with its passwordSecretRef(s) pointing at those Secrets.
      return k8sCreate<K8sObject>(cfg.createPath(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: cfg.kind,
        metadata: { name, namespace },
        spec: specWithRefs(fd),
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(cfg.listPath) });
      cfg.onCreated(namespace, name);
    },
  });

  const nameError = nameTouched ? rfc1123Error(name) : null;
  const credsValid = () => creds.every((c) => (passwords[c.path] ?? "").length > 0);

  const onSubmit = (e: IChangeEvent) => {
    if (!isValidName(name) || !credsValid()) {
      setNameTouched(true);
      setCredTouched(true);
      return;
    }
    createMutation.mutate(e.formData as Record<string, unknown>);
  };

  const onCreateClick = () => {
    // Cloudscape: never disable Create; validate on click and show inline errors, then live-validate.
    setNameTouched(true);
    setCredTouched(true);
    setLiveValidate(true);
    if (!isValidName(name) || !credsValid()) return;
    formRef.current?.submit();
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6 pb-24">
      <div>
        <Button variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground" onClick={cfg.onCancel}>
          <ArrowLeft className="size-4" /> Back
        </Button>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          {cfg.icon} Create {cfg.kind}
          <span className="ml-1">
            <InfoLink title={cfg.kind} body={<p>{cfg.description}</p>} docsHref={kindDocsUrl(cfg.kind)} />
          </span>
        </h1>
        <p className="mt-1 flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
          {cfg.description}
          {kindDocsUrl(cfg.kind) ? <LearnMore href={kindDocsUrl(cfg.kind)!} /> : null}
        </p>
      </div>

      {/* Identity */}
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Identity</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="oi-name">Name</Label>
            <Input
              id="oi-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setNameTouched(true)}
              placeholder={`my-${cfg.kind.toLowerCase()}`}
              autoFocus
            />
            {nameError ? <p className="text-xs text-destructive">{nameError}</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="oi-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="oi-ns">
                <SelectValue placeholder="Namespace" />
              </SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>
                    {ns}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {/* Spec, from the CRD schema */}
      {schemaQuery.isLoading ? (
        <LoadingState label={`Loading ${cfg.kind} schema…`} />
      ) : schemaQuery.isError ? (
        <ErrorState error={schemaQuery.error} onRetry={() => void schemaQuery.refetch()} />
      ) : specSchema ? (
        <div className="oi-rjsf">
          <Form
            ref={formRef}
            schema={specSchema}
            uiSchema={cfg.uiSchema}
            validator={validator}
            templates={createTemplates}
            formContext={{ rootId: ROOT_ID, sections: cfg.sections }}
            formData={formData}
            onChange={(e) => setFormData(e.formData as Record<string, unknown>)}
            onSubmit={onSubmit}
            showErrorList={false}
            liveValidate={liveValidate}
            idPrefix={ROOT_ID}
          >
            <></>
          </Form>
        </div>
      ) : null}

      {/* Credentials — collected here, stored as Kubernetes Secrets, referenced (never inlined). */}
      {creds.length > 0 ? (
        <div className="space-y-4 rounded-lg border border-border p-4">
          <div>
            <h3 className="text-sm font-semibold">Credentials</h3>
            <p className="text-xs text-muted-foreground">
              Passwords are written to Kubernetes Secrets; the resource references them, never the plaintext.
            </p>
          </div>
          {creds.map((c) => (
            <div key={c.path} className="space-y-1.5">
              <Label htmlFor={`oi-pw-${c.path}`}>{c.label}</Label>
              <Input
                id={`oi-pw-${c.path}`}
                type="password"
                value={passwords[c.path] ?? ""}
                onChange={(e) => setPasswords((p) => ({ ...p, [c.path]: e.target.value }))}
                placeholder="••••••••"
              />
              {credTouched && !(passwords[c.path] ?? "") ? (
                <p className="text-xs text-destructive">Password is required.</p>
              ) : (
                <p className="text-xs text-muted-foreground">
                  → Secret <code>{secretNameFor(c.path)}</code>
                </p>
              )}
            </div>
          ))}
        </div>
      ) : null}

      {/* YAML preview — the declarative escape hatch (GitOps-native; AWS has no equivalent). */}
      <ExpandableSection title="YAML preview" description="Exactly what will be applied">
        <YamlViewer value={manifest} />
      </ExpandableSection>

      {createMutation.error ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {createMutation.error instanceof ApiError ? createMutation.error.message : `Failed to create the ${cfg.kind}.`}
        </div>
      ) : null}

      {/* Sticky actions */}
      <div className="fixed inset-x-0 bottom-0 z-10 border-t border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-3xl items-center justify-end gap-3 p-4">
          <Button variant="outline" onClick={cfg.onCancel} disabled={createMutation.isPending}>
            Cancel
          </Button>
          <Button onClick={onCreateClick} disabled={createMutation.isPending}>
            {createMutation.isPending ? <Spinner className="text-current" /> : <Rocket className="size-4" />}
            Create {cfg.kind}
          </Button>
        </div>
      </div>
    </div>
  );
}
