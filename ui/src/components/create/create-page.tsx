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
import { createTemplates } from "@/components/create/rjsf-templates";
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
  /** Spec property names to show up-front; the rest collapse under "Advanced settings". */
  essential: string[];
  /** RJSF layout hints (ui:order, ui:widget, ui:placeholder, …). */
  uiSchema?: UiSchema;
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

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [nameTouched, setNameTouched] = useState(false);
  const [formData, setFormData] = useState<Record<string, unknown>>({});
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
    if (props && "spec" in props) return props["spec"] as RJSFSchema;
    return raw as RJSFSchema;
  }, [schemaQuery.data]);

  const manifest = useMemo(
    (): K8sObject => ({
      apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
      kind: cfg.kind,
      metadata: { name: name || `my-${cfg.kind.toLowerCase()}`, namespace },
      spec: formData,
    }),
    [cfg.kind, name, namespace, formData],
  );

  const createMutation = useMutation({
    mutationFn: (obj: K8sObject) => k8sCreate<K8sObject>(cfg.createPath(namespace), obj),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(cfg.listPath) });
      cfg.onCreated(namespace, name);
    },
  });

  const nameError = nameTouched ? rfc1123Error(name) : null;

  const onSubmit = (e: IChangeEvent) => {
    if (!isValidName(name)) {
      setNameTouched(true);
      return;
    }
    createMutation.mutate({ ...manifest, spec: e.formData as Record<string, unknown> });
  };

  const onCreateClick = () => {
    // Cloudscape: never disable Create; validate on click and show inline errors, then live-validate.
    setNameTouched(true);
    setLiveValidate(true);
    if (!isValidName(name)) return;
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
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{cfg.description}</p>
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
            formContext={{ rootId: ROOT_ID, essential: cfg.essential }}
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
