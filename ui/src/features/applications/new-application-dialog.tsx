import { useMemo, useRef, useState } from "react";
import Form from "@rjsf/core";
import type { IChangeEvent } from "@rjsf/core";
import type { RJSFSchema, UiSchema } from "@rjsf/utils";
import validator from "@rjsf/validator-ajv8";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Rocket } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorState, LoadingState, Spinner } from "@/components/common/states";
import { ApiError, getCrdSchema, k8sCreate } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import {
  APPLICATIONS_CRD_NAME,
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Application,
  type ApplicationSpec,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/** Layout hints for the rjsf-rendered spec form. */
const uiSchema: UiSchema = {
  "ui:order": [
    "image",
    "port",
    "domain",
    "scaling",
    "database",
    "storage",
    "queues",
    "env",
    "secrets",
    "*",
  ],
  image: { "ui:placeholder": "ghcr.io/me/my-api:latest" },
  domain: { "ui:placeholder": "my-api.example.com" },
};

interface NewApplicationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Namespace pre-selected from the switcher (concrete ns or undefined). */
  defaultNamespace?: string;
  /** Known namespaces to choose from. */
  namespaces: string[];
  /** List path of Applications, used to refresh the live list after create. */
  listPath: string;
}

export function NewApplicationDialog({
  open,
  onOpenChange,
  defaultNamespace,
  namespaces,
  listPath,
}: NewApplicationDialogProps) {
  const queryClient = useQueryClient();
  const formRef = useRef<Form<unknown, RJSFSchema> | null>(null);
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [formData, setFormData] = useState<Partial<ApplicationSpec>>({});
  const [nameTouched, setNameTouched] = useState(false);

  const schemaQuery = useQuery({
    queryKey: ["crd-schema", APPLICATIONS_CRD_NAME],
    queryFn: () => getCrdSchema(APPLICATIONS_CRD_NAME),
    enabled: open,
    staleTime: 5 * 60_000,
  });

  // The BFF returns a normalized JSON Schema. Accept either the full object
  // schema (with a `spec` property) or a schema describing the spec directly.
  const specSchema = useMemo<RJSFSchema | null>(() => {
    const raw = schemaQuery.data as Record<string, unknown> | undefined;
    if (!raw) return null;
    const props = raw["properties"] as Record<string, unknown> | undefined;
    if (props && "spec" in props) {
      return props["spec"] as RJSFSchema;
    }
    return raw as RJSFSchema;
  }, [schemaQuery.data]);

  const createMutation = useMutation({
    mutationFn: async (manifest: Application) => {
      return k8sCreate<Application>(openinfraPaths.applications(namespace), manifest);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(listPath) });
      reset();
      onOpenChange(false);
    },
  });

  function reset() {
    setName("");
    setNameTouched(false);
    setFormData({});
    createMutation.reset();
  }

  const nameError =
    nameTouched && !RFC1123.test(name)
      ? "Lowercase letters, numbers and hyphens; must start/end alphanumeric."
      : null;

  const onSubmit = (e: IChangeEvent) => {
    if (!RFC1123.test(name)) {
      setNameTouched(true);
      return;
    }
    const manifest: Application = {
      apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
      kind: "Application",
      metadata: { name, namespace },
      spec: e.formData as ApplicationSpec,
    };
    createMutation.mutate(manifest);
  };

  const submitError = createMutation.error;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (createMutation.isPending) return;
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent className="flex max-h-[90vh] max-w-2xl flex-col gap-0 p-0">
        <DialogHeader className="border-b border-border p-5">
          <DialogTitle className="flex items-center gap-2">
            <Boxes className="size-5 text-primary" />
            New Application
          </DialogTitle>
          <DialogDescription>
            Declare intent — open-infra provisions hosting, scaling, and any
            attached database, buckets, or queues from this spec.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-auto p-5">
          {/* Identity */}
          <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="app-name">Name</Label>
              <Input
                id="app-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onBlur={() => setNameTouched(true)}
                placeholder="my-api"
                autoFocus
              />
              {nameError ? (
                <p className="text-xs text-destructive">{nameError}</p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="app-ns">Namespace</Label>
              <Select value={namespace} onValueChange={setNamespace}>
                <SelectTrigger id="app-ns">
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

          {/* Spec from CRD schema */}
          {schemaQuery.isLoading ? (
            <LoadingState label="Loading Application schema…" />
          ) : schemaQuery.isError ? (
            <ErrorState
              error={schemaQuery.error}
              onRetry={() => void schemaQuery.refetch()}
            />
          ) : specSchema ? (
            <div className="oi-rjsf">
              <Form
                ref={formRef}
                schema={specSchema}
                uiSchema={uiSchema}
                validator={validator}
                formData={formData}
                onChange={(e) => setFormData(e.formData as Partial<ApplicationSpec>)}
                onSubmit={onSubmit}
                showErrorList={false}
                liveValidate={false}
                idPrefix="oi-app"
              >
                {/* Custom footer below; hide rjsf's default submit button. */}
                <></>
              </Form>
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-muted-foreground">
              The BFF returned an empty schema for {APPLICATIONS_CRD_NAME}.
            </p>
          )}

          {submitError ? (
            <div className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {submitError instanceof ApiError
                ? submitError.message
                : "Failed to create the Application."}
            </div>
          ) : null}
        </div>

        <DialogFooter className="border-t border-border p-4">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={createMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={() => {
              // Run rjsf schema validation + submit through the form ref.
              formRef.current?.submit();
            }}
            disabled={
              createMutation.isPending ||
              schemaQuery.isLoading ||
              !specSchema ||
              !RFC1123.test(name)
            }
          >
            {createMutation.isPending ? (
              <Spinner className="text-current" />
            ) : (
              <Rocket className="size-4" />
            )}
            Create Application
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
