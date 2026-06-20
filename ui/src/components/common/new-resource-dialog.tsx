import { type ReactNode, useMemo, useRef, useState } from "react";
import Form from "@rjsf/core";
import type { IChangeEvent } from "@rjsf/core";
import type { RJSFSchema } from "@rjsf/utils";
import validator from "@rjsf/validator-ajv8";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Rocket } from "lucide-react";
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
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Generic "create an openinfra.dev resource" dialog: fetches the CRD schema,
 * renders the spec as an rjsf form, and POSTs the claim. Used for Functions and
 * Models (Applications keep their own richer dialog).
 */
export function NewResourceDialog({
  open,
  onOpenChange,
  kind,
  crdName,
  createPath,
  listPath,
  namespaces,
  defaultNamespace,
  icon,
  description,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  kind: string;
  crdName: string;
  createPath: (ns?: string) => string;
  listPath: string;
  namespaces: string[];
  defaultNamespace?: string;
  icon: ReactNode;
  description: string;
}) {
  const queryClient = useQueryClient();
  const formRef = useRef<Form<unknown, RJSFSchema> | null>(null);
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [formData, setFormData] = useState<Record<string, unknown>>({});
  const [nameTouched, setNameTouched] = useState(false);

  const schemaQuery = useQuery({
    queryKey: ["crd-schema", crdName],
    queryFn: () => getCrdSchema(crdName),
    enabled: open,
    staleTime: 5 * 60_000,
  });

  const specSchema = useMemo<RJSFSchema | null>(() => {
    const raw = schemaQuery.data as Record<string, unknown> | undefined;
    if (!raw) return null;
    const props = raw["properties"] as Record<string, unknown> | undefined;
    if (props && "spec" in props) return props["spec"] as RJSFSchema;
    return raw as RJSFSchema;
  }, [schemaQuery.data]);

  const createMutation = useMutation({
    mutationFn: (manifest: K8sObject) =>
      k8sCreate<K8sObject>(createPath(namespace), manifest),
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
    createMutation.mutate({
      apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
      kind,
      metadata: { name, namespace },
      spec: e.formData as Record<string, unknown>,
    });
  };

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
            {icon}
            New {kind}
          </DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-auto p-5">
          <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="res-name">Name</Label>
              <Input
                id="res-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onBlur={() => setNameTouched(true)}
                placeholder={`my-${kind.toLowerCase()}`}
                autoFocus
              />
              {nameError ? (
                <p className="text-xs text-destructive">{nameError}</p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="res-ns">Namespace</Label>
              <Select value={namespace} onValueChange={setNamespace}>
                <SelectTrigger id="res-ns">
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

          {schemaQuery.isLoading ? (
            <LoadingState label={`Loading ${kind} schema…`} />
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
                validator={validator}
                formData={formData}
                onChange={(e) =>
                  setFormData(e.formData as Record<string, unknown>)
                }
                onSubmit={onSubmit}
                showErrorList={false}
                liveValidate={false}
                idPrefix="oi-res"
              >
                <></>
              </Form>
            </div>
          ) : null}

          {createMutation.error ? (
            <div className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {createMutation.error instanceof ApiError
                ? createMutation.error.message
                : `Failed to create the ${kind}.`}
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
            onClick={() => formRef.current?.submit()}
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
            Create {kind}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
