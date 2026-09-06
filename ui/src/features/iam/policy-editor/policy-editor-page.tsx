import { useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, FileText, Info, Lightbulb } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState, ErrorState } from "@/components/common/states";
import {
  createIamPolicy,
  getIamConfig,
  getIamPolicy,
  updateIamPolicy,
  type IamPolicy,
} from "@/lib/api";
import { VisualEditor } from "./visual-editor";
import { JsonEditor } from "./json-editor";
import { PermissionsSummary } from "./permissions-summary";
import {
  docToModel,
  emptyModel,
  modelToDoc,
  modelToJson,
  parseDoc,
  validateModel,
  type PolicyModel,
} from "./model";

/**
 * The single-page Policy authoring surface — the crown jewel. Create and edit share it (edit loads the
 * existing CR first). It reproduces AWS's Policy editor: a Visual|JSON toggle over ONE model (so the
 * switch is lossless), a live permissions summary, and three-severity validation. Replaces the old
 * modal (new-policy-dialog.tsx), honoring the no-modal-for-large-edits convention.
 */
export function PolicyEditorPage({ editName }: { editName?: string }) {
  const isEdit = Boolean(editName);
  const cfg = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const existing = useQuery({
    queryKey: ["iam", "policy", editName],
    queryFn: () => getIamPolicy(editName as string),
    enabled: isEdit,
  });

  if (isEdit && existing.isLoading) return <LoadingState label="Loading policy…" />;
  if (isEdit && (existing.isError || !existing.data))
    return <ErrorState error={existing.error} onRetry={existing.refetch} />;

  return (
    <Editor
      isEdit={isEdit}
      initial={existing.data}
      controlResources={cfg.data?.policyResources ?? []}
    />
  );
}

function Editor({
  isEdit,
  initial,
  controlResources,
}: {
  isEdit: boolean;
  initial?: IamPolicy;
  controlResources: string[];
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [name, setName] = useState(initial?.name ?? "");
  const [model, setModel] = useState<PolicyModel>(() =>
    initial
      ? docToModel({
          description: initial.description,
          statements: initial.statements,
          dataPlane: initial.dataPlane,
          controlPlane: initial.controlPlane,
        })
      : emptyModel(),
  );
  const [view, setView] = useState<"visual" | "json">("visual");
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const validation = useMemo(
    () => validateModel(model, { name, isCreate: !isEdit }),
    [model, name, isEdit],
  );

  // Baseline for discard-confirm: the JSON the loaded (or empty) model projects. Comparing the current
  // projection against it means Cancel only confirms when something actually changed.
  const baseline = useMemo(
    () =>
      initial
        ? modelToJson(
            docToModel({
              description: initial.description,
              statements: initial.statements,
              dataPlane: initial.dataPlane,
              controlPlane: initial.controlPlane,
            }),
          )
        : modelToJson(emptyModel()),
    [initial],
  );

  const save = useMutation({
    mutationFn: () => {
      const doc = modelToDoc(model);
      if (isEdit) {
        return updateIamPolicy(name, {
          description: doc.description,
          statements: doc.statements,
          dataPlane: doc.dataPlane,
          controlPlane: doc.controlPlane,
        });
      }
      return createIamPolicy({
        name,
        description: doc.description,
        statements: doc.statements,
        dataPlane: doc.dataPlane,
        controlPlane: doc.controlPlane,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "policies"] });
      void qc.invalidateQueries({ queryKey: ["iam", "policy", name] });
      navigate({ to: "/policies/$name", params: { name } });
    },
  });

  // Tab switching keeps the two views bound to one model (lossless, unlike AWS's "restructure").
  const switchTo = (next: "visual" | "json") => {
    if (next === view) return;
    if (next === "json") {
      setJsonText(modelToJson(model));
      setJsonError(null);
    } else if (jsonError) {
      // Can't leave a broken JSON document for the visual editor.
      return;
    }
    setView(next);
  };

  const onJsonChange = (text: string) => {
    setJsonText(text);
    try {
      const doc = parseDoc(text);
      setModel(docToModel(doc));
      setJsonError(null);
    } catch (e) {
      setJsonError((e as Error).message);
    }
  };

  const submit = () => {
    setTouched(true);
    if (view === "json" && jsonError) return;
    if (validation.errors.length > 0) return;
    save.mutate();
  };

  const doc = modelToDoc(model);
  const dirty = (!isEdit && name.length > 0) || modelToJson(model) !== baseline;

  return (
    <CreateShell
      icon={<FileText className="size-6 text-primary" />}
      title={isEdit ? `Edit policy ${name}` : "Create Policy"}
      description="An attachable set of permissions. Platform permissions compile to Kubernetes RBAC (the boundary); data-service permissions are enforced by Cedar and can Deny, scope, and set conditions. A policy grants nothing until a Role includes it or a principal is named."
      onCancel={() => navigate(isEdit ? { to: "/policies/$name", params: { name } } : { to: "/policies" })}
      onSubmit={submit}
      submitLabel={isEdit ? "Save policy" : "Create Policy"}
      pending={save.isPending}
      error={save.error}
      dirty={dirty}
    >
      {/* Identity */}
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Policy details</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="p-name">Name</Label>
            <Input
              id="p-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="virtual-machine-operator"
              disabled={isEdit}
              autoFocus={!isEdit}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="p-desc">Description - optional</Label>
            <Input
              id="p-desc"
              value={model.description}
              onChange={(e) => setModel({ ...model, description: e.target.value })}
              placeholder="Full control of VMs and their disks"
            />
          </div>
        </div>
      </div>

      {/* Policy editor: Visual | JSON */}
      <div className="space-y-3">
        <Tabs value={view} onValueChange={(v) => switchTo(v as "visual" | "json")}>
          <div className="flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="visual">Visual editor</TabsTrigger>
              <TabsTrigger value="json">JSON</TabsTrigger>
            </TabsList>
            {view === "json" ? (
              <span className="text-xs text-muted-foreground">
                This is the Policy resource itself — the single source of truth.
              </span>
            ) : null}
          </div>

          <TabsContent value="visual" className="pt-3">
            <VisualEditor model={model} onChange={setModel} controlResources={controlResources} />
          </TabsContent>

          <TabsContent value="json" className="pt-3">
            <JsonEditor value={jsonText} onChange={onJsonChange} error={jsonError} />
          </TabsContent>
        </Tabs>
      </div>

      {/* Live validation (three severities). Errors block submit; the button stays enabled per AWS rule. */}
      {(validation.errors.length > 0 && touched) ||
      validation.warnings.length > 0 ||
      validation.suggestions.length > 0 ? (
        <div className="space-y-2">
          {touched
            ? validation.errors.map((m, i) => (
                <Note key={`e${i}`} tone="error" icon={<AlertTriangle className="size-4" />}>
                  {m}
                </Note>
              ))
            : null}
          {validation.warnings.map((m, i) => (
            <Note key={`w${i}`} tone="warning" icon={<AlertTriangle className="size-4" />}>
              {m}
            </Note>
          ))}
          {validation.suggestions.map((m, i) => (
            <Note key={`s${i}`} tone="info" icon={<Lightbulb className="size-4" />}>
              {m}
            </Note>
          ))}
        </div>
      ) : null}

      {/* Live permissions summary (AWS's review table, always visible). */}
      <Card>
        <CardContent className="p-0">
          <div className="flex items-center gap-2 border-b border-border p-3">
            <Info className="size-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold">Permissions summary</h3>
          </div>
          <PermissionsSummary doc={doc} />
        </CardContent>
      </Card>
    </CreateShell>
  );
}

function Note({
  tone,
  icon,
  children,
}: {
  tone: "error" | "warning" | "info";
  icon: ReactNode;
  children: ReactNode;
}) {
  const cls = {
    error: "border-destructive/40 bg-destructive/10 text-destructive",
    warning: "border-warning/40 bg-warning/10 text-warning",
    info: "border-border bg-muted/40 text-muted-foreground",
  }[tone];
  return (
    <div className={`flex items-start gap-2 rounded-md border p-2.5 text-xs ${cls}`}>
      <span className="mt-px shrink-0">{icon}</span>
      <span>{children}</span>
    </div>
  );
}
