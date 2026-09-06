import { useParams } from "@tanstack/react-router";
import { PolicyEditorPage } from "./policy-editor/policy-editor-page";

/**
 * Single-page create for kind: Policy. The authoring surface (Visual editor + JSON tab) lives in
 * policy-editor/; this is the create-mode entry. Edit reuses the same surface via {@link EditPolicyPage}
 * on the /policies/$name/edit route — replacing the old modal (new-policy-dialog.tsx), per the
 * no-modal-for-large-edits convention.
 */
export function CreatePolicyPage() {
  return <PolicyEditorPage />;
}

/** Edit-mode entry for the /policies/$name/edit route. */
export function EditPolicyPage() {
  const { name } = useParams({ strict: false }) as { name: string };
  return <PolicyEditorPage editName={name} />;
}
