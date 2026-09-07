import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { HardDrive } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createBucket } from "@/lib/api";

/**
 * Validate a bucket name against the S3/MinIO naming rules (the same set MinIO
 * enforces server-side) so the user sees the problem inline before submitting,
 * rather than a raw 400 from the BFF.
 */
function bucketNameError(name: string): string | null {
  if (!name) return null; // empty = pristine; the primary stays enabled (AWS rule)
  if (name.length < 3 || name.length > 63)
    return "Must be 3–63 characters long.";
  if (!/^[a-z0-9.-]+$/.test(name))
    return "Use only lowercase letters, numbers, dots, and hyphens.";
  if (!/^[a-z0-9]/.test(name) || !/[a-z0-9]$/.test(name))
    return "Must start and end with a letter or number.";
  if (name.includes(".."))
    return "Cannot contain two adjacent dots.";
  if (/\.-|-\./.test(name))
    return "Cannot have a dot next to a hyphen.";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name))
    return "Cannot be formatted as an IP address.";
  return null;
}

/**
 * Full-page, single-page create for an object-storage bucket (S3/MinIO). Buckets
 * are a BFF resource (not a CRD), so this uses the bespoke {@link CreateShell}
 * rather than the schema-driven CreatePage — matching the console's single-page
 * create convention instead of the old modal.
 */
export function CreateBucketPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);

  const validationError = bucketNameError(name);
  const createMutation = useMutation({
    mutationFn: () => createBucket(name.trim()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["buckets"] });
      navigate({ to: "/buckets/$bucket", params: { bucket: name.trim() } });
    },
  });

  const submit = () => {
    // Cloudscape: never block the primary for validity — validate on submit and
    // surface the inline error instead.
    setTouched(true);
    if (!name.trim() || validationError) return;
    createMutation.mutate();
  };

  return (
    <CreateShell
      icon={<HardDrive className="size-6 text-primary" />}
      title="Create bucket"
      description="Object storage — open-infra's S3 (MinIO). Names are globally unique within the cluster's object store."
      onCancel={() => navigate({ to: "/buckets" })}
      onSubmit={submit}
      submitLabel="Create bucket"
      pending={createMutation.isPending}
      error={createMutation.error}
      dirty={name.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">General configuration</h3>
        <div className="space-y-1.5">
          <Label htmlFor="bucket-name">Bucket name</Label>
          <Input
            id="bucket-name"
            value={name}
            autoFocus
            placeholder="my-bucket"
            onChange={(e) => setName(e.target.value)}
            onBlur={() => setTouched(true)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
          />
          {touched && !name.trim() ? (
            <p className="text-xs text-destructive">A bucket name is required.</p>
          ) : validationError ? (
            <p className="text-xs text-destructive">{validationError}</p>
          ) : (
            <p className="text-xs text-muted-foreground">
              Lowercase letters, numbers, dots, and hyphens; 3–63 characters.
            </p>
          )}
        </div>
      </div>
    </CreateShell>
  );
}
