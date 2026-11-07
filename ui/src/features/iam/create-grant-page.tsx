import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Clock, Search } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamGrant, listIamPolicies } from "@/lib/api";
import { cn } from "@/lib/utils";
import { ManagedBadge } from "./attach-policy-picker";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DURATION = /^([0-9]+h)?([0-9]+m)?([0-9]+s)?$/;
const MAX_POLICIES = 10;
const selectCls =
  "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

/** Seconds in a duration of the grant form (whole h/m/s), or NaN when it is not one. */
function durationSeconds(d: string): number {
  if (d === "" || !DURATION.test(d)) return NaN;
  const unit: Record<string, number> = { h: 3600, m: 60, s: 1 };
  let total = 0;
  for (const [, n, u] of d.matchAll(/([0-9]+)([hms])/g)) total += Number(n) * (unit[u ?? ""] ?? 0);
  return total;
}

/**
 * Single-page create (request) for temporary access: a Grant that attaches IAM policies to a user or
 * group for a while. This only REQUESTS access — the grant attaches nothing until someone other than
 * the requester approves it (AC-2(2)/AC-5); its window then runs from the approval, at most 24 hours.
 */
export function CreateGrantPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies });
  const [name, setName] = useState("");
  const [subjectKind, setSubjectKind] = useState("User");
  const [subjectName, setSubjectName] = useState("");
  const [attached, setAttached] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [duration, setDuration] = useState("4h");
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);

  const visiblePolicies = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (policies.data ?? [])
      .filter((p) => !q || p.name.toLowerCase().includes(q) || (p.description ?? "").toLowerCase().includes(q))
      .sort((a, b) => Number(b.managed) - Number(a.managed) || a.name.localeCompare(b.name));
  }, [policies.data, search]);

  const create = useMutation({
    mutationFn: () =>
      createIamGrant({ name, subjectKind, subjectName: subjectName.trim(), policies: attached, duration, reason }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "grants"] });
      navigate({ to: "/grants/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const secs = durationSeconds(duration);
  const durationOk = secs > 0 && secs <= 24 * 3600;
  const policiesOk = attached.length > 0 && attached.length <= MAX_POLICIES;
  const canSubmit = nameOk && subjectName.trim() !== "" && policiesOk && durationOk;
  const toggle = (n: string) =>
    setAttached((list) => (list.includes(n) ? list.filter((x) => x !== n) : [...list, n]));
  const submit = () => {
    setTouched(true);
    if (!canSubmit) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Clock className="size-6 text-primary" />}
      title="Request temporary access"
      description="Requests that policies be attached to a user or group for a while. Nothing is attached until someone other than you approves it; the time starts at approval, and the policies are detached on their own when it ends (at most 24 hours)."
      onCancel={() => navigate({ to: "/grants" })}
      onSubmit={submit}
      submitLabel="Request access"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || subjectName.length > 0 || reason.length > 0 || attached.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Request</h3>
        <div className="space-y-1.5">
          <Label htmlFor="g-name">Name</Label>
          <Input id="g-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="jit-alice-incident-1234" autoFocus />
          {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p> : null}
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="g-skind">Attach to</Label>
            <select id="g-skind" className={selectCls} value={subjectKind} onChange={(e) => setSubjectKind(e.target.value)}>
              <option value="User">User</option>
              <option value="Group">User group</option>
            </select>
          </div>
          <div className="col-span-2 space-y-1.5">
            <Label htmlFor="g-sname">{subjectKind === "User" ? "User name" : "User group name"}</Label>
            <Input id="g-sname" value={subjectName} onChange={(e) => setSubjectName(e.target.value)} placeholder={subjectKind === "User" ? "alice" : "oncall"} />
            {touched && subjectName.trim() === "" ? <p className="text-xs text-destructive">Name the user or group.</p> : null}
          </div>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="g-dur">Duration</Label>
            <Input id="g-dur" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="4h" />
            {touched && !durationOk ? <p className="text-xs text-destructive">Use hours, minutes or seconds like 30m, 4h or 1h30m (at most 24h).</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="g-reason">Reason</Label>
            <Input id="g-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="oncall incident 1234" />
          </div>
        </div>
      </div>

      <div className="space-y-3 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">Permissions policies ({attached.length} selected)</h3>
          <p className="text-xs text-muted-foreground">
            The policies attached for the duration once the request is approved, such as ReadOnlyAccess or
            PowerUserAccess. Up to {MAX_POLICIES}.
          </p>
          {touched && !policiesOk ? (
            <p className="text-xs text-destructive">Select between 1 and {MAX_POLICIES} policies.</p>
          ) : null}
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input className="pl-8" placeholder="Filter policies" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="max-h-80 overflow-y-auto rounded-md border">
          {visiblePolicies.length === 0 ? (
            <p className="p-3 text-sm text-muted-foreground">{policies.isLoading ? "Loading policies…" : "No policies match."}</p>
          ) : (
            visiblePolicies.map((p) => {
              const on = attached.includes(p.name);
              return (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => toggle(p.name)}
                  className={cn(
                    "flex w-full items-start gap-3 border-b p-3 text-left last:border-0 transition-colors",
                    on ? "bg-primary/5" : "hover:bg-muted/40",
                  )}
                >
                  <span
                    className={cn(
                      "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded border",
                      on ? "border-primary bg-primary text-primary-foreground" : "border-border",
                    )}
                  >
                    {on ? <Check className="size-3" /> : null}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2 text-sm font-medium">
                      {p.name}
                      <ManagedBadge managed={p.managed} category={p.category} />
                    </span>
                    <span className="block text-xs text-muted-foreground">{p.description || "—"}</span>
                  </span>
                </button>
              );
            })
          )}
        </div>
      </div>
    </CreateShell>
  );
}
