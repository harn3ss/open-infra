import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createIamGrant, listIamRoles } from "@/lib/api";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DURATION = /^([0-9]+h)?([0-9]+m)?([0-9]+s)?$/;
const BUILTIN_ROLES = ["open-infra-readonly", "open-infra-poweruser"];
const selectCls =
  "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

/**
 * Single-page create (request) for a temporal Grant (issue #96). This only REQUESTS access — the grant
 * is created AwaitingApproval and confers nothing until a different admin approves it (AC-2(2)/AC-5).
 */
export function CreateGrantPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });
  const [name, setName] = useState("");
  const [subjectKind, setSubjectKind] = useState("User");
  const [subjectName, setSubjectName] = useState("");
  const [clusterRole, setClusterRole] = useState("");
  const [duration, setDuration] = useState("4h");
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);

  const grantableRoles = [
    ...BUILTIN_ROLES,
    ...(roles.data ?? []).map((r) => r.clusterRole).filter((c) => c && !BUILTIN_ROLES.includes(c)),
  ];

  const create = useMutation({
    mutationFn: () => createIamGrant({ name, subjectKind, subjectName, clusterRole, duration, reason }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["iam", "grants"] });
      navigate({ to: "/grants/$name", params: { name } });
    },
  });

  const nameOk = RFC1123.test(name);
  const durationOk = duration !== "" && DURATION.test(duration);
  const canSubmit = nameOk && subjectName.trim() !== "" && clusterRole !== "" && durationOk;
  const submit = () => {
    setTouched(true);
    if (!canSubmit) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Clock className="size-6 text-primary" />}
      title="Request temporal access"
      description="Creates a grant that is AwaitingApproval and confers no access until a different admin approves it (separation of duties, AC-5). The access clock starts at approval and self-revokes when the duration elapses."
      onCancel={() => navigate({ to: "/grants" })}
      onSubmit={submit}
      submitLabel="Request grant"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0 || subjectName.length > 0 || reason.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Grant</h3>
        <div className="space-y-1.5">
          <Label htmlFor="g-name">Name</Label>
          <Input id="g-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="jit-alice-incident-1234" autoFocus />
          {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, digits and dashes only.</p> : null}
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="g-skind">Subject</Label>
            <select id="g-skind" className={selectCls} value={subjectKind} onChange={(e) => setSubjectKind(e.target.value)}>
              <option value="User">User</option>
              <option value="Group">Group</option>
            </select>
          </div>
          <div className="col-span-2 space-y-1.5">
            <Label htmlFor="g-sname">{subjectKind} name</Label>
            <Input id="g-sname" value={subjectName} onChange={(e) => setSubjectName(e.target.value)} placeholder={subjectKind === "User" ? "alice" : "oncall"} />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="g-role">ClusterRole</Label>
          <select id="g-role" className={selectCls} value={clusterRole} onChange={(e) => setClusterRole(e.target.value)}>
            <option value="" disabled>Select a grantable role…</option>
            {grantableRoles.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <p className="text-xs text-muted-foreground">
            Only kind: Role (<code>openinfra-role-*</code>) or the bounded built-in console roles can be
            granted — the same ceiling as a Group.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="g-dur">Duration</Label>
            <Input id="g-dur" value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="4h" />
            {touched && !durationOk ? <p className="text-xs text-destructive">Use a Go duration like 30m, 4h, 8h (max 24h).</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="g-reason">Reason</Label>
            <Input id="g-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="oncall incident 1234" />
          </div>
        </div>
      </div>
    </CreateShell>
  );
}
