import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, User as UserIcon, UsersRound } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/common/states";
import { listIamGroups, listIamRoles, listIamUsers } from "@/lib/api";
import { PRINCIPAL_TYPES, type PrincipalType } from "@/lib/iam-cedar-vocab";

/** The principal to simulate: a type (User/Group/Role) and a chosen name. */
export interface PrincipalValue {
  type: PrincipalType;
  /** The selected principal's metadata.name; "" until one is chosen. */
  name: string;
}

const TYPE_META: Record<PrincipalType, { icon: LucideIcon; hint: string }> = {
  User: { icon: UserIcon, hint: "A console sign-in identity (kind: User)." },
  Group: { icon: UsersRound, hint: "A permission group (kind: Group)." },
  Role: { icon: ShieldCheck, hint: "An assumable bundle of policies (kind: Role)." },
};

/**
 * The AWS Policy Simulator's "Users, Groups, and Roles" picker: choose a principal TYPE, then the
 * specific principal to evaluate against the CURRENT policies. Emits `{ type, name }`; the page turns it
 * into the "Type::name" string the simulator's `principal` field takes. Reuses the same react-query keys
 * as the IAM list pages so the roster is shared/cached.
 */
export function PrincipalPicker({
  value,
  onChange,
  invalid,
}: {
  value: PrincipalValue;
  onChange: (next: PrincipalValue) => void;
  /** When true, render the "choose a principal" prompt in the error colour (after a failed submit). */
  invalid?: boolean;
}) {
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers });
  const groups = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles });

  const source = {
    User: { loading: users.isLoading, names: (users.data ?? []).map((u) => u.name) },
    Group: { loading: groups.isLoading, names: (groups.data ?? []).map((g) => g.name) },
    Role: { loading: roles.isLoading, names: (roles.data ?? []).map((r) => r.name) },
  }[value.type];

  return (
    <div className="space-y-3">
      {/* Principal type — segmented, mirroring the visual editor's chip pattern. */}
      <div className="flex flex-wrap gap-1.5">
        {PRINCIPAL_TYPES.map((t) => {
          const Icon = TYPE_META[t].icon;
          const on = value.type === t;
          return (
            <button
              key={t}
              type="button"
              onClick={() => onChange({ type: t, name: "" })}
              className={[
                "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                on
                  ? "border-primary/40 bg-primary/15 text-primary"
                  : "border-border text-muted-foreground hover:bg-muted",
              ].join(" ")}
            >
              <Icon className="size-3.5" />
              {t}
            </button>
          );
        })}
      </div>

      <p className="text-xs text-muted-foreground">{TYPE_META[value.type].hint}</p>

      {/* The specific principal. */}
      {source.loading ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Spinner /> Loading {value.type.toLowerCase()}s…
        </div>
      ) : source.names.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No {value.type.toLowerCase()}s exist yet.
        </p>
      ) : (
        <Select value={value.name} onValueChange={(name) => onChange({ ...value, name })}>
          <SelectTrigger
            className={[
              "h-9 w-full text-sm",
              invalid && !value.name ? "border-destructive" : "",
            ].join(" ")}
          >
            <SelectValue placeholder={`Choose a ${value.type.toLowerCase()}…`} />
          </SelectTrigger>
          <SelectContent>
            {source.names.map((n) => (
              <SelectItem key={n} value={n}>
                {n}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {invalid && !value.name ? (
        <p className="text-xs text-destructive">Choose a principal to simulate.</p>
      ) : value.name ? (
        <p className="text-xs text-muted-foreground">
          Evaluating as{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-foreground">
            {value.type}::{value.name}
          </code>
        </p>
      ) : null}
    </div>
  );
}
