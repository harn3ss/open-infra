import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Clock,
  FileText,
  FlaskConical,
  Info,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  Users,
  UsersRound,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/common/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/common/copy-button";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { InfoLink } from "@/components/help/info-link";
import { LearnMore } from "@/components/help/learn-more";
import { ErrorState, LoadingState } from "@/components/common/states";
import { StatCard } from "@/features/dashboard/stat-card";
import { useConfig } from "@/lib/config-context";
import { docsUrl } from "@/lib/kind-docs";
import {
  getAccessReview,
  getIamConfig,
  listIamGrants,
  listIamGroups,
  listIamPolicies,
  listIamRoles,
  listIamUsers,
} from "@/lib/api";

/**
 * IAM Dashboard — the landing page for the Security & Identity section, mirroring
 * AWS's "IAM → Dashboard" three-region layout (Security recommendations · IAM
 * resource counts · Account/sign-in facts). The recommendation checklist is
 * open-infra-specific by design: the posture questions differ from AWS's
 * (no root MFA, no access-key age — no account, no root keys), so every item here
 * is derived from live cluster data (Users/Groups/Roles/Policies/Grants + the
 * access review) EXCEPT the clearly-labelled advisories, which are not derivable.
 */

type Severity = "critical" | "warning" | "info";

interface Recommendation {
  id: string;
  title: string;
  /** Severity when `count > 0`. A count of 0 renders as a resolved (green) row. */
  severity: Severity;
  count: number;
  /** What the count means / what to do — shown muted under the title. */
  detail: string;
  /** Copy shown (green) when `count === 0`. */
  okText: string;
  /** Deep link to the surface where the item is fixed. Existing routes only. */
  to: string;
}

const SEV_META: Record<Severity, { icon: typeof Info; tone: string; badge: "destructive" | "warning" | "accent" }> = {
  critical: { icon: ShieldAlert, tone: "text-destructive", badge: "destructive" },
  warning: { icon: AlertTriangle, tone: "text-warning", badge: "warning" },
  info: { icon: Info, tone: "text-primary", badge: "accent" },
};

const SEV_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

function RecommendationRow({ rec }: { rec: Recommendation }) {
  const resolved = rec.count === 0;
  const meta = SEV_META[rec.severity];
  const Icon = resolved ? CheckCircle2 : meta.icon;
  return (
    <div className="flex items-start gap-3 px-4 py-3">
      <Icon className={`mt-0.5 size-4 shrink-0 ${resolved ? "text-success" : meta.tone}`} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground">{rec.title}</span>
          {resolved ? (
            <Badge variant="success">No issues</Badge>
          ) : (
            <Badge variant={meta.badge}>{rec.count}</Badge>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{resolved ? rec.okText : rec.detail}</p>
      </div>
      {!resolved ? (
        <Link
          to={rec.to}
          className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-xs font-medium text-primary hover:underline"
        >
          Review <ArrowRight className="size-3" />
        </Link>
      ) : null}
    </div>
  );
}

export function IamDashboardPage() {
  const config = useConfig();

  const usersQ = useQuery({ queryKey: ["iam", "users"], queryFn: listIamUsers, refetchInterval: 30000 });
  const groupsQ = useQuery({ queryKey: ["iam", "groups"], queryFn: listIamGroups, refetchInterval: 30000 });
  const rolesQ = useQuery({ queryKey: ["iam", "roles"], queryFn: listIamRoles, refetchInterval: 30000 });
  const policiesQ = useQuery({ queryKey: ["iam", "policies"], queryFn: listIamPolicies, refetchInterval: 30000 });
  const grantsQ = useQuery({ queryKey: ["iam", "grants"], queryFn: listIamGrants, refetchInterval: 30000 });
  const configQ = useQuery({ queryKey: ["iam", "config"], queryFn: getIamConfig });
  const reviewQ = useQuery({ queryKey: ["access-review"], queryFn: getAccessReview, refetchInterval: 120000 });

  const users = usersQ.data ?? [];
  const groups = groupsQ.data ?? [];
  const roles = rolesQ.data ?? [];
  const policies = policiesQ.data ?? [];
  const grants = grantsQ.data ?? [];
  const review = reviewQ.data;

  const refetchAll = () => {
    usersQ.refetch();
    groupsQ.refetch();
    rolesQ.refetch();
    policiesQ.refetch();
    grantsQ.refetch();
    reviewQ.refetch();
  };

  // Sub-stats for the resource tiles.
  const enabledUsers = users.filter((u) => !u.disabled).length;
  const inertGroups = groups.filter((g) => !g.impersonable).length;
  const readyPolicies = policies.filter((p) => p.ready).length;
  const activeGrants = grants.filter((g) => g.phase === "Active").length;

  // Recommendations — all derived from live data. Each entry is honest about what
  // it counts; a count of 0 renders green ("No issues"), mirroring AWS's checklist.
  const recommendations = useMemo<Recommendation[]>(() => {
    const recs: Recommendation[] = [];

    if (usersQ.data) {
      const noEffective = users.filter((u) => {
        if (u.disabled) return false;
        const eff = u.groups.filter((g) => !(u.unboundGroups ?? []).includes(g));
        return eff.length === 0;
      }).length;
      recs.push({
        id: "users-no-access",
        title: "Users authorized for nothing",
        severity: "warning",
        count: noEffective,
        detail: `${noEffective} enabled user(s) belong to no group that grants access — they can sign in but are authorized for nothing (fail-closed footgun).`,
        okText: "Every enabled user belongs to at least one effective group.",
        to: "/users",
      });

      const inertMembers = users.filter((u) => (u.unboundGroups ?? []).length > 0).length;
      recs.push({
        id: "users-inert-groups",
        title: "Memberships that grant nothing",
        severity: "warning",
        count: inertMembers,
        detail: `${inertMembers} user(s) are members of a group that is outside the impersonation ceiling — the membership silently confers no access until an operator widens the ceiling.`,
        okText: "No user is a member of an inert group.",
        to: "/users",
      });

      const noPassword = users.filter((u) => u.source === "local" && !u.hasPassword && !u.disabled).length;
      recs.push({
        id: "users-no-password",
        title: "Local users without a sign-in credential",
        severity: "info",
        count: noPassword,
        detail: `${noPassword} enabled local user(s) have no password Secret and cannot sign in. Set a password, or expect them to authenticate via a directory.`,
        okText: "Every enabled local user has a sign-in credential.",
        to: "/users",
      });
    }

    if (groupsQ.data) {
      const inert = groups.filter((g) => !g.impersonable).length;
      recs.push({
        id: "groups-inert",
        title: "Inert groups",
        severity: "warning",
        count: inert,
        detail: `${inert} group(s) map to an "openinfra:<name>" outside the impersonator ClusterRole ceiling — they grant nothing until an operator widens it (this cannot be self-served from the console).`,
        okText: "Every group is within the impersonation ceiling.",
        to: "/groups",
      });
    }

    if (rolesQ.data) {
      const noTrust = roles.filter((r) => Array.isArray(r.trust) && r.trust.length === 0).length;
      recs.push({
        id: "roles-no-trust",
        title: "Roles assumable by no one",
        severity: "info",
        count: noTrust,
        detail: `${noTrust} role(s) have an empty trust policy and can be assumed by no one (fail-closed). Add a trusted principal if the role is meant to be assumable.`,
        okText: "Every role names at least one trusted principal.",
        to: "/roles",
      });
    }

    if (grantsQ.data) {
      const awaiting = grants.filter((g) => g.phase === "AwaitingApproval").length;
      recs.push({
        id: "grants-awaiting",
        title: "Grants awaiting approval",
        severity: "info",
        count: awaiting,
        detail: `${awaiting} temporal access request(s) are awaiting a second-party approval (they confer nothing until a different admin approves).`,
        okText: "No temporal access request is awaiting approval.",
        to: "/grants",
      });

      const active = grants.filter((g) => g.phase === "Active").length;
      recs.push({
        id: "grants-active",
        title: "Standing temporal elevation",
        severity: "info",
        count: active,
        detail: `${active} grant(s) are currently Active — standing elevated access that self-revokes at expiry. Confirm each is still needed.`,
        okText: "No temporal grant is currently active.",
        to: "/grants",
      });

      const notGrantable = grants.filter((g) => g.phase === "NotGrantable").length;
      recs.push({
        id: "grants-notgrantable",
        title: "Grants that cannot bind",
        severity: "warning",
        count: notGrantable,
        detail: `${notGrantable} grant(s) are NotGrantable — the requested role is outside the allowlist or its group is inert, so the grant silently does nothing. Fix or delete them.`,
        okText: "No grant is stuck in a NotGrantable state.",
        to: "/grants",
      });
    }

    if (review) {
      recs.push({
        id: "disabled-retaining",
        title: "Disabled accounts retaining access",
        severity: "critical",
        count: review.summary.disabledRetaining,
        detail: `${review.summary.disabledRetaining} account(s) are disabled yet still bound to standing access. Disabling blocks console sign-in but does not remove group-conferred authority — remove the memberships too.`,
        okText: "No disabled account retains standing access.",
        to: "/access-review",
      });

      if (review.activitySourceReachable) {
        const stale = review.summary.dormant + review.summary.noRecentActivity;
        recs.push({
          id: "stale-access",
          title: "Stale access",
          severity: "warning",
          count: stale,
          detail: `${stale} principal(s) hold standing access but have not been seen in the audit trail recently (dormant ≥ ${review.dormancyDays}d, or no activity in ${review.lookbackDays}d). Right-size or recertify.`,
          okText: "No principal with standing access looks stale.",
          to: "/access-review",
        });
      }

      recs.push({
        id: "privileged",
        title: "Privileged principals",
        severity: "info",
        count: review.summary.privileged,
        detail: `${review.summary.privileged} principal(s) hold console-admin or permissions-management authority. Keep this set small and recertified.`,
        okText: "No principal holds privileged authority.",
        to: "/access-review",
      });
    }

    return recs.sort((a, b) => {
      // Open items first (by severity), resolved (count 0) sink to the bottom.
      const aOpen = a.count > 0 ? 0 : 1;
      const bOpen = b.count > 0 ? 0 : 1;
      if (aOpen !== bOpen) return aOpen - bOpen;
      if (aOpen === 0 && SEV_ORDER[a.severity] !== SEV_ORDER[b.severity]) {
        return SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
      }
      return b.count - a.count;
    });
  }, [usersQ.data, groupsQ.data, rolesQ.data, grantsQ.data, users, groups, roles, grants, review]);

  const openCount = recommendations.filter((r) => r.count > 0).length;
  const anySourceFailed =
    usersQ.isError || groupsQ.isError || rolesQ.isError || policiesQ.isError || grantsQ.isError || reviewQ.isError;
  const consoleUrl = typeof window !== "undefined" ? window.location.origin : "";
  const iamNamespace = review?.consoleNamespace ?? configQ.data?.namespace ?? "—";
  const authModeLabel =
    config.authMode === "none"
      ? "None (unauthenticated)"
      : config.authMode === "local"
        ? "Local (console-managed)"
        : config.authMode.toUpperCase();

  // IAM is admins-only on the BFF; if the roster itself is unreachable (typically a
  // 403 for a non-admin), surface that honestly rather than a half-empty dashboard.
  if (usersQ.isLoading && !usersQ.data) {
    return (
      <div className="space-y-6">
        <PageHeader icon={<ShieldCheck />} title="IAM Dashboard" description="Identity and access posture at a glance." />
        <LoadingState label="Loading IAM posture…" />
      </div>
    );
  }
  if (usersQ.isError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={<ShieldCheck />} title="IAM Dashboard" description="Identity and access posture at a glance." />
        <ErrorState error={usersQ.error} onRetry={() => usersQ.refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ShieldCheck />}
        title="IAM Dashboard"
        description={`Identity and access management for ${config.clusterName || "open-infra"} — posture, resource counts and sign-in facts at a glance.`}
        actions={
          <>
            <InfoLink
              title="IAM Dashboard"
              body={
                <div className="space-y-2 text-sm">
                  <p>
                    The open-infra IAM home mirrors AWS's IAM dashboard layout — security recommendations, resource
                    counts, and sign-in facts — but the recommendation checklist is ours: the posture questions differ
                    from AWS's.
                  </p>
                  <p>
                    Every recommendation here is computed live from your Users, Groups, Roles, Policies, Grants and the
                    access review. AWS's root-MFA and access-key-age nudges have no equivalent — there is no 12-digit
                    account, no root access keys, and MFA (when used) is the identity provider's job. Those appear as
                    labelled advisories, not fabricated checks.
                  </p>
                </div>
              }
              docsHref={docsUrl("iam.md")}
            />
            <Button variant="outline" onClick={refetchAll}>
              <RefreshCw className="size-4" /> Refresh
            </Button>
          </>
        }
      />

      {anySourceFailed ? (
        <Card className="border-warning/40 bg-warning/10">
          <CardContent className="flex items-start gap-2 p-4 text-sm">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
            <span>
              <span className="font-medium text-foreground">Some sources were unavailable.</span> One or more IAM lists
              (or the access review) failed to load this run, so the counts and recommendations below may be incomplete.
            </span>
          </CardContent>
        </Card>
      ) : null}

      {/* Resource counts — each tile links to its list. */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-5">
        <StatCard
          label="Users"
          value={users.length}
          sub={`${enabledUsers} enabled`}
          icon={Users}
          to="/users"
          loading={usersQ.isLoading}
          error={usersQ.isError}
          accent="primary"
        />
        <StatCard
          label="Groups"
          value={groups.length}
          sub={inertGroups > 0 ? `${inertGroups} inert` : "all effective"}
          icon={UsersRound}
          to="/groups"
          loading={groupsQ.isLoading}
          error={groupsQ.isError}
          accent="accent"
        />
        <StatCard
          label="Roles"
          value={roles.length}
          icon={ShieldCheck}
          to="/roles"
          loading={rolesQ.isLoading}
          error={rolesQ.isError}
          accent="primary"
        />
        <StatCard
          label="Policies"
          value={policies.length}
          sub={`${readyPolicies} ready`}
          icon={FileText}
          to="/policies"
          loading={policiesQ.isLoading}
          error={policiesQ.isError}
          accent="success"
        />
        <StatCard
          label="Grants"
          value={grants.length}
          sub={activeGrants > 0 ? `${activeGrants} active` : "none active"}
          icon={Clock}
          to="/grants"
          loading={grantsQ.isLoading}
          error={grantsQ.isError}
          accent="warning"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Security recommendations (spans two columns on wide viewports). */}
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold">Security recommendations</h2>
            </div>
            <Badge variant={openCount > 0 ? "warning" : "success"}>
              {openCount > 0 ? `${openCount} to review` : "All clear"}
            </Badge>
          </div>
          <CardContent className="p-0">
            {recommendations.length === 0 ? (
              <p className="px-4 py-6 text-center text-sm text-muted-foreground">
                Recommendations appear once IAM data has loaded.
              </p>
            ) : (
              <div className="divide-y divide-border">
                {recommendations.map((rec) => (
                  <RecommendationRow key={rec.id} rec={rec} />
                ))}
              </div>
            )}
          </CardContent>
          {/* Advisories — NOT derivable from data; shown so the posture picture is honest. */}
          <div className="border-t border-border bg-muted/30 px-4 py-3">
            <p className="text-xs font-medium text-muted-foreground">Advisories (not derivable from data)</p>
            <ul className="mt-1.5 space-y-1.5 text-xs text-muted-foreground">
              <li className="flex items-start gap-2">
                <KeyRound className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  <span className="font-medium text-foreground">Break-glass root.</span> The recovery account lives in a
                  Secret, not as a <code className="rounded bg-muted px-1">kind: User</code>, and never appears in the
                  Users list. Its last-used and MFA are not tracked here — keep its credentials offline and rotate them
                  manually.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Info className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  <span className="font-medium text-foreground">MFA.</span> Multi-factor is not implemented in the
                  console sign-in path; when <code className="rounded bg-muted px-1">source=oidc</code>, MFA is the
                  identity provider's responsibility.
                </span>
              </li>
            </ul>
          </div>
        </Card>

        {/* Access & sign-in facts. */}
        <Card>
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <ShieldCheck className="size-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold">Access &amp; sign-in</h2>
          </div>
          <CardContent className="space-y-4 p-4">
            <KeyValuePairs
              columns={1}
              items={[
                {
                  label: "Console sign-in URL",
                  value: consoleUrl ? (
                    <span className="inline-flex items-center gap-1 break-all">
                      {consoleUrl}
                      <CopyButton value={consoleUrl} label="Copy console URL" />
                    </span>
                  ) : (
                    "—"
                  ),
                },
                { label: "Authentication mode", value: authModeLabel },
                { label: "Cluster", value: config.clusterName || "—" },
                {
                  label: "IAM namespace",
                  value: <code className="rounded bg-muted px-1 py-0.5 text-xs">{iamNamespace}</code>,
                },
                { label: "Break-glass root", value: "Enabled (out-of-band recovery)" },
              ]}
            />
            <div className="space-y-2 border-t border-border pt-3">
              <p className="text-xs font-medium text-muted-foreground">Quick actions</p>
              <div className="flex flex-col gap-1.5">
                <Link
                  to="/users/new"
                  className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                >
                  <UserPlus className="size-4" /> Create user
                </Link>
                <Link
                  to="/policies/new"
                  className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                >
                  <FileText className="size-4" /> Create policy
                </Link>
                <Link
                  to="/roles/new"
                  className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                >
                  <ShieldCheck className="size-4" /> Create role
                </Link>
                <Link
                  to="/policy-simulator"
                  className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                >
                  <FlaskConical className="size-4" /> Policy simulator
                </Link>
                <Link
                  to="/access-review"
                  className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                >
                  <ClipboardCheck className="size-4" /> Access review
                </Link>
              </div>
            </div>
            <div className="border-t border-border pt-3">
              <LearnMore href={docsUrl("iam.md")}>IAM documentation</LearnMore>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
