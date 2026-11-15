package main

// CloudFormation service roles (RoleARN), as AWS has them. A stack operation given a RoleARN acts as that
// role, not the caller: the stack's resources are created, changed and deleted with exactly what the role
// is allowed, whatever the caller is allowed. Passing the role takes iam:PassRole on it
// (iam:PassedToService cloudformation.amazonaws.com), and the role must trust CloudFormation
// (cloudformation.amazonaws.com) or CloudFormation can't use it. The role then stays with the stack: a later
// update, delete or change set that names none acts as it too (without iam:PassRole, as AWS lets any caller
// allowed the operation use the stack's role), and DescribeStacks shows it. A change set records the role
// passed to CreateChangeSet, which ExecuteChangeSet then acts as.
//
// The caller is still decided for the operation itself (cloudformation:<Action> on the stack) before
// anything acts as the role.

import (
	"context"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const cfnServicePrincipal = "cloudformation.amazonaws.com"

// cfnServiceRoleSession is the session name CloudFormation's role session carries (assumed-role/<role>/<it>).
const cfnServiceRoleSession = "AWSCloudFormation"

// serviceRoleActions are the operations that act on a stack's resources, and so as its service role.
var serviceRoleActions = map[string]bool{
	"CreateStack": true, "UpdateStack": true, "DeleteStack": true, "CreateChangeSet": true, "ExecuteChangeSet": true,
}

// cfnRoleErr is an AWS error a service role refuses an operation with.
type cfnRoleErr struct {
	status        int
	code, message string
}

// serviceRoleOf is the role an operation acts as: the RoleARN it passes, else — for an operation on an
// existing stack — the change set's (ExecuteChangeSet) or the stack's. passed reports whether the request
// named it.
func (h *cfnDoorway) serviceRoleOf(ctx context.Context, r *http.Request, action string) (arn string, passed bool) {
	if v := strings.TrimSpace(r.PostFormValue("RoleARN")); v != "" {
		return v, true
	}
	stack := r.PostFormValue("StackName")
	switch action {
	case "ExecuteChangeSet":
		if cs, err := h.getChangeSet(ctx, stack, r.PostFormValue("ChangeSetName")); err == nil && cs.RoleARN != "" {
			return cs.RoleARN, false
		}
	case "UpdateStack", "DeleteStack":
	default:
		return "", false // a create has no stack yet; a change set not given one is created as the caller
	}
	if rec, ok, err := h.getRecord(ctx, stack); err == nil && ok {
		return rec.RoleARN, false
	}
	return "", false
}

// serviceRoleApplier is the applier an operation acts with when it has a service role (nil when it has
// none): the role's identity, after iam:PassRole (when the request passes the role) and the role's trust
// of CloudFormation are checked.
func (h *cfnDoorway) serviceRoleApplier(ctx context.Context, r *http.Request, claims iam.Claims, action string) (*impersonatingApplier, *cfnRoleErr) {
	if !serviceRoleActions[action] {
		return nil, nil
	}
	arn, passed := h.serviceRoleOf(ctx, r, action)
	if arn == "" {
		return nil, nil
	}
	invalid := &cfnRoleErr{http.StatusBadRequest, "ValidationError", "Role " + arn + " is invalid or cannot be assumed"}
	roleName := roleNameFromArn(arn)
	if roleName == "" || !strings.Contains(arn, ":role/") {
		return nil, invalid
	}
	// A role of the caller's own account: CloudFormation never passes another account's role.
	acct := callerAccount(ctx)
	if !isMemberRequest(ctx) {
		acct = h.account
	}
	if a := awsidentity.AccountOfARN(arn); a != "" && a != acct {
		return nil, &cfnRoleErr{http.StatusForbidden, "AccessDenied", "Cross-account pass role is not allowed."}
	}
	if h.roles == nil {
		return nil, invalid
	}
	home := h.rolesNS
	if home == "" {
		home = dataplaneauthz.DefaultHomeNamespace
	}
	roleNS := "" // where the role is: the management account's IAM home, or a member account's home
	var role resolvedRole
	var ok bool
	if isMemberRequest(ctx) {
		in, can := h.roles.(roleResolverIn)
		if !can || accountHomeOf(ctx) == "" {
			return nil, invalid
		}
		roleNS = accountHomeOf(ctx)
		role, ok = in.ResolveIn(ctx, roleNS, roleName)
	} else {
		role, ok = h.roles.Resolve(ctx, roleName)
	}
	if !ok {
		return nil, invalid
	}
	if passed {
		passNS := home
		if roleNS != "" {
			passNS = roleNS
		}
		if ok, reason := callerMayPassRole(ctx, h.cs, h.authz, claims, passNS, roleName, cfnServicePrincipal, r); !ok {
			return nil, &cfnRoleErr{http.StatusForbidden, "AccessDenied", reason}
		}
	}
	// CloudFormation can use the role only when the role trusts it (and with no condition the service would
	// have to meet, which is not evaluated for it: fail closed).
	if !trustsService(role.trust, cfnServicePrincipal) || trustConditioned(role.trustDoc) {
		return nil, invalid
	}
	rc := iam.Claims{
		Sub:         "assumed-role/" + roleName + "/" + cfnServiceRoleSession,
		Groups:      role.groups,
		AssumedRole: dataplaneauthz.QualifiedName(home, roleNS, strings.ToLower(roleName)),
		Account:     claims.Account,
	}
	ap, err := h.applierForIn(ctx, rc)
	if err != nil {
		return nil, invalid
	}
	ap.serviceRole = arn
	return ap, nil
}
