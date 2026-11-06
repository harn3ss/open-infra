// Each account's AppSync APIs.
//
// On AWS a GraphQL API belongs to the account that made it: its apiId is found, read, changed and listed in
// that account alone, and its ARN names the account. Here an API is a kind: GraphQLApi claim, and a claim
// belongs to the account of its namespace (the accounts directory): the management plane reaches an API
// only in a namespace of the caller's account — any other is not found — ListGraphqlApis lists the
// caller's account's APIs alone, and an API's ARN names its account. A bare apiId ("<name>") names an API
// in the default namespace for the management account, as before accounts, and in its home for a member
// account. The management account keeps every namespace that is not a member account's.
//
// The GraphQL data plane is the platform's one open-appsync engine, which is the management account's: a
// member account's principal is decided there as across accounts, as before (appsync.go).
package main

import (
	"context"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

func init() { accountScopedServices["appsync"] = true }

// appsyncAccounts is what the AppSync door needs of the account directory (internal/accounts.Directory).
type appsyncAccounts interface {
	// AccountOf is the account namespace ns belongs to ("" for a platform namespace).
	AccountOf(ns string) string
}

// ownsNamespace reports whether namespace ns belongs to the caller's account: for a member account a
// namespace the directory places in it (without a directory, its home alone); for the management account
// every namespace that is not a member account's.
func (h *appsyncHandler) ownsNamespace(ctx context.Context, ns string) bool {
	if ns == "" {
		return false
	}
	var owner string
	if h.accounts != nil {
		owner = h.accounts.AccountOf(ns)
	}
	if !isMemberRequest(ctx) {
		return awsidentity.Current().IsManagement(owner) // "" (no directory, a platform namespace) included
	}
	if h.accounts == nil {
		home, _ := ctx.Value(accountHomeKey{}).(string)
		return ns == home
	}
	return owner == callerAccount(ctx)
}

// apiAccount is the account the caller's account's APIs belong to: the member account's id, the
// install's configured one for the management account.
func (h *appsyncHandler) apiAccount(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// inCallerAccount places a parsed management request's API in the caller's account: a member account's
// bare apiId names an API in its home (the management account's stays in the default namespace).
func inCallerAccount(ctx context.Context, p mgmtParams) mgmtParams {
	if isMemberRequest(ctx) && p.apiID != "" && !strings.Contains(p.apiID, ".") {
		p.ns = accountNamespace(ctx, p.ns)
	}
	return p
}
