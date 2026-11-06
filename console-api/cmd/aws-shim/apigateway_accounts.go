// API Gateway keeps each account's APIs apart, as AWS does. A REST API (v1) or an HTTP API (v2), an API
// key and a usage plan record the account they belong to ("" for the management account: every one made
// before accounts, and every one it makes, so nothing migrates). Their ids are random and global, so the
// id stays the key; an operation reaches the caller's account's alone, another account's id is, as on
// AWS, one that does not exist, and a listing lists the caller's account's.
//
// The invoke URL is unsigned: an invoke acts in the account of the API it reaches, taken from the API's
// row — its Lambda integration's function is found among that account's functions, the proxy event's
// requestContext.accountId is that account, an API key unlocks it only when the key and its usage plan
// are that account's, and a Cognito authorizer admits only tokens of that account's user pools.
package main

import (
	"context"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// REST v1 and HTTP v2 share the "apigateway" signing name, and both keep each account's APIs apart.
func init() { accountScopedServices["apigateway"] = true }

// apigwAccount is the account the request's APIs, API keys and usage plans are recorded under: "" for the
// management account (where every one always was), the member account's id for a member's.
func apigwAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return ""
	}
	return callerAccount(ctx)
}

// inAPIAccount is the context an invoke of an API of account ("" the management account) acts in: that
// account's identity and home, as the router gives a signed request of the account. An invoke is unsigned,
// so the account is always the API's own.
func inAPIAccount(ctx context.Context, account string, homeOf func(string) (string, bool)) context.Context {
	if account == "" {
		return ctx
	}
	home := ""
	if homeOf != nil {
		home, _ = homeOf(account)
	}
	return withAccount(ctx, account, home)
}

// fnAccountOfURI is the account a Lambda integration URI's function ARN names — arn:aws:lambda:<region>:
// <account>:function:<name>, alone or inside API Gateway's integration ARN (…/functions/<function ARN>/
// invocations), or a partial ARN <account>:function:<name>; "" for a bare name or one carrying no 12-digit
// account.
func fnAccountOfURI(uri string) string {
	i := strings.Index(uri, ":function:")
	if i < 0 {
		return ""
	}
	acct := uri[:i]
	if j := strings.LastIndexByte(acct, ':'); j >= 0 {
		acct = acct[j+1:]
	}
	if len(acct) == 12 && strings.Trim(acct, "0123456789") == "" {
		return acct
	}
	return ""
}

// fnOfAnotherAccount reports whether a Lambda integration URI names a function of an account other than
// the one ctx acts in, and that function's ARN. An API reaches its own account's functions: another
// account's needs that function's resource-based policy to allow API Gateway (Lambda AddPermission), and
// a Function here has none — so it is refused, as the Lambda front door refuses it, and the function of
// the same name in the API's own account is never taken for it. The management account's API is refused
// only a function ARN naming a member account the directory knows: an ARN carrying any other account (one
// kept from before accounts, or from the estate a stack came from) names the management account's
// function, by name, as it always has.
func fnOfAnotherAccount(ctx context.Context, fns *fnLocator, uri string) (string, bool) {
	acct := fnAccountOfURI(uri)
	if acct == "" || acct == callerAccount(ctx) {
		return "", false
	}
	if !isMemberRequest(ctx) && !fns.memberAccount(acct) {
		return "", false
	}
	return "arn:aws:lambda:" + awsidentity.FromContext(ctx).Region + ":" + acct + ":function:" + functionFromURI(uri), true
}

// crossAccountFnReason is the refusal of integrating another account's function (fnOfAnotherAccount):
// AWS's message for an invoke no resource-based policy allows.
func crossAccountFnReason(ctx context.Context, claims iam.Claims, fnARN string) string {
	return notAuthorized(principalOf(ctx, claims), "lambda:InvokeFunction", fnARN, "") +
		" because no resource-based policy allows the lambda:InvokeFunction action"
}

// userPoolOf is the Cognito user pool id a COGNITO_USER_POOLS provider names: a pool ARN's
// (…:userpool/<id>), else an issuer URL's last path segment (the shim's own pools' issuers end in the
// pool id); "" for neither.
func userPoolOf(provider string) string {
	if i := strings.Index(provider, "userpool/"); i >= 0 && strings.HasPrefix(provider, "arn:") {
		return provider[i+len("userpool/"):]
	}
	if strings.HasPrefix(provider, "https://") || strings.HasPrefix(provider, "http://") {
		u := strings.TrimRight(provider, "/")
		if i := strings.LastIndexByte(u, '/'); i >= 0 && i > strings.Index(u, "://")+2 {
			return u[i+1:]
		}
	}
	return ""
}

// poolOfAnotherAccount reports whether one of providers (an authorizer's providerARNs, or the issuer they
// resolved to) names a user pool the shim keeps for an account other than the one ctx acts in, and which.
// Such a pool's tokens never authorize this account's API. Without the user-pool store there is no pool
// of the shim's to name.
func (h *apigwV1Handler) poolOfAnotherAccount(ctx context.Context, providers ...string) (string, bool, error) {
	if h.pools == nil {
		return "", false, nil
	}
	seen := map[string]bool{}
	for _, p := range providers {
		id := userPoolOf(p)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		pool, found, err := h.pools.getPool(ctx, id)
		if err != nil {
			return "", false, err
		}
		if found && pool.Account != apigwAccount(ctx) {
			return id, true, nil
		}
	}
	return "", false, nil
}
