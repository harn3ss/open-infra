package main

import (
	"context"
	"regexp"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// Account-scoped front doors keep each account's resources apart, AWS's model: a resource belongs to the
// account that made it, its name is unique within that account, and its ARN names that account. The
// management account's resources stay exactly where they always were — the same namespaces, the same store
// keys, the same ARNs — so a door becomes account-scoped with nothing to migrate; a member account's are
// kept beside them under the member account's own namespace or key. The router marks a request served by
// such a door (accountScopedServices, inAccountScope), and decide then decides a member account's principal
// on its own account's resources.

// callerAccount is the account the request acts in: the member account the router put on the request
// (awsidentity.WithIdentity), else the install's own, the management account.
func callerAccount(ctx context.Context) string { return awsidentity.FromContext(ctx).AccountID }

// isMemberRequest reports whether the request acts in a member account.
func isMemberRequest(ctx context.Context) bool {
	return !awsidentity.Current().IsManagement(callerAccount(ctx))
}

// accountNamespace is the namespace a door keeps the caller's account's Kubernetes objects in: the door's
// own namespace (managementNS) for the management account, the member account's home for a member's.
func accountNamespace(ctx context.Context, managementNS string) string {
	if !isMemberRequest(ctx) {
		return managementNS
	}
	if home, _ := ctx.Value(accountHomeKey{}).(string); home != "" {
		return home
	}
	return managementNS + "\x00no-home" // never a namespace: a member request without a home reaches nothing
}

// accountKey is the store key of a resource of the caller's account: its name in the management account
// (where every resource always was), "<account>:<name>" in a member account. ":" appears in no AWS
// resource name a door keys by (queue, topic, table, parameter, secret, function, stream names), so a
// member account's key can never equal the management account's, nor another member's.
func accountKey(ctx context.Context, name string) string {
	if !isMemberRequest(ctx) {
		return name
	}
	return callerAccount(ctx) + ":" + name
}

// nameOfAccountKey is accountKey's inverse for the caller's account: the resource's name, and whether key
// is the caller's account's at all (a listing skips every other account's keys).
func nameOfAccountKey(ctx context.Context, key string) (string, bool) {
	if !isMemberRequest(ctx) {
		if memberKeyRe.MatchString(key) {
			return "", false // a member account's key, not the management account's
		}
		return key, true
	}
	prefix := callerAccount(ctx) + ":"
	if len(key) > len(prefix) && key[:len(prefix)] == prefix {
		return key[len(prefix):], true
	}
	return "", false
}

// memberKeyRe matches a member account's store key ("<12-digit account>:<name>").
var memberKeyRe = regexp.MustCompile(`^[0-9]{12}:.`)
