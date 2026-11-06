// Each account's ECR registry.
//
// On AWS every account has its own private registry (<account>.dkr.ecr.<region>.amazonaws.com): a
// repository name is unique within it, its ARN and registryId name the account, and no other account sees
// it (cross-account pulls need a repository policy, which this door does not serve). Here one backing
// registry holds every account's images, so a member account's registry is a path prefix in it: its
// repository <name> lives at the registry path "<account>/<name>", and its repositoryUri is
// <proxyEndpoint>/<account>/<name>. The management account's registry is the registry's root, exactly as
// before accounts: its repository records, registry paths, URIs and ARNs do not change.
//
// So that the management account's root never reaches into a member account's registry, a name whose
// first segment is a 12-digit account id other than the management account's own
// (ecrMemberRegistryName) is left to that account's registry: the management account cannot create such a
// repository, finds and lists none, and is granted no docker scope on such a path.
//
// The repository records (ecr_store.go) stay in the door's namespace, written by the shim's own
// ServiceAccount, keyed by the account key (accountKey); the per-repository registry tokens (/ecr/token)
// translate a docker scope's registry path back to the caller's account's repository before authorizing,
// and grant it on the registry path itself.
package main

import (
	"context"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

func init() { accountScopedServices["ecr"] = true }

// ecrMemberRegistryRe matches a registry path inside a member account's registry ("<12-digit account>/…").
var ecrMemberRegistryRe = regexp.MustCompile(`^[0-9]{12}/.`)

// ecrMemberRegistryName reports whether name (a registry path, or a management account's repository
// name) lies in a member account's registry: its first segment is a 12-digit account id other than the
// management account's own.
func ecrMemberRegistryName(name string) bool {
	return ecrMemberRegistryRe.MatchString(name) && !awsidentity.Current().IsManagement(name[:12])
}

// ecrRecordAccount is the account a repository record of the caller's account carries: the member
// account's id, "" for the management account's (as every record was before accounts).
func ecrRecordAccount(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return ""
}

// registryID is the caller's account's registryId (the account id; the install's configured one for the
// management account).
func (h *ecrHandler) registryID(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// registryPath is where the caller's account's repository name lives in the backing registry: the name
// itself for the management account, "<account>/<name>" in a member account's registry.
func registryPath(ctx context.Context, name string) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx) + "/" + name
	}
	return name
}

// repoOfRegistryPath is registryPath's inverse for the caller's account: the repository a docker scope's
// registry path names, and whether the path is in the caller's account's registry at all (a member
// account's path is under its own prefix; the management account's is any path outside every member
// account's registry).
func repoOfRegistryPath(ctx context.Context, path string) (string, bool) {
	if isMemberRequest(ctx) {
		prefix := callerAccount(ctx) + "/"
		if len(path) > len(prefix) && strings.HasPrefix(path, prefix) {
			return path[len(prefix):], true
		}
		return "", false
	}
	if ecrMemberRegistryName(path) {
		return "", false
	}
	return path, true
}
