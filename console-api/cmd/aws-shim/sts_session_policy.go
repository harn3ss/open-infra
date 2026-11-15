package main

// STS session policies: AssumeRole's (and AssumeRoleWithWebIdentity's) Policy and PolicyArns, as AWS
// takes them. The session may then do only what both the role's own policies and the session policies
// allow — the session policies can narrow a session, never widen it. They are sealed in the session token,
// so the caller can't change them later, and the one evaluator applies them (iamauthz: explicit Denies in
// them deny; otherwise the request must be inside them). Inline and managed session policies together are
// one set: an Allow in any of them counts.

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

// AWS's limits on session policies (sts:AssumeRole).
const (
	maxSessionPolicyChars = 2048
	maxSessionPolicyArns  = 10
)

var policyArnsKey = regexp.MustCompile(`^PolicyArns\.member\.([0-9]+)\.arn$`)

// sessionPolicies reads a request's session policies: the inline document (validated) and the managed
// policies' World names. roleAcct is the account of the role being assumed and roleNS its home namespace
// ("" for the management account): a customer managed policy must be that account's (another account's
// resolves to nothing, so it only narrows); an AWS managed policy is the shipped library's. code and msg are
// AWS's error when the parameters are not valid.
func sessionPolicies(r *http.Request, roleAcct, roleNS string) (doc string, refs []string, code, msg string) {
	doc = r.PostFormValue("Policy")
	if len(doc) > maxSessionPolicyChars {
		return "", nil, "ValidationError", "1 validation error detected: Value at 'policy' failed to satisfy constraint: " +
			"Member must have length less than or equal to " + strconv.Itoa(maxSessionPolicyChars)
	}
	if strings.TrimSpace(doc) != "" {
		if _, _, err := iamauthz.CompileDocument(doc); err != nil {
			return "", nil, "MalformedPolicyDocument", "The session policy is not a valid policy document: " + err.Error()
		}
	} else {
		doc = ""
	}
	type member struct {
		n   int
		arn string
	}
	var arns []member
	for k, vs := range r.PostForm {
		if m := policyArnsKey.FindStringSubmatch(k); m != nil && len(vs) > 0 {
			n, _ := strconv.Atoi(m[1])
			arns = append(arns, member{n, strings.TrimSpace(vs[0])})
		}
	}
	if len(arns) > maxSessionPolicyArns {
		return "", nil, "ValidationError", "1 validation error detected: Value at 'policyArns' failed to satisfy constraint: " +
			"Member must have length less than or equal to " + strconv.Itoa(maxSessionPolicyArns)
	}
	sort.Slice(arns, func(i, j int) bool { return arns[i].n < arns[j].n })
	for _, a := range arns {
		ref, ok := sessionPolicyRef(a.arn, roleAcct, roleNS)
		if !ok {
			return "", nil, "ValidationError", "Invalid ARN in PolicyArns: " + a.arn
		}
		refs = append(refs, ref)
	}
	return doc, refs, "", ""
}

// sessionPolicyRef is the IAM policy world name a managed session policy's ARN refers to. ok=false when
// the value is not a policy ARN. A policy that can't be one of the role's (another account's, an AWS
// managed name the platform doesn't ship) gets a name no policy has, so it contributes nothing.
func sessionPolicyRef(arn, roleAcct, roleNS string) (string, bool) {
	if !strings.HasPrefix(arn, "arn:aws:iam::") || !strings.Contains(arn, ":policy/") {
		return "", false
	}
	if strings.HasPrefix(arn, "arn:aws:iam::aws:policy/") {
		if mp, ok := cfn.ManagedPolicyByARN(arn); ok {
			return mp.ObjectName(), true // the shipped library lives in the IAM home: a bare name
		}
		return "unresolvable:" + arn, true
	}
	if acct := awsidentity.AccountOfARN(arn); acct != "" && acct != roleAcct {
		return "unresolvable:" + arn, true
	}
	name := policyNameFromArn(arn)
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "", false
	}
	return iamauthz.QualifiedName("", roleNS, policyObjectName(name)), true
}
