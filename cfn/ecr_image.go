package cfn

import (
	"regexp"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// An image named the way AWS names an account's private registry (ECR) —
// <account>.dkr.ecr.<region>.amazonaws.com/<repository>[:tag|@digest] — is that account's repository in the
// platform's registry, as on AWS, where a task or function pulls it with its execution role. The node's
// runtime never resolves the AWS name (that would ask AWS's ECR, outside the platform): it is rewritten to the
// platform registry's own name for the same repository (Capabilities.ECRRepositoryHost, the host
// DescribeRepositories' repositoryUri starts with). A member account's repositories are under its account id
// there; the management account's are not.
var ecrImageRe = regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?/(.+)$`)

// ecrImageRef is the image a container pulls for img: img itself when it does not name ECR, else the same
// repository in the platform's registry. refusal is why an ECR image cannot be served here ("" when it can).
func ecrImageRef(img string, ctx *stackCtx) (ref, refusal string) {
	m := ecrImageRe.FindStringSubmatch(img)
	if m == nil {
		return img, ""
	}
	acct, region, rest := m[1], m[2], m[3]
	if ctx != nil && ctx.region() != "" && region != ctx.region() {
		return "", "the image " + img + " names ECR in " + region + "; this platform's registry is " + ctx.region() + "'s"
	}
	host := ""
	if ctx != nil {
		host = ctx.caps.ECRRepositoryHost
	}
	if host == "" {
		return "", "the image " + img + " names an ECR registry, which only the aws-shim front door serves (its registry); deploy through it, or name the image by its repositoryUri"
	}
	if acct == awsidentity.Current().AccountID {
		return host + "/" + rest, ""
	}
	return host + "/" + acct + "/" + rest, ""
}
