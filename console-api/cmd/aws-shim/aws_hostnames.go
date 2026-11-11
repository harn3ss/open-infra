package main

import (
	"net/http"
	"regexp"
	"strings"
)

// AWS's own hostnames arriving at this shim. A VM guest's resolver (platform/aws-shim/guest-aws-endpoints.yaml)
// answers the amazonaws.com names of the services this shim serves with the shim's address, so a URL a guest
// carries from its AWS-side configuration — a queue URL, a bucket's virtual-hosted URL, an SDK that ignores
// AWS_ENDPOINT_URL — reaches the shim instead of AWS. The shim serves those names on its AWS-names TLS
// listener with a certificate only guests trust (TLS_CERT_FILE, from the openinfra-aws-endpoints CA).

// awsSQSHostRe matches SQS's hostnames: sqs.<region>.amazonaws.com and the legacy <region>.queue.amazonaws.com /
// queue.amazonaws.com.
var awsSQSHostRe = regexp.MustCompile(`^(?:sqs\.[a-z0-9-]+|(?:[a-z0-9-]+\.)?queue)\.amazonaws\.com$`)

// awsSQSHost reports whether the request came in by an SQS hostname of AWS's.
func awsSQSHost(r *http.Request) bool {
	return r != nil && awsSQSHostRe.MatchString(hostNoPort(r.Host))
}

// awsCloudFormationHostRe matches CloudFormation's hostname, cloudformation.<region>.amazonaws.com.
var awsCloudFormationHostRe = regexp.MustCompile(`^cloudformation\.[a-z0-9-]+\.amazonaws\.com$`)

// awsCloudFormationHost reports whether the request came in by AWS's CloudFormation hostname (a VM guest).
func awsCloudFormationHost(r *http.Request) bool {
	return r != nil && awsCloudFormationHostRe.MatchString(hostNoPort(r.Host))
}

// splitSuffixes merges comma-separated host-suffix lists (empty entries dropped, duplicates kept once).
func splitSuffixes(lists ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, s := range splitCommaTrim(l) {
			s = strings.ToLower(strings.Trim(s, "."))
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// awsNameRules are AWS's own hostnames the platform answers for its functions and VM guests, in order, as the
// guest and function resolvers' Corefiles have them (platform/aws-shim/guest-aws-endpoints.yaml and
// function-aws-endpoints.yaml; a test holds the three equal). A name matching one resolves as its target: the
// aws-shim, or the registry that serves ECR's names. The VPC resolver applies them for functions in a VPC.
var awsNameRules = []awsNameRule{
	{regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.aws-shim\.open-infra-aws-shim\.svc(\.cluster\.local)?\.$`), awsShimTarget},
	{regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z]{2}(-gov)?-[a-z]+-[0-9]+\.amazonaws\.com\.$`), "ecr-registry-aws.open-infra-ecr.svc.cluster.local."},
	{regexp.MustCompile(`^(acm|api\.ecr|athena|apigateway|appsync|cloudformation|cognito-idp|dynamodb|ec2|ecr|ecs|eks|email|events|glue|kinesis|kms|lambda|logs|monitoring|organizations|rds|route53resolver|s3|secretsmanager|servicequotas|sns|sqs|ssm|states|streams\.dynamodb|sts|sync-states)\.[a-z]{2}(-gov)?-[a-z]+-[0-9]+\.amazonaws\.com\.$`), awsShimTarget},
	{regexp.MustCompile(`^[a-z0-9]+\.(execute-api|appsync-api)\.[a-z]{2}(-gov)?-[a-z]+-[0-9]+\.amazonaws\.com\.$`), awsShimTarget},
	{regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(\.[a-z]{2}(-gov)?-[a-z]+-[0-9]+)?\.amazonaws\.com\.$`), awsShimTarget},
	{regexp.MustCompile(`^(sts|iam|cloudfront|s3|queue|[a-z]{2}(-gov)?-[a-z]+-[0-9]+\.queue)\.amazonaws\.com\.$`), awsShimTarget},
}

// awsShimTarget is the aws-shim's own name, the target of the names of the services it serves.
const awsShimTarget = "aws-shim.open-infra-aws-shim.svc.cluster.local."

type awsNameRule struct {
	re     *regexp.Regexp
	target string
}

// awsNameTarget is what an AWS hostname resolves as on this platform: its rule's target; or, for any other
// amazonaws.com name (a service the platform does not serve), sinkhole: answered NXDOMAIN, never sent to AWS.
// A name that is neither returns "", false.
func awsNameTarget(name string) (target string, sinkhole bool) {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	for _, r := range awsNameRules {
		if r.re.MatchString(n) {
			return r.target, false
		}
	}
	return "", n == "amazonaws.com." || strings.HasSuffix(n, ".amazonaws.com.")
}
