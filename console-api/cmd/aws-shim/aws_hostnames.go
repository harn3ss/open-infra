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
