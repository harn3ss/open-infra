// Package awserr turns the Kubernetes and Crossplane errors the platform runs into into the errors an AWS
// user expects: an AWS error code and a message that names the AWS resource and says what went wrong,
// never "forbidden: User … cannot create resource … in API group …", an admission webhook's name or a
// composition pipeline's template position. The platform's own messages (validation text the shim and
// the console write themselves) pass through unchanged, so Clean is safe on any error message.
//
// Callers keep the original text in their logs; only what a user is shown is rewritten.
package awserr

import (
	"net/http"
	"regexp"
	"strings"
)

// Code is the AWS error code for a Kubernetes API failure, from its HTTP status and Status reason (the
// metav1.StatusReason, e.g. "Forbidden", "AlreadyExists", "Invalid"). message is the original Status
// message: an admission webhook's denial is a validation failure, not an authorization one, whichever
// status the webhook chose.
func Code(httpStatus int, reason, message string) string {
	if isAdmissionDenial(message) && !isAuthzDenial(message) {
		return "ValidationException"
	}
	switch reason {
	case "Forbidden":
		return "AccessDeniedException"
	case "NotFound":
		return "ResourceNotFoundException"
	case "AlreadyExists":
		return "ResourceAlreadyExistsException"
	case "Conflict":
		return "ConflictException"
	case "Invalid", "BadRequest":
		return "ValidationException"
	case "TooManyRequests":
		return "ThrottlingException"
	case "Unauthorized":
		return "UnrecognizedClientException"
	case "Timeout", "ServerTimeout":
		return "RequestTimeoutException"
	case "ServiceUnavailable":
		return "ServiceUnavailableException"
	case "Gone", "Expired":
		return "ExpiredIteratorException"
	case "MethodNotAllowed", "NotAcceptable", "UnsupportedMediaType":
		return "ValidationException"
	}
	switch {
	case httpStatus == http.StatusForbidden:
		return "AccessDeniedException"
	case httpStatus == http.StatusNotFound:
		return "ResourceNotFoundException"
	case httpStatus == http.StatusConflict:
		return "ConflictException"
	case httpStatus == http.StatusUnauthorized:
		return "UnrecognizedClientException"
	case httpStatus == http.StatusTooManyRequests:
		return "ThrottlingException"
	case httpStatus == http.StatusServiceUnavailable, httpStatus == http.StatusBadGateway:
		return "ServiceUnavailableException"
	case httpStatus == http.StatusGatewayTimeout:
		return "RequestTimeoutException"
	case httpStatus >= 400 && httpStatus < 500:
		return "ValidationException"
	}
	return "InternalFailure"
}

var (
	// `admission webhook "x.y" denied the request: <reason>` (any webhook: Kyverno, a validating policy,
	// the platform's own). Kyverno's reason itself starts with a policy report preamble.
	reAdmission = regexp.MustCompile(`(?s)admission webhook "[^"]*" denied the request:\s*`)
	// Kyverno: `resource <Kind>/<ns>/<name> was blocked due to the following policies\n\n<policy>:\n  <rule>: <message>`
	reKyvernoBlocked = regexp.MustCompile(`(?s)resource \S+ was blocked due to the following policies\s*`)
	reKyvernoRule    = regexp.MustCompile(`(?m)^\s{2,}[\w.-]+:\s*'?(.+?)'?\s*$`)
	// A ValidatingAdmissionPolicy: `<resource> "<name>" is forbidden: ValidatingAdmissionPolicy '<p>' with binding '<b>' denied request: <reason>`
	reVAP = regexp.MustCompile(`(?s)ValidatingAdmissionPolicy '[^']*' with binding '[^']*' denied request:\s*`)
	// RBAC / authorization webhook: `<resource>.<group> "<name>" is forbidden: User "<u>" cannot <verb> resource "<r>"[ in API group "<g>"][ in the namespace "<ns>"][: <why>]`
	reForbidden = regexp.MustCompile(`^(?:(\S+?)(?: "([^"]*)")? is )?forbidden: User "([^"]*)" cannot (\w+) resource "([^"]+)"(?: in API group "[^"]*")?(?: in the namespace "[^"]*")?(?: at the cluster scope)?(?::\s*(.*))?$`)
	// `<resource>.<group> "<name>" is invalid: <causes>` — causes are `<field>: <Type>[: <value>][: <msg>]`, comma-joined (bracketed when several).
	reInvalid    = regexp.MustCompile(`(?s)^(\S+?) "([^"]*)" is invalid:\s*(.*)$`)
	reCauseStart = regexp.MustCompile(`(?:^|, )([\w.\[\]-]+): (Invalid value|Required value|Unsupported value|Forbidden|Duplicate value|Too long|Too many|Not found)`)
	reCauseValue = regexp.MustCompile(`^: (?:"(?:[^"\\]|\\.)*"|[^:"]*?)(?::|$)`)
	// `<resource>.<group> "<name>" not found` / `already exists`
	reNotFound = regexp.MustCompile(`^(\S+?) "([^"]*)" not found$`)
	reExists   = regexp.MustCompile(`^(\S+?) "([^"]*)" already exists$`)
	// `Operation cannot be fulfilled on <resource>.<group> "<name>": the object has been modified; …`
	reConflict = regexp.MustCompile(`^Operation cannot be fulfilled on (\S+?) "([^"]*)": (.*)$`)
	// Crossplane's composition pipeline: `cannot compose resources: pipeline step "x" returned a fatal result: … error calling fail: <msg>`
	reFailCall = regexp.MustCompile(`(?s)error calling fail:\s*(.*)$`)
	reCompose  = regexp.MustCompile(`(?s)^(?:cannot compose resources|cannot render composed resource|cannot run composition function pipeline|cannot apply composed resource)[^:]*:\s*`)
	// A webhook or aggregated API the request needed could not be reached.
	reUnreachable = regexp.MustCompile(`(?i)failed calling webhook|connection refused|no endpoints available for service|context deadline exceeded|the server is currently unable to handle the request|i/o timeout`)
)

// Clean rewrites a Kubernetes- or Crossplane-shaped error message into AWS-shaped text. A message that is
// not one of those shapes is returned unchanged.
func Clean(msg string) string {
	m := strings.TrimSpace(msg)
	if m == "" {
		return msg
	}
	if reUnreachable.MatchString(m) && !isAdmissionDenial(m) {
		return "The service is temporarily unavailable. Try again shortly."
	}
	if loc := reVAP.FindStringIndex(m); loc != nil {
		return Clean(strings.TrimSpace(m[loc[1]:]))
	}
	if loc := reAdmission.FindStringIndex(m); loc != nil {
		return cleanAdmission(strings.TrimSpace(m[loc[1]:]))
	}
	if sm := reForbidden.FindStringSubmatch(m); sm != nil {
		res, name, user, verb, plural, why := sm[1], sm[2], sm[3], sm[4], sm[5], sm[6]
		if res == "" {
			res = plural
		}
		out := "User: " + principal(user) + " is not authorized to perform: " + verb + " on resource: " + resourceRef(res, name)
		if w := strings.TrimSpace(why); w != "" {
			out += " (" + strings.TrimSuffix(w, ".") + ")"
		}
		return out
	}
	if sm := reInvalid.FindStringSubmatch(m); sm != nil {
		return "Invalid " + resourceRef(sm[1], sm[2]) + ": " + invalidCauses(sm[3])
	}
	if sm := reNotFound.FindStringSubmatch(m); sm != nil {
		return resourceRef(sm[1], sm[2]) + " was not found"
	}
	if sm := reExists.FindStringSubmatch(m); sm != nil {
		return resourceRef(sm[1], sm[2]) + " already exists"
	}
	if sm := reConflict.FindStringSubmatch(m); sm != nil {
		return resourceRef(sm[1], sm[2]) + " was changed by another request. Reload it and try again."
	}
	if sm := reFailCall.FindStringSubmatch(m); sm != nil {
		return strings.TrimSpace(sm[1])
	}
	if loc := reCompose.FindStringIndex(m); loc != nil {
		return strings.TrimSpace(m[loc[1]:])
	}
	// A handler's own short prefix ahead of a Kubernetes error ("create model package: <error>"): keep the
	// prefix, rewrite what follows.
	if i := strings.Index(m, ": "); i > 0 && i < 80 && !strings.ContainsAny(m[:i], `"'`) {
		if rest := m[i+2:]; Clean(rest) != rest {
			return m[:i] + ": " + Clean(rest)
		}
	}
	return msg
}

func cleanAdmission(rest string) string {
	if loc := reKyvernoBlocked.FindStringIndex(rest); loc != nil {
		var msgs []string
		for _, sm := range reKyvernoRule.FindAllStringSubmatch(rest[loc[1]:], -1) {
			if s := strings.TrimSpace(sm[1]); s != "" {
				msgs = append(msgs, s)
			}
		}
		if len(msgs) > 0 {
			return strings.Join(msgs, "; ")
		}
	}
	return Clean(rest)
}

func invalidCauses(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "["), "]"))
	starts := reCauseStart.FindAllStringSubmatchIndex(s, -1)
	var parts []string
	for i, st := range starts {
		end := len(s)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		field := strings.TrimPrefix(s[st[2]:st[3]], "spec.")
		// After the error type: an optional `: <value>`, then an optional `: <message>`.
		rest := s[st[1]:end]
		why := ""
		if loc := reCauseValue.FindStringIndex(rest); loc != nil {
			why = strings.TrimSpace(rest[loc[1]:])
			if !strings.HasSuffix(rest[:loc[1]], ":") {
				why = "" // only a value, no message
			}
		}
		if why == "" {
			why = "is not valid"
			if s[st[4]:st[5]] == "Required value" {
				why = "is required"
			}
		}
		parts = append(parts, field+": "+why)
	}
	if len(parts) == 0 {
		return s
	}
	return strings.Join(parts, "; ")
}

func isAdmissionDenial(m string) bool {
	return reAdmission.MatchString(m) || reVAP.MatchString(m)
}

// isAuthzDenial reports a denial by the platform's own authorization webhook (an access decision, not a
// validation one), which names its decision "no policy allows" / "explicitly denied".
func isAuthzDenial(m string) bool {
	l := strings.ToLower(m)
	return strings.Contains(l, "no policy allows") || strings.Contains(l, "explicitly denied") || strings.Contains(l, "explicit deny")
}

// principal renders a Kubernetes user name as the identity a user knows: an IAM user's own name, a role
// session as its role, the platform's own service identities as such.
func principal(u string) string {
	switch {
	case strings.HasPrefix(u, "system:serviceaccount:"):
		parts := strings.Split(strings.TrimPrefix(u, "system:serviceaccount:"), ":")
		return "service " + parts[len(parts)-1]
	case strings.HasPrefix(u, "openinfra:role:"):
		return "assumed-role/" + strings.TrimPrefix(u, "openinfra:role:")
	}
	return u
}

// resourceNames maps a Kubernetes resource (plural, optionally group-qualified) to the AWS resource a
// user knows it as.
var resourceNames = map[string]string{
	"functions": "Lambda function", "virtualmachines": "EC2 instance", "buckets": "S3 bucket",
	"applications": "application", "databases": "DB instance", "databaseproxies": "RDS proxy",
	"queues": "SQS queue", "topics": "SNS topic", "tables": "DynamoDB table", "streams": "Kinesis stream",
	"statemachines": "state machine", "executions": "execution", "volumes": "EBS volume",
	"elasticips": "Elastic IP", "securitygroups": "security group", "vpcs": "VPC", "subnets": "subnet",
	"natgateways": "NAT gateway", "transitgateways": "transit gateway", "vpcendpoints": "VPC endpoint",
	"flowlogs": "flow log", "staticsites": "CloudFront distribution", "graphqlapis": "GraphQL API",
	"httpapis": "HTTP API", "userpools": "user pool", "identityproviders": "identity provider",
	"encryptionkeys": "KMS key", "destructions": "key deletion", "parameters": "SSM parameter",
	"emailsenders": "SES identity", "scheduledjobs": "schedule", "autoscalinggroups": "Auto Scaling group",
	"trainingjobs": "training job", "processingjobs": "processing job", "batchtransforms": "transform job",
	"tuningjobs": "tuning job", "models": "model", "modelpackages": "model package",
	"modelmonitors": "monitoring schedule", "featuregroups": "feature group", "queries": "query",
	"backupvaults": "backup vault", "backupplans": "backup plan", "configrules": "Config rule",
	"certificateauthorities": "private CA", "fileshares": "file system", "directories": "directory",
	"vmimages": "AMI", "dataflows": "data flow", "replications": "replication", "migrations": "migration",
	"users": "IAM user", "groups": "IAM group", "roles": "IAM role", "policies": "IAM policy",
	"grants": "access grant", "secrets": "secret", "configmaps": "configuration", "namespaces": "account",
	"pods": "task", "services": "endpoint", "persistentvolumeclaims": "EBS volume",
}

// lookupResource finds a resource by its plural (`functions`) or its kind (`Function`, as a validation
// error names it): the kind's plural is the kind plus s, es, or y→ies.
func lookupResource(key string) (string, bool) {
	for _, k := range []string{key, key + "s", key + "es", strings.TrimSuffix(key, "y") + "ies"} {
		if v, ok := resourceNames[k]; ok {
			return v, true
		}
	}
	return "", false
}

// resourceRef is `<AWS resource> <name>` for a Kubernetes resource reference such as
// `functions.openinfra.dev` and name, or just the resource when there is no name.
func resourceRef(res, name string) string {
	plural := res
	if i := strings.IndexByte(res, '.'); i > 0 {
		plural = res[:i]
	}
	kind, ok := lookupResource(strings.ToLower(plural))
	if !ok {
		kind = strings.TrimSuffix(plural, "s")
	}
	if name == "" {
		return kind
	}
	return kind + " " + name
}
