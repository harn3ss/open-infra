package awserr

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"rbac denial with the authorization webhook's reason",
			`functions.openinfra.dev "orders" is forbidden: User "alice" cannot create resource "functions" in API group "openinfra.dev" in the namespace "main-dev": no policy allows this action (default deny)`,
			`User: alice is not authorized to perform: create on resource: Lambda function orders (no policy allows this action (default deny))`},
		{"list denial, no name",
			`virtualmachines.openinfra.dev is forbidden: User "bob" cannot list resource "virtualmachines" in API group "openinfra.dev" in the namespace "team-a"`,
			`User: bob is not authorized to perform: list on resource: EC2 instance`},
		{"cluster-scoped denial of a service identity",
			`namespaces is forbidden: User "system:serviceaccount:minio:openinfra-bucket-reaper" cannot get resource "namespaces" in API group "" at the cluster scope`,
			`User: service openinfra-bucket-reaper is not authorized to perform: get on resource: account`},
		{"assumed role",
			`buckets.openinfra.dev "logs" is forbidden: User "openinfra:role:deployer" cannot delete resource "buckets" in API group "openinfra.dev" in the namespace "prod"`,
			`User: assumed-role/deployer is not authorized to perform: delete on resource: S3 bucket logs`},
		{"CEL validation on a claim kind",
			`Function.openinfra.dev "orders" is invalid: spec: Invalid value: "object": memoryRequest must not exceed memory`,
			`Invalid Lambda function orders: spec: memoryRequest must not exceed memory`},
		{"several field errors",
			`Database.openinfra.dev "db1" is invalid: [spec.engine: Unsupported value: "oracle": supported values: "postgres", "mysql", spec.size: Required value]`,
			`Invalid DB instance db1: engine: supported values: "postgres", "mysql"; size: is required`},
		{"not found", `statemachines.openinfra.dev "orders-flow" not found`, `state machine orders-flow was not found`},
		{"already exists", `buckets.openinfra.dev "site" already exists`, `S3 bucket site already exists`},
		{"optimistic-concurrency conflict",
			`Operation cannot be fulfilled on securitygroups.openinfra.dev "web": the object has been modified; please apply your changes to the latest version and try again`,
			`security group web was changed by another request. Reload it and try again.`},
		{"admission webhook denial keeps its reason",
			`admission webhook "vfunction.openinfra.dev" denied the request: memory must be at least 128Mi`,
			`memory must be at least 128Mi`},
		{"Kyverno policy report",
			"admission webhook \"validate.kyverno.svc-fail\" denied the request: \n\nresource Function/main-dev/orders was blocked due to the following policies \n\nrequire-memory:\n  check-memory: 'validation error: memory is required'\n",
			`validation error: memory is required`},
		{"ValidatingAdmissionPolicy",
			`functions.openinfra.dev "orders" is forbidden: ValidatingAdmissionPolicy 'kind-architectures' with binding 'kind-architectures' denied request: arm64 is not available for this kind`,
			`arm64 is not available for this kind`},
		{"Crossplane composition failure surfaces its fail() message",
			`cannot compose resources: pipeline step "render-resources" returned a fatal result: cannot execute template: template: manifests:278:6: executing "manifests" at <fail "a migrated disk needs firmware.mode">: error calling fail: a migrated disk needs firmware.mode (bios or uefi)`,
			`a migrated disk needs firmware.mode (bios or uefi)`},
		{"other composition failure keeps the cause",
			`cannot apply composed resource "vm": cannot patch object: quota exceeded for volumes`,
			`cannot patch object: quota exceeded for volumes`},
		{"a handler's own prefix is kept",
			`create model package: modelpackages.openinfra.dev "churn-v2" already exists`,
			`create model package: model package churn-v2 already exists`},
		{"unreachable webhook",
			`Internal error occurred: failed calling webhook "authz.openinfra.dev": failed to call webhook: Post "https://authz-webhook.open-infra-authz.svc:443/authorize?timeout=10s": dial tcp 10.43.1.2:443: connect: connection refused`,
			`The service is temporarily unavailable. Try again shortly.`},
	}
	for _, c := range cases {
		if got := Clean(c.in); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// The platform's own messages, and anything else that is not Kubernetes-shaped, pass through unchanged.
func TestClean_LeavesOtherMessagesAlone(t *testing.T) {
	for _, m := range []string{
		"Template format error: unresolved resource dependencies [Missing] in the Resources block of the template",
		"The specified log group already exists.",
		"Stack with id orders does not exist",
		"Invalid parameter: FilterPolicy: unexpected token",
		"",
	} {
		if got := Clean(m); got != m {
			t.Errorf("Clean(%q) = %q, want it unchanged", m, got)
		}
	}
}

// What a user is shown never carries Kubernetes' vocabulary: API groups, webhook names, template
// positions, the word "namespace".
func TestClean_NoKubernetesVocabularyLeaks(t *testing.T) {
	for _, m := range []string{
		`functions.openinfra.dev "f" is forbidden: User "u" cannot get resource "functions" in API group "openinfra.dev" in the namespace "n"`,
		`admission webhook "x.y.z" denied the request: no`,
		`cannot compose resources: pipeline step "render-resources" returned a fatal result: cannot execute template: template: manifests:1:2: executing "manifests" at <fail "m">: error calling fail: m`,
	} {
		got := Clean(m)
		for _, leak := range []string{"API group", "namespace", "admission webhook", "openinfra.dev", "manifests:", "pipeline step"} {
			if strings.Contains(got, leak) {
				t.Errorf("Clean(%q) = %q still contains %q", m, got, leak)
			}
		}
	}
}

func TestCode(t *testing.T) {
	cases := []struct {
		status          int
		reason, message string
		want            string
	}{
		{403, "Forbidden", `functions.openinfra.dev "f" is forbidden: User "u" cannot create resource "functions"`, "AccessDeniedException"},
		{403, "Forbidden", `admission webhook "v.x" denied the request: bad memory`, "ValidationException"},
		{400, "BadRequest", `admission webhook "v.x" denied the request: bad`, "ValidationException"},
		{403, "Forbidden", `admission webhook "authz.openinfra.dev" denied the request: no policy allows this action`, "AccessDeniedException"},
		{404, "NotFound", "", "ResourceNotFoundException"},
		{409, "AlreadyExists", "", "ResourceAlreadyExistsException"},
		{409, "Conflict", "", "ConflictException"},
		{422, "Invalid", "", "ValidationException"},
		{429, "TooManyRequests", "", "ThrottlingException"},
		{503, "", "", "ServiceUnavailableException"},
		{500, "InternalError", "", "InternalFailure"},
		{410, "Expired", "", "ExpiredIteratorException"},
	}
	for _, c := range cases {
		if got := Code(c.status, c.reason, c.message); got != c.want {
			t.Errorf("Code(%d, %q, %q) = %q, want %q", c.status, c.reason, c.message, got, c.want)
		}
	}
}
