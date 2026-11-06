package render

import (
	"strings"
	"testing"
)

const mfaGuardYAML = "../../platform/aws-shim/mfa-device-guard.yaml"

// IAM virtual MFA devices (CreateVirtualMFADevice, EnableMFADevice) keep their TOTP seeds in the credential
// store namespace. The admission guard pins their shape there: a device is exactly an iam-mfa-* Secret
// labelled as one, for one account, assigned to at most one user, which only deactivation changes. Its CEL
// is evaluated case by case in test/admission; this pins the objects, their scope and that they fail
// closed, and that a cluster administrator (who recovers a lost device) is not held.
func TestMFADeviceGuard_Objects(t *testing.T) {
	p := yamlDoc(t, mfaGuardYAML, "ValidatingAdmissionPolicy", "openinfra-mfa-device-guard")
	mustContain(t, "MFA device guard", p,
		"failurePolicy: Fail",
		`apiGroups: [""]`, `resources: ["secrets"]`, `operations: ["CREATE", "UPDATE", "DELETE"]`,
		"request.namespace == 'open-infra-aws-shim'",
		"!('system:masters' in request.userInfo.groups)",
		"request.operation == 'DELETE' ? oldObject : object",
		"startsWith('iam-mfa-')", "'openinfra.dev/mfa-device'", "'openinfra.dev/account-id'",
		"'openinfra.dev/iam-user'", "'openinfra.dev/iam-user-namespace'")
	b := yamlDoc(t, mfaGuardYAML, "ValidatingAdmissionPolicyBinding", "openinfra-mfa-device-guard")
	mustContain(t, "MFA device guard binding", b, "policyName: openinfra-mfa-device-guard", "validationActions: [Deny]")
	if strings.Contains(b, "matchResources") || strings.Contains(b, "paramRef") {
		t.Errorf("the binding must apply the policy as written: no matchResources or paramRef narrowing it")
	}
}
