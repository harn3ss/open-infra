package awsidentity

import (
	"context"
	"strings"
	"testing"
)

// The management account (the install's own) is the identity unchanged: every ARN and StackId an install
// handed out before accounts stays the same.
func TestForAccount_ManagementIsUnchanged(t *testing.T) {
	mgmt := Default()
	mgmt.PublicDNSSuffix = "example.test"
	for _, acct := range []string{"", mgmt.AccountID} {
		if got := mgmt.ForAccount(acct, "anything"); got != mgmt {
			t.Errorf("ForAccount(%q) = %+v, want the management identity unchanged", acct, got)
		}
	}
	if !mgmt.IsManagement("") || !mgmt.IsManagement(mgmt.AccountID) || mgmt.IsManagement("912345678901") {
		t.Error("IsManagement must be true for the install's own account (or none) only")
	}
	if got, want := mgmt.ForAccount("", "").StackID("app"), mgmt.StackID("app"); got != want {
		t.Errorf("management StackId changed: %s, want %s", got, want)
	}
}

// A member account presents the install's region, partition and DNS suffix with its own id, and keeps its
// stacks in its home namespace — so its ARNs and derived StackIds are its own.
func TestForAccount_Member(t *testing.T) {
	mgmt := Default()
	mgmt.PublicDNSSuffix = "example.test"
	m := mgmt.ForAccount("912345678901", "team-a")
	if m.AccountID != "912345678901" || m.Region != mgmt.Region || m.StackNamespace != "team-a" || m.PublicDNSSuffix != "example.test" {
		t.Fatalf("member identity %+v", m)
	}
	if got := m.IAMARN("role/r"); got != "arn:aws:iam::912345678901:role/r" {
		t.Errorf("member IAM ARN %s", got)
	}
	if !strings.Contains(m.StackID("app"), ":912345678901:stack/app/") || m.StackID("app") == mgmt.StackID("app") {
		t.Errorf("member StackId %s must be the member's own", m.StackID("app"))
	}
	if keep := mgmt.ForAccount("912345678901", ""); keep.StackNamespace != mgmt.StackNamespace {
		t.Errorf("an empty home keeps the stack namespace, got %s", keep.StackNamespace)
	}
}

func TestAccountOfARN(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:iam::912345678901:role/r":                    "912345678901",
		"arn:aws:sqs:us-east-1:000000000000:q":                "000000000000",
		"arn:aws:s3:::bucket":                                 "",
		"arn:aws:iam::aws:policy/AdministratorAccess":         "",
		"arn:aws:iam::open-infra:role/legacy":                 "",
		"not-an-arn":                                          "",
		"arn:aws:cloudformation:us-east-1:123456789012:stack": "123456789012",
	} {
		if got := AccountOfARN(in); got != want {
			t.Errorf("AccountOfARN(%q) = %q, want %q", in, got, want)
		}
	}
}

// A request carries the identity of the account it acts in; without one, it is the management account's.
func TestIdentityOnContext(t *testing.T) {
	if got := FromContext(context.Background()); got != Current() {
		t.Errorf("no identity on the context: got %+v, want Current", got)
	}
	//nolint:staticcheck // a nil context is what an untraced caller may pass
	if got := FromContext(nil); got != Current() {
		t.Errorf("nil context: got %+v, want Current", got)
	}
	m := Current().ForAccount("912345678901", "team-a")
	if got := FromContext(WithIdentity(context.Background(), m)); got != m {
		t.Errorf("FromContext = %+v, want the member identity", got)
	}
}
