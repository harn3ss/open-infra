package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
	"github.com/harn3ss/open-infra/policyengine"
)

// The account setting reads off until it is turned on, and Enable / Disable answer the new state, in
// EC2's shape; DryRun answers DryRunOperation and changes nothing.
func TestEC2_SerialConsoleAccess(t *testing.T) {
	h, _ := ec2Fixture(t)
	h.settingsNS = "open-infra-aws-shim"
	status := func() string {
		w := ec2Call(h, ec2Alice, url.Values{"Action": {"GetSerialConsoleAccessStatus"}})
		if w.Code != 200 {
			t.Fatalf("GetSerialConsoleAccessStatus: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if b := status(); !strings.Contains(b, "<serialConsoleAccessEnabled>false</serialConsoleAccessEnabled>") || !strings.Contains(b, "<managedBy>account</managedBy>") {
		t.Errorf("a new account: %s", b)
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"EnableSerialConsoleAccess"}, "DryRun": {"true"}}); w.Code != 412 {
		t.Errorf("DryRun: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(status(), ">false<") {
		t.Error("DryRun changed the setting")
	}
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"EnableSerialConsoleAccess"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<EnableSerialConsoleAccessResponse") || !strings.Contains(w.Body.String(), ">true<") {
		t.Fatalf("EnableSerialConsoleAccess: %d %s", w.Code, w.Body.String())
	}
	if on, _ := serialconsole.Enabled(context.Background(), h.door.cs, "open-infra-aws-shim", h.serialAccount(context.Background())); !on {
		t.Error("the management account's setting is not on")
	}
	if !strings.Contains(status(), ">true<") {
		t.Error("status after Enable is not true")
	}
	if w := ec2Call(h, ec2Alice, url.Values{"Action": {"DisableSerialConsoleAccess"}}); w.Code != 200 || !strings.Contains(w.Body.String(), ">false<") {
		t.Errorf("DisableSerialConsoleAccess: %d %s", w.Code, w.Body.String())
	}
}

// Each is ec2:<Action> on "*": a principal denied it is refused (UnauthorizedOperation) and the setting
// is unchanged; an assumed role needs a grant of it.
func TestEC2_SerialConsoleAccessAuthorization(t *testing.T) {
	h, _ := ec2Fixture(t)
	h.settingsNS = "open-infra-aws-shim"
	h.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"ec2:EnableSerialConsoleAccess"}, Resources: []string{"*"}})
	if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {"EnableSerialConsoleAccess"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("a denied Enable: %d %s", w.Code, w.Body.String())
	}
	if on, _ := serialconsole.Enabled(context.Background(), h.door.cs, "open-infra-aws-shim", h.serialAccount(context.Background())); on {
		t.Error("a refused Enable turned access on")
	}
	role := iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/s", AssumedRole: ecrTestRole}
	h.door.authz = roleChecker(dpAllow([]string{"ec2:DescribeInstances"}, "*"))
	if w := ec2Call(h, role, url.Values{"Action": {"GetSerialConsoleAccessStatus"}}); w.Code != 403 {
		t.Errorf("a role without the grant: %d %s", w.Code, w.Body.String())
	}
	h.door.authz = roleChecker(dpAllow([]string{"ec2:GetSerialConsoleAccessStatus"}, "*"))
	if w := ec2Call(h, role, url.Values{"Action": {"GetSerialConsoleAccessStatus"}}); w.Code != 200 {
		t.Errorf("a role with the grant: %d %s", w.Code, w.Body.String())
	}
}
