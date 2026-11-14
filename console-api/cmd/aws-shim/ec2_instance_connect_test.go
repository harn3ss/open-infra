package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
	"github.com/harn3ss/open-infra/policyengine"
)

const testSettingsNS = "open-infra-aws-shim"

// eicFixture is the EC2 Instance Connect door over the EC2 fixture (a running web instance, a stopped
// one), the account's serial console access as given.
func eicFixture(t *testing.T, access bool) (*eicHandler, *ec2Handler) {
	t.Helper()
	e, _ := ec2Fixture(t, ec2Web(), ec2Stopped())
	e.settingsNS = testSettingsNS
	if access {
		if err := serialconsole.SetEnabled(context.Background(), e.door.cs, testSettingsNS, e.serialAccount(context.Background()), true); err != nil {
			t.Fatal(err)
		}
	}
	h := newEICHandler(e, newSerialKeys(), nil)
	h.busy = func(context.Context, string) (bool, error) { return false, nil }
	h.running = func(_ context.Context, _, vm string) error { // the web instance runs, the db one is stopped
		if vm == "s-web" {
			return nil
		}
		return vmconsole.ErrNotRunning
	}
	return h, e
}

func edKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	signer, _ := ssh.NewSignerFromKey(priv)
	return sp, signer
}

func eicCall(h *eicHandler, claims iam.Claims, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://shim/", strings.NewReader(body))
	r.Header.Set("X-Amz-Target", "AWSEC2InstanceConnectService.SendSerialConsoleSSHPublicKey")
	r.Header.Set("Content-Type", eicContentType)
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	return w
}

func pushBody(id string, key ssh.PublicKey, extra string) string {
	return `{"InstanceId":"` + id + `","SSHPublicKey":"` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + `"` + extra + `}`
}

// A pushed key is good for its instance for 60 seconds, answered as EC2 Instance Connect does.
func TestEIC_SendSerialConsoleSSHPublicKey(t *testing.T) {
	h, _ := eicFixture(t, true)
	key, _ := edKey(t)
	w := eicCall(h, ec2Alice, pushBody(webID, key, `,"SerialPort":0`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"Success":true`) || !strings.Contains(w.Body.String(), `"RequestId":"req-1"`) {
		t.Fatalf("push: %d %s", w.Code, w.Body.String())
	}
	k, ok := h.keys.match(webID, key)
	if !ok || k.vm != "s-web" || k.ns != ec2TestNS {
		t.Fatalf("the pushed key: %+v %v", k, ok)
	}
	if _, ok := h.keys.match("i-0fedcba9876543210", key); ok {
		t.Error("a key pushed for one instance matched another")
	}
	h.keys.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if _, ok := h.keys.match(webID, key); ok {
		t.Error("a key matched after 60 seconds")
	}
}

// EC2 Instance Connect's errors, each before anything is pushed.
func TestEIC_Errors(t *testing.T) {
	key, _ := edKey(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	weak, _ := ssh.NewPublicKey(&small.PublicKey)
	off, _ := eicFixture(t, false)
	if w := eicCall(off, ec2Alice, pushBody(webID, key, "")); !strings.Contains(w.Body.String(), "SerialConsoleAccessDisabledException") {
		t.Errorf("access off: %d %s", w.Code, w.Body.String())
	}
	h, _ := eicFixture(t, true)
	for _, c := range []struct{ body, code string }{
		{pushBody("i-00000000000000000", key, ""), "EC2InstanceNotFoundException"},
		{pushBody("i-0fedcba9876543210", key, ""), "EC2InstanceStateInvalidException"},
		{pushBody("s-web", key, ""), "InvalidArgsException"},
		{pushBody(webID, key, `,"SerialPort":1`), "InvalidArgsException"},
		{pushBody(webID, weak, ""), "InvalidArgsException"},
		{`{"InstanceId":"` + webID + `","SSHPublicKey":"not a key"}`, "InvalidArgsException"},
		{`{"InstanceId":"` + webID + `"}`, "InvalidArgsException"},
	} {
		if w := eicCall(h, ec2Alice, c.body); w.Code != 400 || !strings.Contains(w.Body.String(), `"__type":"`+c.code+`"`) {
			t.Errorf("%s: want %s, got %d %s", c.body, c.code, w.Code, w.Body.String())
		}
	}
	h.busy = func(context.Context, string) (bool, error) { return true, nil }
	if w := eicCall(h, ec2Alice, pushBody(webID, key, "")); !strings.Contains(w.Body.String(), "SerialConsoleSessionLimitExceededException") {
		t.Errorf("a session open: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.keys.match(webID, key); ok || len(off.keys.pending) != 0 {
		t.Error("a refused push was kept")
	}
}

// ec2-instance-connect:SendSerialConsoleSSHPublicKey on the instance: a User's Deny refuses it, an assumed
// role needs a grant on that instance (one on another is refused), and nothing is pushed when refused.
func TestEIC_Authorization(t *testing.T) {
	key, _ := edKey(t)
	h, e := eicFixture(t, true)
	e.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"ec2-instance-connect:SendSerialConsoleSSHPublicKey"}, Resources: []string{"*"}})
	if w := eicCall(h, iam.Claims{Sub: "tester"}, pushBody(webID, key, "")); w.Code != 400 || !strings.Contains(w.Body.String(), `"__type":"AccessDeniedException"`) {
		t.Errorf("a User's Deny: %d %s", w.Code, w.Body.String())
	}
	role := iam.Claims{Sub: "assumed-role/" + ecrTestRole + "/s", AssumedRole: ecrTestRole}
	e.door.authz = roleChecker(dpAllow([]string{"ec2-instance-connect:SendSerialConsoleSSHPublicKey", "ec2:DescribeInstances"}, "Instance::i-0fedcba9876543210"))
	if w := eicCall(h, role, pushBody(webID, key, "")); !strings.Contains(w.Body.String(), "AccessDeniedException") {
		t.Errorf("a grant on another instance: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.keys.match(webID, key); ok {
		t.Error("a refused push was kept")
	}
	e.door.authz = roleChecker(dpAllow([]string{"ec2-instance-connect:SendSerialConsoleSSHPublicKey"}, "Instance::"+webID), dpAllow([]string{"ec2:DescribeInstances"}, "*"))
	if w := eicCall(h, role, pushBody(webID, key, "")); w.Code != 200 {
		t.Errorf("a grant on the instance: %d %s", w.Code, w.Body.String())
	}
}
