package main

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
	"github.com/harn3ss/open-infra/policyengine"
)

// consoleFixture is the EC2 fixture with the console reads recorded: reads lists each instance read.
func consoleFixture(t *testing.T, out []byte, outErr error, img []byte, imgErr error) (*ec2Handler, *[]string) {
	t.Helper()
	h, _ := ec2Fixture(t, ec2Web(), ec2Stopped())
	var reads []string
	h.consoleOutput = func(_ context.Context, ns, name string) ([]byte, error) {
		reads = append(reads, "output "+ns+"/"+name)
		return out, outErr
	}
	h.consoleScreenshot = func(_ context.Context, ns, name string, wake bool) ([]byte, error) {
		reads = append(reads, "screenshot "+ns+"/"+name+map[bool]string{true: " wake", false: ""}[wake])
		return img, imgErr
	}
	return h, &reads
}

// GetConsoleOutput answers EC2's shape: the instance, a timestamp, and the output base64-encoded.
func TestEC2_GetConsoleOutput(t *testing.T) {
	h, reads := consoleFixture(t, []byte("[    0.000000] Linux version 6.8\nubuntu login: "), nil, nil, nil)
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"GetConsoleOutput"}, "InstanceId": {webID}, "Latest": {"true"}})
	if w.Code != 200 {
		t.Fatalf("GetConsoleOutput: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		InstanceID string `xml:"instanceId"`
		Timestamp  string `xml:"timestamp"`
		Output     string `xml:"output"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out, _ := base64.StdEncoding.DecodeString(resp.Output)
	if resp.InstanceID != webID || !strings.Contains(string(out), "ubuntu login:") {
		t.Errorf("response %+v (output %q)", resp, out)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", resp.Timestamp); err != nil {
		t.Errorf("timestamp %q: %v", resp.Timestamp, err)
	}
	if len(*reads) != 1 || (*reads)[0] != "output "+ec2TestNS+"/s-web" {
		t.Errorf("reads %v, want one of s-web in the caller's account", *reads)
	}
}

// An instance with no output (stopped, or started before console logging was on) answers as EC2 does
// for one with nothing buffered: the instance and a timestamp, no output element.
func TestEC2_GetConsoleOutputNone(t *testing.T) {
	for _, e := range []error{vmconsole.ErrNotRunning, vmconsole.ErrNoLog} {
		h, _ := consoleFixture(t, nil, e, nil, nil)
		w := ec2Call(h, ec2Alice, url.Values{"Action": {"GetConsoleOutput"}, "InstanceId": {webID}})
		if w.Code != 200 || strings.Contains(w.Body.String(), "<output>") || !strings.Contains(w.Body.String(), "<instanceId>"+webID) {
			t.Errorf("%v: %d %s", e, w.Code, w.Body.String())
		}
	}
}

// GetConsoleScreenshot answers the JPEG base64-encoded with the instance; WakeUp is passed on; an
// instance that isn't running is IncorrectInstanceState.
func TestEC2_GetConsoleScreenshot(t *testing.T) {
	jpg := []byte{0xff, 0xd8, 0xff, 0xe0, 'J', 'F', 'I', 'F'}
	h, reads := consoleFixture(t, nil, nil, jpg, nil)
	w := ec2Call(h, ec2Alice, url.Values{"Action": {"GetConsoleScreenshot"}, "InstanceId": {webID}, "WakeUp": {"true"}})
	if w.Code != 200 {
		t.Fatalf("GetConsoleScreenshot: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		ImageData  string `xml:"imageData"`
		InstanceID string `xml:"instanceId"`
	}
	_ = xml.Unmarshal(w.Body.Bytes(), &resp)
	if got, _ := base64.StdEncoding.DecodeString(resp.ImageData); string(got) != string(jpg) || resp.InstanceID != webID {
		t.Errorf("response %+v", resp)
	}
	if len(*reads) != 1 || (*reads)[0] != "screenshot "+ec2TestNS+"/s-web wake" {
		t.Errorf("reads %v", *reads)
	}

	h, _ = consoleFixture(t, nil, nil, nil, vmconsole.ErrNotRunning)
	w = ec2Call(h, ec2Alice, url.Values{"Action": {"GetConsoleScreenshot"}, "InstanceId": {webID}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>IncorrectInstanceState</Code>") {
		t.Errorf("a stopped instance: %d %s", w.Code, w.Body.String())
	}
	h, _ = consoleFixture(t, nil, nil, nil, errors.New("virt-api timeout"))
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"GetConsoleScreenshot"}, "InstanceId": {webID}}); w.Code != 503 {
		t.Errorf("a failed read is Unavailable: %d %s", w.Code, w.Body.String())
	}
}

// The request's id: missing, malformed or unknown is EC2's error, and nothing is read.
func TestEC2_ConsoleRequestErrors(t *testing.T) {
	h, reads := consoleFixture(t, []byte("x"), nil, []byte("y"), nil)
	for _, op := range []string{"GetConsoleOutput", "GetConsoleScreenshot"} {
		for _, c := range []struct {
			form url.Values
			code string
		}{
			{url.Values{"Action": {op}}, "MissingParameter"},
			{url.Values{"Action": {op}, "InstanceId": {"s-web"}}, "InvalidInstanceID.Malformed"},
			{url.Values{"Action": {op}, "InstanceId": {"i-00000000000000000"}}, "InvalidInstanceID.NotFound"},
		} {
			if w := ec2Call(h, ec2Alice, c.form); w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>"+c.code+"</Code>") {
				t.Errorf("%v: want %s, got %d %s", c.form, c.code, w.Code, w.Body.String())
			}
		}
	}
	if len(*reads) != 0 {
		t.Errorf("a refused request must read nothing: %v", *reads)
	}
}

// Authorization on the instance: an assumed role needs ec2:<Action> on that instance (a grant on another
// is refused), a User's explicit Deny refuses it, nothing is read when refused, and DryRun answers
// DryRunOperation only when it would be allowed.
func TestEC2_ConsoleAuthorization(t *testing.T) {
	roleChecker := func(action, resource string) *dataplaneauthz.Checker {
		return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
			return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "ops", AppliesTo: []string{"Role::ops"},
				Statements: []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{action, "ec2:DescribeInstances"}, Resources: []string{resource}}}}}}, nil
		}, time.Minute)
	}
	role := iam.Claims{Sub: "assumed-role/ops/s", AssumedRole: "ops"}
	for _, op := range []string{"GetConsoleOutput", "GetConsoleScreenshot"} {
		h, reads := consoleFixture(t, []byte("x"), nil, []byte("y"), nil)
		h.door.authz = roleChecker("ec2:"+op, "Instance::i-0ffffffffffffffff")
		if w := ec2Call(h, role, url.Values{"Action": {op}, "InstanceId": {webID}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
			t.Errorf("%s: a grant on another instance must be refused: %d %s", op, w.Code, w.Body.String())
		}
		if w := ec2Call(h, role, url.Values{"Action": {op}, "InstanceId": {webID}, "DryRun": {"true"}}); w.Code != 403 {
			t.Errorf("%s: DryRun of a refused call is UnauthorizedOperation: %d", op, w.Code)
		}
		h.door.authz = roleChecker("ec2:"+op, "Instance::"+webID)
		if w := ec2Call(h, role, url.Values{"Action": {op}, "InstanceId": {webID}, "DryRun": {"true"}}); w.Code != 412 || !strings.Contains(w.Body.String(), "DryRunOperation") {
			t.Errorf("%s: DryRun of an allowed call: %d %s", op, w.Code, w.Body.String())
		}
		if len(*reads) != 0 {
			t.Errorf("%s: refused or DryRun calls must read nothing: %v", op, *reads)
		}
		if w := ec2Call(h, role, url.Values{"Action": {op}, "InstanceId": {webID}}); w.Code != 200 {
			t.Errorf("%s: a grant on the instance allows it: %d %s", op, w.Code, w.Body.String())
		}

		h, reads = consoleFixture(t, []byte("x"), nil, []byte("y"), nil)
		h.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"ec2:" + op}, Resources: []string{"*"}})
		if w := ec2Call(h, iam.Claims{Sub: "tester"}, url.Values{"Action": {op}, "InstanceId": {webID}}); w.Code != 403 || len(*reads) != 0 {
			t.Errorf("%s: a User's Deny must refuse it and read nothing: %d (reads %v)", op, w.Code, *reads)
		}
	}
}
