package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/xml"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
	"github.com/harn3ss/open-infra/policyengine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// mfaWorld is the IAM door with users alice and bob (each with a UID), and the STS door reading the same
// device store.
func mfaWorld(t *testing.T) (*iamHandler, *stsHandler) {
	t.Helper()
	h, dyn := iamWorld(t)
	for name, uid := range map[string]string{"alice": "uid-alice", "bob": "uid-bob"} {
		u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
			"metadata": map[string]any{"name": name, "namespace": iamHome}, "spec": map[string]any{"source": "local"}}}
		u.SetUID(types.UID(uid))
		if _, err := dyn.Resource(gvrUsers).Namespace(iamHome).Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	sts := &stsHandler{account: testMgmt, minter: testMinter(t), logger: discardLogger(),
		mfa: &shimMFA{store: h.mfaStore(), dyn: dyn, usersNS: iamHome, account: testMgmt, logger: discardLogger()}}
	return h, sts
}

// newDevice creates a virtual MFA device and returns its serial and seed (decoded from the answer as an
// SDK decodes the Base32StringSeed blob).
func newDevice(t *testing.T, h *iamHandler, ctx context.Context, claims iam.Claims, name string) (string, []byte) {
	t.Helper()
	w := call(t, h, ctx, claims, 200, "Action", "CreateVirtualMFADevice", "VirtualMFADeviceName", name)
	body := w.Body.String()
	serial := between(body, "<SerialNumber>", "</SerialNumber>")
	b32, err := base64.StdEncoding.DecodeString(between(body, "<Base32StringSeed>", "</Base32StringSeed>"))
	if err != nil {
		t.Fatalf("Base32StringSeed is not a base64 blob: %v", err)
	}
	seed, err := base64Base32(string(b32))
	if err != nil || len(seed) != mfa.SeedBytes {
		t.Fatalf("seed: %v (%d bytes)", err, len(seed))
	}
	img, err := base64.StdEncoding.DecodeString(between(body, "<QRCodePNG>", "</QRCodePNG>"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(img)); err != nil {
		t.Fatalf("QRCodePNG is not a PNG: %v", err)
	}
	return serial, seed
}

func base64Base32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// code is a device's code n steps from now.
func code(seed []byte, n int64) string { return mfa.Code(seed, mfa.StepAt(time.Now())+n) }

func enable(t *testing.T, h *iamHandler, user, serial string, seed []byte) {
	t.Helper()
	call(t, h, nil, iamAdmin, 200, "Action", "EnableMFADevice", "UserName", user, "SerialNumber", serial,
		"AuthenticationCode1", code(seed, -1), "AuthenticationCode2", code(seed, 0))
}

func TestMFA_DeviceLifecycleThroughIAM(t *testing.T) {
	h, _ := mfaWorld(t)
	serial, seed := newDevice(t, h, nil, iamAdmin, "alice-phone")
	if serial != "arn:aws:iam::"+testMgmt+":mfa/alice-phone" {
		t.Fatalf("serial %q, want the device ARN", serial)
	}
	if w := call(t, h, nil, iamAdmin, 409, "Action", "CreateVirtualMFADevice", "VirtualMFADeviceName", "ALICE-phone"); !strings.Contains(w.Body.String(), "EntityAlreadyExists") {
		t.Fatalf("a name taken in the account: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 400, "Action", "CreateVirtualMFADevice", "VirtualMFADeviceName", "has space")
	call(t, h, nil, iamAdmin, 400, "Action", "CreateVirtualMFADevice", "VirtualMFADeviceName", "x", "Path", "no-slash")

	// Unassigned until enabled; ListVirtualMFADevices filters by assignment.
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListVirtualMFADevices", "AssignmentStatus", "Unassigned"); !strings.Contains(w.Body.String(), serial) {
		t.Fatalf("unassigned listing: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 400, "Action", "ListVirtualMFADevices", "AssignmentStatus", "Some")

	// Enable needs two CONSECUTIVE codes.
	for _, c := range [][2]string{{code(seed, 0), code(seed, 0)}, {code(seed, 0), code(seed, -1)}, {"123456", "654321"}} {
		w := call(t, h, nil, iamAdmin, 403, "Action", "EnableMFADevice", "UserName", "alice", "SerialNumber", serial,
			"AuthenticationCode1", c[0], "AuthenticationCode2", c[1])
		if !strings.Contains(w.Body.String(), "InvalidAuthenticationCode") {
			t.Fatalf("codes %v: %s", c, w.Body.String())
		}
	}
	call(t, h, nil, iamAdmin, 400, "Action", "EnableMFADevice", "UserName", "alice", "SerialNumber", serial,
		"AuthenticationCode1", "12345", "AuthenticationCode2", "123456")
	call(t, h, nil, iamAdmin, 404, "Action", "EnableMFADevice", "UserName", "nobody", "SerialNumber", serial,
		"AuthenticationCode1", code(seed, -1), "AuthenticationCode2", code(seed, 0))
	call(t, h, nil, iamAdmin, 404, "Action", "EnableMFADevice", "UserName", "alice", "SerialNumber", "arn:aws:iam::"+testMgmt+":mfa/missing",
		"AuthenticationCode1", code(seed, -1), "AuthenticationCode2", code(seed, 0))
	enable(t, h, "alice", serial, seed)
	if w := call(t, h, nil, iamAdmin, 409, "Action", "EnableMFADevice", "UserName", "bob", "SerialNumber", serial,
		"AuthenticationCode1", code(seed, 0), "AuthenticationCode2", code(seed, 1)); !strings.Contains(w.Body.String(), "EntityAlreadyExists") {
		t.Fatalf("an assigned device for another user: %s", w.Body.String())
	}

	w := call(t, h, nil, iamAdmin, 200, "Action", "ListMFADevices", "UserName", "alice")
	if !strings.Contains(w.Body.String(), "<SerialNumber>"+serial+"</SerialNumber>") || !strings.Contains(w.Body.String(), "<EnableDate>") {
		t.Fatalf("ListMFADevices: %s", w.Body.String())
	}
	// The caller's own devices when UserName is omitted.
	if w := call(t, h, nil, iam.Claims{Sub: "alice", Groups: []string{"openinfra:admins"}}, 200, "Action", "ListMFADevices"); !strings.Contains(w.Body.String(), serial) {
		t.Fatalf("ListMFADevices as alice: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListMFADevices", "UserName", "bob"); strings.Contains(w.Body.String(), serial) {
		t.Fatalf("bob holds no device: %s", w.Body.String())
	}
	w = call(t, h, nil, iamAdmin, 200, "Action", "ListVirtualMFADevices", "AssignmentStatus", "Assigned")
	if !strings.Contains(w.Body.String(), "<UserName>alice</UserName>") {
		t.Fatalf("an assigned device names its user: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListVirtualMFADevices", "AssignmentStatus", "Unassigned"); strings.Contains(w.Body.String(), serial) {
		t.Fatalf("an assigned device is not unassigned: %s", w.Body.String())
	}
	// The seed is never answered again.
	if strings.Contains(w.Body.String(), "Base32StringSeed") {
		t.Fatal("a listing returned a seed")
	}

	// Tags.
	call(t, h, nil, iamAdmin, 200, "Action", "TagMFADevice", "SerialNumber", serial, "Tags.member.1.Key", "team", "Tags.member.1.Value", "a")
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListMFADeviceTags", "SerialNumber", serial); !strings.Contains(w.Body.String(), "<Key>team</Key><Value>a</Value>") {
		t.Fatalf("tags: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 200, "Action", "UntagMFADevice", "SerialNumber", serial, "TagKeys.member.1", "team")
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListMFADeviceTags", "SerialNumber", serial); strings.Contains(w.Body.String(), "team") {
		t.Fatalf("untagged: %s", w.Body.String())
	}

	// Resync with two consecutive codes.
	call(t, h, nil, iamAdmin, 200, "Action", "ResyncMFADevice", "UserName", "alice", "SerialNumber", serial,
		"AuthenticationCode1", code(seed, 1), "AuthenticationCode2", code(seed, 2))

	// An assigned device blocks its own delete and its user's.
	if w := call(t, h, nil, iamAdmin, 409, "Action", "DeleteVirtualMFADevice", "SerialNumber", serial); !strings.Contains(w.Body.String(), "DeleteConflict") {
		t.Fatalf("delete of an assigned device: %s", w.Body.String())
	}
	if w := call(t, h, nil, iamAdmin, 409, "Action", "DeleteUser", "UserName", "alice"); !strings.Contains(w.Body.String(), "must remove MFA device first") {
		t.Fatalf("delete of a user with MFA: %s", w.Body.String())
	}
	call(t, h, nil, iamAdmin, 404, "Action", "DeactivateMFADevice", "UserName", "bob", "SerialNumber", serial)
	call(t, h, nil, iamAdmin, 200, "Action", "DeactivateMFADevice", "UserName", "alice", "SerialNumber", serial)
	call(t, h, nil, iamAdmin, 200, "Action", "DeleteVirtualMFADevice", "SerialNumber", serial)
	call(t, h, nil, iamAdmin, 404, "Action", "DeleteVirtualMFADevice", "SerialNumber", serial)
	call(t, h, nil, iamAdmin, 200, "Action", "DeleteUser", "UserName", "alice")
}

// The operations AWS authorizes on the device are asked on its ARN; the user's on the user.
func TestMFA_AuthorizedOnAWSResources(t *testing.T) {
	r := formOp(url.Values{"Action": {"CreateVirtualMFADevice"}, "VirtualMFADeviceName": {"d"}, "Path": {"/team/"}})
	h, _ := mfaWorld(t)
	if got := h.mfaARN(context.Background(), "CreateVirtualMFADevice", r); got != "arn:aws:iam::"+testMgmt+":mfa/team/d" {
		t.Errorf("CreateVirtualMFADevice resource %s", got)
	}
	for op, want := range map[string]string{
		"CreateVirtualMFADevice": mfaResourceType, "DeleteVirtualMFADevice": mfaResourceType, "TagMFADevice": mfaResourceType,
		"EnableMFADevice": "User", "DeactivateMFADevice": "User", "ResyncMFADevice": "User", "ListMFADevices": "User",
		"ListVirtualMFADevices": "",
	} {
		if got, _ := iamResource(op, formOp(url.Values{"UserName": {"alice"}})); got != want {
			t.Errorf("%s authorized on %q, want %q", op, got, want)
		}
	}
}

// A member account's devices are its own: its serials name it, the management account's are not its.
func TestMFA_AccountsKeepTheirOwnDevices(t *testing.T) {
	h, dyn := iamWorld(t)
	t.Setenv(iamauthz.EnvMode, "legacy")
	bob := iam.Claims{Sub: "bob", Account: testMember}
	h.authz = allowAllChecker(memberHome + "/bob")
	ctx := withAccountHome(awsidentity.WithIdentity(context.Background(), awsidentity.Current().ForAccount(testMember, memberHome)), memberHome)
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
		"metadata": map[string]any{"name": "bob", "namespace": memberHome}, "spec": map[string]any{"source": "local"}}}
	if _, err := dyn.Resource(gvrUsers).Namespace(memberHome).Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	mgmtSerial, _ := newDevice(t, h, nil, iamAdmin, "phone")
	memberSerial, seed := newDevice(t, h, ctx, bob, "phone") // the same name in another account
	if memberSerial != "arn:aws:iam::"+testMember+":mfa/phone" || memberSerial == mgmtSerial {
		t.Fatalf("member serial %q", memberSerial)
	}
	call(t, h, ctx, bob, 404, "Action", "DeleteVirtualMFADevice", "SerialNumber", mgmtSerial)
	call(t, h, ctx, bob, 200, "Action", "EnableMFADevice", "UserName", "bob", "SerialNumber", memberSerial,
		"AuthenticationCode1", code(seed, -1), "AuthenticationCode2", code(seed, 0))
	if w := call(t, h, nil, iamAdmin, 200, "Action", "ListVirtualMFADevices"); strings.Contains(w.Body.String(), testMember) {
		t.Fatalf("the management account listed a member account's device: %s", w.Body.String())
	}
	if w := call(t, h, ctx, bob, 200, "Action", "ListVirtualMFADevices"); strings.Contains(w.Body.String(), ":"+testMgmt+":") {
		t.Fatalf("a member account listed the management account's device: %s", w.Body.String())
	}
}

// allowAllChecker is a policy world in which user may do anything.
func allowAllChecker(user string) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{Name: "all", AppliesTo: []string{"User::" + user},
			Statements: []policyengine.Statement{dpAllow([]string{"*"}, "*")}}}}, nil
	}, time.Minute)
}

// ── STS ─────────────────────────────────────────────────────────────────────────

func stsCall(h *stsHandler, claims iam.Claims, kv ...string) *httptest.ResponseRecorder {
	form := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		form.Set(kv[i], kv[i+1])
	}
	req := httptest.NewRequest(http.MethodPost, "http://sts.local/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, req, claims, "rid")
	return w
}

// sessionOf opens a GetSessionToken / AssumeRole answer's session as the authenticator does.
func sessionOf(t *testing.T, m *awssts.Minter, body string) awssts.Session {
	t.Helper()
	akid := between(body, "<AccessKeyId>", "</AccessKeyId>")
	tok := between(body, "<SessionToken>", "</SessionToken>")
	sess, ok := m.Verify(akid, tok)
	if !ok {
		t.Fatalf("the answer's session does not verify: %s", body)
	}
	return sess
}

func TestGetSessionToken_MFA(t *testing.T) {
	h, sts := mfaWorld(t)
	serial, seed := newDevice(t, h, nil, iamAdmin, "alice-phone")
	enable(t, h, "alice", serial, seed)
	alice := iam.Claims{Sub: "alice"} // a long-term access key

	// Without MFA: a session, authenticated without it.
	w := stsCall(sts, alice, "Action", "GetSessionToken", "DurationSeconds", "900")
	if w.Code != 200 {
		t.Fatalf("GetSessionToken: %d %s", w.Code, w.Body.String())
	}
	var resp getSessionTokenResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil || !strings.HasPrefix(resp.Result.Credentials.AccessKeyId, "ASIA") {
		t.Fatalf("answer: %v %s", err, w.Body.String())
	}
	if s := sessionOf(t, sts.minter, w.Body.String()); s.User != "alice" || s.MFA || s.RoleName != "" {
		t.Fatalf("a session without MFA: %+v", s)
	}

	// A wrong code, a code for another user's device, a malformed code.
	if w := stsCall(sts, alice, "Action", "GetSessionToken", "SerialNumber", serial, "TokenCode", "000000"); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "AccessDenied") || !strings.Contains(w.Body.String(), "invalid MFA one time pass code") {
		t.Fatalf("a wrong code: %d %s", w.Code, w.Body.String())
	}
	if w := stsCall(sts, iam.Claims{Sub: "bob"}, "Action", "GetSessionToken", "SerialNumber", serial, "TokenCode", code(seed, 1)); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "unable to validate MFA code") {
		t.Fatalf("bob with alice's device: %d %s", w.Code, w.Body.String())
	}
	if w := stsCall(sts, alice, "Action", "GetSessionToken", "SerialNumber", serial, "TokenCode", "12ab56"); w.Code != 400 {
		t.Fatalf("a malformed code: %d %s", w.Code, w.Body.String())
	}
	if w := stsCall(sts, alice, "Action", "GetSessionToken", "DurationSeconds", "129601"); w.Code != 400 {
		t.Fatalf("over 36 hours: %d", w.Code)
	}

	// The right code: a session that carries MFA. The same code again is refused (replay).
	good := code(seed, 1)
	w = stsCall(sts, alice, "Action", "GetSessionToken", "SerialNumber", serial, "TokenCode", good)
	if w.Code != 200 {
		t.Fatalf("GetSessionToken with MFA: %d %s", w.Code, w.Body.String())
	}
	sess := sessionOf(t, sts.minter, w.Body.String())
	if !sess.MFA || time.Since(time.Unix(sess.MFAAuthTime, 0)) > time.Minute || sess.Expiry.Sub(sess.IssuedAt) != 12*time.Hour {
		t.Fatalf("a session with MFA: %+v", sess)
	}
	if w := stsCall(sts, alice, "Action", "GetSessionToken", "SerialNumber", serial, "TokenCode", good); w.Code != 403 {
		t.Fatalf("a replayed code must be refused: %d %s", w.Code, w.Body.String())
	}

	// The session as the authenticator presents it: alice, temporary, with MFA.
	auth := &authenticator{resolve: func(_ context.Context, owner string) ([]string, bool) { return nil, owner == "alice" }}
	claims, ok := auth.sessionClaims(context.Background(), sess)
	if !ok || claims.Sub != "alice" || claims.AssumedRole != "" || !claims.UserSession || !claims.MFAPresent() {
		t.Fatalf("session claims: %+v %v", claims, ok)
	}
	rc := requestContext(claims, httptest.NewRequest("GET", "/", nil))
	if rc["multiFactorAuthPresent"] != true || rc["multiFactorAuthAge"] == nil {
		t.Fatalf("request context: %v", rc)
	}

	// Session credentials do not get another session; a GetSessionToken session without MFA calls no IAM.
	if w := stsCall(sts, claims, "Action", "GetSessionToken"); w.Code != 403 || !strings.Contains(w.Body.String(), "Cannot call GetSessionToken with session credentials") {
		t.Fatalf("GetSessionToken with session credentials: %d %s", w.Code, w.Body.String())
	}
	noMFA := iam.Claims{Sub: "alice", Groups: []string{"openinfra:admins"}, UserSession: true, MFA: iam.NoMFA()}
	if w := call(t, h, nil, noMFA, 403, "Action", "ListUsers"); !strings.Contains(w.Body.String(), "InvalidClientTokenId") {
		t.Fatalf("IAM with a session without MFA: %s", w.Body.String())
	}
	withMFA := noMFA
	withMFA.MFA = iam.WithMFA(time.Now())
	call(t, h, nil, withMFA, 200, "Action", "ListUsers")
	if w := stsCall(sts, withMFA, "Action", "GetCallerIdentity"); w.Code != 200 || !strings.Contains(w.Body.String(), ":user/alice") {
		t.Fatalf("GetCallerIdentity of a user session: %d %s", w.Code, w.Body.String())
	}
}

// AWS's "deny unless MFA": the same policy allows a session authenticated with MFA and denies the
// long-term key that obtained it — through the one evaluator, with the request context the doors build.
func TestMFA_DenyUnlessMFAPolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
	  {"Effect":"Deny","NotAction":["iam:ListMFADevices","sts:GetSessionToken"],"Resource":"*",
	   "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	stmts, report, err := iamauthz.CompileDocument(doc)
	if err != nil || len(report) > 0 {
		t.Fatalf("compile: %v %v", err, report)
	}
	eng, err := policyengine.NewEngine(stmts)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	decide := func(c iam.Claims) policyengine.Decision {
		return eng.Authorize(policyengine.Request{Principal: policyengine.Principal{Type: "User", ID: "alice"},
			Action: "s3:ListAllMyBuckets", Resource: policyengine.Resource{Type: "Any", ID: "*"}, Context: requestContext(c, req)})
	}
	if d := decide(iam.Claims{Sub: "alice"}); d.Allowed || !d.ExplicitDeny {
		t.Errorf("the long-term key must be denied: %+v", d)
	}
	if d := decide(iam.Claims{Sub: "alice", MFA: iam.NoMFA(), UserSession: true}); d.Allowed {
		t.Errorf("a session without MFA must be denied: %+v", d)
	}
	if d := decide(iam.Claims{Sub: "alice", MFA: iam.WithMFA(time.Now()), UserSession: true}); !d.Allowed {
		t.Errorf("the MFA session must be allowed: %+v", d)
	}
}

// A role whose trust policy requires MFA: assumed with a code (or from a session that has MFA), never
// without; the session it mints carries MFA on.
func TestAssumeRole_TrustPolicyRequiresMFA(t *testing.T) {
	h, sts := mfaWorld(t)
	serial, seed := newDevice(t, h, nil, iamAdmin, "alice-phone")
	enable(t, h, "alice", serial, seed)
	trustDoc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + testMgmt + `:root"},
	  "Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`
	sts.roles = trustDocRoles{"admin": {trust: []string{"*"}, doc: trustDoc}}
	alice := iam.Claims{Sub: "alice"}
	assume := func(c iam.Claims, kv ...string) *httptest.ResponseRecorder {
		return stsCall(sts, c, append([]string{"Action", "AssumeRole", "RoleArn", "arn:aws:iam::" + testMgmt + ":role/admin", "RoleSessionName", "s"}, kv...)...)
	}
	if w := assume(alice); w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("without MFA the trust policy refuses: %d %s", w.Code, w.Body.String())
	}
	if w := assume(alice, "SerialNumber", serial, "TokenCode", "000000"); w.Code != 403 || !strings.Contains(w.Body.String(), "invalid MFA one time pass code") {
		t.Fatalf("a wrong code: %d %s", w.Code, w.Body.String())
	}
	w := assume(alice, "SerialNumber", serial, "TokenCode", code(seed, 1))
	if w.Code != 200 {
		t.Fatalf("with MFA: %d %s", w.Code, w.Body.String())
	}
	if s := sessionOf(t, sts.minter, w.Body.String()); !s.MFA || s.RoleName != "admin" {
		t.Fatalf("the role session carries MFA: %+v", s)
	}
	// A user session obtained with MFA assumes without a new code, and its MFA carries over.
	mfaSession := iam.Claims{Sub: "alice", UserSession: true, MFA: iam.WithMFA(time.Now().Add(-time.Minute))}
	w = assume(mfaSession)
	if w.Code != 200 {
		t.Fatalf("from an MFA session: %d %s", w.Code, w.Body.String())
	}
	if s := sessionOf(t, sts.minter, w.Body.String()); !s.MFA || s.MFAAuthTime != mfaSession.MFA.AuthTime {
		t.Fatalf("the MFA (and its time) carries over: %+v", s)
	}
	// A role session presents no MFA device of its own.
	role := iam.Claims{Sub: "assumed-role/x/s", AssumedRole: "x"}
	if w := assume(role, "SerialNumber", serial, "TokenCode", code(seed, 2)); w.Code != 403 {
		t.Fatalf("a role session with a serial: %d %s", w.Code, w.Body.String())
	}
}

type trustDocRoles map[string]struct {
	trust []string
	doc   string
}

func (f trustDocRoles) Resolve(_ context.Context, name string) (resolvedRole, bool) {
	r, ok := f[name]
	return resolvedRole{trust: r.trust, groups: []string{"openinfra:users"}, trustDoc: r.doc}, ok
}
