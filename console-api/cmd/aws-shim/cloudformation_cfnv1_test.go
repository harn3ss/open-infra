package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const cfnV1Tmpl = `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Metadata:
      AWS::CloudFormation::Init: { config: { commands: { hello: { command: "echo hi" } } } }
    Properties: { ImageId: ubuntu-24.04 }
  Ready:
    Type: AWS::CloudFormation::WaitConditionHandle
`

type cfnV1Fixture struct {
	h      *cfnDoorway
	ap     *impersonatingApplier
	signer *identitySigner
	dyn    *dynamicfake.FakeDynamicClient
	now    *time.Time
}

// Two stacks, each with one running VM: web (its instance web-web) and other (other-box).
func newCFNV1Fixture(t *testing.T) *cfnV1Fixture {
	t.Helper()
	h, ap := cfnTestDoorway(t, "")
	h.signals = &signalStore{h: h}
	h.callerDyn = func(string, []string) (dynamic.Interface, error) { return ap.caller, nil }
	s, _, now := testIDSigner(t)
	h.identity = s
	dyn := h.shimDyn.(*dynamicfake.FakeDynamicClient)
	ctx := context.Background()
	for _, rec := range []*cfn.StackRecord{
		{Name: "web", Namespace: "default", Status: "CREATE_IN_PROGRESS", Template: cfnV1Tmpl, CreatedAt: "2026-11-03T10:00:00Z",
			Resources: []cfn.StackResource{{LogicalID: "Web", APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: "web-web",
				Type: "AWS::EC2::Instance", Status: "CREATE_COMPLETE", Timestamp: "2026-11-03T10:05:00Z"}}},
		{Name: "other", Namespace: "default", Status: "CREATE_IN_PROGRESS", Template: cfnV1Tmpl,
			Resources: []cfn.StackResource{{LogicalID: "Web", APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: "other-box"}}},
	} {
		if err := ap.putRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	addVM(t, dyn, "default", "web-web", "uid-web", "Running")
	addVM(t, dyn, "default", "other-box", "uid-other", "Running")
	return &cfnV1Fixture{h: h, ap: ap, signer: s, dyn: dyn, now: now}
}

// cfnV1Auth is the Authorization header aws-cfn-bootstrap writes for a document signed by s.
func cfnV1Auth(t *testing.T, s *identitySigner, f identityFields, notAfter time.Time) string {
	t.Helper()
	doc := identityDocument(f, notAfter)
	sig, _, err := s.sign(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	return "CFN_V1 " + base64.StdEncoding.EncodeToString(doc) + ":" + strings.ReplaceAll(sig, "\n", "")
}

func (fx *cfnV1Fixture) fields(uid string) identityFields {
	return identityFields{AccountID: "000000000000", Region: "us-east-1", AvailabilityZone: "us-east-1a", Architecture: "x86_64",
		ImageID: imageIDForOS("ubuntu-24.04"), InstanceID: instanceIDForUID(uid), PendingTime: "2026-11-03T10:00:00Z"}
}

func (fx *cfnV1Fixture) auth(t *testing.T, uid string) string {
	return cfnV1Auth(t, fx.signer, fx.fields(uid), fx.now.Add(time.Hour))
}

// call sends what cfn-bootstrap sends: GET, the parameters in the query string, ContentType=JSON.
func (fx *cfnV1Fixture) call(auth string, params url.Values) *httptest.ResponseRecorder {
	params.Set("ContentType", "JSON")
	params.Set("Version", "2010-05-15")
	req := httptest.NewRequest(http.MethodGet, "https://cloudformation.us-east-1.amazonaws.com/?"+params.Encode(), nil)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	fx.h.serveCFNV1(rr, req, "req")
	return rr
}

func signalParams(stack string) url.Values {
	return url.Values{"Action": {"SignalResource"}, "StackName": {stack}, "LogicalResourceId": {"Web"}, "UniqueId": {"i-1"}, "Status": {"SUCCESS"}}
}

func jsonErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error struct{ Code, Message string }
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("not a JSON error (%d): %s", rr.Code, rr.Body)
	}
	return e.Error.Code
}

// An instance's own document lets cfn-signal signal its stack and cfn-init read its metadata, in the JSON
// cfn-bootstrap reads.
func TestCFNV1_InstanceReachesItsOwnStack(t *testing.T) {
	fx := newCFNV1Fixture(t)
	auth := fx.auth(t, "uid-web")
	if rr := fx.call(auth, signalParams("web")); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"SignalResourceResponse"`) {
		t.Fatalf("SignalResource: %d %s", rr.Code, rr.Body)
	}
	sigs, err := fx.h.signals.Signals(context.Background(), "web", "Web")
	if err != nil || len(sigs) != 1 || sigs[0].UniqueID != "i-1" {
		t.Fatalf("the signal is recorded: %+v %v", sigs, err)
	}
	// A stack ARN works as its name does (cfn-init --stack ${AWS::StackId}).
	arn := "arn:aws:cloudformation:us-east-1:000000000000:stack/web/0000"
	rr := fx.call(auth, url.Values{"Action": {"DescribeStackResource"}, "StackName": {arn}, "LogicalResourceId": {"Web"}})
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("DescribeStackResource: %d %s", rr.Code, rr.Body)
	}
	var out struct {
		DescribeStackResourceResponse struct {
			DescribeStackResourceResult struct {
				StackResourceDetail map[string]any
			}
		}
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	d := out.DescribeStackResourceResponse.DescribeStackResourceResult.StackResourceDetail
	meta, _ := d["Metadata"].(string)
	if _, isNum := d["LastUpdatedTimestamp"].(float64); !isNum || d["LogicalResourceId"] != "Web" || d["ResourceType"] != "AWS::EC2::Instance" ||
		!strings.Contains(meta, "AWS::CloudFormation::Init") {
		t.Fatalf("StackResourceDetail as cfn-init reads it: %v", d)
	}
	if rr := fx.call(auth, url.Values{"Action": {"DescribeStackResources"}, "StackName": {"web"}}); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), `"StackResources":[`) {
		t.Fatalf("DescribeStackResources: %d %s", rr.Code, rr.Body)
	}
}

// Every way a document must fail: forged, tampered, expired, over-long, another account, another stack, a
// stack that does not exist, a VM re-created under the same name, a VM that is not running, a claim that
// points at another VM's composite, another action, and a call through the LAN Ingress.
func TestCFNV1_Refusals(t *testing.T) {
	fx := newCFNV1Fixture(t)
	ctx := context.Background()
	denied := func(name string, rr *httptest.ResponseRecorder) {
		t.Helper()
		if rr.Code != http.StatusForbidden || jsonErrorCode(t, rr) != "AccessDenied" {
			t.Errorf("%s: want 403 AccessDenied, got %d %s", name, rr.Code, rr.Body)
		}
	}
	// Forged: the right document, signed by a key that is not the platform's.
	forger, _, _ := testIDSigner(t)
	denied("a forged signature", fx.call(cfnV1Auth(t, forger, fx.fields("uid-web"), fx.now.Add(time.Hour)), signalParams("web")))
	// Tampered: another instance id under the web instance's signature.
	good := fx.auth(t, "uid-web")
	doc, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(good, "CFN_V1 ")[:strings.Index(strings.TrimPrefix(good, "CFN_V1 "), ":")])
	sig := good[strings.LastIndex(good, ":")+1:]
	tampered := strings.Replace(string(doc), instanceIDForUID("uid-web"), instanceIDForUID("uid-other"), 1)
	denied("a tampered document", fx.call("CFN_V1 "+base64.StdEncoding.EncodeToString([]byte(tampered))+":"+sig, signalParams("other")))
	denied("garbage", fx.call("CFN_V1 not-a-document", signalParams("web")))
	// Expired, and valid for longer than one is issued for.
	denied("an expired document", fx.call(cfnV1Auth(t, fx.signer, fx.fields("uid-web"), fx.now.Add(-time.Second)), signalParams("web")))
	denied("an over-long document", fx.call(cfnV1Auth(t, fx.signer, fx.fields("uid-web"), fx.now.Add(48*time.Hour)), signalParams("web")))
	// Another account's document.
	f := fx.fields("uid-web")
	f.AccountID = "111111111111"
	denied("another account", fx.call(cfnV1Auth(t, fx.signer, f, fx.now.Add(time.Hour)), signalParams("web")))
	// The web instance may not touch the other stack, nor one that does not exist — with the same answer.
	rrOther := fx.call(good, signalParams("other"))
	denied("another stack's resource", rrOther)
	denied("another stack's metadata", fx.call(good, url.Values{"Action": {"DescribeStackResource"}, "StackName": {"other"}, "LogicalResourceId": {"Web"}}))
	rrNone := fx.call(good, signalParams("nope"))
	denied("a stack that does not exist", rrNone)
	if strings.Contains(rrNone.Body.String(), "does not exist") {
		t.Errorf("a missing stack must answer as a foreign one does: %s", rrNone.Body)
	}
	// Another action than cfn-bootstrap's three.
	denied("CreateStack", fx.call(good, url.Values{"Action": {"CreateStack"}, "StackName": {"web"}}))
	denied("DeleteStack", fx.call(good, url.Values{"Action": {"DeleteStack"}, "StackName": {"web"}}))
	// Through the LAN Ingress: not served at all.
	req := httptest.NewRequest(http.MethodGet, "https://shim/?"+signalParams("web").Encode(), nil)
	req.Header.Set("Authorization", good)
	req.Header.Set("X-Forwarded-For", "192.0.2.10")
	rr := httptest.NewRecorder()
	fx.h.serveCFNV1(rr, req, "req")
	if rr.Code != http.StatusNotFound {
		t.Errorf("through the LAN Ingress: %d", rr.Code)
	}
	// The VM stops: its document no longer acts.
	vmi, _ := fx.dyn.Resource(vmiGVRTest).Namespace("default").Get(ctx, "web-web", metav1.GetOptions{})
	vmi.Object["status"] = map[string]any{"phase": "Succeeded"}
	_, _ = fx.dyn.Resource(vmiGVRTest).Namespace("default").Update(ctx, vmi, metav1.UpdateOptions{})
	rrStopped := fx.call(good, signalParams("web"))
	denied("a VM that is not running", rrStopped)
	if !strings.Contains(rrStopped.Body.String(), "not running") {
		t.Errorf("say why: %s", rrStopped.Body)
	}
	// The VM is deleted and re-created under the same name: a new composite, a new instance id; the old
	// document is refused, the new VM's accepted.
	_ = fx.dyn.Resource(vmClaimGVR).Namespace("default").Delete(ctx, "web-web", metav1.DeleteOptions{})
	_ = fx.dyn.Resource(vmXRGVR).Delete(ctx, "web-web-xr", metav1.DeleteOptions{})
	_ = fx.dyn.Resource(vmiGVRTest).Namespace("default").Delete(ctx, "web-web", metav1.DeleteOptions{})
	denied("a deleted VM's document", fx.call(good, signalParams("web")))
	addVM(t, fx.dyn, "default", "web-web", "uid-web-2", "Running")
	denied("a re-created VM's predecessor's document", fx.call(good, signalParams("web")))
	if rr := fx.call(fx.auth(t, "uid-web-2"), signalParams("web")); rr.Code != http.StatusOK {
		t.Errorf("the re-created VM's own document: %d %s", rr.Code, rr.Body)
	}
}

// A stack whose VM claim names another VM's composite in spec.resourceRef does not gain that VM's
// document: membership is decided by the composite bound to the claim.
func TestCFNV1_ClaimNamingAnotherCompositeIsNotThatInstance(t *testing.T) {
	fx := newCFNV1Fixture(t)
	ctx := context.Background()
	addVM(t, fx.dyn, "default", "evil-box", "", "Running", "web-web-xr") // resourceRef -> the web VM's composite
	if err := fx.ap.putRecord(ctx, &cfn.StackRecord{Name: "evil", Namespace: "default", Status: "CREATE_IN_PROGRESS", Template: cfnV1Tmpl,
		Resources: []cfn.StackResource{{LogicalID: "Web", APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: "evil-box"}}}); err != nil {
		t.Fatal(err)
	}
	if rr := fx.call(fx.auth(t, "uid-web"), signalParams("evil")); rr.Code != http.StatusForbidden {
		t.Fatalf("the web instance's document must not reach the evil stack: %d %s", rr.Code, rr.Body)
	}
}

// The router hands a CFN_V1 call to the CloudFormation front door (before: an S3-shaped AccessDenied, since
// it is not SigV4).
func TestRouter_RoutesCFNV1ToCloudFormation(t *testing.T) {
	fx := newCFNV1Fixture(t)
	rt := &serviceRouter{services: map[string]awsService{"cloudformation": fx.h}, logger: discardLogger()}
	params := url.Values{"Action": {"DescribeStackResource"}, "StackName": {"web"}, "LogicalResourceId": {"Web"}, "ContentType": {"JSON"}}
	req := httptest.NewRequest(http.MethodGet, "https://cloudformation.us-east-1.amazonaws.com/?"+params.Encode(), nil)
	req.Header.Set("Authorization", fx.auth(t, "uid-web"))
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "DescribeStackResourceResponse") {
		t.Fatalf("CFN_V1 through the router: %d %s", rr.Code, rr.Body)
	}
}

// `cfn-signal --role` / `cfn-init --role` (SigV4) also send GET + ContentType=JSON: the parameters are read
// from the query string and the answer is JSON (before: MissingAction, in XML).
func TestCFN_GETQueryJSONForSigV4Callers(t *testing.T) {
	fx := newCFNV1Fixture(t)
	params := url.Values{"Action": {"DescribeStackResource"}, "StackName": {"web"}, "LogicalResourceId": {"Web"}, "ContentType": {"JSON"}}
	req := httptest.NewRequest(http.MethodGet, "https://cloudformation.us-east-1.amazonaws.com/?"+params.Encode(), nil)
	rr := serveWith(fx.h, req, iam.Claims{Sub: "openinfra:alice", Groups: []string{"openinfra:admins"}})
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" || !strings.Contains(rr.Body.String(), `"LastUpdatedTimestamp":`) {
		t.Fatalf("GET + ContentType=JSON: %d %s %s", rr.Code, rr.Header().Get("Content-Type"), rr.Body)
	}
	params.Set("StackName", "nope")
	req = httptest.NewRequest(http.MethodGet, "https://shim/?"+params.Encode(), nil)
	rr = serveWith(fx.h, req, iam.Claims{Sub: "openinfra:alice", Groups: []string{"openinfra:admins"}})
	if rr.Code != http.StatusBadRequest || jsonErrorCode(t, rr) != "ValidationError" {
		t.Fatalf("errors are JSON too: %d %s", rr.Code, rr.Body)
	}
	// Without ContentType=JSON the answer stays XML.
	params.Del("ContentType")
	params.Set("StackName", "web")
	req = httptest.NewRequest(http.MethodGet, "https://shim/?"+params.Encode(), nil)
	rr = serveWith(fx.h, req, iam.Claims{Sub: "openinfra:alice", Groups: []string{"openinfra:admins"}})
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Body.String(), "<?xml") {
		t.Fatalf("XML by default: %d %s", rr.Code, rr.Body)
	}
}
