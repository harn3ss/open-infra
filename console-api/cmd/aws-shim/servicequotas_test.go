package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func sqAccount(id string, overrides ...map[string]any) *unstructured.Unstructured {
	spec := map[string]any{"accountId": id, "namespaces": []any{"team-" + id[:4]}}
	if len(overrides) > 0 {
		var qs []any
		for _, o := range overrides {
			qs = append(qs, o)
		}
		spec["serviceQuotas"] = qs
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account", "metadata": map[string]any{"name": id}, "spec": spec}}
}

func sqTestHandler(t *testing.T, sarAllowed bool, objs ...runtime.Object) (*serviceQuotasHandler, *fake.Clientset) {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrAccounts: "AccountList"}, objs...)
	cs := csWithSAR(sarAllowed)
	h := newServiceQuotasHandler(cs, dyn, "open-infra-aws-shim", "default", nil, orgMgmt, "us-east-1", discardLogger())
	h.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return h, cs
}

func sqCall(t *testing.T, h *serviceQuotasHandler, claims iam.Claims, op string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	r.Header.Set("X-Amz-Target", serviceQuotasTargetPrefix+op)
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestServiceQuotas_AppliedAndAWSDefaults(t *testing.T) {
	member := "912345678901"
	h, _ := sqTestHandler(t, true, sqAccount(member,
		map[string]any{"serviceCode": "lambda", "quotaCode": "L-B99A9384", "value": float64(50)}))
	alice := iam.Claims{Sub: "alice", Account: member}

	_, out := sqCall(t, h, alice, "GetServiceQuota", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-B99A9384"})
	q, _ := out["Quota"].(map[string]any)
	if q["Value"] != float64(50) || q["QuotaName"] != "Concurrent executions" ||
		q["QuotaArn"] != "arn:aws:servicequotas:us-east-1:"+member+":lambda/L-B99A9384" {
		t.Fatalf("an approved quota must be the account's applied value: %v", out)
	}
	_, out = sqCall(t, h, alice, "GetAWSDefaultServiceQuota", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-B99A9384"})
	if q, _ = out["Quota"].(map[string]any); q["Value"] != float64(1000) || q["QuotaArn"] != "arn:aws:servicequotas:us-east-1::lambda/L-B99A9384" {
		t.Fatalf("AWS's default carries no account and AWS's value: %v", out)
	}
	// EC2's vCPU quota: AWS's default 5, the platform's applied default 64.
	_, out = sqCall(t, h, alice, "GetServiceQuota", map[string]any{"ServiceCode": "ec2", "QuotaCode": "L-1216C47A"})
	if q, _ = out["Quota"].(map[string]any); q["Value"] != float64(64) {
		t.Fatalf("ec2 applied %v", out)
	}
	_, out = sqCall(t, h, alice, "GetAWSDefaultServiceQuota", map[string]any{"ServiceCode": "ec2", "QuotaCode": "L-1216C47A"})
	if q, _ = out["Quota"].(map[string]any); q["Value"] != float64(5) {
		t.Fatalf("ec2 AWS default %v", out)
	}
	// Another account sees its own values: the defaults.
	_, out = sqCall(t, h, iam.Claims{Sub: "bob"}, "GetServiceQuota", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-B99A9384"})
	if q, _ = out["Quota"].(map[string]any); q["Value"] != float64(1000) || !strings.Contains(q["QuotaArn"].(string), ":"+orgMgmt+":") {
		t.Fatalf("the management account's quota %v", out)
	}
	w, out := sqCall(t, h, alice, "GetServiceQuota", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-00000000"})
	if w.Code != http.StatusBadRequest || out["__type"] != "NoSuchResourceException" {
		t.Fatalf("an unknown quota %d %v", w.Code, out)
	}
}

func TestServiceQuotas_ListServicesAndQuotas(t *testing.T) {
	h, _ := sqTestHandler(t, true)
	_, out := sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServices", map[string]any{})
	svcs, _ := out["Services"].([]any)
	if len(svcs) != 5 {
		t.Fatalf("services %v", out)
	}
	_, out = sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServiceQuotas", map[string]any{"ServiceCode": "ec2"})
	if qs, _ := out["Quotas"].([]any); len(qs) != 2 {
		t.Fatalf("ec2 quotas %v", out)
	}
	_, out = sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServices", map[string]any{"MaxResults": 2})
	if svcs, _ = out["Services"].([]any); len(svcs) != 2 || out["NextToken"] == nil {
		t.Fatalf("paged services %v", out)
	}
	_, out = sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServices", map[string]any{"MaxResults": 2, "NextToken": out["NextToken"]})
	if svcs, _ = out["Services"].([]any); len(svcs) != 2 {
		t.Fatalf("second page %v", out)
	}
	w, out := sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServices", map[string]any{"NextToken": "garbage"})
	if w.Code != http.StatusBadRequest || out["__type"] != "InvalidPaginationTokenException" {
		t.Fatalf("a bad token %d %v", w.Code, out)
	}
	w, out = sqCall(t, h, iam.Claims{Sub: "alice"}, "ListServiceQuotas", map[string]any{"ServiceCode": "redshift"})
	if w.Code != http.StatusBadRequest || out["__type"] != "NoSuchResourceException" {
		t.Fatalf("an unserved service %d %v", w.Code, out)
	}
}

// A request is recorded PENDING, a second for the same quota is refused while it is, a value at or under
// the applied one is refused, and once an operator applies the value it reads APPROVED.
func TestServiceQuotas_RequestIncreaseLifecycle(t *testing.T) {
	member := "912345678901"
	h, _ := sqTestHandler(t, true, sqAccount(member))
	alice := iam.Claims{Sub: "alice", Account: member}
	body := map[string]any{"ServiceCode": "dynamodb", "QuotaCode": "L-F98FE922", "DesiredValue": 3000}

	w, out := sqCall(t, h, alice, "RequestServiceQuotaIncrease", body)
	rq, _ := out["RequestedQuota"].(map[string]any)
	if w.Code != http.StatusOK || rq["Status"] != "PENDING" || rq["DesiredValue"] != float64(3000) || rq["Id"] == "" {
		t.Fatalf("request %d %v", w.Code, out)
	}
	id := rq["Id"].(string)
	if w, out = sqCall(t, h, alice, "RequestServiceQuotaIncrease", body); out["__type"] != "ResourceAlreadyExistsException" {
		t.Fatalf("a second pending request must be refused: %d %v", w.Code, out)
	}
	low := map[string]any{"ServiceCode": "s3", "QuotaCode": "L-DC2B2D3D", "DesiredValue": 100}
	if w, out = sqCall(t, h, alice, "RequestServiceQuotaIncrease", low); out["__type"] != "IllegalArgumentException" {
		t.Fatalf("a value under the applied one must be refused: %d %v", w.Code, out)
	}
	_, out = sqCall(t, h, alice, "ListRequestedServiceQuotaChangeHistory", map[string]any{"ServiceCode": "dynamodb"})
	if rqs, _ := out["RequestedQuotas"].([]any); len(rqs) != 1 {
		t.Fatalf("history %v", out)
	}
	// Another account does not see this account's requests.
	if _, out = sqCall(t, h, iam.Claims{Sub: "bob"}, "ListRequestedServiceQuotaChangeHistory", map[string]any{}); len(out["RequestedQuotas"].([]any)) != 0 {
		t.Fatalf("another account's history %v", out)
	}

	// The operator approves: the account's quota is set at least as high.
	acct := sqAccount(member, map[string]any{"serviceCode": "dynamodb", "quotaCode": "L-F98FE922", "value": float64(3000)})
	h.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrAccounts: "AccountList"}, acct)
	_, out = sqCall(t, h, alice, "GetRequestedServiceQuotaChange", map[string]any{"RequestId": id})
	if rq, _ = out["RequestedQuota"].(map[string]any); rq["Status"] != "APPROVED" {
		t.Fatalf("an applied value must read APPROVED: %v", out)
	}
	_, out = sqCall(t, h, alice, "GetServiceQuota", map[string]any{"ServiceCode": "dynamodb", "QuotaCode": "L-F98FE922"})
	if q, _ := out["Quota"].(map[string]any); q["Value"] != float64(3000) {
		t.Fatalf("applied %v", out)
	}
}

func TestServiceQuotas_Authorization(t *testing.T) {
	h, _ := sqTestHandler(t, false)
	w, out := sqCall(t, h, iam.Claims{Sub: "nobody"}, "ListServices", map[string]any{})
	if w.Code != http.StatusBadRequest || out["__type"] != "AccessDeniedException" {
		t.Fatalf("a caller RBAC refuses must be AccessDenied: %d %v", w.Code, out)
	}
	// A data-plane Deny on the one quota.
	h, _ = sqTestHandler(t, true)
	h.authz = userPolicy(dpAllow([]string{"servicequotas:*"}, "*"), dpDeny([]string{"servicequotas:RequestServiceQuotaIncrease"}, "Quota::lambda/L-B99A9384"))
	w, out = sqCall(t, h, testUser, "RequestServiceQuotaIncrease", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-B99A9384", "DesiredValue": 2000})
	if out["__type"] != "AccessDeniedException" {
		t.Fatalf("a Deny on the quota must refuse the request: %d %v", w.Code, out)
	}
	if w, out = sqCall(t, h, testUser, "GetServiceQuota", map[string]any{"ServiceCode": "lambda", "QuotaCode": "L-B99A9384"}); w.Code != http.StatusOK {
		t.Fatalf("reads stay allowed: %d %v", w.Code, out)
	}
	if w, out = sqCall(t, h, testUser, "PutServiceQuotaIncreaseRequestIntoTemplate", map[string]any{}); out["__type"] != "UnsupportedAPIEndpointException" {
		t.Fatalf("an unserved op %d %v", w.Code, out)
	}
}

// The Account composition renders the same defaults the front door answers (codes, names, values), so the
// ConfigMap in an account's home and GetServiceQuota never disagree.
func TestServiceQuotas_CompositionDefaultsMatch(t *testing.T) {
	raw, err := os.ReadFile("../../../platform/abstraction/account-composition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\(dict "s" "([a-z0-9-]+)" "c" "(L-[0-9A-F]{8})" "n" "([^"]+)" "v" ([0-9]+)\)`)
	found := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		q, ok := quotaFor(m[1], m[2])
		if !ok {
			t.Errorf("the composition renders %s/%s, which the front door does not serve", m[1], m[2])
			continue
		}
		v, _ := strconv.ParseFloat(m[4], 64)
		if q.QuotaName != m[3] || q.Default != v {
			t.Errorf("%s/%s: composition %q %v, front door %q %v", m[1], m[2], m[3], v, q.QuotaName, q.Default)
		}
		found[m[1]+"/"+m[2]] = true
	}
	for _, q := range serviceQuotas {
		if !found[q.ServiceCode+"/"+q.QuotaCode] {
			t.Errorf("%s/%s is served but not rendered by the Account composition", q.ServiceCode, q.QuotaCode)
		}
	}
}
