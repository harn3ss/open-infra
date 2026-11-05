// AWS Service Quotas front door for the aws-shim: each account's quotas (JSON 1.1, X-Amz-Target
// ServiceQuotasV20190624.<Op>):
//   - ListServices, ListServiceQuotas, GetServiceQuota (the account's applied values);
//   - ListAWSDefaultServiceQuotas, GetAWSDefaultServiceQuota (AWS's own defaults);
//   - RequestServiceQuotaIncrease, GetRequestedServiceQuotaChange, ListRequestedServiceQuotaChangeHistory,
//     ListRequestedServiceQuotaChangeHistoryByQuota.
//
// An account's applied value is the platform's default (serviceQuotas below; AWS's quota codes and names)
// unless its kind: Account sets spec.serviceQuotas — an operator's approved increase. A request is recorded
// PENDING (in the ConfigMap servicequota-requests, the shim's namespace) for an operator to approve by
// setting that value; it reads APPROVED once the applied value reaches what was asked, as AWS reports a
// request its support approved. Lambda's concurrent executions is enforced for a member account: the Account
// composition labels each of its namespaces openinfra.dev/function-concurrency, which the compliance
// component turns into a ResourceQuota on that namespace's burstable function pods. The others are reported
// as the account's quota.
//
// Authorized as every front door: the coarse impersonated SubjectAccessReview, then the data-plane policy
// check as servicequotas:<Op> on Quota::<ServiceCode>/<QuotaCode> (Quota::* for an operation that names
// none).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const serviceQuotasTargetPrefix = "ServiceQuotasV20190624."

// quotaRequestsConfigMap holds every account's quota-increase requests (one data key per account).
const quotaRequestsConfigMap = "servicequota-requests"

// serviceQuota is one quota the platform reports: AWS's code, name and default, and this platform's
// default applied value. Kept in step with the defaults the Account composition renders
// (platform/abstraction/account-composition.yaml) by TestServiceQuotas_CompositionDefaultsMatch.
type serviceQuota struct {
	ServiceCode, ServiceName, QuotaCode, QuotaName string
	// AWSDefault is AWS's default (GetAWSDefaultServiceQuota); Default is the value an account gets here.
	AWSDefault, Default float64
	Global              bool // an account-wide quota (S3's buckets), not a regional one
	Enforced            bool // the platform caps usage at it (Lambda concurrency)
	Description         string
}

// serviceQuotas are the quotas served, verified against AWS's service-quota tables
// (docs.aws.amazon.com/general/latest/gr/<service>.html).
var serviceQuotas = []serviceQuota{
	{"cloudformation", "AWS CloudFormation", "L-0485CB21", "Stacks", 2000, 2000, false, false,
		"The maximum number of active stacks; an active stack is any stack with a status other than DELETE_COMPLETE"},
	{"dynamodb", "Amazon DynamoDB", "L-F98FE922", "Maximum number of tables", 2500, 2500, false, false,
		"The maximum number of tables that can be created per region."},
	{"ec2", "Amazon Elastic Compute Cloud (Amazon EC2)", "L-0263D0A3", "EC2-VPC Elastic IPs", 5, 5, false, false,
		"The maximum number of Elastic IP addresses that you can allocate for EC2-VPC in this Region."},
	{"ec2", "Amazon Elastic Compute Cloud (Amazon EC2)", "L-1216C47A", "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances", 5, 64, false, false,
		"The maximum number of vCPUs assigned to the Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances."},
	{"lambda", "AWS Lambda", "L-B99A9384", "Concurrent executions", 1000, 1000, false, true,
		"The maximum number of events that functions can process simultaneously in the current Region."},
	{"s3", "Amazon Simple Storage Service (Amazon S3)", "L-DC2B2D3D", "General purpose buckets", 10000, 10000, true, false,
		"The number of Amazon S3 general purpose buckets that you can create in an account"},
}

func quotaFor(service, code string) (serviceQuota, bool) {
	for _, q := range serviceQuotas {
		if q.ServiceCode == service && q.QuotaCode == code {
			return q, true
		}
	}
	return serviceQuota{}, false
}

func knownService(service string) bool {
	for _, q := range serviceQuotas {
		if q.ServiceCode == service {
			return true
		}
	}
	return false
}

type serviceQuotasHandler struct {
	cs         kubernetes.Interface
	dyn        dynamic.Interface // the shim's own client: reads kind: Account (its spec.serviceQuotas)
	ns         string            // the shim's namespace: the requests ConfigMap
	authz      *dataplaneauthz.Checker
	authzNS    string
	management string
	region     string
	accountOf  func(iam.Claims) string
	now        func() time.Time
	logger     *slog.Logger
}

func newServiceQuotasHandler(cs kubernetes.Interface, dyn dynamic.Interface, ns, authzNS string,
	authz *dataplaneauthz.Checker, management, region string, logger *slog.Logger) *serviceQuotasHandler {
	h := &serviceQuotasHandler{cs: cs, dyn: dyn, ns: ns, authz: authz, authzNS: authzNS, management: management,
		region: region, now: time.Now, logger: logger}
	h.accountOf = func(c iam.Claims) string {
		if c.Account == "" {
			return h.management
		}
		return c.Account
	}
	return h
}

func (h *serviceQuotasHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeSQError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func writeSQError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "Message": message})
}

func writeSQJSON(w http.ResponseWriter, requestID string, body any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// sqRequest is the JSON body of a Service Quotas call (the fields the served operations take).
type sqRequest struct {
	ServiceCode  string   `json:"ServiceCode"`
	QuotaCode    string   `json:"QuotaCode"`
	DesiredValue *float64 `json:"DesiredValue"`
	RequestID    string   `json:"RequestId"`
	Status       string   `json:"Status"`
	MaxResults   int      `json:"MaxResults"`
	NextToken    string   `json:"NextToken"`
}

// quotaRequest is a recorded RequestServiceQuotaIncrease (AWS's RequestedServiceQuotaChange).
type quotaRequest struct {
	ID           string  `json:"Id"`
	ServiceCode  string  `json:"ServiceCode"`
	QuotaCode    string  `json:"QuotaCode"`
	DesiredValue float64 `json:"DesiredValue"`
	// Status is PENDING as recorded; an operator may set DENIED. APPROVED is read from the applied value.
	Status    string  `json:"Status"`
	Created   float64 `json:"Created"`
	Updated   float64 `json:"LastUpdated"`
	Requester string  `json:"Requester"`
}

var sqOps = map[string]bool{"ListServices": true, "ListServiceQuotas": true, "GetServiceQuota": true,
	"ListAWSDefaultServiceQuotas": true, "GetAWSDefaultServiceQuota": true, "RequestServiceQuotaIncrease": true,
	"GetRequestedServiceQuotaChange": true, "ListRequestedServiceQuotaChangeHistory": true,
	"ListRequestedServiceQuotaChangeHistoryByQuota": true}

func (h *serviceQuotasHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), serviceQuotasTargetPrefix)
	if !sqOps[op] {
		writeSQError(w, http.StatusBadRequest, "UnsupportedAPIEndpointException", requestID,
			"Service Quotas "+op+" is not implemented by the open-infra shim.")
		return
	}
	var in sqRequest
	if body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)); len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID, "The request body is not valid JSON.")
			return
		}
	}
	// The resource the call names: one quota, or every quota (Quota::*).
	resID := "*"
	switch op {
	case "GetServiceQuota", "GetAWSDefaultServiceQuota", "RequestServiceQuotaIncrease",
		"ListRequestedServiceQuotaChangeHistoryByQuota":
		if in.ServiceCode == "" || in.QuotaCode == "" {
			writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID, "ServiceCode and QuotaCode are required.")
			return
		}
		resID = in.ServiceCode + "/" + in.QuotaCode
	}
	verb := "get"
	if op == "RequestServiceQuotaIncrease" {
		verb = "create"
	}
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, ""); !allowed {
		h.audit(ctx, op, resID, "deny", reason)
		writeSQError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "You don't have permissions to access this resource.")
		return
	}
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "servicequotas:"+op, "Quota", resID, r); denied {
		h.audit(ctx, op, resID, "deny", reason)
		writeSQError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "You don't have permissions to access this resource.")
		return
	}
	acct := h.accountOf(claims)
	switch op {
	case "ListServices":
		h.listServices(w, requestID, in)
	case "ListServiceQuotas", "ListAWSDefaultServiceQuotas":
		h.listQuotas(ctx, w, requestID, in, acct, op == "ListAWSDefaultServiceQuotas")
	case "GetServiceQuota", "GetAWSDefaultServiceQuota":
		h.getQuota(ctx, w, requestID, in, acct, op == "GetAWSDefaultServiceQuota")
	case "RequestServiceQuotaIncrease":
		h.requestIncrease(ctx, w, requestID, in, acct, claims)
	case "GetRequestedServiceQuotaChange":
		h.getRequest(ctx, w, requestID, in, acct)
	case "ListRequestedServiceQuotaChangeHistory", "ListRequestedServiceQuotaChangeHistoryByQuota":
		h.listRequests(ctx, w, requestID, in, acct, op == "ListRequestedServiceQuotaChangeHistoryByQuota")
	}
	h.audit(ctx, op, resID, "allow", "")
}

// applied is the account's applied quota values where its kind: Account overrides the defaults.
func (h *serviceQuotasHandler) applied(ctx context.Context, acct string) (map[string]float64, error) {
	out := map[string]float64{}
	if h.dyn == nil {
		return out, nil
	}
	a, err := h.dyn.Resource(gvrAccounts).Get(ctx, acct, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, nil // an account with no Account object (the install before its bootstrap): the defaults
	}
	if err != nil {
		return nil, err
	}
	spec, _ := a.Object["spec"].(map[string]any)
	items, _ := spec["serviceQuotas"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		svc, _ := m["serviceCode"].(string)
		code, _ := m["quotaCode"].(string)
		if svc == "" || code == "" {
			continue
		}
		switch v := m["value"].(type) {
		case float64:
			out[svc+"/"+code] = v
		case int64:
			out[svc+"/"+code] = float64(v)
		case int:
			out[svc+"/"+code] = float64(v)
		}
	}
	return out, nil
}

func (h *serviceQuotasHandler) quotaARN(q serviceQuota, acct string) string {
	if acct == "" { // an AWS default carries no account
		return fmt.Sprintf("arn:aws:servicequotas:%s::%s/%s", h.region, q.ServiceCode, q.QuotaCode)
	}
	return fmt.Sprintf("arn:aws:servicequotas:%s:%s:%s/%s", h.region, acct, q.ServiceCode, q.QuotaCode)
}

// quotaJSON is AWS's ServiceQuota shape: the account's applied value, or AWS's default (awsDefault).
func (h *serviceQuotasHandler) quotaJSON(q serviceQuota, acct string, applied map[string]float64, awsDefault bool) map[string]any {
	v, arnAcct := q.Default, acct
	if awsDefault {
		v, arnAcct = q.AWSDefault, ""
	} else if o, ok := applied[q.ServiceCode+"/"+q.QuotaCode]; ok {
		v = o
	}
	return map[string]any{
		"ServiceCode": q.ServiceCode, "ServiceName": q.ServiceName, "QuotaArn": h.quotaARN(q, arnAcct),
		"QuotaCode": q.QuotaCode, "QuotaName": q.QuotaName, "Value": v, "Unit": "None", "Adjustable": true,
		"GlobalQuota": q.Global, "QuotaAppliedAtLevel": "ACCOUNT", "Description": q.Description,
	}
}

func (h *serviceQuotasHandler) listServices(w http.ResponseWriter, requestID string, in sqRequest) {
	seen := map[string]bool{}
	var all []any
	for _, q := range serviceQuotas {
		if !seen[q.ServiceCode] {
			seen[q.ServiceCode] = true
			all = append(all, map[string]any{"ServiceCode": q.ServiceCode, "ServiceName": q.ServiceName})
		}
	}
	page, next, err := sqPage(all, in.MaxResults, in.NextToken)
	if err != nil {
		writeSQError(w, http.StatusBadRequest, "InvalidPaginationTokenException", requestID, err.Error())
		return
	}
	body := map[string]any{"Services": page}
	if next != "" {
		body["NextToken"] = next
	}
	writeSQJSON(w, requestID, body)
}

func (h *serviceQuotasHandler) listQuotas(ctx context.Context, w http.ResponseWriter, requestID string, in sqRequest, acct string, awsDefault bool) {
	if in.ServiceCode == "" {
		writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID, "ServiceCode is required.")
		return
	}
	if !knownService(in.ServiceCode) {
		writeSQError(w, http.StatusBadRequest, "NoSuchResourceException", requestID, "The request failed because the specified service does not exist.")
		return
	}
	applied, err := h.applied(ctx, acct)
	if err != nil {
		writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not read the account's quotas; retry.")
		return
	}
	var all []any
	for _, q := range serviceQuotas {
		if q.ServiceCode == in.ServiceCode && (in.QuotaCode == "" || in.QuotaCode == q.QuotaCode) {
			all = append(all, h.quotaJSON(q, acct, applied, awsDefault))
		}
	}
	page, next, err := sqPage(all, in.MaxResults, in.NextToken)
	if err != nil {
		writeSQError(w, http.StatusBadRequest, "InvalidPaginationTokenException", requestID, err.Error())
		return
	}
	body := map[string]any{"Quotas": page}
	if next != "" {
		body["NextToken"] = next
	}
	writeSQJSON(w, requestID, body)
}

func (h *serviceQuotasHandler) getQuota(ctx context.Context, w http.ResponseWriter, requestID string, in sqRequest, acct string, awsDefault bool) {
	q, ok := quotaFor(in.ServiceCode, in.QuotaCode)
	if !ok {
		writeSQError(w, http.StatusBadRequest, "NoSuchResourceException", requestID, "The request failed because the specified quota does not exist.")
		return
	}
	applied, err := h.applied(ctx, acct)
	if err != nil {
		writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not read the account's quotas; retry.")
		return
	}
	writeSQJSON(w, requestID, map[string]any{"Quota": h.quotaJSON(q, acct, applied, awsDefault)})
}

// requests reads an account's recorded requests (and the ConfigMap, for an update).
func (h *serviceQuotasHandler) requests(ctx context.Context, acct string) ([]quotaRequest, *corev1.ConfigMap, error) {
	cm, err := h.cs.CoreV1().ConfigMaps(h.ns).Get(ctx, quotaRequestsConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []quotaRequest
	if raw := cm.Data[acct+".json"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, nil, fmt.Errorf("the account's recorded requests are malformed: %w", err)
		}
	}
	return out, cm, nil
}

// status is a request's status as AWS reports it: APPROVED once the applied value reaches the desired one,
// else as recorded (PENDING, or DENIED by an operator).
func (h *serviceQuotasHandler) status(rq quotaRequest, applied map[string]float64) string {
	if rq.Status == "DENIED" || rq.Status == "NOT_APPROVED" {
		return rq.Status
	}
	q, ok := quotaFor(rq.ServiceCode, rq.QuotaCode)
	if !ok {
		return "INVALID_REQUEST"
	}
	v := q.Default
	if o, ok := applied[rq.ServiceCode+"/"+rq.QuotaCode]; ok {
		v = o
	}
	if v >= rq.DesiredValue {
		return "APPROVED"
	}
	return "PENDING"
}

func (h *serviceQuotasHandler) requestJSON(rq quotaRequest, acct string, applied map[string]float64) map[string]any {
	q, _ := quotaFor(rq.ServiceCode, rq.QuotaCode)
	return map[string]any{
		"Id": rq.ID, "ServiceCode": rq.ServiceCode, "ServiceName": q.ServiceName, "QuotaCode": rq.QuotaCode,
		"QuotaName": q.QuotaName, "DesiredValue": rq.DesiredValue, "Status": h.status(rq, applied),
		"Created": rq.Created, "LastUpdated": rq.Updated, "Requester": rq.Requester, "QuotaArn": h.quotaARN(q, acct),
		"GlobalQuota": q.Global, "Unit": "None", "QuotaRequestedAtLevel": "ACCOUNT",
	}
}

func (h *serviceQuotasHandler) requestIncrease(ctx context.Context, w http.ResponseWriter, requestID string, in sqRequest, acct string, claims iam.Claims) {
	q, ok := quotaFor(in.ServiceCode, in.QuotaCode)
	if !ok {
		writeSQError(w, http.StatusBadRequest, "NoSuchResourceException", requestID, "The request failed because the specified quota does not exist.")
		return
	}
	if in.DesiredValue == nil {
		writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID, "DesiredValue is required.")
		return
	}
	applied, err := h.applied(ctx, acct)
	if err != nil {
		writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not read the account's quotas; retry.")
		return
	}
	cur := q.Default
	if o, ok := applied[q.ServiceCode+"/"+q.QuotaCode]; ok {
		cur = o
	}
	if *in.DesiredValue <= cur {
		writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID,
			fmt.Sprintf("The quota value requested (%s) must be greater than the current quota value (%s).",
				strconv.FormatFloat(*in.DesiredValue, 'f', -1, 64), strconv.FormatFloat(cur, 'f', -1, 64)))
		return
	}
	for attempt := 0; attempt < 5; attempt++ {
		reqs, cm, err := h.requests(ctx, acct)
		if err != nil {
			writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not record the request; retry.")
			return
		}
		for _, rq := range reqs {
			if rq.ServiceCode == q.ServiceCode && rq.QuotaCode == q.QuotaCode && h.status(rq, applied) == "PENDING" {
				writeSQError(w, http.StatusBadRequest, "ResourceAlreadyExistsException", requestID,
					"A request for this quota is already pending ("+rq.ID+").")
				return
			}
		}
		now := float64(h.now().Unix())
		rq := quotaRequest{ID: fmt.Sprintf("%x", h.now().UnixNano()), ServiceCode: q.ServiceCode, QuotaCode: q.QuotaCode,
			DesiredValue: *in.DesiredValue, Status: "PENDING", Created: now, Updated: now,
			Requester: sqRequester(claims, acct)}
		reqs = append(reqs, rq)
		raw, _ := json.Marshal(reqs)
		if cm == nil {
			cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: quotaRequestsConfigMap, Namespace: h.ns,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "aws-shim"}}, Data: map[string]string{acct + ".json": string(raw)}}
			_, err = h.cs.CoreV1().ConfigMaps(h.ns).Create(ctx, cm, metav1.CreateOptions{})
		} else {
			if cm.Data == nil {
				cm.Data = map[string]string{}
			}
			cm.Data[acct+".json"] = string(raw)
			_, err = h.cs.CoreV1().ConfigMaps(h.ns).Update(ctx, cm, metav1.UpdateOptions{})
		}
		if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
			continue // another request was recorded meanwhile: re-read and retry
		}
		if err != nil {
			writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not record the request; retry.")
			return
		}
		h.logger.Info("service quota increase requested", "account", acct, "service", q.ServiceCode, "quota", q.QuotaCode,
			"desired", *in.DesiredValue, "id", rq.ID)
		writeSQJSON(w, requestID, map[string]any{"RequestedQuota": h.requestJSON(rq, acct, applied)})
		return
	}
	writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not record the request; retry.")
}

func sqRequester(c iam.Claims, acct string) string {
	if c.AssumedRole != "" {
		return fmt.Sprintf(`{"accountId":"%s","callerArn":"arn:aws:sts::%s:assumed-role/%s"}`, acct, acct, c.AssumedRole)
	}
	return fmt.Sprintf(`{"accountId":"%s","callerArn":"arn:aws:iam::%s:user/%s"}`, acct, acct, c.Sub)
}

func (h *serviceQuotasHandler) getRequest(ctx context.Context, w http.ResponseWriter, requestID string, in sqRequest, acct string) {
	if in.RequestID == "" {
		writeSQError(w, http.StatusBadRequest, "IllegalArgumentException", requestID, "RequestId is required.")
		return
	}
	reqs, _, err := h.requests(ctx, acct)
	applied, aerr := h.applied(ctx, acct)
	if err != nil || aerr != nil {
		writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not read the request; retry.")
		return
	}
	for _, rq := range reqs {
		if rq.ID == in.RequestID {
			writeSQJSON(w, requestID, map[string]any{"RequestedQuota": h.requestJSON(rq, acct, applied)})
			return
		}
	}
	writeSQError(w, http.StatusBadRequest, "NoSuchResourceException", requestID, "The request failed because the specified request does not exist.")
}

func (h *serviceQuotasHandler) listRequests(ctx context.Context, w http.ResponseWriter, requestID string, in sqRequest, acct string, byQuota bool) {
	reqs, _, err := h.requests(ctx, acct)
	applied, aerr := h.applied(ctx, acct)
	if err != nil || aerr != nil {
		writeSQError(w, http.StatusInternalServerError, "ServiceException", requestID, "Service Quotas could not read the requests; retry.")
		return
	}
	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].Created > reqs[j].Created }) // newest first
	var all []any
	for _, rq := range reqs {
		if in.ServiceCode != "" && rq.ServiceCode != in.ServiceCode {
			continue
		}
		if byQuota && rq.QuotaCode != in.QuotaCode {
			continue
		}
		j := h.requestJSON(rq, acct, applied)
		if in.Status != "" && j["Status"] != in.Status {
			continue
		}
		all = append(all, j)
	}
	page, next, err := sqPage(all, in.MaxResults, in.NextToken)
	if err != nil {
		writeSQError(w, http.StatusBadRequest, "InvalidPaginationTokenException", requestID, err.Error())
		return
	}
	body := map[string]any{"RequestedQuotas": page}
	if next != "" {
		body["NextToken"] = next
	}
	writeSQJSON(w, requestID, body)
}

// sqPage pages items by an opaque offset token, at most max (default and cap 100) per page.
func sqPage(items []any, max int, token string) ([]any, string, error) {
	if max <= 0 || max > 100 {
		max = 100
	}
	start := 0
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		n, cerr := strconv.Atoi(strings.TrimPrefix(string(raw), "sq:"))
		if err != nil || cerr != nil || n < 0 || n > len(items) || !strings.HasPrefix(string(raw), "sq:") {
			return nil, "", fmt.Errorf("the pagination token is not valid")
		}
		start = n
	}
	end := start + max
	if end >= len(items) {
		if items[start:] == nil {
			return []any{}, "", nil
		}
		return items[start:], "", nil
	}
	return items[start:end], base64.RawURLEncoding.EncodeToString([]byte("sq:" + strconv.Itoa(end))), nil
}

func (h *serviceQuotasHandler) audit(ctx context.Context, op, resource, decision, detail string) {
	args := []any{"service", "servicequotas", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if resource != "" {
		args = append(args, "resource", resource)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "servicequotas audit", args...)
}
