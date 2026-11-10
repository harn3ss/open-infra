// AWS Organizations front door for the aws-shim: the accounts of this install (kind: Account,
// organizations.openinfra.dev — platform/abstraction/account-xrd.yaml).
//
// The install's own account is the organization's management account; every other kind: Account is a
// member account, its namespaces labeled into it (console-api/internal/accounts). Served, as AWS shapes them
// (JSON 1.1, X-Amz-Target AWSOrganizationsV20161128.<Op>):
//   - DescribeOrganization, ListRoots;
//   - ListAccounts, ListAccountsForParent, DescribeAccount;
//   - CreateAccount (a new member account: a kind: Account whose home namespace the composition creates),
//     DescribeCreateAccountStatus.
//
// Only the management account calls Organizations, as on AWS; a member account's caller is AccessDenied.
// Authorized as every front door: the coarse impersonated SubjectAccessReview on the Account kind, then
// the data-plane policy check as organizations:<Op> on Account::<id> (Account::* for an operation that names
// none). Accounts are read and created AS THE CALLER (an impersonating client), so the Kubernetes API applies
// the caller's own authority too and the shim holds no rights on accounts of its own.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const organizationsTargetPrefix = "AWSOrganizationsV20161128."

var gvrAccounts = schema.GroupVersionResource{Group: "organizations.openinfra.dev", Version: "v1", Resource: "accounts"}

const (
	annAccountName   = "openinfra.dev/account-name"   // the account's name as CreateAccount was given it
	annCreateRequest = "openinfra.dev/create-request" // the CreateAccount request that made the account
	labelCreatedBy   = "openinfra.dev/created-by"
)

type organizationsHandler struct {
	cs         kubernetes.Interface
	callerDyn  func(user string, groups []string) (dynamic.Interface, error)
	shimDyn    dynamic.Interface // the shim's own client: reads accounts (get, list), never writes them
	authz      *dataplaneauthz.Checker
	authzNS    string
	management string // the install's account id: the organization's management account
	// accountOf is the account a caller acts in: its Claims' account, the management account when they
	// carry none.
	accountOf func(iam.Claims) string
	// namespaceExists reports whether a namespace of that name exists (CreateAccount picks a free home).
	namespaceExists func(ctx context.Context, name string) (bool, error)
	now             func() time.Time
	logger          *slog.Logger
}

func newOrganizationsHandler(cs kubernetes.Interface, cfg *rest.Config, authzNS string, authz *dataplaneauthz.Checker,
	management string, logger *slog.Logger) *organizationsHandler {
	h := &organizationsHandler{cs: cs, authz: authz, authzNS: authzNS, management: management, logger: logger,
		now: time.Now}
	h.accountOf = func(c iam.Claims) string {
		if c.Account == "" {
			return h.management
		}
		return c.Account
	}
	if cfg != nil {
		if d, err := dynamic.NewForConfig(cfg); err == nil {
			h.shimDyn = d
		}
		h.callerDyn = func(user string, groups []string) (dynamic.Interface, error) {
			icfg := rest.CopyConfig(cfg)
			icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
			return dynamic.NewForConfig(icfg)
		}
	}
	h.namespaceExists = func(ctx context.Context, name string) (bool, error) {
		_, err := h.cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	}
	return h
}

func (h *organizationsHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeOrgError(w, http.StatusForbidden, authCode(r, "InvalidSignatureException"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."))
}

func writeOrgError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "Message": message})
}

func writeOrgJSON(w http.ResponseWriter, requestID string, body any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// orgRequest is the JSON body of an Organizations call (the fields the served operations take).
type orgRequest struct {
	AccountID              string `json:"AccountId"`
	ParentID               string `json:"ParentId"`
	AccountName            string `json:"AccountName"`
	Email                  string `json:"Email"`
	RoleName               string `json:"RoleName"`
	CreateAccountRequestID string `json:"CreateAccountRequestId"`
	MaxResults             int    `json:"MaxResults"`
	NextToken              string `json:"NextToken"`
}

func (h *organizationsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), organizationsTargetPrefix)
	var in orgRequest
	if body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)); len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "The request body is not valid JSON.")
			return
		}
	}
	switch op {
	case "DescribeOrganization", "ListRoots", "ListAccounts", "ListAccountsForParent", "DescribeAccount",
		"CreateAccount", "DescribeCreateAccountStatus":
	default:
		writeOrgError(w, http.StatusBadRequest, "UnsupportedAPIEndpointException", requestID,
			"Organizations "+op+" is not implemented by the open-infra shim.")
		return
	}
	// Organizations is the management account's: a member account's principal is refused, as on AWS.
	if acct := h.accountOf(claims); acct != h.management {
		h.audit(ctx, op, "", "deny", "not the management account")
		writeOrgError(w, http.StatusBadRequest, "AccessDeniedException", requestID,
			"You don't have permissions to access this resource: only the organization's management account calls AWS Organizations.")
		return
	}
	verb := "list"
	resID := "*"
	switch op {
	case "DescribeAccount":
		verb, resID = "get", in.AccountID
	case "CreateAccount":
		verb = "create"
	}
	action := "organizations:" + op
	named := ""
	if resID != "*" {
		named = resID
	}
	allowed, reason := decide(ctx, r, h.authz, claims, action, "Account", named, func() (bool, string) {
		if ok, why := iam.CanDo(ctx, h.cs, claims, verb, gvrAccounts.Group, gvrAccounts.Resource, "", ""); !ok {
			return false, why
		}
		if denied, why := deniedByDataPlane(ctx, h.authz, claims, action, "Account", resID, r); denied {
			return false, why
		}
		return true, ""
	})
	if !allowed {
		h.audit(ctx, op, resID, "deny", reason)
		writeOrgError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "You don't have permissions to access this resource.")
		return
	}
	dyn, err := h.client(ctx, claims, op)
	if err != nil {
		writeOrgError(w, http.StatusInternalServerError, "ServiceException", requestID, "Organizations is not available on this shim.")
		return
	}
	switch op {
	case "DescribeOrganization":
		h.describeOrganization(ctx, w, requestID, dyn)
	case "ListRoots":
		writeOrgJSON(w, requestID, map[string]any{"Roots": []any{h.root()}})
	case "ListAccounts":
		h.listAccounts(ctx, w, requestID, dyn, in, "")
	case "ListAccountsForParent":
		if in.ParentID == "" {
			writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "ParentId is required.")
			return
		}
		h.listAccounts(ctx, w, requestID, dyn, in, in.ParentID)
	case "DescribeAccount":
		h.describeAccount(ctx, w, requestID, dyn, in.AccountID)
	case "CreateAccount":
		h.createAccount(ctx, w, requestID, dyn, in)
	case "DescribeCreateAccountStatus":
		h.describeCreateAccountStatus(ctx, w, requestID, dyn, in.CreateAccountRequestID)
	}
	h.audit(ctx, op, resID, "allow", "")
}

// client is the cluster client an allowed call is made with. In legacy a call acts with the caller's
// Kubernetes authority, its RBAC being its permission. In enforce IAM policy has already decided the call:
// a read is what it allowed, made with the shim's own read-only client — the caller's RBAC (generated
// from the same policy by the IAM compiler, and not there before it runs) is never a second decision on
// a read IAM policy allowed — and CreateAccount still acts as the caller, in its account identity.
func (h *organizationsHandler) client(ctx context.Context, claims iam.Claims, op string) (dynamic.Interface, error) {
	if op != "CreateAccount" && enforcing(ctx, h.authz, claims) {
		if h.shimDyn == nil {
			return nil, fmt.Errorf("the shim's client is not configured")
		}
		return h.shimDyn, nil
	}
	user, groups, ok := callerIdentity(ctx, h.authz, claims)
	if !ok || h.callerDyn == nil {
		return nil, fmt.Errorf("no caller identity or client")
	}
	return h.callerDyn(user, groups)
}

// orgID is the organization's id (o-…), derived from the management account so it is stable.
func (h *organizationsHandler) orgID() string { return "o-" + base36(h.management, 10) }

// rootID is the organization root's id (r-…).
func (h *organizationsHandler) rootID() string { return "r-" + base36("root/"+h.management, 4) }

func base36(seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	s := strconv.FormatUint(binary.BigEndian.Uint64(sum[:8]), 36)
	for len(s) < n {
		s = "0" + s
	}
	return s[:n]
}

func (h *organizationsHandler) orgARN(resource string) string {
	return "arn:aws:organizations::" + h.management + ":" + resource
}

func (h *organizationsHandler) root() map[string]any {
	return map[string]any{"Id": h.rootID(), "Arn": h.orgARN("root/" + h.orgID() + "/" + h.rootID()),
		"Name": "Root", "PolicyTypes": []any{}}
}

func (h *organizationsHandler) describeOrganization(ctx context.Context, w http.ResponseWriter, requestID string, dyn dynamic.Interface) {
	email := ""
	if obj, err := dyn.Resource(gvrAccounts).Get(ctx, h.management, metav1.GetOptions{}); err == nil {
		email, _, _ = unstructured.NestedString(obj.Object, "spec", "email")
	}
	writeOrgJSON(w, requestID, map[string]any{"Organization": map[string]any{
		"Id":                   h.orgID(),
		"Arn":                  h.orgARN("organization/" + h.orgID()),
		"FeatureSet":           "ALL",
		"MasterAccountArn":     h.orgARN("account/" + h.orgID() + "/" + h.management),
		"MasterAccountId":      h.management,
		"MasterAccountEmail":   email,
		"AvailablePolicyTypes": []any{},
	}})
}

// orgAccount is one account as Organizations describes it.
type orgAccount struct {
	ID, Name, Email, Status, JoinedMethod, Parent string
	Joined                                        time.Time
}

func (a orgAccount) json(h *organizationsHandler) map[string]any {
	return map[string]any{
		"Id": a.ID, "Arn": h.orgARN("account/" + h.orgID() + "/" + a.ID), "Email": a.Email, "Name": a.Name,
		"Status": a.Status, "JoinedMethod": a.JoinedMethod, "JoinedTimestamp": float64(a.Joined.Unix()),
	}
}

func accountFrom(obj *unstructured.Unstructured) orgAccount {
	spec, _ := obj.Object["spec"].(map[string]any)
	str := func(k string) string { v, _ := spec[k].(string); return v }
	a := orgAccount{ID: str("accountId"), Email: str("email"), Parent: str("parent"), Status: accounts.StatusActive,
		JoinedMethod: "INVITED", Joined: obj.GetCreationTimestamp().Time}
	if obj.GetLabels()[labelCreatedBy] == "aws-shim" {
		a.JoinedMethod = "CREATED"
	}
	if s, _ := spec["suspended"].(bool); s {
		a.Status = accounts.StatusSuspended
	}
	a.Name = obj.GetAnnotations()[annAccountName]
	if a.Name == "" {
		a.Name = str("alias")
	}
	if a.Name == "" {
		a.Name = a.ID
	}
	return a
}

// allAccounts are the organization's accounts: every kind: Account, and the management account even when
// no object names it yet (an install before accounts). Sorted by id, the management account first.
func (h *organizationsHandler) allAccounts(ctx context.Context, dyn dynamic.Interface) ([]orgAccount, error) {
	l, err := dyn.Resource(gvrAccounts).List(ctx, metav1.ListOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	var out []orgAccount
	seenMgmt := false
	if l != nil {
		for i := range l.Items {
			a := accountFrom(&l.Items[i])
			if a.ID == "" {
				continue
			}
			if a.ID == h.management {
				seenMgmt = true
			}
			out = append(out, a)
		}
	}
	if !seenMgmt {
		out = append(out, orgAccount{ID: h.management, Name: h.management, Status: accounts.StatusActive, JoinedMethod: "INVITED"})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == h.management) != (out[j].ID == h.management) {
			return out[i].ID == h.management
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (h *organizationsHandler) listAccounts(ctx context.Context, w http.ResponseWriter, requestID string, dyn dynamic.Interface, in orgRequest, parent string) {
	if in.MaxResults < 0 || in.MaxResults > 20 {
		writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "MaxResults must be between 1 and 20.")
		return
	}
	all, err := h.allAccounts(ctx, dyn)
	if err != nil {
		h.accountsError(w, requestID, err)
		return
	}
	if parent != "" {
		var under []orgAccount
		known := parent == h.rootID()
		for _, a := range all {
			p := a.Parent
			if p == "" {
				p = h.rootID()
			}
			if p == parent {
				under = append(under, a)
				known = true
			}
		}
		if !known {
			writeOrgError(w, http.StatusBadRequest, "ParentNotFoundException", requestID, "We can't find a root or OU with the ParentId that you specified.")
			return
		}
		all = under
	}
	start := 0
	if in.NextToken != "" {
		b, derr := base64.RawURLEncoding.DecodeString(in.NextToken)
		n, perr := strconv.Atoi(string(b))
		if derr != nil || perr != nil || n < 0 || n > len(all) {
			writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "The NextToken is not valid.")
			return
		}
		start = n
	}
	size := in.MaxResults
	if size == 0 {
		size = 20
	}
	end := min(start+size, len(all))
	page := make([]any, 0, end-start)
	for _, a := range all[start:end] {
		page = append(page, a.json(h))
	}
	out := map[string]any{"Accounts": page}
	if end < len(all) {
		out["NextToken"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	writeOrgJSON(w, requestID, out)
}

func (h *organizationsHandler) describeAccount(ctx context.Context, w http.ResponseWriter, requestID string, dyn dynamic.Interface, id string) {
	if !accounts.ValidAccountID(id) {
		writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "AccountId must be a 12-digit account id.")
		return
	}
	all, err := h.allAccounts(ctx, dyn)
	if err != nil {
		h.accountsError(w, requestID, err)
		return
	}
	for _, a := range all {
		if a.ID == id {
			writeOrgJSON(w, requestID, map[string]any{"Account": a.json(h)})
			return
		}
	}
	writeOrgError(w, http.StatusBadRequest, "AccountNotFoundException", requestID, "You specified an account that doesn't exist.")
}

var (
	orgAccountNameRe = regexp.MustCompile(`^[\x{0020}-\x{007E}]{1,50}$`)
	orgEmailRe       = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$`)
	nsUnsafeRe       = regexp.MustCompile(`[^a-z0-9-]+`)
	aliasRe          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`)
)

// homeNamespaceBase is the home namespace a new account named name gets: its name lowercased, other
// characters as hyphens, trimmed to a DNS label.
func homeNamespaceBase(name string) string {
	s := strings.Trim(nsUnsafeRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 55 {
		s = strings.Trim(s[:55], "-")
	}
	if s == "" {
		s = "account"
	}
	return s
}

// createRequestID is the CreateAccount request id of the account accountID (car-…): it names the account,
// so DescribeCreateAccountStatus finds it.
func createRequestID(accountID string) string {
	return "car-" + accountID + base36("car/"+accountID, 8)
}

func (h *organizationsHandler) createAccount(ctx context.Context, w http.ResponseWriter, requestID string, dyn dynamic.Interface, in orgRequest) {
	if !orgAccountNameRe.MatchString(in.AccountName) {
		writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "AccountName must be 1 to 50 printable characters.")
		return
	}
	if len(in.Email) > 64 || !orgEmailRe.MatchString(in.Email) {
		writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID, "Email must be a valid email address of up to 64 characters.")
		return
	}
	if in.RoleName != "" && in.RoleName != "OrganizationAccountAccessRole" {
		writeOrgError(w, http.StatusBadRequest, "InvalidInputException", requestID,
			"RoleName: the member account's administrator role is OrganizationAccountAccessRole; another name is not supported.")
		return
	}
	all, err := h.allAccounts(ctx, dyn)
	if err != nil {
		h.accountsError(w, requestID, err)
		return
	}
	for _, a := range all {
		if strings.EqualFold(a.Email, in.Email) {
			// As AWS reports it: the request fails, with the reason in its status.
			writeOrgJSON(w, requestID, map[string]any{"CreateAccountStatus": map[string]any{
				"Id": "car-" + base36("failed/"+in.Email+"/"+h.now().UTC().Format(time.RFC3339Nano), 12), "AccountName": in.AccountName,
				"State": "FAILED", "FailureReason": "EMAIL_ALREADY_EXISTS", "RequestedTimestamp": float64(h.now().Unix()),
			}})
			return
		}
	}
	// A new account's home is a new namespace: never an existing one, never a platform one.
	base := homeNamespaceBase(in.AccountName)
	home := ""
	for n := 0; n < 20 && home == ""; n++ {
		cand := base
		if n > 0 {
			cand = base + "-" + strconv.Itoa(n+1)
		}
		if accounts.IsPlatformNamespace(cand) {
			continue
		}
		exists, err := h.namespaceExists(ctx, cand)
		if err != nil {
			writeOrgError(w, http.StatusInternalServerError, "ServiceException", requestID, "Organizations could not check the account's namespace; retry.")
			return
		}
		if !exists {
			home = cand
		}
	}
	if home == "" {
		writeOrgError(w, http.StatusBadRequest, "ConstraintViolationException", requestID, "No free namespace for an account of this name; choose another AccountName.")
		return
	}
	taken := map[string]bool{}
	for _, a := range all {
		taken[a.ID] = true
	}
	id, err := accounts.NewAccountID(home, func(id string) bool { return taken[id] || id == h.management })
	if err != nil {
		writeOrgError(w, http.StatusBadRequest, "ConstraintViolationException", requestID, err.Error())
		return
	}
	spec := map[string]any{"accountId": id, "email": in.Email, "namespaces": []any{home}}
	if alias := homeNamespaceBase(in.AccountName); aliasRe.MatchString(alias) && len(alias) >= 3 {
		spec["alias"] = alias
	}
	car := createRequestID(id)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "organizations.openinfra.dev/v1",
		"kind":       "Account",
		"metadata": map[string]any{
			"name":        id,
			"labels":      map[string]any{labelCreatedBy: "aws-shim"},
			"annotations": map[string]any{annAccountName: in.AccountName, annCreateRequest: car},
		},
		"spec": spec,
	}}
	if _, err := dyn.Resource(gvrAccounts).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		h.accountsError(w, requestID, err)
		return
	}
	writeOrgJSON(w, requestID, map[string]any{"CreateAccountStatus": map[string]any{
		"Id": car, "AccountName": in.AccountName, "State": "IN_PROGRESS", "RequestedTimestamp": float64(h.now().Unix()),
	}})
}

var createRequestRe = regexp.MustCompile(`^car-([0-9]{12})[0-9a-z]{8}$`)

func (h *organizationsHandler) describeCreateAccountStatus(ctx context.Context, w http.ResponseWriter, requestID string, dyn dynamic.Interface, car string) {
	m := createRequestRe.FindStringSubmatch(car)
	notFound := func() {
		writeOrgError(w, http.StatusBadRequest, "CreateAccountStatusNotFoundException", requestID,
			"We can't find a create account request with the CreateAccountRequestId that you specified.")
	}
	if m == nil || createRequestID(m[1]) != car {
		notFound()
		return
	}
	obj, err := dyn.Resource(gvrAccounts).Get(ctx, m[1], metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		notFound()
		return
	}
	if err != nil {
		h.accountsError(w, requestID, err)
		return
	}
	if obj.GetAnnotations()[annCreateRequest] != car {
		notFound()
		return
	}
	st := map[string]any{"Id": car, "AccountName": obj.GetAnnotations()[annAccountName], "AccountId": m[1],
		"RequestedTimestamp": float64(obj.GetCreationTimestamp().Unix())}
	if ready, _, _ := unstructured.NestedBool(obj.Object, "status", "ready"); ready {
		st["State"] = "SUCCEEDED"
		st["CompletedTimestamp"] = float64(h.now().Unix())
	} else {
		st["State"] = "IN_PROGRESS"
	}
	writeOrgJSON(w, requestID, map[string]any{"CreateAccountStatus": st})
}

// accountsError answers a Kubernetes error on the Account kind in Organizations' dialect.
func (h *organizationsHandler) accountsError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case apierrors.IsForbidden(err):
		writeOrgError(w, http.StatusBadRequest, "AccessDeniedException", requestID, "You don't have permissions to access this resource.")
	case apierrors.IsAlreadyExists(err):
		writeOrgError(w, http.StatusBadRequest, "ConcurrentModificationException", requestID, "The target of the operation is currently being modified by a different request. Try again later.")
	case apierrors.IsInvalid(err):
		writeOrgError(w, http.StatusBadRequest, "ConstraintViolationException", requestID, "The account does not meet the organization's constraints.")
	default:
		h.logger.Error("organizations: accounts", "error", err.Error())
		writeOrgError(w, http.StatusInternalServerError, "ServiceException", requestID, "AWS Organizations can't complete your request because of an internal service error. Try again later.")
	}
}

func (h *organizationsHandler) audit(ctx context.Context, op, resource, decision, detail string) {
	args := []any{"service", "organizations", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if resource != "" {
		args = append(args, "resource", resource)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "organizations audit", args...)
}
