// CloudFront (SigV4 service `cloudfront`, REST-XML, API 2020-05-31): the invalidation calls on a
// distribution a CloudFormation stack created — CreateInvalidation, GetInvalidation and ListInvalidations,
// the last step of the standard static-site deploy (`aws s3 sync`, then `aws cloudfront create-invalidation`
// and `aws cloudfront wait invalidation-completed`).
//
// A distribution is a kind: StaticSite (cfn/translate_cloudfront.go): an nginx server that serves a copy
// of its bucket and re-syncs that copy every spec.syncIntervalSeconds. There is no edge cache, so the only
// stale content is the copy, and an invalidation's work is the next full sync of it. An invalidation is
// therefore Completed once the site reports a successful sync that STARTED after the invalidation was
// created — the sync loop records each successful sync's start time, and the site serves it on its status
// port (staticsite-composition.yaml) — so `wait invalidation-completed` returns once the site serves what
// was uploaded before the invalidation. Every invalidation covers the whole site, whatever its paths.
//
// The distribution id is the stack's Ref of the distribution (cfn/resource_attrs.go), found in the stack
// records. Invalidations are kept in the CloudFormation front door's record store (cfn-invalidations-<stack>,
// one data key per distribution) and removed with the stack.
//
// Accounts: a distribution is its stack's, and a stack is its account's (cfn_accounts.go). A request finds
// distributions among its own account's stack records alone, its invalidations are kept with that
// account's records, and a distribution's ARN names its account.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cloudFrontXMLNS = "http://cloudfront.amazonaws.com/doc/2020-05-31/"
	// cloudFrontDistributionType is the CloudFormation type whose Ref is a distribution id.
	cloudFrontDistributionType = "AWS::CloudFront::Distribution"
	// cfStatusPort is the StaticSite server's status port; GET /synced there is the start time (Unix
	// seconds) of the last successful sync of the site's copy of its bucket (staticsite-composition.yaml).
	cfStatusPort = 8081
	// cfSyncMargin is how many seconds after an invalidation's creation a sync must have started to count:
	// it absorbs clock skew between the shim and the site's node, and the whole-second resolution of both.
	cfSyncMargin = 2
	// cfMaxPaths is the most paths one invalidation batch may carry (AWS's limit for one request).
	cfMaxPaths = 3000
	// cfMaxKept is how many invalidations are kept per distribution; the oldest beyond it are forgotten.
	cfMaxKept = 100
)

// cfOps are the operations served; anything else under the API is an honest 501.
var cfOps = "CreateInvalidation, GetInvalidation, ListInvalidations, GetDistribution, GetDistributionConfig, " +
	"ListDistributions, GetCachePolicy, GetOriginRequestPolicy, GetResponseHeadersPolicy, GetOriginAccessControl, " +
	"GetCloudFrontOriginAccessIdentity"

// cfAPIVersionRe matches the API-version path segment (/2020-05-31/...).
var cfAPIVersionRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// cfDistributionIDRe matches a distribution id (E + upper-case letters and digits).
var cfDistributionIDRe = regexp.MustCompile(`^[A-Z0-9]{1,128}$`)

type cloudFrontHandler struct {
	cfn *cfnDoorway // the stack records the distributions are found in, and the authorization clients
	// client fetches a site's last-sync time from its status port.
	client *http.Client
	// statusURL is where a StaticSite's last-sync time is read: http://<site>-site.<ns>.svc.<suffix>:8081/synced.
	statusURL func(ns, site string) string
	now       func() time.Time
	newID     func() string
	logger    *slog.Logger
	mu        sync.Mutex // serializes this replica's writes to a record (the record's resourceVersion guards replicas)
}

func init() { accountScopedServices["cloudfront"] = true }

// distributionARN is the ARN of a distribution of the account the request acts in (CloudFront is global:
// no region).
func (h *cloudFrontHandler) distributionARN(ctx context.Context, id string) string {
	return "arn:aws:cloudfront::" + h.cfn.accountFor(ctx) + ":distribution/" + id
}

func newCloudFrontHandler(c *cfnDoorway, logger *slog.Logger) *cloudFrontHandler {
	suffix := c.svcSuffix
	if suffix == "" {
		suffix = "svc.cluster.local"
	}
	return &cloudFrontHandler{
		cfn:    c,
		client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		statusURL: func(ns, site string) string {
			return fmt.Sprintf("http://%s-site.%s.%s:%d/synced", site, ns, suffix, cfStatusPort)
		},
		now:    time.Now,
		newID:  newInvalidationID,
		logger: logger,
	}
}

// newInvalidationID is an invalidation id in AWS's shape: I + 13 upper-case letters and digits.
func newInvalidationID() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 13)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			n = big.NewInt(int64(time.Now().UnixNano() % int64(len(alphabet))))
		}
		b[i] = alphabet[n.Int64()]
	}
	return "I" + string(b)
}

func (h *cloudFrontHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeCFError(w, http.StatusForbidden, authCode(r, "SignatureDoesNotMatch"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."))
}

// writeCFError writes CloudFront's error shape (<ErrorResponse><Error>…</Error><RequestId>).
func writeCFError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("x-amz-request-id", requestID)
	writeQueryError(w, status, code, requestID, message, cloudFrontXMLNS)
}

// cfRoute is a parsed CloudFront request path: /<version>/distribution/<id>/invalidation[/<invalidation id>],
// or a read (cloudfront_read.go); resID is the id of the policy, origin access control or identity read.
type cfRoute struct {
	op, distID, invID, resID string
}

func parseCFRoute(method, path string) (cfRoute, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || !cfAPIVersionRe.MatchString(parts[0]) {
		return cfRoute{}, false
	}
	if method == http.MethodGet {
		if rt, ok := parseCFReadRoute(parts[1:]); ok {
			return rt, true
		}
	}
	if len(parts) < 4 || parts[1] != "distribution" || parts[3] != "invalidation" {
		return cfRoute{op: "?"}, true
	}
	rt := cfRoute{distID: parts[2]}
	switch {
	case len(parts) == 4 && method == http.MethodPost:
		rt.op = "CreateInvalidation"
	case len(parts) == 4 && method == http.MethodGet:
		rt.op = "ListInvalidations"
	case len(parts) == 5 && method == http.MethodGet:
		rt.op, rt.invID = "GetInvalidation", parts[4]
	default:
		rt.op = "?"
	}
	return rt, true
}

func (h *cloudFrontHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	rt, ok := parseCFRoute(r.Method, r.URL.Path)
	if !ok {
		writeCFError(w, http.StatusNotFound, "InvalidArgument", requestID, "The request path is not a CloudFront API path.")
		return
	}
	if rt.op == "?" {
		writeCFError(w, http.StatusNotImplemented, "NotImplemented", requestID,
			"This CloudFront operation is not fronted by the open-infra shim (served: "+cfOps+").")
		return
	}
	if cfReadOp(rt.op) {
		h.serveRead(w, r, claims, requestID, rt)
		return
	}
	// Authorization, as AWS evaluates it: cloudfront:<Action> on the distribution's ARN, before anything
	// reveals whether it exists — even that its id could not be one. For a User this is additive to the
	// RBAC check below; for an assumed role it is the whole, default-deny authority.
	if ok, reason := decide(r.Context(), r, h.cfn.authz, claims, "cloudfront:"+rt.op, "Distribution", rt.distID,
		scopedDataPlaneOnly(r.Context(), r, h.cfn.authz, claims, "cloudfront:"+rt.op, "Distribution", rt.distID)); !ok {
		writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
		return
	}
	if !cfDistributionIDRe.MatchString(rt.distID) {
		writeCFError(w, http.StatusNotFound, "NoSuchDistribution", requestID, "The specified distribution does not exist.")
		return
	}
	d, found, err := h.findDistribution(r.Context(), rt.distID)
	if err != nil {
		h.logger.Warn("cloudfront: reading the stack records failed", "error", err.Error())
		writeCFError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "The distribution could not be read; retry.")
		return
	}
	if !found {
		writeCFError(w, http.StatusNotFound, "NoSuchDistribution", requestID, "The specified distribution does not exist.")
		return
	}
	// A User needs rights on the distribution itself: the kind: StaticSite it is, in its namespace — the
	// object the invalidation is about, not the stack or the front door.
	verb := "get"
	if rt.op == "CreateInvalidation" {
		verb = "update"
	}
	if h.cfn.cs == nil && claims.AssumedRole == "" {
		writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, "CloudFront authorization is not configured on this shim")
		return
	}
	// In legacy a User also needs the RBAC verb on the distribution's kind: StaticSite; in enforce IAM policy
	// decided above.
	if !enforcing(r.Context(), h.cfn.authz, claims) {
		if allowed, reason := coarseOnly(r.Context(), h.cfn.cs, claims, verb, "openinfra.dev", "staticsites", d.ns, d.site)(); !allowed {
			writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
			return
		}
	}
	switch rt.op {
	case "CreateInvalidation":
		h.createInvalidation(w, r, d, requestID)
	case "GetInvalidation":
		h.getInvalidation(w, r, d, rt.invID, requestID)
	case "ListInvalidations":
		h.listInvalidations(w, r, d, requestID)
	}
}

// cfDistribution is a stack's distribution: its id, the stack it is in, and the kind: StaticSite it is.
type cfDistribution struct {
	id, stack, ns, site string
}

// findDistribution finds the distribution a stack reports as id (its Ref) among the stack records of the
// request's account.
func (h *cloudFrontHandler) findDistribution(ctx context.Context, id string) (*cfDistribution, bool, error) {
	st := h.cfn.recsFor(ctx)
	list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil, false, err
	}
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "cfn-stack-") {
			continue
		}
		rec, ok := st.stackRecord(&list.Items[i])
		if !ok {
			continue
		}
		if d := distributionIn(rec, id, h.cfn.nsFor(ctx)); d != nil {
			return d, true, nil
		}
	}
	return nil, false, nil
}

// distributionIn is the distribution with Ref id in rec, if rec has one (fallbackNS: a record from before the
// namespace was kept).
func distributionIn(rec *cfn.StackRecord, id, fallbackNS string) *cfDistribution {
	for _, res := range rec.Resources {
		if res.Type != cloudFrontDistributionType || res.Kind != "StaticSite" || res.PhysicalID != id || res.Name == "" {
			continue
		}
		ns := rec.Namespace
		if ns == "" {
			ns = fallbackNS
		}
		return &cfDistribution{id: id, stack: rec.Name, ns: ns, site: res.Name}
	}
	return nil
}

// --- records ---

// cfInvalidation is one invalidation as kept: Status is InProgress until the site has synced since
// CreateTime, then Completed.
type cfInvalidation struct {
	ID              string    `json:"id"`
	CallerReference string    `json:"callerReference"`
	Paths           []string  `json:"paths"`
	CreateTime      time.Time `json:"createTime"`
	Status          string    `json:"status"`
}

func invalidationsRecordName(stack string) string { return "cfn-invalidations-" + stack }

// load reads a distribution's invalidations, oldest first.
func (h *cloudFrontHandler) load(ctx context.Context, d *cfDistribution) ([]cfInvalidation, error) {
	st := h.cfn.recsFor(ctx)
	u, err := st.client().Get(ctx, invalidationsRecordName(d.stack), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []cfInvalidation
	if v := st.value(u, d.id); v != "" {
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// errCFNoWrite is returned by a mutate function that decided nothing should be written.
var errCFNoWrite = errors.New("no write")

// mutate read-modify-writes a distribution's invalidations (retried when the record changed meanwhile).
// fn returns the new list, or errCFNoWrite to leave the record as it is.
func (h *cloudFrontHandler) mutate(ctx context.Context, d *cfDistribution, fn func([]cfInvalidation) ([]cfInvalidation, error)) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.cfn.recsFor(ctx)
	name := invalidationsRecordName(d.stack)
	labels := map[string]any{"app.kubernetes.io/managed-by": "cfn-invalidations", "cfn.openinfra.dev/stack": d.stack}
	for attempt := 0; attempt < 5; attempt++ {
		u, err := st.client().Get(ctx, name, metav1.GetOptions{})
		exists := err == nil
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		var list []cfInvalidation
		data := map[string]string{}
		if exists {
			if v := st.value(u, d.id); v != "" {
				if err := json.Unmarshal([]byte(v), &list); err != nil {
					return err
				}
			}
			if m, ok := u.Object["data"].(map[string]any); ok {
				for k := range m {
					if k != d.id {
						data[k] = st.value(u, k)
					}
				}
			}
		}
		next, err := fn(list)
		if err != nil {
			return err
		}
		if len(next) > cfMaxKept {
			next = next[len(next)-cfMaxKept:]
		}
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		data[d.id] = string(b)
		obj := st.object(name, labels, nil, data)
		if exists {
			obj.SetResourceVersion(u.GetResourceVersion())
			if _, uerr := st.client().Update(ctx, obj, metav1.UpdateOptions{}); uerr == nil {
				return nil
			} else if !apierrors.IsConflict(uerr) {
				return uerr
			}
			continue
		}
		if _, cerr := st.client().Create(ctx, obj, metav1.CreateOptions{}); cerr == nil {
			return nil
		} else if !apierrors.IsAlreadyExists(cerr) {
			return cerr
		}
	}
	return fmt.Errorf("could not record the invalidation (the record kept changing)")
}

// --- status ---

// lastSync is the start time (Unix seconds) of the site's last successful sync, as the site reports it;
// ok is false when the site does not answer (it is starting, or it predates the status port).
func (h *cloudFrontHandler) lastSync(ctx context.Context, d *cfDistribution) (int64, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.statusURL(d.ns, d.site), nil)
	if err != nil {
		return 0, false
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Debug("cloudfront: the site's status port did not answer", "site", d.ns+"/"+d.site, "error", err.Error())
		return 0, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// syncedSince reports whether a sync that started at synced (Unix seconds) began after created.
func syncedSince(synced int64, created time.Time) bool {
	return synced >= created.Unix()+cfSyncMargin
}

// settle marks Completed the in-progress invalidations the site has synced past, and records that
// (best effort: a failed write is retried by the next read).
func (h *cloudFrontHandler) settle(ctx context.Context, d *cfDistribution, list []cfInvalidation) []cfInvalidation {
	pending := false
	for _, inv := range list {
		if inv.Status != "Completed" {
			pending = true
			break
		}
	}
	if !pending {
		return list
	}
	synced, ok := h.lastSync(ctx, d)
	if !ok {
		return list
	}
	done := map[string]bool{}
	for i := range list {
		if list[i].Status != "Completed" && syncedSince(synced, list[i].CreateTime) {
			list[i].Status = "Completed"
			done[list[i].ID] = true
		}
	}
	if len(done) == 0 {
		return list
	}
	err := h.mutate(ctx, d, func(cur []cfInvalidation) ([]cfInvalidation, error) {
		changed := false
		for i := range cur {
			if done[cur[i].ID] && cur[i].Status != "Completed" {
				cur[i].Status, changed = "Completed", true
			}
		}
		if !changed {
			return nil, errCFNoWrite
		}
		return cur, nil
	})
	if err != nil && !errors.Is(err, errCFNoWrite) {
		h.logger.Warn("cloudfront: recording a completed invalidation failed", "distribution", d.id, "error", err.Error())
	}
	return list
}

// --- operations ---

// cfBatchIn is a CreateInvalidation request body. Quantity is a string so a missing one is told apart.
type cfBatchIn struct {
	XMLName xml.Name `xml:"InvalidationBatch"`
	Paths   struct {
		Quantity *string `xml:"Quantity"`
		Items    struct {
			Path []string `xml:"Path"`
		} `xml:"Items"`
	} `xml:"Paths"`
	CallerReference string `xml:"CallerReference"`
}

type cfPathItemsXML struct {
	Path []string `xml:"Path"`
}

type cfPathsXML struct {
	Quantity int             `xml:"Quantity"`
	Items    *cfPathItemsXML `xml:"Items,omitempty"`
}

type cfBatchXML struct {
	Paths           cfPathsXML `xml:"Paths"`
	CallerReference string     `xml:"CallerReference"`
}

type cfInvalidationXML struct {
	XMLName           xml.Name   `xml:"Invalidation"`
	Xmlns             string     `xml:"xmlns,attr"`
	ID                string     `xml:"Id"`
	Status            string     `xml:"Status"`
	CreateTime        string     `xml:"CreateTime"`
	InvalidationBatch cfBatchXML `xml:"InvalidationBatch"`
}

type cfSummaryXML struct {
	ID         string `xml:"Id"`
	CreateTime string `xml:"CreateTime"`
	Status     string `xml:"Status"`
}

type cfSummaryItemsXML struct {
	Summary []cfSummaryXML `xml:"InvalidationSummary"`
}

type cfInvalidationListXML struct {
	XMLName     xml.Name           `xml:"InvalidationList"`
	Xmlns       string             `xml:"xmlns,attr"`
	Marker      string             `xml:"Marker"`
	NextMarker  string             `xml:"NextMarker,omitempty"`
	MaxItems    int                `xml:"MaxItems"`
	IsTruncated bool               `xml:"IsTruncated"`
	Quantity    int                `xml:"Quantity"`
	Items       *cfSummaryItemsXML `xml:"Items,omitempty"`
}

func cfTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func invalidationXML(inv cfInvalidation) cfInvalidationXML {
	out := cfInvalidationXML{Xmlns: cloudFrontXMLNS, ID: inv.ID, Status: inv.Status, CreateTime: cfTime(inv.CreateTime)}
	out.InvalidationBatch.CallerReference = inv.CallerReference
	out.InvalidationBatch.Paths.Quantity = len(inv.Paths)
	if len(inv.Paths) > 0 {
		out.InvalidationBatch.Paths.Items = &cfPathItemsXML{Path: inv.Paths}
	}
	return out
}

func writeCFXML(w http.ResponseWriter, status int, requestID string, v any) {
	out, err := xml.Marshal(v)
	if err != nil {
		writeCFError(w, http.StatusInternalServerError, "InternalError", requestID, "could not encode the response")
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// validatePaths checks an invalidation batch's paths as CloudFront does: each starts with "/", and a "*"
// wildcard may only end one.
func validatePaths(paths []string) bool {
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || len(p) > 4000 {
			return false
		}
		if i := strings.Index(p, "*"); i >= 0 && i != len(p)-1 {
			return false
		}
	}
	return true
}

func samePaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (h *cloudFrontHandler) location(r *http.Request, d *cfDistribution, invID string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/2020-05-31/distribution/" + d.id + "/invalidation/" + invID
}

func (h *cloudFrontHandler) createInvalidation(w http.ResponseWriter, r *http.Request, d *cfDistribution, requestID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(strings.TrimSpace(string(body))) == 0 {
		writeCFError(w, http.StatusBadRequest, "MissingBody", requestID, "This operation requires a body. Ensure that the body is present and the Content-Type header is set.")
		return
	}
	var in cfBatchIn
	if err := xml.Unmarshal(body, &in); err != nil {
		writeCFError(w, http.StatusBadRequest, "MalformedXML", requestID,
			"The XML document you provided was not well-formed or did not validate against our published schema.")
		return
	}
	paths := in.Paths.Items.Path
	if in.CallerReference == "" {
		writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID, "CallerReference is required.")
		return
	}
	if in.Paths.Quantity == nil {
		writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID, "Paths.Quantity is required.")
		return
	}
	if q, err := strconv.Atoi(strings.TrimSpace(*in.Paths.Quantity)); err != nil || q != len(paths) {
		writeCFError(w, http.StatusBadRequest, "InconsistentQuantities", requestID, "The value of Quantity and the size of Items don't match.")
		return
	}
	if len(paths) == 0 {
		writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID, "An invalidation batch needs at least one path.")
		return
	}
	if len(paths) > cfMaxPaths {
		writeCFError(w, http.StatusRequestEntityTooLarge, "BatchTooLarge", requestID, "Invalidation batch specified is too large.")
		return
	}
	if !validatePaths(paths) {
		writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID,
			"Your request contains one or more invalid invalidation paths: each path starts with / and may end with a single * wildcard.")
		return
	}
	var out cfInvalidation
	conflict := false
	err = h.mutate(r.Context(), d, func(list []cfInvalidation) ([]cfInvalidation, error) {
		// The same CallerReference again is the same request: the earlier invalidation answers it, as on
		// AWS; with different paths it is refused.
		for _, inv := range list {
			if inv.CallerReference == in.CallerReference {
				if !samePaths(inv.Paths, paths) {
					conflict = true
				}
				out = inv
				return nil, errCFNoWrite
			}
		}
		out = cfInvalidation{ID: h.newID(), CallerReference: in.CallerReference, Paths: paths,
			CreateTime: h.now().UTC(), Status: "InProgress"}
		return append(list, out), nil
	})
	if err != nil && !errors.Is(err, errCFNoWrite) {
		h.logger.Warn("cloudfront: recording an invalidation failed", "distribution", d.id, "error", err.Error())
		writeCFError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "The invalidation could not be recorded; retry.")
		return
	}
	if conflict {
		writeCFError(w, http.StatusConflict, "InvalidationBatchAlreadyExists", requestID,
			"The CallerReference you attempted to create the invalidation with is already being used.")
		return
	}
	w.Header().Set("Location", h.location(r, d, out.ID))
	writeCFXML(w, http.StatusCreated, requestID, invalidationXML(out))
}

func (h *cloudFrontHandler) getInvalidation(w http.ResponseWriter, r *http.Request, d *cfDistribution, invID, requestID string) {
	list, err := h.load(r.Context(), d)
	if err != nil {
		writeCFError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "The invalidation could not be read; retry.")
		return
	}
	idx := -1
	for i := range list {
		if list[i].ID == invID {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeCFError(w, http.StatusNotFound, "NoSuchInvalidation", requestID, "The specified invalidation does not exist.")
		return
	}
	one := h.settle(r.Context(), d, []cfInvalidation{list[idx]})
	writeCFXML(w, http.StatusOK, requestID, invalidationXML(one[0]))
}

func (h *cloudFrontHandler) listInvalidations(w http.ResponseWriter, r *http.Request, d *cfDistribution, requestID string) {
	list, err := h.load(r.Context(), d)
	if err != nil {
		writeCFError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "The invalidations could not be read; retry.")
		return
	}
	list = h.settle(r.Context(), d, list)
	// Newest first, as CloudFront lists them; Marker is the id the page starts after.
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreateTime.After(list[j].CreateTime) })
	q := r.URL.Query()
	marker := q.Get("Marker")
	maxItems := 100
	if v := q.Get("MaxItems"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID, "MaxItems must be a positive integer.")
			return
		}
		if n < maxItems {
			maxItems = n
		}
	}
	start := 0
	if marker != "" {
		start = len(list)
		for i := range list {
			if list[i].ID == marker {
				start = i + 1
				break
			}
		}
	}
	page := list[start:]
	out := cfInvalidationListXML{Xmlns: cloudFrontXMLNS, Marker: marker, MaxItems: maxItems}
	if len(page) > maxItems {
		page = page[:maxItems]
		out.IsTruncated, out.NextMarker = true, page[len(page)-1].ID
	}
	out.Quantity = len(page)
	if len(page) > 0 {
		out.Items = &cfSummaryItemsXML{}
		for _, inv := range page {
			out.Items.Summary = append(out.Items.Summary, cfSummaryXML{ID: inv.ID, CreateTime: cfTime(inv.CreateTime), Status: inv.Status})
		}
	}
	writeCFXML(w, http.StatusOK, requestID, out)
}
