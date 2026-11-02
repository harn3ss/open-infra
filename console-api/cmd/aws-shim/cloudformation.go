// AWS CloudFormation front door for the aws-shim — the cloudformation.* API over the
// existing owned cfn engine (github.com/harn3ss/open-infra/cfn: plan/deploy/changeset/update/destroy/
// drift + the resource-type->kind mapping table).
//
// Speaks the AWS query protocol (form-encoded request, XML response; API version 2010-05-15) — the
// classic CloudFormation wire shape (it has not migrated to JSON).
//
// Authority — the way AWS does it: a stack operation provisions under the CALLER's own authority (AWS
// CloudFormation's default: the calling principal's IAM permissions), never the shim's. This is realized
// by driving the engine through an impersonatingApplier (see cfn_applier.go): every resource op runs as
// the caller (Impersonate-User openinfra:<sub> + their groups), so the API server's RBAC + Cedar
// admission bound the whole stack to exactly the caller's authority. A stack service role (AWS's
// RoleARN mode) is the natural follow-on, reusing the STS->groups mechanism from Step Functions (#172).
//
// Long-running operations (CreateStack/UpdateStack/DeleteStack/ExecuteChangeSet) are ASYNCHRONOUS like
// AWS: they validate synchronously, then run the engine in the background and return a StackId; the
// caller polls DescribeStacks. Read/preview ops (Validate/ChangeSet/Drift/Describe) run synchronously.
// A background operation is owned and leased on its stack record, so one interrupted by a front-door
// restart is failed and rolled back by the next front door instead of staying *_IN_PROGRESS forever
// (cloudformation_ops.go).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/minio/minio-go/v7"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryclient "k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

const cfnXMLNamespace = "http://cloudformation.amazonaws.com/doc/2010-05-15/"

// how long an async stack operation may run in the background. It covers the engine's longest wait: a
// stack whose Outputs name an instance with an encrypted root waits for that VM to copy its OS image and
// start (cfn's outputBootWaitCap, 45 minutes), after its resources are in place, with time left to record
// the result or roll back.
const cfnAsyncTimeout = 60 * time.Minute
const cfnWaitTimeout = 10 * time.Minute

type cfnDoorway struct {
	cfg       *rest.Config      // base in-cluster config; copied + impersonated per caller
	shimDyn   dynamic.Interface // shim SA client for stack-record / changeset / drift bookkeeping
	mapper    meta.RESTMapper
	account   string
	region    string
	ns        string
	svcSuffix string       // cluster-local DNS suffix for Knative Functions (custom-resource invoke, #269)
	invoker   *http.Client // invokes a custom resource's backing Function synchronously
	logger    *slog.Logger
	restV1    *apigwV1Handler // drives the apigateway REST v1 store for AWS::ApiGateway::* resources (#295); nil = unconfigured
	// authz is the data-plane engine: an assumed role's stack operations are default-deny under it
	// (cloudformation:<Action> on Stack::<name>). nil = no engine — a role is then denied every action.
	authz *dataplaneauthz.Checker
	// objectEncryption (OBJECT_ENCRYPTION=true) asserts that every NEW MinIO bucket is encrypted at rest
	// by default — an outcome, not "KMS is configured": MinIO carrying a key while only buckets someone
	// ran `mc encrypt set` on are encrypted is not enough, since a bucket this front door creates later
	// would be unencrypted (docs/encryption.md). Default false = fail-closed: an S3 BucketEncryption
	// request refuses rather than deploy an unencrypted bucket the template asked to encrypt.
	objectEncryption bool
	// objectEncryptionFile, when set, is a file that says "true" once the platform has turned object
	// encryption on: the enabled key of configmap/openinfra-object-encryption, mounted here. The
	// minio-kms-enable Job writes it only after MinIO's key works and new buckets get default encryption
	// (storage/minio-kms.yaml), so it is the same outcome as OBJECT_ENCRYPTION, read live (no restart).
	objectEncryptionFile string
	// validatedDomainsFile, when set, lists the domains the operator has validated (ACM's domain
	// validation, done once: certificates.validatedDomains), one per line or comma-separated: the
	// validatedDomains key of configmap/openinfra-certificates, mounted here and read live. A CloudFront
	// alias outside them refuses; absent or empty, sites keep the self-signed issuer.
	validatedDomainsFile string
	// ops makes the long stack operations durable across a front-door restart: ownership leases on the
	// stack records, the recovery pass for interrupted operations, and refusal of new operations while
	// shutting down (cloudformation_ops.go).
	ops cfnOps
	// callerDyn, when set, builds the caller-impersonating client instead of impersonating via cfg (tests).
	callerDyn func(user string, groups []string) (dynamic.Interface, error)
	// cs + authzNS are the coarse RBAC gate for a User (iam.CanDo, as every front door): the stack and
	// change-set records are read and written with the shim's own client, so this gate is what keeps a
	// key without CloudFormation rights out of them. nil cs denies every User.
	cs      kubernetes.Interface
	authzNS string
	// noecho keeps NoEcho parameter values out of the plain records (cfn_noecho.go); nil keeps none.
	noecho *noEchoSecrets
	// recNS is the namespace whose Secrets hold this front door's stack, change-set and drift records —
	// the shim's own (cfn_records.go). "" keeps them as ConfigMaps in ns (tests).
	recNS string
	// buckets is the S3 store a stack's kind: Bucket claims hold their buckets in: a stack delete refuses a
	// bucket that still holds data and removes an empty one, as AWS does. nil = left to the bucket reaper.
	buckets *minio.Client
	// services are the shim's own AWS API stores a stack's queues, topics, parameters and keys are
	// provisioned into (cfn_services.go); nil = none (the engine then keeps its kind mappings).
	services *cfnServices
	// sqsURLBase is the endpoint a stack's queue URLs name (SQS_QUEUE_URL_BASE, default the shim's
	// in-cluster address). The SQS front door answers any URL by its queue name; this only decides what
	// a stack reports, and is where a client that routes by the URL's host sends.
	sqsURLBase string
	// signals stores the resource signals SignalResource and wait-condition handle URLs deliver; the
	// engine waits on them (cloudformation_api.go). nil = signals cannot arrive (such a stack refuses).
	signals *signalStore
	// signalBase is the base URL of WaitConditionHandle URLs (CFN_SIGNAL_BASE_URL): one guests reach.
	signalBase string
	keyOnce    sync.Once
	sigKey     []byte
	// s3 reads TemplateURL objects from the shim's own S3 (cloudformation_templateurl.go); nil = refused.
	s3 *s3Handler
	// fns finds a function by name across the namespaces the Lambda API invokes in (fn_locate.go): a
	// stack's function is refused a name another of them already has, since a function name is unique,
	// as on AWS. nil = not checked.
	fns *fnLocator
}

// caps are the deploy-environment Capabilities this doorway vouches for. Plan, changeset, validate and
// deploy all use the same value, so a PROVISIONABLE* plan still means deploy won't refuse.
func (h *cfnDoorway) caps() cfn.Capabilities {
	c := cfn.Capabilities{ObjectEncryption: h.objectEncryption || fileSaysTrue(h.objectEncryptionFile),
		SQSAPI: h.services.sqsOK(), SNSAPI: h.services.snsOK(), SSMAPI: h.services.ssmOK(), KMSAPI: h.services.kmsOK(),
		SQSURLBase:        h.sqsURLBase,
		SecretsManagerAPI: h.services.doorOK("secretsmanager"), LogsAPI: h.services.doorOK("logs"),
		EventsAPI: h.services.doorOK("events"), ECRAPI: h.services.doorOK("ecr"), CloudWatchAPI: h.services.doorOK("monitoring"),
		// Elastic IP allocations are holder Services the shim keeps in the stack namespace, recorded with
		// their stack like the other service resources (cfn_addresses.go).
		EC2AddressAPI:    h.shimDyn != nil && h.services != nil && h.services.owners != nil,
		ValidatedDomains: fileDomains(h.validatedDomainsFile)}
	if ecr, ok := h.services.door("ecr").(*ecrHandler); ok && ecr != nil && c.ECRAPI {
		c.ECRRepositoryHost = stripScheme(ecr.proxyEndpoint)
	}
	return c
}

// fileDomains reads a list of domains (one per line, or comma/space separated) from path, lowercased,
// without a leading "*." or a trailing dot. A missing or unreadable file, or an empty path, is none.
func fileDomains(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(string(b), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		if d := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(f), "*."), "."); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// fileSaysTrue reports whether path holds "true" (surrounding whitespace ignored). A missing or
// unreadable file, or an empty path, is false.
func fileSaysTrue(path string) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(b)) == "true"
}

func newCFNDoorway(cfg *rest.Config, shimDyn dynamic.Interface, account, region, ns, svcSuffix string, logger *slog.Logger) (*cfnDoorway, error) {
	dc, err := discoveryclient.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cfn doorway discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	if region == "" {
		region = "us-east-1"
	}
	if svcSuffix == "" {
		svcSuffix = "svc.cluster.local"
	}
	// A generous timeout: Knative scale-from-zero makes the FIRST request to a custom resource's Function
	// block while the pod cold-starts; the request is queued, not dropped.
	h := &cfnDoorway{cfg: cfg, shimDyn: shimDyn, mapper: mapper, account: account, region: region, ns: ns,
		svcSuffix: svcSuffix, invoker: &http.Client{Timeout: 3 * time.Minute}, logger: logger,
		objectEncryption:     os.Getenv("OBJECT_ENCRYPTION") == "true",
		objectEncryptionFile: getenv("OBJECT_ENCRYPTION_FILE", "/etc/openinfra/object-encryption/enabled"),
		validatedDomainsFile: getenv("CERT_VALIDATED_DOMAINS_FILE", "/etc/openinfra/certificates/validatedDomains"),
		// The in-cluster TLS address VM guests already reach and trust (their credentials come from it).
		signalBase: getenv("CFN_SIGNAL_BASE_URL", "https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567")}
	h.signals = &signalStore{h: h}
	return h, nil
}

// invokeCustomResourceFn is the cfn.InvokeFunc for a Lambda-backed custom resource (#269): it POSTs the
// CloudFormation custom-resource event to the in-stack Function's cluster-local Knative URL and parses the
// handler's {Status, Data, Reason} response. The open-infra adaptation of the ResponseURL callback — the
// handler RETURNS its response synchronously rather than PUT-ing it to a pre-signed S3 URL.
func (h *cfnDoorway) invokeCustomResourceFn(ctx context.Context, namespace, functionName string, event []byte) (map[string]any, error) {
	target := "http://" + functionName + "." + namespace + "." + h.svcSuffix + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(event))
	if err != nil {
		return nil, fmt.Errorf("building custom-resource invoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.invoker.Do(req)
	if err != nil {
		return nil, fmt.Errorf("invoking custom-resource Function %q at %s: %w", functionName, target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("custom-resource Function %q returned HTTP %d: %s", functionName, resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("custom-resource Function %q returned a non-JSON response: %w", functionName, err)
	}
	return out, nil
}

func (h *cfnDoorway) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", cfnXMLNamespace)
}

// applierFor builds an Applier that impersonates the caller for resource ops (the authority seam).
func (h *cfnDoorway) applierFor(claims iam.Claims) (*impersonatingApplier, error) {
	user, groups, ok := iam.Identity(claims)
	if !ok {
		return nil, fmt.Errorf("no caller identity")
	}
	ap, err := h.applierForIdentity(user, groups)
	if err != nil {
		return nil, err
	}
	c := claims
	ap.claims = &c
	return ap, nil
}

// applierForIdentity builds the Applier impersonating an already-resolved identity — a request's caller,
// or (recovery) the caller recorded on an interrupted operation's stack record.
func (h *cfnDoorway) applierForIdentity(user string, groups []string) (*impersonatingApplier, error) {
	var cdyn dynamic.Interface
	var err error
	if h.callerDyn != nil {
		cdyn, err = h.callerDyn(user, groups)
	} else {
		icfg := rest.CopyConfig(h.cfg)
		icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
		cdyn, err = dynamic.NewForConfig(icfg)
	}
	if err != nil {
		return nil, err
	}
	rs := h.recs()
	return &impersonatingApplier{caller: cdyn, shim: h.shimDyn, mapper: h.mapper, ns: h.ns, user: user, groups: groups,
		noecho: h.noecho, records: &rs, svc: h.services, door: h}, nil
}

// cfnVerb is the coarse RBAC verb a User needs for a CloudFormation action: get for the reads (as AWS's
// ReadOnlyAccess, which includes Detect*), a write verb for anything that creates, changes or deletes a
// stack or change set. "" for an action this front door does not implement.
func cfnVerb(action string) string {
	switch action {
	case "DescribeStacks", "DescribeStackResources", "ListStacks", "ListExports", "GetTemplateSummary",
		"GetTemplate", "ValidateTemplate", "DescribeChangeSet", "DetectStackDrift",
		"DescribeStackDriftDetectionStatus", "DescribeStackResourceDrifts",
		"DescribeStackEvents", "ListStackResources", "DescribeStackResource", "ListChangeSets", "ListImports":
		return "get"
	case "CreateStack", "CreateChangeSet", "ExecuteChangeSet":
		return "create"
	case "UpdateStack":
		return "update"
	case "DeleteStack", "DeleteChangeSet":
		return "delete"
	}
	return ""
}

// stackScope is the data-plane resource id for a stack action: the stack it names, else "*" (any stack).
func stackScope(stack string) string {
	if stack == "" {
		return anyResource
	}
	return stack
}

// canDo is the coarse gate (iam.CanDo passes an assumed role, whose authority is the data-plane check).
// Without an RBAC client a User is denied: the records are never opened to an unchecked caller.
func (h *cfnDoorway) canDo(ctx context.Context, claims iam.Claims, verb, stack string) (bool, string) {
	if h.cs == nil && claims.AssumedRole == "" {
		return false, "CloudFormation authorization is not configured on this shim"
	}
	return iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, stack)
}

func (h *cfnDoorway) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	normalizeStackArgs(r)
	action := r.PostFormValue("Action")
	if action == "" {
		writeQueryError(w, http.StatusBadRequest, "MissingAction", requestID, "no Action in the request.", cfnXMLNamespace)
		return
	}
	// SignalResource decides its own authorization (cloudformation_api.go): an instance of the stack may
	// signal it with nothing more than its instance role, as cfn-signal does on AWS.
	if action == "SignalResource" {
		h.signalResource(w, r, claims, requestID)
		return
	}
	r = withCallerClaims(r, claims) // a TemplateURL is read as the caller
	// Authorization, before anything reads or writes a record. The records are the shim's own bookkeeping
	// (read and written with its client), so the caller must be allowed the action itself — as on AWS,
	// where cloudformation:DescribeStacks etc. are permissions of their own:
	//   - a User needs the coarse RBAC verb for the action (cfnVerb), as at every front door; resources the
	//     stack provisions are then checked again as the caller (impersonation);
	//   - every caller gets the data-plane check, cloudformation:<Action> on the stack it names
	//     (normalizeStackArgs has reduced a stack ARN to its name): additive for a User, and the whole,
	//     default-deny authority of an assumed role. An action that names no stack — ListStacks,
	//     ListExports, ValidateTemplate, a DescribeStacks of every stack — is checked on Stack::* for every
	//     caller, as AWS evaluates such a call on Resource "*": a policy that does not allow it there (or
	//     denies it) refuses the call.
	if verb := cfnVerb(action); verb != "" {
		if allowed, reason := h.canDo(r.Context(), claims, verb, r.PostFormValue("StackName")); !allowed {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cfnXMLNamespace)
			return
		}
	}
	if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "cloudformation:"+action, "Stack",
		stackScope(r.PostFormValue("StackName")), r); denied {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cfnXMLNamespace)
		return
	}
	ap, err := h.applierFor(claims)
	if err != nil {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	if action != "ValidateTemplate" {
		h.migrateLegacyRecords(r.Context()) // records an earlier front door kept as ConfigMaps (cfn_records.go)
	}
	switch action {
	case "CreateStack":
		h.createStack(w, r, ap, requestID)
	case "UpdateStack":
		h.updateStack(w, r, ap, requestID)
	case "DeleteStack":
		h.deleteStack(w, r, ap, requestID)
	case "DescribeStacks":
		h.describeStacks(w, r, ap, requestID)
	case "DescribeStackResources":
		h.describeStackResources(w, r, ap, requestID)
	case "ListStacks":
		h.listStacks(w, r, ap, requestID)
	case "ListExports":
		h.listExports(w, r, requestID)
	case "GetTemplateSummary":
		h.getTemplateSummary(w, r, ap, requestID)
	case "GetTemplate":
		h.getTemplate(w, r, ap, requestID)
	case "ValidateTemplate":
		h.validateTemplate(w, r, requestID)
	case "CreateChangeSet":
		h.createChangeSet(w, r, ap, requestID)
	case "DescribeChangeSet":
		h.describeChangeSet(w, r, ap, requestID)
	case "ExecuteChangeSet":
		h.executeChangeSet(w, r, ap, requestID)
	case "DeleteChangeSet":
		h.deleteChangeSet(w, r, ap, requestID)
	case "DetectStackDrift":
		h.detectStackDrift(w, r, ap, requestID)
	case "DescribeStackDriftDetectionStatus":
		h.describeDriftStatus(w, r, ap, requestID)
	case "DescribeStackResourceDrifts":
		h.describeResourceDrifts(w, r, ap, requestID)
	case "DescribeStackEvents":
		h.describeStackEvents(w, r, ap, requestID)
	case "ListStackResources":
		h.listStackResources(w, r, ap, requestID)
	case "DescribeStackResource":
		h.describeStackResource(w, r, ap, requestID)
	case "ListChangeSets":
		h.listChangeSets(w, r, ap, requestID)
	case "ListImports":
		h.listImports(w, r, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"CloudFormation "+action+" is not implemented by the open-infra shim.", cfnXMLNamespace)
	}
}

// --- template + params ---

// templateBody returns the request's template — inline (TemplateBody), or a TemplateURL object in this
// shim's own S3, read as the caller (cloudformation_templateurl.go: parsed, never fetched over the
// network) — with any nested stacks flattened into it.
func (h *cfnDoorway) templateBody(r *http.Request) (string, error) {
	body := r.PostFormValue("TemplateBody")
	if strings.TrimSpace(body) == "" {
		u := r.PostFormValue("TemplateURL")
		if strings.TrimSpace(u) == "" {
			return "", fmt.Errorf("TemplateBody or TemplateURL is required")
		}
		b, err := h.readTemplateURL(r, u)
		if err != nil {
			return "", err
		}
		body = b
	}
	return h.withNestedFlattened(r, body)
}

func parseCFNParams(r *http.Request) map[string]string {
	out, _ := parseCFNParamsPrev(r)
	return out
}

// parseCFNParamsPrev parses Parameters.member.N and also returns the keys sent with
// UsePreviousValue=true (`aws cloudformation deploy` sends every parameter it was not told to
// override that way on an update).
func parseCFNParamsPrev(r *http.Request) (map[string]string, []string) {
	out := map[string]string{}
	var prev []string
	for i := 1; ; i++ {
		k := r.PostFormValue(fmt.Sprintf("Parameters.member.%d.ParameterKey", i))
		if k == "" {
			break
		}
		if strings.EqualFold(r.PostFormValue(fmt.Sprintf("Parameters.member.%d.UsePreviousValue", i)), "true") {
			prev = append(prev, k)
			continue
		}
		out[k] = r.PostFormValue(fmt.Sprintf("Parameters.member.%d.ParameterValue", i))
	}
	return out, prev
}

// withPreviousValues fills each UsePreviousValue parameter from the value the stack was last deployed
// with: the record's plain parameters, or — for a NoEcho one — noEcho(), the stored NoEcho values (read
// only when one is asked for). A key the stack never had keeps the template default, as a new parameter does.
func withPreviousValues(params map[string]string, prev []string, current *cfn.StackRecord,
	noEcho func() map[string]string) map[string]string {
	if current == nil {
		return params
	}
	var secret map[string]string
	for _, k := range prev {
		if v, ok := current.Parameters[k]; ok {
			params[k] = v
			continue
		}
		if !contains(current.NoEchoParameters, k) || noEcho == nil {
			continue
		}
		if secret == nil {
			secret = noEcho()
		}
		if v, ok := secret[k]; ok {
			params[k] = v
		}
	}
	return params
}

// previousNoEcho reads a stack's stored NoEcho values for UsePreviousValue (empty on error, logged).
func (h *cfnDoorway) previousNoEcho(ctx context.Context, stack string) func() map[string]string {
	return func() map[string]string {
		v, err := h.noecho.get(ctx, stackRecordName(stack))
		if err != nil {
			h.logger.Warn("cfn: could not read the stack's NoEcho parameters", "stack", stack, "error", err.Error())
			return map[string]string{}
		}
		return v
	}
}

// describedParams is what DescribeStacks shows for a stack's parameters: a NoEcho one as "****", as AWS
// does. NoEcho is taken from the record and from its template, so a record written before NoEcho
// values were kept apart is masked too.
func describedParams(rec *cfn.StackRecord) map[string]string {
	noEcho := cfn.NoEchoNames([]byte(rec.Template))
	for _, k := range rec.NoEchoParameters {
		noEcho[k] = true
	}
	out := map[string]string{}
	for k, v := range rec.Parameters {
		if noEcho[k] {
			v = "****"
		}
		out[k] = v
	}
	for k := range noEcho {
		if _, ok := out[k]; ok || !contains(rec.NoEchoParameters, k) {
			continue
		}
		out[k] = "****"
	}
	// As on AWS, every template parameter is listed: one the stack was not given a value for shows its
	// default (masked when NoEcho).
	for k, v := range cfn.ParameterDefaults([]byte(rec.Template)) {
		if _, ok := out[k]; ok {
			continue
		}
		if noEcho[k] {
			v = "****"
		}
		out[k] = v
	}
	return out
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// stackID is the stack's StackId — the same value its templates resolve AWS::StackId to (awsidentity).
func (h *cfnDoorway) stackID(name string) string {
	return awsidentity.Identity{AccountID: h.account, Region: h.region, StackNamespace: h.ns}.StackID(name)
}

func (h *cfnDoorway) opts(name string, params map[string]string) cfn.DeployOptions {
	o := cfn.DeployOptions{
		StackName: name, Namespace: h.ns, Params: params, Wait: true, Timeout: cfnWaitTimeout,
		// In-cluster: a custom resource's backing Function is invokable (#269). The CLI deploy path leaves
		// this nil, so a custom-resource stack there refuses rather than guessing.
		Invoke: h.invokeCustomResourceFn,
		// The same Capabilities the doorway's plan/changeset/validate use (#347 Phase 1.8).
		Caps: h.caps(),
	}
	// Resource signals (CreationPolicy ResourceSignal, WaitCondition) arrive through this front door.
	if h.signals != nil {
		o.Signals = h.signals
		o.SignalURL = h.signalURL
	}
	// In-cluster: an AWS::ApiGateway::RestApi stack is provisioned via the apigateway REST v1 store (#295).
	// Nil when the apigateway data layer is unconfigured (or on the CLI), so such a stack refuses.
	if h.restV1 != nil && h.restV1.store != nil {
		o.ProvisionRestAPI = func(ctx context.Context, planSpec map[string]any) (string, error) {
			plan, perr := cfn.ParseRestAPIPlan(planSpec)
			if perr != nil {
				return "", perr
			}
			return h.restV1.provisionRestAPIPlan(ctx, plan)
		}
		o.DeprovisionRestAPI = h.restV1.deprovisionRestAPI
	}
	if h.buckets != nil {
		mc := h.buckets
		o.BucketData = func(ctx context.Context, bucket string) (bool, bool, error) {
			exists, err := mc.BucketExists(ctx, bucket)
			if err != nil || !exists {
				return false, false, err
			}
			empty, err := bucketEmpty(ctx, mc, bucket)
			return true, empty, err
		}
		o.RemoveBucket = func(ctx context.Context, bucket string) error {
			if err := removeEmptyBucket(ctx, mc, bucket); err != nil {
				if errors.Is(err, errBucketNotEmpty) {
					return cfn.ErrBucketNotEmpty
				}
				return err
			}
			return nil
		}
	}
	return o
}

// --- stack lifecycle (async) ---

func (h *cfnDoorway) createStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	if name == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "StackName is required.", cfnXMLNamespace)
		return
	}
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params := parseCFNParams(r)
	ctx := r.Context()
	ex := h.exportsFor(ctx, name) // other stacks' exports, for Fn::ImportValue

	// Synchronous validation gate — an unsupported type / bad template is refused WHOLE here, before
	// anything is created (the DoD's "refused at validation, nothing created"). This mirrors the engine's
	// own plan gate but surfaces it as an immediate ValidationError to the caller.
	plan, perr := cfn.BuildPlanWithCaps([]byte(body), params, ex.values, name, h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing created):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	if msg := exportCollision(body, params, ex, name); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}

	alreadyExists := func() {
		writeQueryError(w, http.StatusBadRequest, "AlreadyExistsException", requestID,
			"Stack ["+name+"] already exists.", cfnXMLNamespace)
	}
	if _, found, _ := ap.GetStack(ctx, name); found {
		alreadyExists()
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "AlreadyExistsException", "Stack ["+name+"] already exists.")
		return
	}
	// The record is created already owned by this operation (lease + caller), in one atomic Create.
	now := time.Now().UTC().Format(time.RFC3339)
	seed := &cfn.StackRecord{Name: name, Namespace: h.ns, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now, Owner: ap.user}
	if err := h.seedRecord(ctx, seed, "CreateStack", ap.identity()); err != nil {
		h.ops.end(name)
		if apierrors.IsAlreadyExists(err) {
			alreadyExists()
			return
		}
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not seed stack record: "+err.Error(), cfnXMLNamespace)
		return
	}
	createOpts := h.asCaller(h.stackOpts(name, params, ex, body), ap)
	h.runStackOp(name, "CreateStack", "CREATE_FAILED", ap, func(bctx context.Context) error {
		rec, derr := cfn.Deploy(bctx, []byte(body), createOpts, ap)
		if derr == nil {
			h.logOutputs("CreateStack", name, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "CreateStack", "<StackId>"+xesc(h.stackID(name))+"</StackId>")
}

func (h *cfnDoorway) updateStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params, prevKeys := parseCFNParamsPrev(r)
	ctx := r.Context()
	current, found, _ := ap.GetStack(ctx, name)
	params = withPreviousValues(params, prevKeys, current, h.previousNoEcho(ctx, name))
	if !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
		return
	}
	if msg := h.notUpdatable(name, current.Status); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	h.auditNonOwner("UpdateStack", current, ap)
	ex := h.exportsFor(ctx, name)
	plan, perr := cfn.BuildPlanWithCaps([]byte(body), params, ex.values, name, h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused (nothing changed):\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, name); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+name+"] is being changed by another operation; retry once it settles.")
		return
	}
	if cur, err := h.claimRecord(ctx, name, "UpdateStack", ap.identity()); err != nil || cur == nil {
		h.ops.end(name)
		if err == nil {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
			return
		}
		h.claimRefusal(w, requestID, name, "update", err)
		return
	}
	updateOpts := h.asCaller(h.stackOpts(name, params, ex, body), ap)
	h.runStackOp(name, "UpdateStack", "UPDATE_FAILED", ap, func(bctx context.Context) error {
		rec, derr := cfn.Update(bctx, []byte(body), updateOpts, ap)
		if derr == nil {
			h.logOutputs("UpdateStack", name, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "UpdateStack", "<StackId>"+xesc(h.stackID(name))+"</StackId>")
}

func (h *cfnDoorway) deleteStack(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	ctx := r.Context()
	rec, found, _ := ap.GetStack(ctx, name)
	if !found || rec.Status == "DELETE_IN_PROGRESS" {
		// AWS treats deleting an absent stack — or one already being deleted — as a successful no-op. (An
		// orphaned DELETE_IN_PROGRESS is resumed by the recovery pass.)
		h.writeResult(w, requestID, "DeleteStack", "")
		return
	}
	if inProgress(rec.Status) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"Stack ["+name+"] cannot be deleted while in status "+rec.Status+".", cfnXMLNamespace)
		return
	}
	// Before any teardown step (some run with the shim's authority — cfn_authz.go): the caller must be
	// allowed to delete everything the stack would remove, or nothing is touched.
	if ok, reason := h.authorizeTeardown(ctx, ap, rec); !ok {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cfnXMLNamespace)
		return
	}
	h.auditNonOwner("DeleteStack", rec, ap)
	// AWS's export rule: a stack whose export another stack imports can't be deleted from under it.
	if msg := exportsInUse(h.allRecords(ctx), name, exportNames(rec)); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(name); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+name+"] cannot be deleted while another operation on it is in progress.")
		return
	}
	if cur, err := h.claimRecord(ctx, name, "DeleteStack", ap.identity()); err != nil || cur == nil {
		h.ops.end(name)
		if err == nil { // gone since it was read: already deleted
			h.writeResult(w, requestID, "DeleteStack", "")
			return
		}
		h.claimRefusal(w, requestID, name, "delete", err)
		return
	}
	h.runStackOp(name, "DeleteStack", "DELETE_FAILED", ap, func(bctx context.Context) error {
		_, derr := cfn.Destroy(bctx, h.asCaller(h.opts(name, nil), ap), ap)
		if derr == nil {
			// As on AWS, deleting a stack deletes its change sets — and its stored NoEcho values, events and
			// signals.
			h.deleteChangeSetsOf(bctx, name)
			h.deleteStackSide(bctx, name)
			if err := h.noecho.deleteStack(bctx, name); err != nil {
				h.logger.Warn("cfn: could not delete the stack's NoEcho parameters", "stack", name, "error", err.Error())
			}
		}
		return derr
	})
	h.writeResult(w, requestID, "DeleteStack", "")
}

// --- describe (sync) ---

func (h *cfnDoorway) describeStacks(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	var recs []*cfn.StackRecord
	if name != "" {
		rec, found, err := ap.GetStack(r.Context(), name)
		if err != nil {
			writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
			return
		}
		if !found {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+name+" does not exist", cfnXMLNamespace)
			return
		}
		recs = []*cfn.StackRecord{rec}
	} else {
		// Every stack, less those the caller's policy denies DescribeStacks on by name: the call itself
		// was allowed on Stack::* (serve), but a stack the caller may not describe shows nothing of itself
		// (its outputs, parameters or status) here either.
		claims := ap.callerClaims()
		for _, rec := range h.allRecords(r.Context()) {
			if denied, _ := deniedByDataPlane(r.Context(), h.authz, claims, "cloudformation:DescribeStacks", "Stack", rec.Name, r); !denied {
				recs = append(recs, rec)
			}
		}
	}
	var members strings.Builder
	for _, rec := range recs {
		members.WriteString(h.stackMemberXML(rec))
	}
	h.writeResult(w, requestID, "DescribeStacks", "<Stacks>"+members.String()+"</Stacks>")
}

func (h *cfnDoorway) stackMemberXML(rec *cfn.StackRecord) string {
	var b strings.Builder
	b.WriteString("<member>")
	b.WriteString("<StackId>" + xesc(h.stackID(rec.Name)) + "</StackId>")
	b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
	b.WriteString("<StackStatus>" + xesc(rec.Status) + "</StackStatus>")
	switch {
	case rec.Message != "":
		b.WriteString("<StackStatusReason>" + xesc(rec.Message) + "</StackStatusReason>")
	case rec.Fidelity != "":
		// What the stack accepted that open-infra does not emulate as AWS does (#347 item D), where
		// `aws cloudformation describe-stacks` shows it.
		b.WriteString("<StackStatusReason>" + xesc("open-infra fidelity: "+rec.Fidelity) + "</StackStatusReason>")
	}
	if rec.Description != "" {
		b.WriteString("<Description>" + xesc(rec.Description) + "</Description>")
	}
	if rec.CreatedAt != "" {
		b.WriteString("<CreationTime>" + xesc(rec.CreatedAt) + "</CreationTime>")
	}
	if rec.UpdatedAt != "" {
		b.WriteString("<LastUpdatedTime>" + xesc(rec.UpdatedAt) + "</LastUpdatedTime>")
	}
	b.WriteString(outputsXML(rec)) // evaluated against the deployed stack at *_COMPLETE (#347)
	if params := describedParams(rec); len(params) > 0 {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("<Parameters>")
		for _, k := range keys {
			b.WriteString("<member><ParameterKey>" + xesc(k) + "</ParameterKey><ParameterValue>" + xesc(params[k]) + "</ParameterValue></member>")
		}
		b.WriteString("</Parameters>")
	}
	b.WriteString("</member>")
	return b.String()
}

func (h *cfnDoorway) describeStackResources(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	rec, found, err := ap.GetStack(r.Context(), name)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+name+"] does not exist.", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	only := r.PostFormValue("LogicalResourceId")
	for _, row := range h.stackResourceRows(r.Context(), rec) {
		if only != "" && row.logicalID != only {
			continue
		}
		b.WriteString("<member>")
		b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
		b.WriteString("<StackId>" + xesc(h.stackID(rec.Name)) + "</StackId>")
		b.WriteString("<LogicalResourceId>" + xesc(row.logicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(row.physicalID) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(row.typ) + "</ResourceType>")
		b.WriteString("<ResourceStatus>" + xesc(row.status) + "</ResourceStatus>")
		if row.reason != "" {
			b.WriteString("<ResourceStatusReason>" + xesc(row.reason) + "</ResourceStatusReason>")
		}
		b.WriteString("<Timestamp>" + xesc(row.timestamp) + "</Timestamp>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "DescribeStackResources", "<StackResources>"+b.String()+"</StackResources>")
}

func (h *cfnDoorway) listStacks(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	var b strings.Builder
	for _, rec := range h.allRecords(r.Context()) {
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(h.stackID(rec.Name)) + "</StackId>")
		b.WriteString("<StackName>" + xesc(rec.Name) + "</StackName>")
		b.WriteString("<StackStatus>" + xesc(rec.Status) + "</StackStatus>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "ListStacks", "<StackSummaries>"+b.String()+"</StackSummaries>")
}

// allRecords lists every stack record in the record store (shim client).
func (h *cfnDoorway) allRecords(ctx context.Context) []*cfn.StackRecord {
	st := h.recs()
	list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil
	}
	var out []*cfn.StackRecord
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "cfn-stack-") {
			continue
		}
		if rec, ok := st.stackRecord(&list.Items[i]); ok {
			out = append(out, rec)
		}
	}
	return out
}

// --- validate (sync) ---

func (h *cfnDoorway) validateTemplate(w http.ResponseWriter, r *http.Request, requestID string) {
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	// Validated without parameter values, as AWS does (a parameter with no default is fine here).
	plan, perr := cfn.ValidatePlan([]byte(body), h.exportsFor(r.Context(), "").values, "validate", h.caps())
	if perr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, perr.Error(), cfnXMLNamespace)
		return
	}
	if plan.Verdict == cfn.Rejected {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"template refused:\n  - "+strings.Join(plan.Blockers, "\n  - "), cfnXMLNamespace)
		return
	}
	desc := "open-infra: " + string(plan.Verdict)
	if fl := fidelityLine(plan); fl != "" {
		desc += " — " + fl
	}
	h.writeResult(w, requestID, "ValidateTemplate", "<Description>"+xesc(desc)+"</Description><Capabilities/>"+templateParametersXML([]byte(body), false))
}

// --- change sets ---

// changeSet is the doorway's persisted change-set bookkeeping (a record cfn-changeset-<stack>.<name>).
type changeSet struct {
	StackName    string            `json:"stackName"`
	Name         string            `json:"name"`
	TemplateBody string            `json:"templateBody"`
	Params       map[string]string `json:"params,omitempty"` // never a NoEcho value
	NoEchoParams []string          `json:"noEchoParams,omitempty"`
	Type         string            `json:"type"` // CREATE | UPDATE
	Changes      []cfn.Change      `json:"changes"`
}

// changeSetCMName is a change set's record name. A change-set name may not contain "." (AWS's pattern,
// enforced at CreateChangeSet), so "." splits the two unambiguously: no two (stack, change set) pairs
// share a record.
func changeSetCMName(stack, name string) string { return "cfn-changeset-" + stack + "." + name }

// legacyChangeSetCMName is the name records were once written under. It is ambiguous (stack "a" with
// change set "b-c" and stack "a-b" with "c" both give cfn-changeset-a-b-c), so a record found under it is
// used only when the record itself names the requested stack and change set.
func legacyChangeSetCMName(stack, name string) string { return "cfn-changeset-" + stack + "-" + name }

// cfnNameRe is AWS's pattern for stack and change-set names.
var cfnNameRe = regexp.MustCompile(`^[a-zA-Z][-a-zA-Z0-9]{0,127}$`)

func (h *cfnDoorway) createChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	if stack == "" || csName == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "StackName and ChangeSetName are required.", cfnXMLNamespace)
		return
	}
	if !cfnNameRe.MatchString(stack) || !cfnNameRe.MatchString(csName) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"StackName and ChangeSetName must start with a letter and contain only letters, digits and hyphens.", cfnXMLNamespace)
		return
	}
	body, err := h.templateBody(r)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	params, prevKeys := parseCFNParamsPrev(r)
	ctx := r.Context()
	ex := h.exportsFor(ctx, stack)
	if len(prevKeys) > 0 {
		if cur, ok, _ := ap.GetStack(ctx, stack); ok {
			params = withPreviousValues(params, prevKeys, cur, h.previousNoEcho(ctx, stack))
		}
	}

	// BuildChangeSet computes the diff against the current stack record and APPLIES NOTHING.
	cs, _, current, cerr := cfn.BuildChangeSet(ctx, []byte(body), h.optsFor(stack, params, ex), ap)
	if cerr != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, cerr.Error(), cfnXMLNamespace)
		return
	}
	if !cs.Exists {
		current = nil
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, stack); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	csType := "UPDATE"
	if !cs.Exists {
		csType = "CREATE"
	}
	// NoEcho values stay out of the change-set record (a ConfigMap): they go to its NoEcho Secret.
	plain, noEchoNames, noEchoValues := cfn.SplitNoEcho([]byte(body), params)
	rec := &changeSet{StackName: stack, Name: csName, TemplateBody: body, Params: plain, NoEchoParams: noEchoNames,
		Type: csType, Changes: cs.Changes}
	if err := h.noecho.put(ctx, changeSetCMName(stack, csName), stack, noEchoValues); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not store the NoEcho parameters: "+err.Error(), cfnXMLNamespace)
		return
	}
	if err := h.putChangeSet(ctx, rec); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	csID := fmt.Sprintf("arn:aws:cloudformation:%s:%s:changeSet/%s/%s", h.region, h.account, csName, shortHash(stack+"/"+csName))
	h.writeResult(w, requestID, "CreateChangeSet",
		"<Id>"+xesc(csID)+"</Id><StackId>"+xesc(h.stackID(stack))+"</StackId>")
}

// changeSetFidelity renders a change set's fidelity summary (every caveat of a resource it adds or
// changes) as one StatusReason line; "" when there is none.
func changeSetFidelity(changes []cfn.Change) string {
	var items []string
	for _, c := range changes {
		if c.Action == cfn.Unchanged || c.Action == cfn.Remove {
			continue
		}
		for _, cv := range c.Caveats {
			items = append(items, c.LogicalID+": "+cv)
		}
	}
	if len(items) == 0 {
		return ""
	}
	return "open-infra accepts but does not emulate as AWS does (" + strconv.Itoa(len(items)) + "): " + strings.Join(items, " | ")
}

// fidelityLine renders a plan's fidelity summary for a response field; "" when there is none.
func fidelityLine(p *cfn.Plan) string {
	if len(p.Fidelity) == 0 {
		return ""
	}
	items := make([]string, 0, len(p.Fidelity))
	for _, f := range p.Fidelity {
		items = append(items, f.Resource+": "+f.Detail)
	}
	return "accepted but not emulated as on AWS (" + strconv.Itoa(len(items)) + "): " + strings.Join(items, " | ")
}

func (h *cfnDoorway) describeChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	cs, err := h.getChangeSet(r.Context(), stack, csName)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ChangeSetNotFound", requestID, "ChangeSet ["+csName+"] not found for stack ["+stack+"].", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, c := range cs.Changes {
		if c.Action == cfn.Unchanged {
			continue
		}
		b.WriteString("<member><Type>Resource</Type><ResourceChange>")
		b.WriteString("<Action>" + xesc(string(c.Action)) + "</Action>")
		b.WriteString("<LogicalResourceId>" + xesc(c.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(c.Kind) + "</ResourceType>")
		b.WriteString("</ResourceChange></member>")
	}
	status, exec := changeSetStatus(cs), changeSetExecutionStatus(cs)
	reason := ""
	if status == "FAILED" {
		// AWS reports an update with nothing to change as a FAILED change set with this exact reason;
		// `aws cloudformation deploy` recognizes it and reports "No changes to deploy".
		reason = "The submitted information didn't contain changes. Submit different information to create a change set."
	} else if fid := changeSetFidelity(cs.Changes); fid != "" {
		// The fidelity summary, where `aws cloudformation describe-change-set` (and the console) show it:
		// what this change accepts that open-infra does not emulate as AWS does.
		reason = fid
	}
	csID := h.changeSetID(cs.StackName, cs.Name)
	inner := "<ChangeSetName>" + xesc(cs.Name) + "</ChangeSetName>" +
		"<ChangeSetId>" + xesc(csID) + "</ChangeSetId>" +
		"<StackName>" + xesc(cs.StackName) + "</StackName>" +
		"<StackId>" + xesc(h.stackID(cs.StackName)) + "</StackId>" +
		"<Status>" + status + "</Status><ExecutionStatus>" + exec + "</ExecutionStatus>" +
		"<StatusReason>" + xesc(reason) + "</StatusReason>" +
		"<Changes>" + b.String() + "</Changes>"
	h.writeResult(w, requestID, "DescribeChangeSet", inner)
}

// changeSetID is a change set's ARN.
func (h *cfnDoorway) changeSetID(stack, name string) string {
	return fmt.Sprintf("arn:aws:cloudformation:%s:%s:changeSet/%s/%s", h.region, h.account, name, shortHash(stack+"/"+name))
}

// changeSetStatus is a change set's Status: an update with nothing to change is FAILED, as on AWS.
func changeSetStatus(cs *changeSet) string {
	if cs.Type != "CREATE" {
		for _, c := range cs.Changes {
			if c.Action != cfn.Unchanged {
				return "CREATE_COMPLETE"
			}
		}
		return "FAILED"
	}
	return "CREATE_COMPLETE"
}

// changeSetExecutionStatus is a change set's ExecutionStatus.
func changeSetExecutionStatus(cs *changeSet) string {
	if changeSetStatus(cs) == "FAILED" {
		return "UNAVAILABLE"
	}
	return "AVAILABLE"
}

func (h *cfnDoorway) executeChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	cs, err := h.getChangeSet(r.Context(), stack, csName)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ChangeSetNotFound", requestID, "ChangeSet ["+csName+"] not found.", cfnXMLNamespace)
		return
	}
	body := cs.TemplateBody
	params, err := h.changeSetParams(r.Context(), cs)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not read the change set's NoEcho parameters: "+err.Error(), cfnXMLNamespace)
		return
	}
	create := cs.Type == "CREATE"
	// An UPDATE change set changes the stack as UpdateStack does, so it needs UpdateStack's verb as well
	// as ExecuteChangeSet's (checked up front, in serve).
	if !create {
		if allowed, reason := h.canDo(r.Context(), ap.callerClaims(), "update", stack); !allowed {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, cfnXMLNamespace)
			return
		}
	}
	// Re-check the export rules at execute time: another stack may have taken an export name, or started
	// importing one this change set would drop, since the change set was created.
	ctx := r.Context()
	ex := h.exportsFor(ctx, stack)
	var current *cfn.StackRecord
	if !create {
		var found bool
		current, found, _ = ap.GetStack(ctx, stack)
		if !found {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stack+"] does not exist.", cfnXMLNamespace)
			return
		}
		if msg := h.notUpdatable(stack, current.Status); msg != "" {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
			return
		}
		h.auditNonOwner("ExecuteChangeSet", current, ap)
	}
	if msg := h.exportGuards(ctx, current, body, params, ex, stack); msg != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, cfnXMLNamespace)
		return
	}
	if err := h.ops.begin(stack); err != nil {
		h.refuseOp(w, requestID, err, "ValidationError", "Stack ["+stack+"] is being changed by another operation; retry once it settles.")
		return
	}
	status := "UPDATE_FAILED"
	if create {
		status = "CREATE_FAILED"
		// A CREATE change set seeds the record like CreateStack: already owned, atomically (a stack that
		// was created since the change set was is refused, never overwritten).
		now := time.Now().UTC().Format(time.RFC3339)
		seed := &cfn.StackRecord{Name: stack, Namespace: h.ns, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now, Owner: ap.user}
		if err := h.seedRecord(ctx, seed, "ExecuteChangeSet", ap.identity()); err != nil {
			h.ops.end(stack)
			if apierrors.IsAlreadyExists(err) {
				writeQueryError(w, http.StatusBadRequest, "AlreadyExistsException", requestID, "Stack ["+stack+"] already exists.", cfnXMLNamespace)
				return
			}
			writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not seed stack record: "+err.Error(), cfnXMLNamespace)
			return
		}
	} else if cur, err := h.claimRecord(ctx, stack, "ExecuteChangeSet", ap.identity()); err != nil || cur == nil {
		h.ops.end(stack)
		if err == nil {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack ["+stack+"] does not exist.", cfnXMLNamespace)
			return
		}
		h.claimRefusal(w, requestID, stack, "update", err)
		return
	}
	execOpts := h.asCaller(h.stackOpts(stack, params, ex, body), ap)
	h.runStackOp(stack, "ExecuteChangeSet", status, ap, func(bctx context.Context) error {
		var rec *cfn.StackRecord
		var derr error
		if create {
			rec, derr = cfn.Deploy(bctx, []byte(body), execOpts, ap)
		} else {
			rec, derr = cfn.Update(bctx, []byte(body), execOpts, ap)
		}
		if derr == nil {
			h.logOutputs("ExecuteChangeSet", stack, rec)
		}
		return derr
	})
	h.writeResult(w, requestID, "ExecuteChangeSet", "")
}

func (h *cfnDoorway) deleteChangeSet(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	csName := r.PostFormValue("ChangeSetName")
	// Only the record that is this stack's change set (findChangeSet) — never one that merely shares a
	// legacy record name.
	if _, cmName, err := h.findChangeSet(r.Context(), stack, csName); err == nil {
		_ = h.recs().client().Delete(r.Context(), cmName, metav1.DeleteOptions{})
	}
	if err := h.noecho.put(r.Context(), changeSetCMName(stack, csName), stack, nil); err != nil {
		h.logger.Warn("cfn: could not delete a change set's NoEcho parameters", "stack", stack, "changeSet", csName, "error", err.Error())
	}
	h.writeResult(w, requestID, "DeleteChangeSet", "")
}

// changeSetParams is a change set's full parameter set: its record's plain values plus its stored
// NoEcho values.
func (h *cfnDoorway) changeSetParams(ctx context.Context, cs *changeSet) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range cs.Params {
		out[k] = v
	}
	if len(cs.NoEchoParams) == 0 {
		return out, nil
	}
	secret, err := h.noecho.get(ctx, changeSetCMName(cs.StackName, cs.Name))
	if err != nil {
		return nil, err
	}
	for k, v := range secret {
		out[k] = v
	}
	return out, nil
}

func (h *cfnDoorway) putChangeSet(ctx context.Context, cs *changeSet) error {
	data, err := json.Marshal(cs)
	if err != nil {
		return err
	}
	return h.recs().apply(ctx, changeSetCMName(cs.StackName, cs.Name),
		map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/changeset": cs.StackName},
		map[string]string{"changeset.json": string(data)})
}

func (h *cfnDoorway) getChangeSet(ctx context.Context, stack, csName string) (*changeSet, error) {
	cs, _, err := h.findChangeSet(ctx, stack, csName)
	return cs, err
}

// findChangeSet reads a change set's record and the name it is stored under. Only a record that names
// the requested stack and change set is returned: never another stack's change set that happens to share
// a (legacy) record name.
func (h *cfnDoorway) findChangeSet(ctx context.Context, stack, csName string) (*changeSet, string, error) {
	var lastErr error
	st := h.recs()
	for _, cmName := range []string{changeSetCMName(stack, csName), legacyChangeSetCMName(stack, csName)} {
		u, err := st.client().Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			continue
		}
		data := st.value(u, "changeset.json")
		var cs changeSet
		if err := json.Unmarshal([]byte(data), &cs); err != nil {
			lastErr = err
			continue
		}
		if cs.StackName != stack || cs.Name != csName {
			lastErr = fmt.Errorf("change set %s not found for stack %s", csName, stack)
			continue
		}
		return &cs, cmName, nil
	}
	return nil, "", lastErr
}

// --- drift ---

func (h *cfnDoorway) detectStackDrift(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	// DetectDrift is read-only and fast, so run it synchronously and store the result under a detection id.
	report, err := cfn.DetectDrift(r.Context(), h.opts(stack, nil), ap)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	detID := shortHash(stack + "/" + time.Now().UTC().Format(time.RFC3339Nano))
	if err := h.putDrift(r.Context(), stack, detID, report); err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "DetectStackDrift", "<StackDriftDetectionId>"+xesc(detID)+"</StackDriftDetectionId>")
}

func (h *cfnDoorway) describeDriftStatus(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	detID := r.PostFormValue("StackDriftDetectionId")
	report, stack, err := h.getDrift(r.Context(), detID)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "drift detection "+detID+" not found.", cfnXMLNamespace)
		return
	}
	status := "DRIFTED"
	if report.InSync {
		status = "IN_SYNC"
	}
	drifted := 0
	for _, rd := range report.Resources {
		if rd.Status != cfn.InSync {
			drifted++
		}
	}
	inner := "<StackId>" + xesc(h.stackID(stack)) + "</StackId>" +
		"<StackDriftDetectionId>" + xesc(detID) + "</StackDriftDetectionId>" +
		"<DetectionStatus>DETECTION_COMPLETE</DetectionStatus>" +
		"<StackDriftStatus>" + status + "</StackDriftStatus>" +
		"<DriftedStackResourceCount>" + strconv.Itoa(drifted) + "</DriftedStackResourceCount>"
	h.writeResult(w, requestID, "DescribeStackDriftDetectionStatus", inner)
}

func (h *cfnDoorway) describeResourceDrifts(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	stack := r.PostFormValue("StackName")
	report, found := h.latestDrift(r.Context(), stack)
	if !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "no drift detection has been run for stack ["+stack+"].", cfnXMLNamespace)
		return
	}
	var b strings.Builder
	for _, rd := range report.Resources {
		cfnStatus := "IN_SYNC"
		switch rd.Status {
		case cfn.Modified:
			cfnStatus = "MODIFIED"
		case cfn.Deleted:
			cfnStatus = "DELETED"
		}
		b.WriteString("<member>")
		b.WriteString("<StackId>" + xesc(h.stackID(stack)) + "</StackId>")
		b.WriteString("<LogicalResourceId>" + xesc(rd.LogicalID) + "</LogicalResourceId>")
		b.WriteString("<PhysicalResourceId>" + xesc(rd.Name) + "</PhysicalResourceId>")
		b.WriteString("<ResourceType>" + xesc(rd.Kind) + "</ResourceType>")
		b.WriteString("<StackResourceDriftStatus>" + cfnStatus + "</StackResourceDriftStatus>")
		b.WriteString("<Timestamp>" + xesc(time.Now().UTC().Format(time.RFC3339)) + "</Timestamp>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "DescribeStackResourceDrifts", "<StackResourceDrifts>"+b.String()+"</StackResourceDrifts>")
}

func (h *cfnDoorway) putDrift(ctx context.Context, stack, detID string, report *cfn.DriftReport) error {
	data, _ := json.Marshal(report)
	st := h.recs()
	obj := st.object("cfn-drift-"+stack,
		map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/drift": stack},
		map[string]any{"cfn.openinfra.dev/detection-id": detID},
		map[string]string{"drift.json": string(data), "detectionId": detID, "stack": stack})
	_, err := st.client().Apply(ctx, "cfn-drift-"+stack, obj, metav1.ApplyOptions{FieldManager: cfnFieldManager, Force: true})
	return err
}

func (h *cfnDoorway) getDrift(ctx context.Context, detID string) (*cfn.DriftReport, string, error) {
	st := h.recs()
	list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil, "", err
	}
	for i := range list.Items {
		u := &list.Items[i]
		if !strings.HasPrefix(u.GetName(), "cfn-drift-") || st.value(u, "detectionId") != detID {
			continue
		}
		data := st.value(u, "drift.json")
		stack := st.value(u, "stack")
		var rep cfn.DriftReport
		if err := json.Unmarshal([]byte(data), &rep); err != nil {
			return nil, "", err
		}
		return &rep, stack, nil
	}
	return nil, "", fmt.Errorf("not found")
}

func (h *cfnDoorway) latestDrift(ctx context.Context, stack string) (*cfn.DriftReport, bool) {
	st := h.recs()
	u, err := st.client().Get(ctx, "cfn-drift-"+stack, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}
	data := st.value(u, "drift.json")
	var rep cfn.DriftReport
	if json.Unmarshal([]byte(data), &rep) != nil {
		return nil, false
	}
	return &rep, true
}

// --- XML rendering ---

// writeResult wraps an operation's result body in the standard CFN query-protocol envelope.
func (h *cfnDoorway) writeResult(w http.ResponseWriter, requestID, op, resultInner string) {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<` + op + `Response xmlns="` + cfnXMLNamespace + `">`)
	if resultInner != "" {
		b.WriteString(`<` + op + `Result>` + resultInner + `</` + op + `Result>`)
	} else {
		b.WriteString(`<` + op + `Result/>`)
	}
	b.WriteString(`<ResponseMetadata><RequestId>` + xesc(requestID) + `</RequestId></ResponseMetadata>`)
	b.WriteString(`</` + op + `Response>`)
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func xesc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// recTime returns a record's most recent timestamp (for the required Timestamp output member).
func recTime(rec *cfn.StackRecord) string {
	if rec.UpdatedAt != "" {
		return rec.UpdatedAt
	}
	if rec.CreatedAt != "" {
		return rec.CreatedAt
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// normalizeStackArgs lets StackName and ChangeSetName be given as their ARNs, as AWS allows: `aws
// cloudformation deploy` creates a change set and then describes/executes it by the Id CreateChangeSet
// returned (arn:...:changeSet/<name>/<id>), and clients pass a stack's StackId (arn:...:stack/<name>/<id>).
// Both are reduced to the bare name every handler keys on.
func normalizeStackArgs(r *http.Request) {
	for key, marker := range map[string]string{"StackName": ":stack/", "ChangeSetName": ":changeSet/"} {
		vals, ok := r.PostForm[key]
		if !ok || len(vals) == 0 {
			continue
		}
		if name, ok := nameFromCFNArn(vals[0], marker); ok {
			r.PostForm.Set(key, name)
			r.Form.Set(key, name)
		}
	}
}

// nameFromCFNArn returns <name> from arn:aws:cloudformation:<region>:<account>:<marker><name>/<id>.
func nameFromCFNArn(v, marker string) (string, bool) {
	if !strings.HasPrefix(v, "arn:") || !strings.Contains(v, ":cloudformation:") {
		return "", false
	}
	i := strings.Index(v, marker)
	if i < 0 {
		return "", false
	}
	rest := v[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		rest = rest[:j]
	}
	return rest, rest != ""
}

// deleteChangeSetsOf removes every change-set record of a stack (best effort; a leftover record
// provisions nothing, it would only be listed).
func (h *cfnDoorway) deleteChangeSetsOf(ctx context.Context, stack string) {
	cms := h.recs().client()
	list, err := cms.List(ctx, metav1.ListOptions{LabelSelector: "cfn.openinfra.dev/changeset=" + stack})
	if err != nil {
		h.logger.Warn("cfn: could not list the stack's change sets", "stack", stack, "error", err.Error())
		return
	}
	for _, it := range list.Items {
		if err := cms.Delete(ctx, it.GetName(), metav1.DeleteOptions{}); err != nil {
			h.logger.Warn("cfn: could not delete a change set", "stack", stack, "changeSet", it.GetName(), "error", err.Error())
		}
	}
}

// templateParametersXML renders a template's declared Parameters as the <Parameters> member AWS returns
// from ValidateTemplate (summary=false: ParameterKey/DefaultValue/NoEcho) and GetTemplateSummary
// (summary=true: also ParameterType). A template that does not parse renders an empty list.
func templateParametersXML(data []byte, summary bool) string {
	t, err := cfn.Parse(data)
	if err != nil || len(t.Parameters) == 0 {
		return "<Parameters/>"
	}
	keys := make([]string, 0, len(t.Parameters))
	for k := range t.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("<Parameters>")
	for _, k := range keys {
		p := t.Parameters[k]
		b.WriteString("<member><ParameterKey>" + xesc(k) + "</ParameterKey>")
		if p.Default != nil {
			b.WriteString("<DefaultValue>" + xesc(fmt.Sprint(p.Default)) + "</DefaultValue>")
		}
		if summary {
			b.WriteString("<ParameterType>" + xesc(p.Type) + "</ParameterType>")
		}
		b.WriteString("<NoEcho>" + strconv.FormatBool(p.NoEcho) + "</NoEcho></member>")
	}
	b.WriteString("</Parameters>")
	return b.String()
}

// getTemplateSummary answers GetTemplateSummary for a template body/URL or a deployed stack (its last
// template) — `aws cloudformation deploy` calls it on every update to learn the template's parameters.
func (h *cfnDoorway) getTemplateSummary(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	var body string
	if name := r.PostFormValue("StackName"); name != "" {
		rec, found, err := ap.GetStack(r.Context(), name)
		if err != nil || !found {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+name+" does not exist", cfnXMLNamespace)
			return
		}
		body = rec.Template
	} else {
		b, err := h.templateBody(r)
		if err != nil {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), cfnXMLNamespace)
			return
		}
		body = b
	}
	t, err := cfn.Parse([]byte(body))
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Template format error: "+err.Error(), cfnXMLNamespace)
		return
	}
	types := map[string]bool{}
	for _, res := range t.Resources {
		types[res.Type] = true
	}
	tl := make([]string, 0, len(types))
	for k := range types {
		tl = append(tl, k)
	}
	sort.Strings(tl)
	var rt strings.Builder
	for _, k := range tl {
		rt.WriteString("<member>" + xesc(k) + "</member>")
	}
	h.writeResult(w, requestID, "GetTemplateSummary", templateParametersXML([]byte(body), true)+
		"<Capabilities/><ResourceTypes>"+rt.String()+"</ResourceTypes><Version>2010-09-09</Version>")
}

// getTemplate returns the template a stack was last deployed with.
func (h *cfnDoorway) getTemplate(w http.ResponseWriter, r *http.Request, ap *impersonatingApplier, requestID string) {
	name := r.PostFormValue("StackName")
	rec, found, err := ap.GetStack(r.Context(), name)
	if err != nil || !found {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Stack with id "+name+" does not exist", cfnXMLNamespace)
		return
	}
	h.writeResult(w, requestID, "GetTemplate", "<TemplateBody>"+xesc(rec.Template)+"</TemplateBody><StagesAvailable><member>Original</member><member>Processed</member></StagesAvailable>")
}
