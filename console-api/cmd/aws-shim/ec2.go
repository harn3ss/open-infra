// EC2 front door (SigV4 service `ec2`, the EC2 Query protocol, API 2016-11-15) — #350 item T, #347 items
// 23 and 24.
//
// EC2 here is the platform's own kinds, read in the account's namespace (the CloudFormation stack
// namespace, where a stack's instances, volumes, security groups, VPCs and subnets are): DescribeInstances
// over kind: VirtualMachine, DescribeVolumes over kind: Volume (plus each VM's root and data disks),
// DescribeSecurityGroups, DescribeVpcs and DescribeSubnets over their kinds, DescribeImages over the OS
// catalog, DescribeRegions and DescribeAvailabilityZones for the install's one region and zone, and
// DescribeAddresses over a stack's Elastic IP allocations (cfn_addresses.go), and a VPC's structure —
// DescribeInternetGateways, DescribeRouteTables, DescribeNetworkAcls and DescribeVpcEndpoints — over the
// kind: Vpc, its subnets and NAT gateways, the kind: VpcEndpoint, and the gateways, route tables and
// associations a stack's template gives it (ec2_structural.go). The ids are the ones
// CloudFormation reports for the same resources (cfn/resource_attrs.go): an instance's is the i- id its
// guest's instance metadata reports (ec2_ids.go); a volume's, group's, VPC's and subnet's is its kind's
// name. What a kind does not model (tags, an instance type, a group's description) comes from the AWS
// view the CloudFormation engine records on it (cfn.AWSViewAnnotation).
//
// Lambda functions in a VPC: their network interfaces (DescribeNetworkInterfaces; ec2_network_interfaces.go)
// and VPC Flow Logs of the traffic their security groups reject (CreateFlowLogs, DescribeFlowLogs,
// DeleteFlowLogs; ec2_flowlogs.go), delivered to CloudWatch Logs (ec2_flowlogs_delivery.go).
//
// Writes: the key pairs (ImportKeyPair, CreateKeyPair, DescribeKeyPairs, DeleteKeyPair; ec2_keypairs.go),
// which an instance's KeyName carries into its VM's spec.sshKey, and DeleteVolume, for a volume an
// instance kept (DeleteOnTermination: false), refused with AWS's VolumeInUse while a VM still has it; and
// the instance state operations StartInstances, StopInstances, RebootInstances and TerminateInstances
// (ec2_instances.go). Launching instances stays CloudFormation's (an unserved operation answers
// NotImplemented in EC2's error shape).
//
// Authorization, as AWS evaluates it: ec2:<Action> on the resource (Instance::<id>, Volume::<id>,
// KeyPair::<name>; a Describe on "*"), additive for a User and the whole, default-deny authority for an
// assumed role. The kinds are read and deleted with the CALLER's own Kubernetes authority (impersonation,
// as the CloudFormation front door applies them), so RBAC decides what a caller sees; key pairs, kept in
// the shim's store, take the coarse RBAC check every store-backed front door makes.
//
// Accounts, as on AWS: each account's resources are its own. The management account's are in the stack
// namespace, as they always were; a member account's are in its home namespace, its key pairs are its own
// (the same name may be a key pair in both), and the OwnerId and ARNs of what it is answered name it. A
// member account never sees, changes or deletes another account's. The catalog's images are the
// platform's in every account (their owner is the install's account, as a public AMI's is its publisher's).
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const ec2XMLNS = "http://ec2.amazonaws.com/doc/2016-11-15/"

var (
	volumeGVR        = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "volumes"}
	securityGroupGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "securitygroups"}
	vpcGVR           = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "vpcs"}
	subnetGVR        = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "subnets"}
)

// ec2Op is a served operation: the resource type its authorization names, and the coarse RBAC verb an
// operation on the shim's own store (key pairs, the catalog) needs.
type ec2Op struct{ resType, verb string }

var ec2Ops = map[string]ec2Op{
	"DescribeInstances":         {"Instance", "get"},
	"DescribeVolumes":           {"Volume", "get"},
	"DescribeSecurityGroups":    {"SecurityGroup", "get"},
	"DescribeVpcs":              {"Vpc", "get"},
	"DescribeSubnets":           {"Subnet", "get"},
	"DescribeImages":            {"Image", "get"},
	"DescribeRegions":           {"Region", "get"},
	"DescribeAvailabilityZones": {"AvailabilityZone", "get"},
	"DescribeAddresses":         {"ElasticIp", "get"},
	"DescribeInternetGateways":  {"InternetGateway", "get"},
	"DescribeRouteTables":       {"RouteTable", "get"},
	"DescribeNetworkAcls":       {"NetworkAcl", "get"},
	"DescribeVpcEndpoints":      {"VpcEndpoint", "get"},
	"DescribeKeyPairs":          {"KeyPair", "get"},
	"ImportKeyPair":             {"KeyPair", "create"},
	"CreateKeyPair":             {"KeyPair", "create"},
	"DeleteKeyPair":             {"KeyPair", "delete"},
	"DeleteVolume":              {"Volume", "delete"},
	"StartInstances":            {"Instance", "update"},
	"StopInstances":             {"Instance", "update"},
	"RebootInstances":           {"Instance", "update"},
	"TerminateInstances":        {"Instance", "delete"},
	"DescribeNetworkInterfaces": {"NetworkInterface", "get"},
	"CreateFlowLogs":            {"VpcFlowLog", "create"},
	"DescribeFlowLogs":          {"VpcFlowLog", "get"},
	"DeleteFlowLogs":            {"VpcFlowLog", "delete"},
}

type ec2Handler struct {
	door   *cfnDoorway  // the account namespace, the caller's and the shim's clients, authorization
	keys   *ec2KeyStore // nil: the key-pair store is not configured (key pair operations answer so)
	logger *slog.Logger
	// restartVM restarts a VM in place (RebootInstances); nil: KubeVirt's restart subresource, as the shim.
	restartVM func(ctx context.Context, namespace, name string) error
	flowLogs  *ec2FlowLogStore // nil: the flow-log store is not configured (flow log operations answer so)
	vpc       *vpcInterfaces   // the Lambda VPC subnet's interfaces (nil: no function is in a VPC)
	fns       *fnLocator       // the namespaces an account keeps its functions in
	rolesNS   string           // the IAM home, where the management account's roles are (iam:PassRole)
}

func newEC2Handler(door *cfnDoorway, keys *ec2KeyStore, logger *slog.Logger) *ec2Handler {
	return &ec2Handler{door: door, keys: keys, logger: logger}
}

func (h *ec2Handler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeEC2Error(w, http.StatusUnauthorized, "AuthFailure", requestID, "AWS was not able to validate the provided access credentials")
}

// writeEC2Error writes EC2's error shape: <Response><Errors><Error><Code/><Message/></Error></Errors><RequestID/>.
func writeEC2Error(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xmlHeader + "<Response><Errors><Error><Code>" + xesc(code) + "</Code><Message>" + xesc(message) +
		"</Message></Error></Errors><RequestID>" + xesc(requestID) + "</RequestID></Response>"))
}

// writeEC2 writes an operation's response: <OpResponse xmlns><requestId/>inner</OpResponse>.
func writeEC2(w http.ResponseWriter, requestID, op, inner string) {
	w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xmlHeader + "<" + op + "Response xmlns=\"" + ec2XMLNS + "\"><requestId>" + xesc(requestID) + "</requestId>" +
		inner + "</" + op + "Response>"))
}

func ec2ServedOps() string {
	out := make([]string, 0, len(ec2Ops))
	for op := range ec2Ops {
		out = append(out, op)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func (h *ec2Handler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	op := r.Form.Get("Action")
	if op == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingAction", requestID, "The request must contain the parameter Action")
		return
	}
	spec, ok := ec2Ops[op]
	if !ok {
		writeEC2Error(w, http.StatusNotImplemented, "NotImplemented", requestID,
			"EC2 "+op+" is not served by the open-infra shim (served: "+ec2ServedOps()+"); instances are launched and changed through CloudFormation")
		return
	}
	resID := ec2ScopeName(op, r.Form)
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	if h.door == nil {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "EC2 needs the CloudFormation front door's account namespace, which is not configured on this shim")
		return
	}
	if ec2InstanceStateOp(op) {
		// Authorized on each named instance (an assumed role's grant on one instance is enough for it, as on
		// AWS), then DryRun answered, inside (ec2_instances.go).
		h.instanceStateOp(ctx, w, r, claims, op, requestID)
		return
	}
	// ec2:<Op> on the resource (decide): in legacy the data-plane refinement here, and the coarse RBAC check
	// below for the shim's own state; in enforce IAM policy alone.
	if ok, reason := decide(ctx, r, h.door.authz, claims, "ec2:"+op, spec.resType, resID,
		dataPlaneOnly(ctx, r, h.door.authz, claims, "ec2:"+op, spec.resType, resID)); !ok {
		h.audit(ctx, op, resID, reason)
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
		return
	}
	// The shim's own state (key pairs, the catalog, the region, the account's addresses) takes the coarse
	// RBAC check in legacy; the kinds are read for the caller below (listForCaller).
	if ec2StoreOp(op) && !enforcing(ctx, h.door.authz, claims) {
		if h.door.cs == nil && claims.AssumedRole == "" {
			writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "EC2 authorization is not configured on this shim")
			return
		}
		if allowed, reason := coarseOnly(ctx, h.door.cs, claims, spec.verb, "openinfra.dev", "applications", h.door.authzNS, resID)(); !allowed {
			h.audit(ctx, op, resID, reason)
			writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+reason)
			return
		}
	}
	if r.Form.Get("DryRun") == "true" {
		writeEC2Error(w, http.StatusPreconditionFailed, "DryRunOperation", requestID, "Request would have succeeded, but DryRun flag is set.")
		return
	}
	switch op {
	case "DescribeInstances":
		h.describeInstances(ctx, w, r, claims, requestID)
	case "DescribeVolumes":
		h.describeVolumes(ctx, w, r, claims, requestID)
	case "DescribeSecurityGroups":
		h.describeSecurityGroups(ctx, w, r, claims, requestID)
	case "DescribeVpcs":
		h.describeVpcs(ctx, w, r, claims, requestID)
	case "DescribeSubnets":
		h.describeSubnets(ctx, w, r, claims, requestID)
	case "DescribeImages":
		h.describeImages(w, r, requestID)
	case "DescribeRegions":
		h.describeRegions(w, r, requestID)
	case "DescribeAvailabilityZones":
		h.describeAvailabilityZones(w, r, requestID)
	case "DescribeAddresses":
		h.describeAddresses(ctx, w, r, claims, requestID)
	case "DescribeInternetGateways":
		h.describeInternetGateways(ctx, w, r, claims, requestID)
	case "DescribeRouteTables":
		h.describeRouteTables(ctx, w, r, claims, requestID)
	case "DescribeNetworkAcls":
		h.describeNetworkAcls(ctx, w, r, claims, requestID)
	case "DescribeVpcEndpoints":
		h.describeVpcEndpoints(ctx, w, r, claims, requestID)
	case "DescribeKeyPairs":
		h.describeKeyPairs(ctx, w, r, requestID)
	case "ImportKeyPair", "CreateKeyPair":
		h.putKeyPair(ctx, w, r, op, requestID)
	case "DeleteKeyPair":
		h.deleteKeyPair(ctx, w, r, requestID)
	case "DeleteVolume":
		h.deleteVolume(ctx, w, r, claims, requestID)
	case "DescribeNetworkInterfaces":
		h.describeNetworkInterfaces(ctx, w, r, claims, requestID)
	case "CreateFlowLogs":
		h.createFlowLogs(ctx, w, r, claims, requestID)
	case "DescribeFlowLogs":
		h.describeFlowLogs(ctx, w, r, requestID)
	case "DeleteFlowLogs":
		h.deleteFlowLogs(ctx, w, r, claims, requestID)
	}
}

// ec2StoreOp reports whether op acts on the shim's own state rather than on a kind read as the caller.
func ec2StoreOp(op string) bool {
	switch op {
	case "DescribeKeyPairs", "ImportKeyPair", "CreateKeyPair", "DeleteKeyPair",
		"DescribeImages", "DescribeRegions", "DescribeAvailabilityZones", "DescribeAddresses",
		"CreateFlowLogs", "DescribeFlowLogs", "DeleteFlowLogs":
		return true
	}
	return false
}

// ec2ScopeName is the one resource an operation authorizes against ("" for a Describe: AWS evaluates
// those on Resource "*").
func ec2ScopeName(op string, form url.Values) string {
	switch op {
	case "ImportKeyPair", "CreateKeyPair":
		return form.Get("KeyName")
	case "DeleteKeyPair":
		if n := form.Get("KeyName"); n != "" {
			return n
		}
		return form.Get("KeyPairId")
	case "DeleteVolume":
		return form.Get("VolumeId")
	case "DeleteFlowLogs":
		return form.Get("FlowLogId.1") // each other one is authorized before anything is deleted (deleteFlowLogs)
	}
	return ""
}

func (h *ec2Handler) audit(ctx context.Context, op, res, reason string) {
	if h.logger != nil {
		h.logger.InfoContext(ctx, "ec2 audit", "service", "ec2", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "resource", res, "reason", reason)
	}
}

// --- request parameters ---

// ec2List is an EC2 query list parameter: Name.1, Name.2, … (contiguous from 1).
func ec2List(form url.Values, name string) []string {
	var out []string
	for i := 1; i <= 1000; i++ {
		v, ok := form[name+"."+strconv.Itoa(i)]
		if !ok || len(v) == 0 {
			break
		}
		out = append(out, v[0])
	}
	return out
}

type ec2Filter struct {
	name   string
	values []string
}

// ec2Filters reads Filter.N.Name / Filter.N.Value.M.
func ec2Filters(form url.Values) []ec2Filter {
	var out []ec2Filter
	for i := 1; i <= 200; i++ {
		p := "Filter." + strconv.Itoa(i)
		name := form.Get(p + ".Name")
		if name == "" {
			break
		}
		out = append(out, ec2Filter{name: name, values: ec2List(form, p+".Value")})
	}
	return out
}

// ec2Record is a described resource as its filters see it: each filter name's values, and its tags.
type ec2Record struct {
	fields map[string][]string
	tags   map[string]string
}

// checkFilters refuses a filter the operation does not have, as AWS does (InvalidParameterValue).
func checkFilters(fs []ec2Filter, known []string) (string, bool) {
	ok := map[string]bool{"tag-key": true, "tag-value": true}
	for _, k := range known {
		ok[k] = true
	}
	for _, f := range fs {
		if !ok[f.name] && !strings.HasPrefix(f.name, "tag:") {
			return "The filter '" + f.name + "' is invalid", false
		}
	}
	return "", true
}

// matches applies the filters: every filter must match (AND), any of a filter's values (OR), with AWS's
// * and ? wildcards.
func (rec ec2Record) matches(fs []ec2Filter) bool {
	for _, f := range fs {
		var have []string
		switch {
		case strings.HasPrefix(f.name, "tag:"):
			if v, ok := rec.tags[strings.TrimPrefix(f.name, "tag:")]; ok {
				have = []string{v}
			}
		case f.name == "tag-key":
			for k := range rec.tags {
				have = append(have, k)
			}
		case f.name == "tag-value":
			for _, v := range rec.tags {
				have = append(have, v)
			}
		default:
			have = rec.fields[f.name]
		}
		if !anyGlob(f.values, have) {
			return false
		}
	}
	return true
}

func anyGlob(patterns, values []string) bool {
	for _, p := range patterns {
		for _, v := range values {
			if ec2Glob(p, v) {
				return true
			}
		}
	}
	return false
}

// ec2Glob matches s against an EC2 filter value: * any run, ? any one character, \ escapes.
func ec2Glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if ec2Glob(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			p, s = p[1:], s[1:]
		case '\\':
			if len(p) > 1 {
				p = p[1:]
			}
			fallthrough
		default:
			if s == "" || s[0] != p[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}

// ec2Page applies MaxResults/NextToken to n results: the [start,end) slice and the next token ("" at the
// end). ok=false with a message for a bad token or a MaxResults below min. A MaxResults above max is
// capped at max, as EC2 does ("if MaxResults is given a value larger than 500, only 500 items are
// returned"): the AWS CLI sends MaxResults=1000 when it paginates, so refusing it broke every plain
// `aws ec2 describe-*` whose maximum is below that.
func ec2Page(form url.Values, n, min, max int) (start, end int, next, msg string, ok bool) {
	end = n
	if t := form.Get("NextToken"); t != "" {
		b, err := base64.RawURLEncoding.DecodeString(t)
		v, aerr := strconv.Atoi(string(b))
		if err != nil || aerr != nil || v < 0 {
			return 0, 0, "", "The NextToken is not valid", false
		}
		start = v
	}
	if start > n {
		start = n
	}
	if m := form.Get("MaxResults"); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil || v < min {
			return 0, 0, "", "MaxResults must be between " + strconv.Itoa(min) + " and " + strconv.Itoa(max), false
		}
		if v > max {
			v = max
		}
		if start+v < n {
			end = start + v
			next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		}
	}
	return start, end, next, "", true
}

// --- XML ---

func xtag(name, value string) string {
	if value == "" {
		return ""
	}
	return "<" + name + ">" + xesc(value) + "</" + name + ">"
}

func xbool(name string, v bool) string {
	return "<" + name + ">" + strconv.FormatBool(v) + "</" + name + ">"
}

func xset(name string, items []string) string {
	if len(items) == 0 {
		return "<" + name + "/>"
	}
	return "<" + name + "><item>" + strings.Join(items, "</item><item>") + "</item></" + name + ">"
}

func xtags(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]string, 0, len(keys))
	for _, k := range keys {
		items = append(items, "<key>"+xesc(k)+"</key><value>"+xesc(tags[k])+"</value>")
	}
	if len(items) == 0 {
		return ""
	}
	return xset("tagSet", items)
}

func ec2Time(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// --- reading the kinds, for the caller ---

// listForCaller lists a kind in the caller's account's namespace (accountNS) for a caller the front door
// has authorized. In legacy the read is made with the caller's Kubernetes authority, its RBAC being its
// read permission (denied reports that RBAC refused it). In enforce IAM policy has already decided the
// call, and the read is what it allowed: it is made with the shim's own client, in the account namespace
// alone — the caller's RBAC (generated from the same policy by the IAM compiler, and not there before it
// runs) is never a second decision on a read IAM policy allowed. A write still acts as the caller
// (applierFor).
func (h *ec2Handler) listForCaller(ctx context.Context, claims iam.Claims, gvr schema.GroupVersionResource) (items []unstructured.Unstructured, denied bool, err error) {
	return h.listForCallerIn(ctx, claims, gvr, h.accountNS(ctx))
}

// accountNS is the namespace the caller's account's instances, volumes, security groups, VPCs, subnets and
// addresses are in (accountNamespace): the stack namespace for the management account, where they always
// were, and a member account's home for a member's — so a member account reads, changes and deletes its
// own alone, never the management account's or another member's.
func (h *ec2Handler) accountNS(ctx context.Context) string { return accountNamespace(ctx, h.door.ns) }

// listForCallerIn is listForCaller in namespace ns (the caller's account's: accountNamespace).
func (h *ec2Handler) listForCallerIn(ctx context.Context, claims iam.Claims, gvr schema.GroupVersionResource, ns string) (items []unstructured.Unstructured, denied bool, err error) {
	var cli dynamic.Interface
	if enforcing(ctx, h.door.authz, claims) {
		if h.door.shimDyn == nil {
			return nil, false, errors.New("the shim's client is not configured")
		}
		cli = h.door.shimDyn
	} else {
		ap, err := h.door.applierFor(claims)
		if err != nil {
			return nil, true, err
		}
		cli = ap.caller
	}
	l, err := cli.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
		return nil, true, err
	case apierrors.IsNotFound(err):
		return nil, false, nil // the kind is not installed: there are none
	case err != nil:
		return nil, false, err
	}
	sort.Slice(l.Items, func(i, j int) bool { return l.Items[i].GetName() < l.Items[j].GetName() })
	return l.Items, false, nil
}

// readFailed answers a list that could not be made.
func (h *ec2Handler) readFailed(w http.ResponseWriter, requestID, what string, denied bool, err error) {
	if denied {
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+err.Error())
		return
	}
	if h.logger != nil {
		h.logger.Warn("ec2: reading "+what+" failed", "error", err.Error())
	}
	writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "The "+what+" could not be read; retry.")
}

func (h *ec2Handler) region() string {
	if h.door != nil && h.door.region != "" {
		return h.door.region
	}
	return "us-east-1"
}

func (h *ec2Handler) zone() string { return h.region() + "a" }

func (h *ec2Handler) account() string {
	if h.door != nil && h.door.account != "" {
		return h.door.account
	}
	return "000000000000"
}

// ownerAccount is the account the caller's resources belong to — their OwnerId, and the account their
// ARNs name: a member account's own id, the install's for the management account (whose answers do not
// change).
func (h *ec2Handler) ownerAccount(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account()
}

// EC2 keeps each account's resources apart: a member account's instances, volumes, groups, VPCs, subnets
// and addresses are in its home namespace, its key pairs are its own (ec2_keypairs.go), and their OwnerId
// and ARNs name it.
func init() { accountScopedServices["ec2"] = true }

// --- key pairs ---

func (h *ec2Handler) describeKeyPairs(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if h.keys == nil {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "the key-pair store is not configured on this shim (set SQS_PG_URI)")
		return
	}
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"key-name", "key-pair-id", "fingerprint", "key-type"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	all, err := h.keys.list(ctx)
	if err != nil {
		h.readFailed(w, requestID, "key pairs", false, err)
		return
	}
	names, ids := ec2List(r.Form, "KeyName"), ec2List(r.Form, "KeyPairId")
	wantName, wantID := setOf(names), setOf(ids)
	found := map[string]bool{}
	includePub := r.Form.Get("IncludePublicKey") == "true"
	var items []string
	for _, k := range all {
		if (len(names) > 0 || len(ids) > 0) && !wantName[k.Name] && !wantID[k.ID] {
			continue
		}
		found[k.Name], found[k.ID] = true, true
		rec := ec2Record{fields: map[string][]string{"key-name": {k.Name}, "key-pair-id": {k.ID}, "fingerprint": {k.Fingerprint}, "key-type": {k.Type}}, tags: k.Tags}
		if !rec.matches(fs) {
			continue
		}
		item := xtag("keyPairId", k.ID) + xtag("keyFingerprint", k.Fingerprint) + xtag("keyName", k.Name) + xtag("keyType", k.Type) +
			xtags(k.Tags) + xtag("createTime", ec2Time(k.Created))
		if includePub {
			item += xtag("publicKey", k.PublicKey)
		}
		items = append(items, item)
	}
	for _, n := range names {
		if !found[n] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidKeyPair.NotFound", requestID, "The key pair '"+n+"' does not exist")
			return
		}
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidKeyPair.NotFound", requestID, "The key pair ID '"+id+"' does not exist")
			return
		}
	}
	writeEC2(w, requestID, "DescribeKeyPairs", xset("keySet", items))
}

func (h *ec2Handler) putKeyPair(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string) {
	if h.keys == nil {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "the key-pair store is not configured on this shim (set SQS_PG_URI)")
		return
	}
	name := r.Form.Get("KeyName")
	if name == "" || len(name) > 255 || strings.IndexFunc(name, func(c rune) bool { return c < 0x20 || c > 0x7e }) >= 0 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "KeyName must be 1 to 255 printable ASCII characters")
		return
	}
	k := ec2KeyPair{Name: name, ID: newKeyPairID(), Tags: ec2TagSpec(r.Form, "key-pair")}
	var material string
	if op == "ImportKeyPair" {
		pub, typ, fp, err := parseImportedKey(r.Form.Get("PublicKeyMaterial"))
		if err != nil {
			writeEC2Error(w, http.StatusBadRequest, "InvalidKey.Format", requestID, err.Error())
			return
		}
		k.PublicKey, k.Type, k.Fingerprint = pub, typ, fp
	} else {
		if f := r.Form.Get("KeyFormat"); f != "" && f != "pem" {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "KeyFormat "+f+" is not supported by the open-infra shim (pem)")
			return
		}
		typ := r.Form.Get("KeyType")
		priv, pub, fp, err := generateKeyPair(typ)
		if err != nil {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, err.Error())
			return
		}
		if typ == "" {
			typ = "rsa"
		}
		material, k.PublicKey, k.Type, k.Fingerprint = priv, pub, typ, fp
	}
	k, err := h.keys.put(ctx, k)
	if err == errKeyPairExists {
		writeEC2Error(w, http.StatusBadRequest, "InvalidKeyPair.Duplicate", requestID, "The keypair '"+name+"' already exists.")
		return
	}
	if err != nil {
		h.readFailed(w, requestID, "key pairs", false, err)
		return
	}
	out := xtag("keyName", k.Name) + xtag("keyFingerprint", k.Fingerprint) + xtag("keyPairId", k.ID) + xtags(k.Tags)
	if material != "" {
		out += xtag("keyMaterial", material)
	}
	writeEC2(w, requestID, op, out)
}

func (h *ec2Handler) deleteKeyPair(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	if h.keys == nil {
		writeEC2Error(w, http.StatusServiceUnavailable, "Unavailable", requestID, "the key-pair store is not configured on this shim (set SQS_PG_URI)")
		return
	}
	name, id := r.Form.Get("KeyName"), r.Form.Get("KeyPairId")
	if name == "" && id == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter KeyName or KeyPairId")
		return
	}
	gone, err := h.keys.delete(ctx, name, id)
	if err != nil {
		h.readFailed(w, requestID, "key pairs", false, err)
		return
	}
	writeEC2(w, requestID, "DeleteKeyPair", "<return>true</return>"+xtag("keyPairId", gone))
}

// ec2TagSpec reads TagSpecification.N (ResourceType, Tag.M.Key/Value) for one resource type.
func ec2TagSpec(form url.Values, resourceType string) map[string]string {
	tags := map[string]string{}
	for i := 1; i <= 50; i++ {
		p := "TagSpecification." + strconv.Itoa(i)
		rt := form.Get(p + ".ResourceType")
		if rt == "" {
			break
		}
		if rt != resourceType {
			continue
		}
		for j := 1; j <= 50; j++ {
			k := form.Get(p + ".Tag." + strconv.Itoa(j) + ".Key")
			if k == "" {
				break
			}
			tags[k] = form.Get(p + ".Tag." + strconv.Itoa(j) + ".Value")
		}
	}
	return tags
}

func setOf(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
