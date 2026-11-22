// Elastic Load Balancing front door (SigV4 service `elasticloadbalancing`, the Query protocol, API
// 2015-12-01): Network Load Balancers in front of EC2 instances.
//
// A load balancer is internet-facing (on this platform, "internet" is the network the installation's
// load-balancer addresses are reachable from: the LAN), placed in a public subnet of the account's default VPC
// (a subnet whose route table sends 0.0.0.0/0 to an internet gateway; ec2_default_vpc.go), and forwards each
// listener's TCP, UDP or TCP_UDP traffic to the instances registered in its target group. As an AWS Network
// Load Balancer with instance targets does, it passes the client's own address to the instance, so the
// instance's security groups decide which clients reach it; and an instance in a subnet with no route out
// answers the clients a load balancer brings it and starts nothing itself.
//
// Served: CreateLoadBalancer, DescribeLoadBalancers, DeleteLoadBalancer, DescribeLoadBalancerAttributes;
// CreateTargetGroup, DescribeTargetGroups, DeleteTargetGroup, DescribeTargetGroupAttributes, RegisterTargets,
// DeregisterTargets, DescribeTargetHealth; CreateListener, DescribeListeners, DeleteListener; AddTags,
// RemoveTags, DescribeTags. Application and Gateway Load Balancers, internal load balancers, a load
// balancer's own security groups, TLS listeners and IP/Lambda targets refuse in ELB's words, saying so; a
// target group's health check settings are kept and reported, and a target is healthy while its instance
// runs (no health check is sent to it).
//
// Authorization, as AWS evaluates it: elasticloadbalancing:<Action> on the resource's ARN as AWS writes it
// (arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/net/<name>/<id>, targetgroup/<name>/<id>,
// listener/net/<lb name>/<lb id>/<id>), so a policy naming those ARNs, with AWS's wildcards, means what it
// says; the Describe actions on "*", as AWS has no resource-level permission for them; tags given at creation
// need elasticloadbalancing:AddTags too. Each account's load balancers are its own (account-scoped door).
//
// Where it is kept: an account's load balancers, target groups and listeners are a record in the shim's own
// namespace (elbv2-<account>, a Secret beside the CloudFormation stack records), written by the shim once the
// caller is authorized. Each load balancer is a LoadBalancer Service there, without a selector, taking its
// address from the installation's load-balancer address pool (ELB_ADDRESS_POOL) with the client's address
// kept (externalTrafficPolicy Local), and EndpointSlices the shim writes from its targets' current addresses
// (elbv2_dataplane.go), kept current as instances stop, start and move.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const elbXMLNS = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"

// Each account's load balancers are its own.
func init() { accountScopedServices["elasticloadbalancing"] = true }

// elbHandler serves Elastic Load Balancing.
type elbHandler struct {
	ec2    *ec2Handler          // the account's instances and default VPC, and the door's authorization
	cs     kubernetes.Interface // the shim's own client: the records, and the load balancers' Services and EndpointSlices
	ns     string               // the shim's namespace, where those are kept
	pool   string               // the address pool load balancers take their addresses from ("" = the installation's default)
	logger *slog.Logger
	mu     sync.Mutex // serializes this replica's record writes (each record's resourceVersion fences the replicas)
}

func newELBHandler(ec2 *ec2Handler, cs kubernetes.Interface, ns, pool string, logger *slog.Logger) *elbHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &elbHandler{ec2: ec2, cs: cs, ns: ns, pool: pool, logger: logger}
}

// elbOps are the served operations, each with the coarse RBAC verb a legacy decision checks.
var elbOps = map[string]string{
	"CreateLoadBalancer": "create", "DescribeLoadBalancers": "get", "DeleteLoadBalancer": "delete",
	"DescribeLoadBalancerAttributes": "get",
	"CreateTargetGroup":              "create", "DescribeTargetGroups": "get", "DeleteTargetGroup": "delete",
	"DescribeTargetGroupAttributes": "get", "RegisterTargets": "create", "DeregisterTargets": "delete",
	"DescribeTargetHealth": "get",
	"CreateListener":       "create", "DescribeListeners": "get", "DeleteListener": "delete",
	"AddTags": "create", "RemoveTags": "delete", "DescribeTags": "get",
}

func elbServedOps() string {
	ops := make([]string, 0, len(elbOps))
	for op := range elbOps {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return strings.Join(ops, ", ")
}

func (h *elbHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeQueryError(w, authStatus(r, http.StatusForbidden), authCode(r, "SignatureDoesNotMatch"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."), elbXMLNS)
}

// elbError is an ELB error: its HTTP status, code and message.
type elbError struct {
	status        int
	code, message string
}

func (e *elbError) Error() string { return e.code + ": " + e.message }

func elbErr(code, format string, args ...any) *elbError {
	return &elbError{status: http.StatusBadRequest, code: code, message: fmt.Sprintf(format, args...)}
}

func writeELBError(w http.ResponseWriter, e *elbError, requestID string) {
	writeQueryError(w, e.status, e.code, requestID, e.message, elbXMLNS)
}

// writeELB writes an operation's response: <Op>Response with its <Op>Result and the request id.
func writeELB(w http.ResponseWriter, requestID, op, result string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n<" + op + `Response xmlns="` + elbXMLNS + `"><` + op + "Result>" +
		result + "</" + op + "Result><ResponseMetadata><RequestId>" + xesc(requestID) + "</RequestId></ResponseMetadata></" + op + "Response>"))
}

// --- the records ---

// elbRecords are an account's load balancers, target groups and listeners.
type elbRecords struct {
	Account       string         `json:"account"`
	Namespace     string         `json:"namespace"` // the account's namespace, where its instances are
	LoadBalancers []*elbLB       `json:"loadBalancers,omitempty"`
	TargetGroups  []*elbTG       `json:"targetGroups,omitempty"`
	Listeners     []*elbListener `json:"listeners,omitempty"`
}

type elbLB struct {
	ID      string            `json:"id"` // 16 hex digits, as AWS's
	Name    string            `json:"name"`
	Scheme  string            `json:"scheme"`
	VPC     string            `json:"vpc"`
	Subnets []string          `json:"subnets"`
	Created time.Time         `json:"created"`
	Tags    map[string]string `json:"tags,omitempty"`
}

type elbHealthCheck struct {
	Protocol           string `json:"protocol"`
	Port               string `json:"port"`
	Path               string `json:"path,omitempty"`
	Interval           int    `json:"interval"`
	Timeout            int    `json:"timeout"`
	HealthyThreshold   int    `json:"healthyThreshold"`
	UnhealthyThreshold int    `json:"unhealthyThreshold"`
	Matcher            string `json:"matcher,omitempty"`
}

type elbTarget struct {
	ID   string `json:"id"`
	Port int    `json:"port"`
}

type elbTG struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Protocol    string            `json:"protocol"`
	Port        int               `json:"port"`
	VPC         string            `json:"vpc"`
	HealthCheck elbHealthCheck    `json:"healthCheck"`
	Targets     []elbTarget       `json:"targets,omitempty"`
	Created     time.Time         `json:"created"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type elbListener struct {
	ID          string            `json:"id"`
	LB          string            `json:"lb"` // its load balancer's id
	Protocol    string            `json:"protocol"`
	Port        int               `json:"port"`
	TargetGroup string            `json:"targetGroup"` // its default action's target group's id
	Tags        map[string]string `json:"tags,omitempty"`
}

const (
	elbRecordsLabel = "openinfra.dev/elbv2"         // "records" on an account's record Secret
	elbAccountLabel = "openinfra.dev/elbv2-account" // the account, on its record and its load balancers' objects
	elbLBLabel      = "openinfra.dev/elbv2-load-balancer"
	elbRecordsKey   = "elbv2.json"
)

func elbRecordName(account string) string { return "elbv2-" + account }

func (rec *elbRecords) lb(id string) *elbLB {
	for _, l := range rec.LoadBalancers {
		if l.ID == id {
			return l
		}
	}
	return nil
}

func (rec *elbRecords) tg(id string) *elbTG {
	for _, g := range rec.TargetGroups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// listenersOf are lb's listeners, by port.
func (rec *elbRecords) listenersOf(lb string) []*elbListener {
	var out []*elbListener
	for _, l := range rec.Listeners {
		if l.LB == lb {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// lbsOf are the load balancers whose listeners forward to target group tg.
func (rec *elbRecords) lbsOf(tg string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range rec.Listeners {
		if l.TargetGroup == tg && !seen[l.LB] {
			seen[l.LB] = true
			out = append(out, l.LB)
		}
	}
	sort.Strings(out)
	return out
}

// load reads account's records (empty, with a nil Secret, when it has none yet).
func (h *elbHandler) load(ctx context.Context, account string) (*elbRecords, *corev1.Secret, error) {
	sec, err := h.cs.CoreV1().Secrets(h.ns).Get(ctx, elbRecordName(account), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return &elbRecords{Account: account}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	rec := &elbRecords{}
	if err := json.Unmarshal(sec.Data[elbRecordsKey], rec); err != nil {
		return nil, nil, fmt.Errorf("the account's load balancer records do not read: %w", err)
	}
	rec.Account = account
	return rec, sec, nil
}

// update applies change to account's records and stores them, retrying when another writer got there first.
// change returning an error stores nothing.
func (h *elbHandler) update(ctx context.Context, account, ns string, change func(*elbRecords) error) (*elbRecords, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for attempt := 0; attempt < 6; attempt++ {
		rec, sec, err := h.load(ctx, account)
		if err != nil {
			return nil, err
		}
		if ns != "" {
			rec.Namespace = ns
		}
		if err := change(rec); err != nil {
			return nil, err
		}
		data, _ := json.Marshal(rec)
		if sec == nil {
			sec = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: elbRecordName(account), Namespace: h.ns,
				Labels: map[string]string{elbRecordsLabel: "records", elbAccountLabel: account}},
				Data: map[string][]byte{elbRecordsKey: data}}
			_, err = h.cs.CoreV1().Secrets(h.ns).Create(ctx, sec, metav1.CreateOptions{})
		} else {
			sec.Data = map[string][]byte{elbRecordsKey: data}
			_, err = h.cs.CoreV1().Secrets(h.ns).Update(ctx, sec, metav1.UpdateOptions{})
		}
		if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return rec, nil
	}
	return nil, errors.New("the account's load balancer records kept changing under this write")
}

// --- ARNs and names ---

type elbScope struct{ region, account string }

func (s elbScope) prefix() string {
	return "arn:" + awsidentity.Partition + ":elasticloadbalancing:" + s.region + ":" + s.account + ":"
}
func (s elbScope) lbARN(l *elbLB) string {
	return s.prefix() + "loadbalancer/net/" + l.Name + "/" + l.ID
}
func (s elbScope) tgARN(g *elbTG) string { return s.prefix() + "targetgroup/" + g.Name + "/" + g.ID }
func (s elbScope) listenerARN(lb *elbLB, l *elbListener) string {
	return s.prefix() + "listener/net/" + lb.Name + "/" + lb.ID + "/" + l.ID
}

// dnsName is a load balancer's DNS name, in AWS's form.
func (s elbScope) dnsName(l *elbLB) string {
	return strings.ToLower(l.Name) + "-" + l.ID + ".elb." + s.region + ".amazonaws.com"
}

// elbHostedZones are the Route 53 hosted zones of Network Load Balancers' DNS names, by region.
var elbHostedZones = map[string]string{"us-east-1": "Z26RNL4JYFTOTI"}

func (h *elbHandler) scope(ctx context.Context) elbScope {
	return elbScope{region: h.ec2.region(), account: callerAccount(ctx)}
}

func newELBID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var elbNameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?$`)

func validELBName(kind, name string) *elbError {
	if name == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not be null")
	}
	if !elbNameRe.MatchString(name) || strings.HasPrefix(strings.ToLower(name), "internal-") {
		return elbErr("ValidationError", "%s name '%s' must be at most 32 characters, contain only letters, digits and hyphens, not begin or end with a hyphen, and not begin with 'internal-'", kind, name)
	}
	return nil
}

// --- request parameters ---

// elbMembers is a Query list parameter: Name.member.1, Name.member.2, … (contiguous from 1).
func elbMembers(form url.Values, name string) []string {
	var out []string
	for i := 1; i <= 1000; i++ {
		v, ok := form[name+".member."+strconv.Itoa(i)]
		if !ok {
			break
		}
		out = append(out, v[0])
	}
	return out
}

// elbTags are Tags.member.N.Key / .Value.
func elbTags(form url.Values) (map[string]string, *elbError) {
	tags := map[string]string{}
	for i := 1; i <= 1000; i++ {
		p := "Tags.member." + strconv.Itoa(i)
		k, ok := form[p+".Key"]
		if !ok {
			break
		}
		if _, dup := tags[k[0]]; dup {
			return nil, elbErr("DuplicateTagKeys", "Tag key '%s' is specified more than once", k[0])
		}
		tags[k[0]] = form.Get(p + ".Value")
	}
	if len(tags) > 50 {
		return nil, elbErr("TooManyTags", "A resource can have at most 50 tags")
	}
	return tags, nil
}

func elbPort(form url.Values, name string, required bool) (int, *elbError) {
	v := form.Get(name)
	if v == "" {
		if required {
			return 0, elbErr("ValidationError", "1 validation error detected: Value null at '%s' failed to satisfy constraint: Member must not be null", lowerFirst(name))
		}
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return 0, elbErr("ValidationError", "1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must have value between 1 and 65535", v, lowerFirst(name))
	}
	return n, nil
}

// elbProtocol is a Network Load Balancer protocol the platform serves (TCP, UDP, TCP_UDP), else the error.
func elbProtocol(what, p string) (string, *elbError) {
	switch p {
	case "TCP", "UDP", "TCP_UDP":
		return p, nil
	case "":
		return "", elbErr("ValidationError", "1 validation error detected: Value null at 'protocol' failed to satisfy constraint: Member must not be null")
	case "TLS":
		return "", elbErr("UnsupportedProtocol", "TLS %ss are not served here: a network load balancer here forwards TCP, UDP and TCP_UDP", what)
	case "HTTP", "HTTPS", "GENEVE":
		return "", elbErr("UnsupportedProtocol", "%s protocol '%s' is for an application or gateway load balancer, which is not served here: a network load balancer forwards TCP, UDP and TCP_UDP", what, p)
	}
	return "", elbErr("ValidationError", "%s protocol '%s' must be one of 'TCP, UDP, TCP_UDP'", what, p)
}

// --- serving ---

func (h *elbHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	op := r.Form.Get("Action")
	if op == "" {
		writeELBError(w, elbErr("MissingAction", "The request must contain the parameter Action"), requestID)
		return
	}
	verb, ok := elbOps[op]
	if !ok {
		writeELBError(w, elbErr("InvalidAction", "Elastic Load Balancing %s is not served by the open-infra shim (served: %s)", op, elbServedOps()), requestID)
		return
	}
	if h.ec2 == nil || h.ec2.door == nil || h.cs == nil {
		writeELBError(w, &elbError{status: http.StatusServiceUnavailable, code: "ServiceUnavailable",
			message: "Elastic Load Balancing needs the EC2 front door and the shim's own client, which are not configured on this shim"}, requestID)
		return
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	c := &elbCall{h: h, ctx: ctx, w: w, r: r, claims: claims, op: op, verb: verb, requestID: requestID, sc: h.scope(ctx)}
	var err *elbError
	switch op {
	case "CreateLoadBalancer":
		err = c.createLoadBalancer()
	case "DescribeLoadBalancers":
		err = c.describeLoadBalancers()
	case "DeleteLoadBalancer":
		err = c.deleteLoadBalancer()
	case "DescribeLoadBalancerAttributes":
		err = c.describeLBAttributes()
	case "CreateTargetGroup":
		err = c.createTargetGroup()
	case "DescribeTargetGroups":
		err = c.describeTargetGroups()
	case "DeleteTargetGroup":
		err = c.deleteTargetGroup()
	case "DescribeTargetGroupAttributes":
		err = c.describeTGAttributes()
	case "RegisterTargets", "DeregisterTargets":
		err = c.changeTargets(op == "RegisterTargets")
	case "DescribeTargetHealth":
		err = c.describeTargetHealth()
	case "CreateListener":
		err = c.createListener()
	case "DescribeListeners":
		err = c.describeListeners()
	case "DeleteListener":
		err = c.deleteListener()
	case "AddTags", "RemoveTags":
		err = c.changeTags(op == "AddTags")
	case "DescribeTags":
		err = c.describeTags()
	}
	if err != nil {
		writeELBError(w, err, requestID)
	}
}

// elbCall is one request being served.
type elbCall struct {
	h         *elbHandler
	ctx       context.Context
	w         http.ResponseWriter
	r         *http.Request
	claims    iam.Claims
	op, verb  string
	requestID string
	sc        elbScope
}

// allow decides action (elasticloadbalancing:<op>, or another, e.g. AddTags for tags given at creation) on
// the resource's ARN as written — "" is a Describe's "*", as AWS has no resource-level permission for them.
func (c *elbCall) allow(action, arn string) *elbError {
	door := c.h.ec2.door
	rt, id := arnType, arn // typedResource: "" is "*"
	verb := elbOps[strings.TrimPrefix(action, "elasticloadbalancing:")]
	if verb == "" {
		verb = c.verb
	}
	if ok, reason := decide(c.ctx, c.r, door.authz, c.claims, action, rt, id,
		coarseThenDataPlane(c.ctx, c.r, door.cs, door.authz, c.claims, verb, "openinfra.dev", "applications", door.authzNS, id,
			action, rt, id)); !ok {
		c.h.logger.InfoContext(c.ctx, "elasticloadbalancing audit", "service", "elasticloadbalancing", "op", c.op, "decision", "deny",
			"principal", principalFromCtx(c.ctx), "resource", typedResource(rt, id), "reason", reason)
		return &elbError{status: http.StatusForbidden, code: "AccessDenied", message: reason}
	}
	return nil
}

func (c *elbCall) records() (*elbRecords, *elbError) {
	rec, _, err := c.h.load(c.ctx, c.sc.account)
	if err != nil {
		return nil, c.internal(err)
	}
	return rec, nil
}

func (c *elbCall) internal(err error) *elbError {
	c.h.logger.ErrorContext(c.ctx, "elasticloadbalancing", "op", c.op, "error", err.Error())
	return &elbError{status: http.StatusInternalServerError, code: "InternalFailure", message: "the request could not be completed: " + err.Error()}
}

// update changes the caller's account's records, then brings its load balancers' traffic in line.
func (c *elbCall) update(change func(*elbRecords) error) (*elbRecords, *elbError) {
	rec, err := c.h.update(c.ctx, c.sc.account, c.h.ec2.accountNS(c.ctx), change)
	var ee *elbError
	if errors.As(err, &ee) {
		return nil, ee
	}
	if err != nil {
		return nil, c.internal(err)
	}
	if serr := c.h.sync(c.ctx, rec); serr != nil {
		c.h.logger.WarnContext(c.ctx, "elasticloadbalancing: a load balancer's traffic is brought in line on the next pass", "account", rec.Account, "error", serr.Error())
	}
	return rec, nil
}

// lbByARN is the caller's account's load balancer arn names (nil if none).
func (c *elbCall) lbByARN(rec *elbRecords, arn string) *elbLB {
	for _, l := range rec.LoadBalancers {
		if c.sc.lbARN(l) == arn {
			return l
		}
	}
	return nil
}

func (c *elbCall) tgByARN(rec *elbRecords, arn string) *elbTG {
	for _, g := range rec.TargetGroups {
		if c.sc.tgARN(g) == arn {
			return g
		}
	}
	return nil
}

func (c *elbCall) listenerByARN(rec *elbRecords, arn string) (*elbListener, *elbLB) {
	for _, l := range rec.Listeners {
		if lb := rec.lb(l.LB); lb != nil && c.sc.listenerARN(lb, l) == arn {
			return l, lb
		}
	}
	return nil, nil
}

// --- load balancers ---

func (c *elbCall) createLoadBalancer() *elbError {
	f := c.r.Form
	name := f.Get("Name")
	if e := validELBName("Load balancer", name); e != nil {
		return e
	}
	switch t := f.Get("Type"); t {
	case "network":
	case "", "application":
		return elbErr("ValidationError", "Application load balancers are not served here (a load balancer's Type is 'application' unless it says otherwise): set Type 'network' for a network load balancer; an HTTP service's routing is its ingress")
	case "gateway":
		return elbErr("ValidationError", "Gateway load balancers are not served here: set Type 'network' for a network load balancer")
	default:
		return elbErr("ValidationError", "Load balancer type '%s' must be one of 'application, network, gateway'", t)
	}
	scheme := f.Get("Scheme")
	switch scheme {
	case "", "internet-facing":
		scheme = "internet-facing"
	case "internal":
		return elbErr("ValidationError", "Internal load balancers are not served here yet: a network load balancer here is internet-facing (reachable from the network the platform's load-balancer addresses are on)")
	default:
		return elbErr("ValidationError", "Scheme '%s' must be one of 'internet-facing, internal'", scheme)
	}
	if t := f.Get("IpAddressType"); t != "" && t != "ipv4" {
		return elbErr("ValidationError", "IP address type '%s' is not served here: a load balancer here is ipv4", t)
	}
	if len(elbMembers(f, "SecurityGroups")) > 0 {
		return elbErr("ValidationError", "Security groups on a network load balancer are not supported here: one without them passes each client's address to its targets, whose security groups decide which clients reach them")
	}
	if f.Get("CustomerOwnedIpv4Pool") != "" {
		return elbErr("ValidationError", "Customer-owned address pools are not served here")
	}
	subnets := elbMembers(f, "Subnets")
	for i := 1; i <= 1000; i++ {
		p := "SubnetMappings.member." + strconv.Itoa(i)
		s := f.Get(p + ".SubnetId")
		if s == "" {
			break
		}
		if f.Get(p+".AllocationId") != "" || f.Get(p+".PrivateIPv4Address") != "" || f.Get(p+".IPv6Address") != "" {
			return elbErr("ValidationError", "A subnet mapping's AllocationId, PrivateIPv4Address and IPv6Address are not supported here: a load balancer's address comes from the platform's load-balancer addresses")
		}
		subnets = append(subnets, s)
	}
	if len(subnets) == 0 {
		return elbErr("ValidationError", "At least one subnet must be specified")
	}
	tags, terr := elbTags(f)
	if terr != nil {
		return terr
	}
	d := c.h.ec2.defaultVPCOf(c.ctx)
	if d == nil {
		return elbErr("InvalidSubnet", "The account has no default VPC: a load balancer is placed in a subnet of it")
	}
	seen := map[string]bool{}
	for _, s := range subnets {
		if seen[s] {
			continue
		}
		seen[s] = true
		if s != d.subnetID() && s != d.publicSubnetID() {
			return elbErr("SubnetNotFound", "The subnet ID '%s' is not valid (a load balancer here is placed in a subnet of the account's default VPC)", s)
		}
	}
	if len(seen) > 1 {
		return elbErr("InvalidConfigurationRequest", "A load balancer cannot be attached to multiple subnets in the same Availability Zone")
	}
	if !d.hasGateway() {
		return elbErr("InvalidSubnet", "VPC %s has no internet gateway", d.vpcID())
	}
	if !d.isPublicSubnet(subnets[0]) {
		return elbErr("InvalidSubnet", "Subnet '%s' has no route to an internet gateway: an internet-facing load balancer is placed in a public subnet", subnets[0])
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	want := &elbLB{ID: newELBID(), Name: name, Scheme: scheme, VPC: d.vpcID(), Subnets: []string{subnets[0]}, Tags: tags}
	for _, l := range rec.LoadBalancers {
		if l.Name == name {
			want.ID = l.ID // CreateLoadBalancer is idempotent: decided on the one it would return
		}
	}
	arn := c.sc.lbARN(want)
	if e := c.allow("elasticloadbalancing:CreateLoadBalancer", arn); e != nil {
		return e
	}
	if len(tags) > 0 {
		if e := c.allow("elasticloadbalancing:AddTags", arn); e != nil {
			return e
		}
	}
	var made *elbLB
	rec, e = c.update(func(rec *elbRecords) error {
		for _, l := range rec.LoadBalancers {
			if l.Name != name {
				continue
			}
			if l.Scheme != want.Scheme || strings.Join(l.Subnets, ",") != strings.Join(want.Subnets, ",") {
				return elbErr("DuplicateLoadBalancerName", "A load balancer with the same name '%s' exists, but with different settings", name)
			}
			made = l
			return nil
		}
		if len(rec.LoadBalancers) >= 50 {
			return elbErr("TooManyLoadBalancers", "The quota for the number of load balancers has been reached (50)")
		}
		want.Created = time.Now().UTC()
		rec.LoadBalancers = append(rec.LoadBalancers, want)
		made = want
		return nil
	})
	if e != nil {
		return e
	}
	addrs := c.h.addresses(c.ctx, rec.Account)
	writeELB(c.w, c.requestID, c.op, "<LoadBalancers><member>"+c.lbXML(made, addrs)+"</member></LoadBalancers>")
	return nil
}

// lbXML is a load balancer as DescribeLoadBalancers lists it. addrs are its account's load balancers'
// addresses, by id: one without its address yet is provisioning.
func (c *elbCall) lbXML(l *elbLB, addrs map[string]string) string {
	state := "provisioning"
	addr := addrs[l.ID]
	if addr != "" {
		state = "active"
	}
	var zones []string
	for _, s := range l.Subnets {
		z := xtag("ZoneName", c.h.ec2.zone()) + xtag("SubnetId", s)
		if addr != "" {
			z += "<LoadBalancerAddresses><member>" + xtag("IpAddress", addr) + "</member></LoadBalancerAddresses>"
		} else {
			z += "<LoadBalancerAddresses/>"
		}
		zones = append(zones, z)
	}
	return xtag("LoadBalancerArn", c.sc.lbARN(l)) + xtag("DNSName", c.sc.dnsName(l)) +
		xtag("CanonicalHostedZoneId", elbHostedZones[c.sc.region]) + xtag("CreatedTime", ec2Time(l.Created)) +
		xtag("LoadBalancerName", l.Name) + xtag("Scheme", l.Scheme) + xtag("VpcId", l.VPC) +
		"<State>" + xtag("Code", state) + "</State>" + xtag("Type", "network") +
		elbMemberList("AvailabilityZones", zones) + xtag("IpAddressType", "ipv4")
}

// elbMemberList is <name><member>…</member>…</name> (<name/> when empty).
func elbMemberList(name string, items []string) string {
	if len(items) == 0 {
		return "<" + name + "/>"
	}
	return "<" + name + "><member>" + strings.Join(items, "</member><member>") + "</member></" + name + ">"
}

func (c *elbCall) describeLoadBalancers() *elbError {
	if e := c.allow("elasticloadbalancing:DescribeLoadBalancers", ""); e != nil {
		return e
	}
	arns, names := elbMembers(c.r.Form, "LoadBalancerArns"), elbMembers(c.r.Form, "Names")
	if len(arns) > 0 && len(names) > 0 {
		return elbErr("ValidationError", "Load balancer names and load balancer ARNs cannot be specified at the same time")
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	var out []*elbLB
	switch {
	case len(arns) > 0:
		for _, a := range arns {
			l := c.lbByARN(rec, a)
			if l == nil {
				return elbErr("LoadBalancerNotFound", "One or more load balancers not found")
			}
			out = append(out, l)
		}
	case len(names) > 0:
		var missing []string
		for _, n := range names {
			found := false
			for _, l := range rec.LoadBalancers {
				if l.Name == n {
					out, found = append(out, l), true
				}
			}
			if !found {
				missing = append(missing, "'"+n+"'")
			}
		}
		if len(missing) > 0 {
			return elbErr("LoadBalancerNotFound", "Load balancers '[%s]' not found", strings.Join(missing, ", "))
		}
	default:
		out = rec.LoadBalancers
	}
	addrs := c.h.addresses(c.ctx, rec.Account)
	var items []string
	for _, l := range out {
		items = append(items, c.lbXML(l, addrs))
	}
	writeELB(c.w, c.requestID, c.op, elbMemberList("LoadBalancers", items))
	return nil
}

func (c *elbCall) deleteLoadBalancer() *elbError {
	arn := c.r.Form.Get("LoadBalancerArn")
	if arn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'loadBalancerArn' failed to satisfy constraint: Member must not be null")
	}
	if e := c.allow("elasticloadbalancing:DeleteLoadBalancer", arn); e != nil {
		return e
	}
	// Deleting a load balancer that does not exist, or was deleted already, succeeds, as on AWS; its
	// listeners go with it.
	_, e := c.update(func(rec *elbRecords) error {
		l := c.lbByARN(rec, arn)
		if l == nil {
			return nil
		}
		rec.LoadBalancers = removeWhere(rec.LoadBalancers, func(x *elbLB) bool { return x.ID == l.ID })
		rec.Listeners = removeWhere(rec.Listeners, func(x *elbListener) bool { return x.LB == l.ID })
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "")
	return nil
}

func removeWhere[T any](s []T, drop func(T) bool) []T {
	out := s[:0]
	for _, v := range s {
		if !drop(v) {
			out = append(out, v)
		}
	}
	return out
}

func (c *elbCall) describeLBAttributes() *elbError {
	arn := c.r.Form.Get("LoadBalancerArn")
	if e := c.allow("elasticloadbalancing:DescribeLoadBalancerAttributes", ""); e != nil {
		return e
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	if c.lbByARN(rec, arn) == nil {
		return elbErr("LoadBalancerNotFound", "One or more load balancers not found")
	}
	writeELB(c.w, c.requestID, c.op, elbAttributes([][2]string{{"deletion_protection.enabled", "false"},
		{"load_balancing.cross_zone.enabled", "false"}, {"access_logs.s3.enabled", "false"}, {"access_logs.s3.bucket", ""},
		{"access_logs.s3.prefix", ""}, {"dns_record.client_routing_policy", "any_availability_zone"}}))
	return nil
}

func elbAttributes(kv [][2]string) string {
	var items []string
	for _, a := range kv {
		items = append(items, "<Key>"+xesc(a[0])+"</Key><Value>"+xesc(a[1])+"</Value>")
	}
	return elbMemberList("Attributes", items)
}

// --- target groups ---

func (c *elbCall) createTargetGroup() *elbError {
	f := c.r.Form
	name := f.Get("Name")
	if e := validELBName("Target group", name); e != nil {
		return e
	}
	switch t := f.Get("TargetType"); t {
	case "", "instance":
	case "ip", "lambda", "alb":
		return elbErr("ValidationError", "Target type '%s' is not served here: a target group's targets here are instances", t)
	default:
		return elbErr("ValidationError", "Target type '%s' must be one of 'instance, ip, lambda, alb'", t)
	}
	proto, pe := elbProtocol("target group", f.Get("Protocol"))
	if pe != nil {
		return pe
	}
	port, pe := elbPort(f, "Port", true)
	if pe != nil {
		return pe
	}
	if t := f.Get("IpAddressType"); t != "" && t != "ipv4" {
		return elbErr("ValidationError", "IP address type '%s' is not served here: a target group here is ipv4", t)
	}
	vpc := f.Get("VpcId")
	if vpc == "" {
		return elbErr("ValidationError", "A VPC ID must be specified for a target group of instances")
	}
	d := c.h.ec2.defaultVPCOf(c.ctx)
	if d == nil || vpc != d.vpcID() {
		return elbErr("ValidationError", "The VPC ID '%s' is not found (a target group here is in the account's default VPC)", vpc)
	}
	hc, he := elbHealthCheckOf(f)
	if he != nil {
		return he
	}
	tags, terr := elbTags(f)
	if terr != nil {
		return terr
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	want := &elbTG{ID: newELBID(), Name: name, Protocol: proto, Port: port, VPC: vpc, HealthCheck: hc, Tags: tags}
	for _, g := range rec.TargetGroups {
		if g.Name == name {
			want.ID = g.ID
		}
	}
	arn := c.sc.tgARN(want)
	if e := c.allow("elasticloadbalancing:CreateTargetGroup", arn); e != nil {
		return e
	}
	if len(tags) > 0 {
		if e := c.allow("elasticloadbalancing:AddTags", arn); e != nil {
			return e
		}
	}
	var made *elbTG
	rec, e = c.update(func(rec *elbRecords) error {
		for _, g := range rec.TargetGroups {
			if g.Name != name {
				continue
			}
			if g.Protocol != proto || g.Port != port || g.VPC != vpc {
				return elbErr("DuplicateTargetGroupName", "A target group with the same name '%s' exists, but with different settings", name)
			}
			made = g
			return nil
		}
		if len(rec.TargetGroups) >= 100 {
			return elbErr("TooManyTargetGroups", "The quota for the number of target groups has been reached (100)")
		}
		want.Created = time.Now().UTC()
		rec.TargetGroups = append(rec.TargetGroups, want)
		made = want
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "<TargetGroups><member>"+c.tgXML(rec, made)+"</member></TargetGroups>")
	return nil
}

// elbHealthCheckOf reads a target group's health check settings, with a network load balancer's defaults.
func elbHealthCheckOf(f url.Values) (elbHealthCheck, *elbError) {
	hc := elbHealthCheck{Protocol: "TCP", Port: "traffic-port", Interval: 30, Timeout: 10, HealthyThreshold: 5, UnhealthyThreshold: 2}
	if f.Get("HealthCheckEnabled") == "false" {
		return hc, elbErr("ValidationError", "Health checks cannot be disabled for a target group of a network load balancer's instances")
	}
	switch p := f.Get("HealthCheckProtocol"); p {
	case "", "TCP":
	case "HTTP", "HTTPS":
		hc.Protocol, hc.Path, hc.Matcher, hc.Timeout = p, "/", "200-399", 6
	default:
		return hc, elbErr("ValidationError", "Health check protocol '%s' must be one of 'TCP, HTTP, HTTPS'", p)
	}
	if p := f.Get("HealthCheckPort"); p != "" && p != "traffic-port" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return hc, elbErr("ValidationError", "Health check port '%s' must be 'traffic-port' or a port between 1 and 65535", p)
		}
		hc.Port = p
	}
	if p := f.Get("HealthCheckPath"); p != "" {
		if hc.Protocol == "TCP" {
			return hc, elbErr("ValidationError", "A health check path cannot be set for a TCP health check")
		}
		hc.Path = p
	}
	if m := f.Get("Matcher.HttpCode"); m != "" {
		hc.Matcher = m
	}
	for _, n := range []struct {
		param    string
		into     *int
		min, max int
	}{{"HealthCheckIntervalSeconds", &hc.Interval, 5, 300}, {"HealthCheckTimeoutSeconds", &hc.Timeout, 2, 120},
		{"HealthyThresholdCount", &hc.HealthyThreshold, 2, 10}, {"UnhealthyThresholdCount", &hc.UnhealthyThreshold, 2, 10}} {
		v := f.Get(n.param)
		if v == "" {
			continue
		}
		x, err := strconv.Atoi(v)
		if err != nil || x < n.min || x > n.max {
			return hc, elbErr("ValidationError", "1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must have value between %d and %d", v, lowerFirst(n.param), n.min, n.max)
		}
		*n.into = x
	}
	return hc, nil
}

func (c *elbCall) tgXML(rec *elbRecords, g *elbTG) string {
	var lbs []string
	for _, id := range rec.lbsOf(g.ID) {
		if l := rec.lb(id); l != nil {
			lbs = append(lbs, xesc(c.sc.lbARN(l)))
		}
	}
	hc := g.HealthCheck
	out := xtag("TargetGroupArn", c.sc.tgARN(g)) + xtag("TargetGroupName", g.Name) + xtag("Protocol", g.Protocol) +
		xtag("Port", strconv.Itoa(g.Port)) + xtag("VpcId", g.VPC) + xtag("HealthCheckProtocol", hc.Protocol) +
		xtag("HealthCheckPort", hc.Port) + "<HealthCheckEnabled>true</HealthCheckEnabled>" +
		xtag("HealthCheckIntervalSeconds", strconv.Itoa(hc.Interval)) + xtag("HealthCheckTimeoutSeconds", strconv.Itoa(hc.Timeout)) +
		xtag("HealthyThresholdCount", strconv.Itoa(hc.HealthyThreshold)) + xtag("UnhealthyThresholdCount", strconv.Itoa(hc.UnhealthyThreshold)) +
		xtag("HealthCheckPath", hc.Path)
	if hc.Matcher != "" {
		out += "<Matcher>" + xtag("HttpCode", hc.Matcher) + "</Matcher>"
	}
	return out + elbMemberList("LoadBalancerArns", lbs) + xtag("TargetType", "instance") + xtag("IpAddressType", "ipv4")
}

func (c *elbCall) describeTargetGroups() *elbError {
	if e := c.allow("elasticloadbalancing:DescribeTargetGroups", ""); e != nil {
		return e
	}
	f := c.r.Form
	arns, names, lbArn := elbMembers(f, "TargetGroupArns"), elbMembers(f, "Names"), f.Get("LoadBalancerArn")
	rec, e := c.records()
	if e != nil {
		return e
	}
	var out []*elbTG
	switch {
	case len(arns) > 0:
		for _, a := range arns {
			g := c.tgByARN(rec, a)
			if g == nil {
				return elbErr("TargetGroupNotFound", "One or more target groups not found")
			}
			out = append(out, g)
		}
	case len(names) > 0:
		for _, n := range names {
			found := false
			for _, g := range rec.TargetGroups {
				if g.Name == n {
					out, found = append(out, g), true
				}
			}
			if !found {
				return elbErr("TargetGroupNotFound", "One or more target groups not found")
			}
		}
	case lbArn != "":
		l := c.lbByARN(rec, lbArn)
		if l == nil {
			return elbErr("LoadBalancerNotFound", "One or more load balancers not found")
		}
		for _, g := range rec.TargetGroups {
			for _, id := range rec.lbsOf(g.ID) {
				if id == l.ID {
					out = append(out, g)
				}
			}
		}
	default:
		out = rec.TargetGroups
	}
	var items []string
	for _, g := range out {
		items = append(items, c.tgXML(rec, g))
	}
	writeELB(c.w, c.requestID, c.op, elbMemberList("TargetGroups", items))
	return nil
}

func (c *elbCall) deleteTargetGroup() *elbError {
	arn := c.r.Form.Get("TargetGroupArn")
	if arn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'targetGroupArn' failed to satisfy constraint: Member must not be null")
	}
	if e := c.allow("elasticloadbalancing:DeleteTargetGroup", arn); e != nil {
		return e
	}
	_, e := c.update(func(rec *elbRecords) error {
		g := c.tgByARN(rec, arn)
		if g == nil {
			return nil
		}
		if len(rec.lbsOf(g.ID)) > 0 {
			return elbErr("ResourceInUse", "Target group '%s' is currently in use by a listener or a rule", arn)
		}
		rec.TargetGroups = removeWhere(rec.TargetGroups, func(x *elbTG) bool { return x.ID == g.ID })
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "")
	return nil
}

func (c *elbCall) describeTGAttributes() *elbError {
	arn := c.r.Form.Get("TargetGroupArn")
	if e := c.allow("elasticloadbalancing:DescribeTargetGroupAttributes", ""); e != nil {
		return e
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	if c.tgByARN(rec, arn) == nil {
		return elbErr("TargetGroupNotFound", "One or more target groups not found")
	}
	writeELB(c.w, c.requestID, c.op, elbAttributes([][2]string{{"deregistration_delay.timeout_seconds", "300"},
		{"deregistration_delay.connection_termination.enabled", "false"}, {"preserve_client_ip.enabled", "true"},
		{"proxy_protocol_v2.enabled", "false"}, {"stickiness.enabled", "false"}, {"stickiness.type", "source_ip"},
		{"load_balancing.cross_zone.enabled", "use_load_balancer_configuration"}}))
	return nil
}

// elbTargetsOf reads Targets.member.N.Id / .Port.
func elbTargetsOf(f url.Values) ([]elbTarget, *elbError) {
	var out []elbTarget
	for i := 1; i <= 1000; i++ {
		p := "Targets.member." + strconv.Itoa(i)
		id := f.Get(p + ".Id")
		if id == "" {
			break
		}
		port, pe := elbPort(f, p+".Port", false)
		if pe != nil {
			return nil, pe
		}
		out = append(out, elbTarget{ID: id, Port: port})
	}
	if len(out) == 0 {
		return nil, elbErr("ValidationError", "1 validation error detected: Value null at 'targets' failed to satisfy constraint: Member must not be null")
	}
	return out, nil
}

func (c *elbCall) changeTargets(register bool) *elbError {
	arn := c.r.Form.Get("TargetGroupArn")
	if arn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'targetGroupArn' failed to satisfy constraint: Member must not be null")
	}
	targets, te := elbTargetsOf(c.r.Form)
	if te != nil {
		return te
	}
	if e := c.allow("elasticloadbalancing:"+c.op, arn); e != nil {
		return e
	}
	var insts map[string]ec2Instance
	if register {
		all, _, err := c.h.ec2.instancesForCaller(c.ctx, c.claims)
		if err != nil {
			return c.internal(err)
		}
		insts = map[string]ec2Instance{}
		for _, in := range all {
			insts[in.id] = in
		}
	}
	_, e := c.update(func(rec *elbRecords) error {
		g := c.tgByARN(rec, arn)
		if g == nil {
			return elbErr("TargetGroupNotFound", "One or more target groups not found")
		}
		for i := range targets {
			if targets[i].Port == 0 {
				targets[i].Port = g.Port
			}
		}
		if !register {
			drop := map[elbTarget]bool{}
			for _, t := range targets {
				drop[t] = true
			}
			g.Targets = removeWhere(g.Targets, func(t elbTarget) bool { return drop[t] })
			return nil
		}
		var invalid, outside []string
		for _, t := range targets {
			in, ok := insts[t.ID]
			switch {
			case !ok:
				invalid = append(invalid, "'"+t.ID+"'")
			case in.vpc != g.VPC:
				outside = append(outside, "'"+t.ID+"'")
			}
		}
		if len(invalid) > 0 {
			return elbErr("InvalidTarget", "The following targets are not valid instances: %s", strings.Join(invalid, ", "))
		}
		if len(outside) > 0 {
			return elbErr("InvalidTarget", "The following targets are not in the target group VPC '%s': %s", g.VPC, strings.Join(outside, ", "))
		}
		have := map[elbTarget]bool{}
		for _, t := range g.Targets {
			have[t] = true
		}
		for _, t := range targets {
			if !have[t] {
				g.Targets = append(g.Targets, t)
				have[t] = true
			}
		}
		if len(g.Targets) > 500 {
			return elbErr("TooManyTargets", "The quota for the number of targets in a target group has been reached (500)")
		}
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "")
	return nil
}

// elbTargetHealth is a registered target's health: unused while its group receives no traffic or its instance
// is not running, initial until its instance has an address, then healthy (no health check is sent to it).
func elbTargetHealth(inUse bool, in *ec2Instance, ready bool) (state, reason, desc string) {
	switch {
	case in == nil:
		return "unused", "Target.InvalidState", "Target is in the terminated state"
	case !inUse:
		return "unused", "Target.NotInUse", "Target group is not configured to receive traffic from the load balancer"
	case in.state == "stopped" || in.state == "stopping":
		return "unused", "Target.InvalidState", "Target is in the stopped state"
	case in.state != "running" || !ready:
		return "initial", "Elb.InitialHealthChecking", "Initial health checks in progress"
	}
	return "healthy", "", ""
}

func (c *elbCall) describeTargetHealth() *elbError {
	arn := c.r.Form.Get("TargetGroupArn")
	if e := c.allow("elasticloadbalancing:DescribeTargetHealth", ""); e != nil {
		return e
	}
	if arn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'targetGroupArn' failed to satisfy constraint: Member must not be null")
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	g := c.tgByARN(rec, arn)
	if g == nil {
		return elbErr("TargetGroupNotFound", "One or more target groups not found")
	}
	targets := g.Targets
	if _, given := c.r.Form["Targets.member.1.Id"]; given {
		asked, te := elbTargetsOf(c.r.Form)
		if te != nil {
			return te
		}
		targets = nil
		for _, t := range asked {
			if t.Port == 0 {
				t.Port = g.Port
			}
			targets = append(targets, t)
		}
	}
	all, _, err := c.h.ec2.instancesForCaller(c.ctx, c.claims)
	if err != nil {
		return c.internal(err)
	}
	insts := map[string]*ec2Instance{}
	for i := range all {
		insts[all[i].id] = &all[i]
	}
	registered := map[elbTarget]bool{}
	for _, t := range g.Targets {
		registered[t] = true
	}
	inUse := len(rec.lbsOf(g.ID)) > 0
	var items []string
	for _, t := range targets {
		state, reason, desc := "unused", "Target.NotRegistered", "Target is not registered to the target group"
		if registered[t] {
			in := insts[t.ID]
			ready := in != nil && c.h.endpointOf(c.ctx, in).ip != ""
			state, reason, desc = elbTargetHealth(inUse, in, ready)
		}
		hp := g.HealthCheck.Port
		if hp == "traffic-port" {
			hp = strconv.Itoa(t.Port)
		}
		th := xtag("State", state) + xtag("Reason", reason) + xtag("Description", desc)
		items = append(items, "<Target>"+xtag("Id", t.ID)+xtag("Port", strconv.Itoa(t.Port))+"</Target>"+
			xtag("HealthCheckPort", hp)+"<TargetHealth>"+th+"</TargetHealth>")
	}
	writeELB(c.w, c.requestID, c.op, elbMemberList("TargetHealthDescriptions", items))
	return nil
}

// --- listeners ---

func (c *elbCall) createListener() *elbError {
	f := c.r.Form
	lbArn := f.Get("LoadBalancerArn")
	if lbArn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'loadBalancerArn' failed to satisfy constraint: Member must not be null")
	}
	proto, pe := elbProtocol("listener", f.Get("Protocol"))
	if pe != nil {
		return pe
	}
	port, pe := elbPort(f, "Port", true)
	if pe != nil {
		return pe
	}
	if f.Get("Certificates.member.1.CertificateArn") != "" || f.Get("SslPolicy") != "" || f.Get("AlpnPolicy.member.1") != "" {
		return elbErr("ValidationError", "Certificates, SslPolicy and AlpnPolicy are for a TLS listener, which is not served here")
	}
	if _, more := f["DefaultActions.member.2.Type"]; more {
		return elbErr("ValidationError", "A network load balancer's listener has exactly one default action")
	}
	if t := f.Get("DefaultActions.member.1.Type"); t != "forward" {
		if t == "" {
			return elbErr("ValidationError", "1 validation error detected: Value null at 'defaultActions' failed to satisfy constraint: Member must not be null")
		}
		return elbErr("ValidationError", "Action type '%s' is not supported for a network load balancer's listener: its default action forwards to a target group", t)
	}
	tgArn := f.Get("DefaultActions.member.1.TargetGroupArn")
	if fc := f.Get("DefaultActions.member.1.ForwardConfig.TargetGroups.member.1.TargetGroupArn"); fc != "" {
		if tgArn != "" && tgArn != fc {
			return elbErr("ValidationError", "A forward action names one target group, in TargetGroupArn or in ForwardConfig")
		}
		if _, more := f["DefaultActions.member.1.ForwardConfig.TargetGroups.member.2.TargetGroupArn"]; more {
			return elbErr("ValidationError", "A network load balancer's listener forwards to one target group")
		}
		tgArn = fc
	}
	if tgArn == "" {
		return elbErr("ValidationError", "A forward action must name a target group")
	}
	tags, terr := elbTags(f)
	if terr != nil {
		return terr
	}
	if e := c.allow("elasticloadbalancing:CreateListener", lbArn); e != nil {
		return e
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	if lb := c.lbByARN(rec, lbArn); lb != nil && len(tags) > 0 {
		id := newELBID()
		for _, l := range rec.listenersOf(lb.ID) {
			if l.Port == port {
				id = l.ID
			}
		}
		if e := c.allow("elasticloadbalancing:AddTags", c.sc.listenerARN(lb, &elbListener{ID: id})); e != nil {
			return e
		}
	}
	var made *elbListener
	var madeLB *elbLB
	rec, e = c.update(func(rec *elbRecords) error {
		lb := c.lbByARN(rec, lbArn)
		if lb == nil {
			return elbErr("LoadBalancerNotFound", "One or more load balancers not found")
		}
		g := c.tgByARN(rec, tgArn)
		if g == nil {
			return elbErr("TargetGroupNotFound", "One or more target groups not found")
		}
		if g.VPC != lb.VPC {
			return elbErr("InvalidConfigurationRequest", "The target group '%s' and the load balancer '%s' must be in the same VPC", tgArn, lbArn)
		}
		if g.Protocol != proto {
			return elbErr("IncompatibleProtocols", "The listener protocol '%s' is not compatible with the target group protocol '%s'", proto, g.Protocol)
		}
		for _, other := range rec.lbsOf(g.ID) {
			if other != lb.ID {
				return elbErr("TargetGroupAssociationLimit", "The following target groups cannot be associated with more than one load balancer: '%s'", tgArn)
			}
		}
		mine := rec.listenersOf(lb.ID)
		for _, l := range mine {
			if l.Port != port {
				continue
			}
			if l.Protocol == proto && l.TargetGroup == g.ID {
				made, madeLB = l, lb // CreateListener is idempotent
				return nil
			}
			return elbErr("DuplicateListener", "A listener already exists on this port for this load balancer '%s'", lbArn)
		}
		if len(mine) >= 50 {
			return elbErr("TooManyListeners", "The quota for the number of listeners per load balancer has been reached (50)")
		}
		made = &elbListener{ID: newELBID(), LB: lb.ID, Protocol: proto, Port: port, TargetGroup: g.ID, Tags: tags}
		madeLB = lb
		rec.Listeners = append(rec.Listeners, made)
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "<Listeners><member>"+c.listenerXML(rec, madeLB, made)+"</member></Listeners>")
	return nil
}

func (c *elbCall) listenerXML(rec *elbRecords, lb *elbLB, l *elbListener) string {
	tgArn := ""
	if g := rec.tg(l.TargetGroup); g != nil {
		tgArn = c.sc.tgARN(g)
	}
	return xtag("ListenerArn", c.sc.listenerARN(lb, l)) + xtag("LoadBalancerArn", c.sc.lbARN(lb)) + xtag("Port", strconv.Itoa(l.Port)) +
		xtag("Protocol", l.Protocol) + "<DefaultActions><member>" + xtag("Type", "forward") + xtag("TargetGroupArn", tgArn) +
		"<ForwardConfig><TargetGroups><member>" + xtag("TargetGroupArn", tgArn) + "<Weight>1</Weight></member></TargetGroups>" +
		"<TargetGroupStickinessConfig><Enabled>false</Enabled></TargetGroupStickinessConfig></ForwardConfig></member></DefaultActions>"
}

func (c *elbCall) describeListeners() *elbError {
	if e := c.allow("elasticloadbalancing:DescribeListeners", ""); e != nil {
		return e
	}
	lbArn, arns := c.r.Form.Get("LoadBalancerArn"), elbMembers(c.r.Form, "ListenerArns")
	if lbArn == "" && len(arns) == 0 {
		return elbErr("ValidationError", "You must specify either listener ARNs or a load balancer ARN")
	}
	if lbArn != "" && len(arns) > 0 {
		return elbErr("ValidationError", "Listener ARNs and a load balancer ARN cannot be specified at the same time")
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	var items []string
	if lbArn != "" {
		lb := c.lbByARN(rec, lbArn)
		if lb == nil {
			return elbErr("LoadBalancerNotFound", "One or more load balancers not found")
		}
		for _, l := range rec.listenersOf(lb.ID) {
			items = append(items, c.listenerXML(rec, lb, l))
		}
	}
	for _, a := range arns {
		l, lb := c.listenerByARN(rec, a)
		if l == nil {
			return elbErr("ListenerNotFound", "One or more listeners not found")
		}
		items = append(items, c.listenerXML(rec, lb, l))
	}
	writeELB(c.w, c.requestID, c.op, elbMemberList("Listeners", items))
	return nil
}

func (c *elbCall) deleteListener() *elbError {
	arn := c.r.Form.Get("ListenerArn")
	if arn == "" {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'listenerArn' failed to satisfy constraint: Member must not be null")
	}
	if e := c.allow("elasticloadbalancing:DeleteListener", arn); e != nil {
		return e
	}
	_, e := c.update(func(rec *elbRecords) error {
		l, _ := c.listenerByARN(rec, arn)
		if l == nil {
			return elbErr("ListenerNotFound", "One or more listeners not found")
		}
		rec.Listeners = removeWhere(rec.Listeners, func(x *elbListener) bool { return x.ID == l.ID })
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "")
	return nil
}

// --- tags ---

// tagsOf is the tag map of the resource arn names in rec (nil, and the not-found error, if none).
func (c *elbCall) tagsOf(rec *elbRecords, arn string) (*map[string]string, *elbError) {
	if l := c.lbByARN(rec, arn); l != nil {
		return &l.Tags, nil
	}
	if g := c.tgByARN(rec, arn); g != nil {
		return &g.Tags, nil
	}
	if l, _ := c.listenerByARN(rec, arn); l != nil {
		return &l.Tags, nil
	}
	switch {
	case strings.Contains(arn, ":targetgroup/"):
		return nil, elbErr("TargetGroupNotFound", "Target groups '%s' not found", arn)
	case strings.Contains(arn, ":listener/"):
		return nil, elbErr("ListenerNotFound", "One or more listeners not found")
	}
	return nil, elbErr("LoadBalancerNotFound", "Load balancer '%s' not found", arn)
}

func (c *elbCall) changeTags(add bool) *elbError {
	f := c.r.Form
	arns := elbMembers(f, "ResourceArns")
	if len(arns) == 0 {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'resourceArns' failed to satisfy constraint: Member must not be null")
	}
	var tags map[string]string
	var keys []string
	if add {
		var te *elbError
		if tags, te = elbTags(f); te != nil {
			return te
		}
		if len(tags) == 0 {
			return elbErr("ValidationError", "1 validation error detected: Value null at 'tags' failed to satisfy constraint: Member must not be null")
		}
	} else if keys = elbMembers(f, "TagKeys"); len(keys) == 0 {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null")
	}
	for _, a := range arns {
		if e := c.allow("elasticloadbalancing:"+c.op, a); e != nil {
			return e
		}
	}
	_, e := c.update(func(rec *elbRecords) error {
		for _, a := range arns {
			m, nf := c.tagsOf(rec, a)
			if nf != nil {
				return nf
			}
			if *m == nil {
				*m = map[string]string{}
			}
			for k, v := range tags {
				(*m)[k] = v
			}
			for _, k := range keys {
				delete(*m, k)
			}
			if len(*m) > 50 {
				return elbErr("TooManyTags", "A resource can have at most 50 tags")
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	writeELB(c.w, c.requestID, c.op, "")
	return nil
}

func (c *elbCall) describeTags() *elbError {
	arns := elbMembers(c.r.Form, "ResourceArns")
	if e := c.allow("elasticloadbalancing:DescribeTags", ""); e != nil {
		return e
	}
	if len(arns) == 0 {
		return elbErr("ValidationError", "1 validation error detected: Value null at 'resourceArns' failed to satisfy constraint: Member must not be null")
	}
	if len(arns) > 20 {
		return elbErr("ValidationError", "At most 20 resource ARNs can be described at a time")
	}
	rec, e := c.records()
	if e != nil {
		return e
	}
	var items []string
	for _, a := range arns {
		m, nf := c.tagsOf(rec, a)
		if nf != nil {
			return nf
		}
		keys := make([]string, 0, len(*m))
		for k := range *m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var tags []string
		for _, k := range keys {
			tags = append(tags, "<Key>"+xesc(k)+"</Key><Value>"+xesc((*m)[k])+"</Value>")
		}
		items = append(items, xtag("ResourceArn", a)+elbMemberList("Tags", tags))
	}
	writeELB(c.w, c.requestID, c.op, elbMemberList("TagDescriptions", items))
	return nil
}
