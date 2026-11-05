// Package awsaction is the platform's table of AWS actions and resource ARNs: for every openinfra kind
// (each XRD's claim kind, the iam.openinfra.dev kinds and the platform CRDs) the AWS service and
// resource type it is, the IAM action each Kubernetes verb on it amounts to, and the ARN of the
// resource it acts on. An IAM policy is the only place authority is written, so every door that
// authorizes — the console's routes, its Kubernetes proxy, the IAM→RBAC compiler — turns what a caller
// asks for into (action, ARN) through this table and evaluates that.
//
// The rules:
//   - A kind with an AWS analog carries AWS's real action names and ARN shape (s3:CreateBucket on
//     arn:aws:s3:::<bucket>, ec2:RunInstances on an instance, lambda:UpdateFunctionCode when a
//     Function's code changes), so an AWS policy written for the analog means the same here.
//   - A kind with no AWS analog uses the service prefix "openinfra" (openinfra:CreateDataFlow), which
//     AdministratorAccess and PowerUserAccess cover and ReadOnlyAccess covers for Get/List/Describe.
//   - Raw Kubernetes objects (pods, nodes, Secrets, the composite x-resources …) are the operator's
//     surface: "openinfra-operator:<Verb><Kind>", which only AdministratorAccess covers.
//   - What the table cannot place is not authorized: every lookup returns ok=false for it, and callers
//     deny.
package awsaction

import (
	"crypto/sha1"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Verb is a Kubernetes verb, normalized to the five the table maps.
type Verb string

const (
	Get    Verb = "get"
	List   Verb = "list"
	Create Verb = "create"
	Update Verb = "update"
	Delete Verb = "delete"
)

// Verbs is the table's verbs in a stable order.
var Verbs = []Verb{Get, List, Create, Update, Delete}

// NormalizeVerb maps a Kubernetes verb onto the table's: watch is a list, patch an update,
// deletecollection a delete. Any other verb (escalate, bind, impersonate, approve …) is not one a
// user's IAM policy can grant, and returns ok=false.
func NormalizeVerb(v string) (Verb, bool) {
	switch strings.ToLower(v) {
	case "get":
		return Get, true
	case "list", "watch":
		return List, true
	case "create":
		return Create, true
	case "update", "patch":
		return Update, true
	case "delete", "deletecollection":
		return Delete, true
	}
	return "", false
}

// Scope is who and where a request is made: the ARN's partition, region and account.
type Scope struct {
	Partition string // "aws" when empty
	Region    string // DefaultRegion when empty
	Account   string // the caller's 12-digit account id
}

// DefaultRegion is the region an ARN carries when the caller names none.
const DefaultRegion = "us-east-1"

func (s Scope) partition() string {
	if s.Partition == "" {
		return "aws"
	}
	return s.Partition
}

func (s Scope) region() string {
	if s.Region == "" {
		return DefaultRegion
	}
	return s.Region
}

// Request is one authorization question: an IAM action on a resource ARN. A Kubernetes request can
// amount to several (an update that changes a Function's code and its memory is UpdateFunctionCode and
// UpdateFunctionConfiguration; creating a state machine with a role also passes the role), and all of
// them must be allowed.
type Request struct {
	Action string `json:"action"`
	ARN    string `json:"arn"`
}

// FieldRule is what changing one top-level spec field takes: Actions always, or ByValue[<new value>]
// when the action depends on the value (a VirtualMachine's running: true is ec2:StartInstances, false
// is ec2:StopInstances).
type FieldRule struct {
	Actions []string            `json:"actions,omitempty"`
	ByValue map[string][]string `json:"byValue,omitempty"`
}

// Variant is a shape of a kind that is another AWS resource: a Queue with fanout is an SNS topic, an
// Application with a database block is also an RDS DB instance. When matches the object's spec; a
// Replace variant stands in for the kind's own entry, otherwise its requests are added to it.
type Variant struct {
	Name    string                    `json:"name"`
	Replace bool                      `json:"replace,omitempty"`
	When    func(map[string]any) bool `json:"-"`
	Entry   *Entry                    `json:"entry"`
}

// Entry is one kind's row: what AWS resource it is and what each verb on it is.
type Entry struct {
	Group        string `json:"group"`               // the API group of the claim kind
	Kind         string `json:"-"`                   // the claim kind (the registry's key)
	Resource     string `json:"resource"`            // its plural, as the Kubernetes API names it
	Service      string `json:"service"`             // the IAM service prefix (s3, ec2, openinfra …)
	ResourceType string `json:"resourceType"`        // the resource type in AWS's service authorization reference
	CfnType      string `json:"cfnType,omitempty"`   // the CloudFormation type of the AWS analog
	ARN          string `json:"arn"`                 // the ARN template: {partition} {region} {account} {name} {uuid} {spec.<field>}
	NameField    string `json:"nameField,omitempty"` // the spec field holding the physical name, when it isn't the claim name
	// GlobalDescribe: the service's Describe/Get for this type takes no resource-level permission, so a
	// get is authorized on "*" (EC2's Describe* calls), as AWS authorizes it.
	GlobalDescribe bool                 `json:"globalDescribe,omitempty"`
	Actions        map[Verb]string      `json:"actions"`
	FieldActions   map[string]FieldRule `json:"fieldActions,omitempty"`
	// PassRoleFields are spec fields naming an IAM role the resource will act as (a state machine's
	// roleArn, an Application's assumeRole): setting one is also iam:PassRole on that role, as on AWS.
	PassRoleFields []string  `json:"passRoleFields,omitempty"`
	Variants       []Variant `json:"variants,omitempty"`
	// NameFormat normalizes the physical name into the ARN (an SSM parameter's ARN carries its path
	// with one leading slash).
	NameFormat func(string) string `json:"-"`
	// Note says why the mapping is what it is, where that isn't obvious.
	Note string `json:"note,omitempty"`
}

// Lookup returns the entry for a claim kind ("Bucket", "User", "TuningJob").
func Lookup(kind string) (Entry, bool) {
	e, ok := byKind[kind]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// KindForResource returns the entry for a Kubernetes (group, plural) — a claim's own resource, so
// ("openinfra.dev", "buckets") is Bucket. The cluster-scoped composites (xbuckets) are not claims and
// are not found here; ForKubernetes treats them as the operator's surface.
func KindForResource(group, resource string) (Entry, bool) {
	e, ok := byResource[group+"/"+resource]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Kinds returns every claim kind the table maps, sorted.
func Kinds() []string {
	out := make([]string, 0, len(byKind))
	for k := range byKind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ARN builds the resource ARN for a claim name (or the physical name in its NameField) in scope s.
func (e Entry) ARNFor(s Scope, name string, spec map[string]any) string {
	if e.NameField != "" {
		if v := specString(spec, e.NameField); v != "" {
			name = v
		}
	}
	if e.NameFormat != nil {
		name = e.NameFormat(name)
	}
	return expandARN(e.ARN, s, name, spec)
}

// Action returns the action a verb on this kind is.
func (e Entry) Action(v Verb) (string, bool) {
	a, ok := e.Actions[v]
	return a, ok && a != ""
}

// ForKind is the primary (action, ARN) for a verb on a claim kind in account: a list is on "*", as
// AWS's List* actions are; a get is on "*" where the service's Describe takes no resource-level
// permission. ok=false for an unknown kind or verb.
func ForKind(kind, verb, name, account string) (action, arn string, ok bool) {
	return Scope{Account: account}.ForKind(kind, verb, name)
}

// ForKind is the package's ForKind in scope s.
func (s Scope) ForKind(kind, verb, name string) (action, arn string, ok bool) {
	e, found := byKind[kind]
	if !found {
		return "", "", false
	}
	v, vok := NormalizeVerb(verb)
	if !vok {
		return "", "", false
	}
	a, aok := e.Action(v)
	if !aok {
		return "", "", false
	}
	return a, e.resourceFor(s, v, name, nil), true
}

func (e *Entry) resourceFor(s Scope, v Verb, name string, spec map[string]any) string {
	if v == List || (v == Get && e.GlobalDescribe) || name == "" {
		return "*"
	}
	return e.ARNFor(s, name, spec)
}

// ForObject is every authorization question a verb on one object amounts to, all of which must be
// allowed: the kind's action (or, for an update, the action of each top-level spec field that
// changes between oldSpec and spec, else the kind's update action), iam:PassRole for each role it is
// given, and the requests of each matching variant. ok=false for an unknown kind or verb.
func (s Scope) ForObject(kind, verb, name string, spec, oldSpec map[string]any) ([]Request, bool) {
	e, found := byKind[kind]
	if !found {
		return nil, false
	}
	v, vok := NormalizeVerb(verb)
	if !vok {
		return nil, false
	}
	var out []Request
	base := e
	for i := range e.Variants {
		vr := &e.Variants[i]
		if vr.When != nil && vr.When(spec) && vr.Replace {
			base = vr.Entry
		}
	}
	reqs, ok := base.requests(s, v, name, spec, oldSpec)
	if !ok {
		return nil, false
	}
	out = append(out, reqs...)
	for i := range e.Variants {
		vr := &e.Variants[i]
		if vr.When == nil || !vr.When(spec) || vr.Replace {
			continue
		}
		if more, ok := vr.Entry.requests(s, v, name, spec, oldSpec); ok {
			out = append(out, more...)
		}
	}
	return dedupe(out), true
}

func (e *Entry) requests(s Scope, v Verb, name string, spec, oldSpec map[string]any) ([]Request, bool) {
	res := e.resourceFor(s, v, name, spec)
	var out []Request
	switch v {
	case Update:
		changed := changedFields(spec, oldSpec)
		for _, f := range changed {
			rule, ok := e.FieldActions[f]
			if !ok {
				a, aok := e.Action(Update)
				if !aok {
					return nil, false
				}
				out = append(out, Request{a, res})
				continue
			}
			acts := rule.Actions
			if rule.ByValue != nil {
				acts = rule.ByValue[fmt.Sprint(spec[f])]
				if len(acts) == 0 {
					acts = rule.Actions
				}
			}
			for _, a := range acts {
				out = append(out, Request{a, res})
			}
		}
		if len(out) == 0 { // a change outside spec (labels, annotations) is an update of the resource
			a, aok := e.Action(Update)
			if !aok {
				return nil, false
			}
			out = append(out, Request{a, res})
		}
		for _, f := range e.PassRoleFields {
			if contains(changed, f) {
				if r := passRole(s, spec, f); r != nil {
					out = append(out, *r)
				}
			}
		}
	default:
		a, aok := e.Action(v)
		if !aok {
			return nil, false
		}
		out = append(out, Request{a, res})
		if v == Create {
			for _, f := range e.PassRoleFields {
				if r := passRole(s, spec, f); r != nil {
					out = append(out, *r)
				}
			}
		}
	}
	return out, true
}

// passRole is iam:PassRole on the role spec field f names (a role ARN, or a role name in the caller's
// account); nil when the field is unset.
func passRole(s Scope, spec map[string]any, f string) *Request {
	v := specString(spec, f)
	if v == "" {
		return nil
	}
	arn := v
	if !strings.HasPrefix(v, "arn:") {
		arn = fmt.Sprintf("arn:%s:iam::%s:role/%s", s.partition(), s.Account, v)
	}
	return &Request{"iam:PassRole", arn}
}

// changedFields lists the top-level spec fields whose values differ, sorted.
func changedFields(spec, oldSpec map[string]any) []string {
	keys := map[string]bool{}
	for k := range spec {
		keys[k] = true
	}
	for k := range oldSpec {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if !reflect.DeepEqual(spec[k], oldSpec[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []Request) []Request {
	seen := map[Request]bool{}
	var out []Request
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// specString reads a spec field that names something: a string, or an object's "name".
func specString(spec map[string]any, field string) string {
	if spec == nil {
		return ""
	}
	switch v := spec[field].(type) {
	case string:
		return v
	case map[string]any:
		if n, ok := v["name"].(string); ok {
			return n
		}
	}
	return ""
}

// expandARN fills an ARN template.
func expandARN(tmpl string, s Scope, name string, spec map[string]any) string {
	out := tmpl
	out = strings.ReplaceAll(out, "{partition}", s.partition())
	out = strings.ReplaceAll(out, "{region}", s.region())
	out = strings.ReplaceAll(out, "{account}", s.Account)
	out = strings.ReplaceAll(out, "{uuid}", stableUUID(s.Account+"/"+name))
	for {
		i := strings.Index(out, "{spec.")
		if i < 0 {
			break
		}
		j := strings.Index(out[i:], "}")
		if j < 0 {
			break
		}
		field := out[i+len("{spec.") : i+j]
		val := specString(spec, field)
		if val == "" {
			val = "*"
		}
		out = out[:i] + val + out[i+j+1:]
	}
	return strings.ReplaceAll(out, "{name}", name)
}

// stableUUID is a deterministic, UUID-shaped id for a resource whose AWS ARN carries a generated id
// (an Auto Scaling group's): the same account and name always give the same ARN.
func stableUUID(seed string) string {
	h := sha1.Sum([]byte(seed))
	h[6] = (h[6] & 0x0f) | 0x50 // version 5
	h[8] = (h[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
