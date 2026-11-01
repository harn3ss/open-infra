package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Physical names. Every stack deploys into one shared namespace, so a resource's Kubernetes name must
// be unique across stacks: two stacks made from one template must never share (and overwrite) an
// object. A new stack names each resource <stack>-<logical id>, as CloudFormation names a resource
// the template leaves unnamed after its stack. A long name is shortened and ends in a hash of the
// stack and logical id, so it stays unique and within Kubernetes and S3 name limits.
//
// A resource an existing stack already recorded keeps the name it was created with: renaming it on an
// update would create a second object and orphan the first. Stacks created before stack-qualified
// names therefore keep their bare (logical id) names; anything such a stack adds later is
// stack-qualified.

// maxPhysNameLen bounds a generated name. Kinds append to it (a Function's revision and its -private
// Service, a VM's -root disk, a database's -rw Service), and an S3 bucket name is at most 63
// characters, so 40 leaves room for all of them.
const maxPhysNameLen = 40

// physNamer decides the Kubernetes name of each in-stack resource for one stack operation.
type physNamer struct {
	stack string
	prior map[string]string // logical id -> the name the existing stack recorded for it
	// priorRes is every resource the existing stack recorded, companions included (a stack KMS key's
	// id lives on a companion, service.go).
	priorRes []StackResource
	// folded is, for the template being named, each Kubernetes-form logical id (lowercased) that more
	// than one logical id reduces to. CloudFormation logical ids are case-sensitive, so MyDB and Mydb are
	// two resources; lowercased they would share one object. Computed once per template.
	folded     map[string]bool
	foldedFrom *Template
	// legacyDefaultKey is set when the existing stack keys disks with the shared namespace default
	// EncryptionKey (defaultEBSKeyName), from before each stack had its own: the stack keeps using it.
	legacyDefaultKey bool
}

// newPhysNamer builds the namer for a stack. prior is the stack's recorded resources (nil for a new
// stack); a companion's record (logical id "<id>/<name>") is not a template resource and is skipped.
func newPhysNamer(stack string, prior []StackResource) *physNamer {
	n := &physNamer{stack: stack, prior: map[string]string{}, priorRes: prior}
	for _, r := range prior {
		if r.Name != "" && !strings.Contains(r.LogicalID, "/") {
			n.prior[r.LogicalID] = r.Name
		}
		if r.Kind == "EncryptionKey" && r.Name == defaultEBSKeyName && strings.Contains(r.LogicalID, "/") {
			n.legacyDefaultKey = true
		}
	}
	return n
}

func (n *physNamer) name(id string) string {
	return n.nameIn(id, nil)
}

// nameIn is name for a resource of template t. Logical ids that differ only in case (or in characters a
// Kubernetes name cannot hold) would reduce to one name; each of them then gets a name that ends in a
// hash of its exact logical id, so they stay two objects. A name the stack already recorded is kept.
func (n *physNamer) nameIn(id string, t *Template) string {
	if v, ok := n.prior[id]; ok {
		return v
	}
	if t != nil && n.foldedFrom != t {
		n.folded, n.foldedFrom = map[string]bool{}, t
		seen := map[string]int{}
		for other := range t.Resources {
			seen[k8sName(other)]++
		}
		for k, c := range seen {
			if c > 1 {
				n.folded[k] = true
			}
		}
	}
	if n.folded[k8sName(id)] {
		return hashedName(n.stack, id, stackQualifiedName(n.stack, id))
	}
	return stackQualifiedName(n.stack, id)
}

// recorded reports the name an existing stack recorded for id, if any.
func (n *physNamer) recorded(id string) (string, bool) {
	v, ok := n.prior[id]
	return v, ok
}

// name is the Kubernetes name of in-stack resource id. With no stack context (a translator called on
// its own, as unit tests do) it is the bare logical id.
func (c *stackCtx) name(id string) string {
	if c == nil || c.namer == nil {
		return k8sName(id)
	}
	return c.namer.nameIn(id, c.template)
}

// PhysicalName is the Kubernetes name a new stack gives in-stack resource id when nothing else decides it
// (no recorded name, no explicit name, no other logical id differing only in case). A front door that
// looks a stack's object up by name reads the stack record first and falls back to this.
func PhysicalName(stack, id string) string { return stackQualifiedName(stack, id) }

// stackQualifiedName is <stack>-<logical id> in RFC 1123 form, shortened with a hash past
// maxPhysNameLen. It is also a valid S3 bucket name: lowercase letters, digits and single hyphens,
// starting and ending with a letter or digit.
func stackQualifiedName(stack, id string) string {
	s, l := collapseHyphens(k8sName(stack)), k8sName(id)
	n := l
	switch {
	case s == "":
	case l == s:
		// A resource named for its own stack (the ECS front door deploys service X as stack X with
		// logical id X) is named after the stack. A template's logical ids have no hyphen, so for a
		// template this only happens with a hyphen-free stack name, which no stack-qualified name can
		// equal. Any other clash is refused by the ownership check at apply (another stack's object).
	default:
		n = s + "-" + l
	}
	if len(n) <= maxPhysNameLen && n != "" && !strings.HasPrefix(n, "xn--") {
		return n
	}
	return hashedName(stack, id, n)
}

// hashedName is n shortened to fit maxPhysNameLen with a hash of the stack and exact logical id appended,
// so it is unique per (stack, logical id) even where n is not.
func hashedName(stack, id, n string) string {
	sum := sha256.Sum256([]byte(stack + "\x00" + id))
	h := hex.EncodeToString(sum[:])[:8]
	head := n
	if len(head) > maxPhysNameLen-9 {
		head = head[:maxPhysNameLen-9]
	}
	head = strings.Trim(strings.TrimPrefix(head, "xn--"), "-")
	if head == "" {
		return "r-" + h
	}
	return head + "-" + h
}

// collapseHyphens turns runs of '-' into one, so a generated name never has "--" (S3 refuses some
// names with it, e.g. a leading "xn--").
func collapseHyphens(s string) string {
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// fnNameRE is a valid kind: Function name: an RFC 1123 label, which the Function's Knative Service and
// the Lambda front door's invoke path both require.
var fnNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// lambdaKindName is the kind: Function name of AWS::Lambda::Function id. A name the stack already
// recorded is kept; otherwise it is the FunctionName (on AWS the function is called by that name), or
// the stack-generated name when FunctionName is unset or not a valid Function name.
func lambdaKindName(id string, props map[string]any, ctx *stackCtx) string {
	if ctx != nil && ctx.namer != nil {
		if v, ok := ctx.namer.recorded(id); ok {
			return v
		}
	}
	if fn, ok := concrete(props["FunctionName"]); ok && fnNameRE.MatchString(fn) {
		return fn
	}
	return ctx.name(id)
}

// functionName is the kind: Function name of in-stack Lambda id — what its Ref and Arn resolve to, and
// what a custom resource's ServiceToken invokes.
func (c *stackCtx) functionName(id string) string {
	if c == nil || c.template == nil {
		return k8sName(id)
	}
	where := c.resolver.where
	p, _ := c.resolveProps(id)
	c.resolver.where = where
	return lambdaKindName(id, p, c)
}

// isInStackName reports whether name is the Kubernetes name of an in-stack resource of cfnType.
func (c *stackCtx) isInStackName(name, cfnType string) bool {
	if c == nil || c.template == nil {
		return false
	}
	for id, r := range c.template.Resources {
		if r.Type == cfnType && c.name(id) == name {
			return true
		}
	}
	return false
}
