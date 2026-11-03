package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
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
	// leftovers are names held by objects an earlier stack of this name left behind (a retained resource,
	// kept unmanaged: a Retain resource of a stack that was deleted or whose create rolled back, or one an
	// update removed). A resource this operation creates fresh is named around them (fresh), as on AWS a
	// new stack's resource is a new resource, never the retained one. Found by the operation
	// (leftoverHits), so it is empty for an offline plan.
	leftovers map[string]bool
	// instance identifies this stack instance — its creation time (StackRecord.CreatedAt) — so a bucket's
	// generated name differs between a stack and a later stack of the same name, as on AWS (bucketName).
	instance string
}

// newPhysNamer builds the namer for a stack. prior is the stack's recorded resources (nil for a new
// stack); a companion's record (logical id "<id>/<name>") is not a template resource and is skipped.
func newPhysNamer(stack string, prior []StackResource) *physNamer {
	n := &physNamer{stack: stack, prior: map[string]string{}, priorRes: prior, leftovers: map[string]bool{}}
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
	base := stackQualifiedName(n.stack, id)
	if n.folded[k8sName(id)] {
		base = hashedName(n.stack, id, base)
	}
	return n.fresh(id, base, maxPhysNameLen)
}

// fresh is base, the name a resource created by this operation gets — unless an object an earlier stack
// of this name left behind (leftovers) holds it: then the first of a deterministic series of alternatives
// (base shortened to max with a hash of the stack, key and generation appended) that none holds. key
// identifies the resource within the stack (its logical id, or the logical id plus what a companion is);
// the series is the same on every pass, so an update that re-derives the name lands on the one the
// stack recorded. A name nothing left behind is base itself, so no existing stack's names change.
func (n *physNamer) fresh(key, base string, max int) string {
	if n == nil {
		return base
	}
	name := base
	for gen := 1; n.leftovers[name] && gen <= 64; gen++ {
		name = leftoverAltName(n.stack, key, base, gen, max)
	}
	return name
}

// avoid adds names to the leftovers this namer names fresh resources around.
func (n *physNamer) avoid(names []string) {
	for _, nm := range names {
		n.leftovers[nm] = true
	}
}

// leftoverAltName is fresh's gen'th alternative to base: base shortened to max-9 characters, then "-" and
// 8 hex digits of a hash of the stack, key and generation — an RFC 1123 label and a valid S3 bucket name,
// like every generated name.
func leftoverAltName(stack, key, base string, gen, max int) string {
	sum := sha256.Sum256([]byte(stack + "\x00" + key + "\x00retained\x00" + strconv.Itoa(gen)))
	h := hex.EncodeToString(sum[:])[:8]
	head := base
	if len(head) > max-9 {
		head = head[:max-9]
	}
	head = strings.Trim(strings.TrimPrefix(head, "xn--"), "-")
	if head == "" {
		return "r-" + h
	}
	return head + "-" + h
}

// recorded reports the name an existing stack recorded for id, if any.
func (n *physNamer) recorded(id string) (string, bool) {
	v, ok := n.prior[id]
	return v, ok
}

// maxBucketNameLen is S3's limit on a bucket name.
const maxBucketNameLen = 63

// bucketSuffixLen is the length of the random-looking part AWS ends a generated bucket name with.
const bucketSuffixLen = 12

// bucketName is the S3 name of in-stack AWS::S3::Bucket id when its template sets no BucketName, and
// whether this operation sets it (spec.bucketName). A bucket this operation creates gets the name AWS
// gives such a bucket, <stack>-<logical id>-<suffix> (generatedBucketName): globally unique like any S3
// name, and different for a later stack of the same name. A bucket the stack already recorded keeps the
// name it was created with — its recorded spec.bucketName, or for a bucket created before generated names
// none at all (set=false: the claim's name is its bucket name, as before), so an update never renames or
// replaces one (spec.bucketName is immutable on kind: Bucket).
func (n *physNamer) bucketName(id string) (name string, set bool) {
	if n == nil {
		return "", false
	}
	for _, r := range n.priorRes {
		if r.LogicalID == id {
			v, _ := r.Spec["bucketName"].(string)
			return v, v != ""
		}
	}
	return generatedBucketName(n.stack, id, n.instance), true
}

// generatedBucketName is AWS's form for an unnamed stack bucket: the stack name and logical id, lowercased
// and shortened to fit, then a 12-character suffix derived from the stack, logical id and stack instance.
// It is a valid S3 bucket name (3-63 lowercase letters, digits and single hyphens, starting and ending with
// a letter or digit, never xn--… or sthree-…).
func generatedBucketName(stack, id, instance string) string {
	sum := sha256.Sum256([]byte(stack + "\x00" + id + "\x00bucket\x00" + instance))
	suffix := base36(sum[:])[:bucketSuffixLen]
	s, l := collapseHyphens(k8sName(stack)), collapseHyphens(k8sName(id))
	room := maxBucketNameLen - 1 - bucketSuffixLen // for "<stack>-<id>"
	if s != "" && len(s)+1+len(l) > room {
		// Shorten the longer part first, as AWS does, keeping some of each.
		half := (room - 1) / 2
		switch {
		case len(l) <= half:
			s = s[:room-1-len(l)]
		case len(s) <= half:
			l = l[:room-1-len(s)]
		default:
			s, l = s[:half], l[:room-1-half]
		}
	} else if s == "" && len(l) > room {
		l = l[:room]
	}
	head := strings.Trim(l, "-")
	if s = strings.Trim(s, "-"); s != "" {
		head = strings.Trim(s+"-"+head, "-")
	}
	head = strings.TrimPrefix(strings.TrimPrefix(head, "xn--"), "sthree-")
	if head == "" {
		return "b-" + suffix
	}
	return head + "-" + suffix
}

// base36 renders b in lowercase base 36 (digits and letters), most significant first.
func base36(b []byte) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	n := make([]byte, len(b))
	copy(n, b)
	var out []byte
	for {
		zero := true
		rem := 0
		for i := range n {
			v := rem*256 + int(n[i])
			n[i] = byte(v / 36)
			rem = v % 36
			if n[i] != 0 {
				zero = false
			}
		}
		out = append(out, digits[rem])
		if zero {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// bucketName is the S3 name of in-stack bucket id: its BucketName when the template sets one, else the
// name bucketName (physNamer) gives it, else (a bucket created before generated names, or no stack
// context) its open-infra name.
func (c *stackCtx) bucketName(id string) string {
	if c != nil && c.template != nil {
		if p, _ := c.resolveProps(id); p != nil {
			if n, ok := concrete(p["BucketName"]); ok && n != "" {
				return n
			}
		}
	}
	if c != nil && c.namer != nil {
		if n, set := c.namer.bucketName(id); set {
			return n
		}
	}
	return c.name(id)
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
