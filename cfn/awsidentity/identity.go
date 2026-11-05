// Package awsidentity is the AWS identity an open-infra install presents: a 12-digit account id, a region
// and the `aws` partition. The install's own account is the management account; a member account
// (kind: Account, console-api/internal/accounts) presents the same region and partition with its own id
// (Identity.ForAccount), carried per request on a context (WithIdentity / FromContext). The aws-shim reports it (STS, ARNs, queue URLs, the StackId), the
// CloudFormation engine resolves the pseudo-parameters from it (AWS::AccountId, AWS::Region,
// AWS::Partition, AWS::URLSuffix, AWS::StackId), and the VM composition gives the guest's instance
// metadata the same values, so an ARN a template builds with ${AWS::AccountId} and ${AWS::Region}
// matches the ARN the shim reports, as it does on AWS.
//
// Earlier releases presented the account as "open-infra" and STS ARNs in an "openinfra" partition.
// Canonical, Legacy and Equivalents translate between that form and this one, so a client that kept an
// ARN or a queue URL from before keeps working.
package awsidentity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAccountID is the account an install presents unless it configures its own (ACCOUNT_ID).
	DefaultAccountID = "000000000000"
	// DefaultRegion is the region an install presents unless it configures its own (AWS_REGION).
	DefaultRegion = "us-east-1"
	// Partition is the ARN partition. Only the standard partition is presented.
	Partition = "aws"
	// URLSuffix is the partition's domain suffix (AWS::URLSuffix).
	URLSuffix = "amazonaws.com"
	// DefaultStackNamespace is the namespace CloudFormation stacks are kept in by default.
	DefaultStackNamespace = "open-infra-cfn"

	// LegacyAccountID is the account earlier releases presented.
	LegacyAccountID = "open-infra"
	// legacyPartition is the partition earlier releases used in STS ARNs.
	legacyPartition = "openinfra"
)

// Identity is an install's AWS identity.
type Identity struct {
	AccountID string
	Region    string
	// StackNamespace is the namespace the CloudFormation front door keeps stacks in. A StackId's unique
	// part is derived from it and the stack name, so a stack keeps its StackId across shim restarts.
	StackNamespace string
	// PublicDNSSuffix is the DNS suffix an instance's public DNS name is built on: ec2-<a-b-c-d>.<suffix>
	// for an instance whose address is a.b.c.d (PUBLIC_DNS_SUFFIX). A site sets one that resolves on its
	// LAN (a wildcard zone that answers a name carrying an address with that address). Empty: instances
	// have no public DNS name, and PublicDnsName is "" — as on AWS in a VPC without DNS hostnames.
	PublicDNSSuffix string
}

// Default is the identity of an install that configures none.
func Default() Identity {
	return Identity{AccountID: DefaultAccountID, Region: DefaultRegion, StackNamespace: DefaultStackNamespace}
}

var accountRe = regexp.MustCompile(`^[0-9]{12}$`)

// dnsSuffixRe is a DNS name: dot-separated labels of lower-case letters, digits and inner hyphens.
var dnsSuffixRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var ipv4Re = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)

// PrivateDNSName is the private DNS name AWS gives an instance with private address ip in region:
// ip-a-b-c-d.ec2.internal in us-east-1, ip-a-b-c-d.<region>.compute.internal elsewhere.
func PrivateDNSName(ip, region string) string {
	host := "ip-" + strings.ReplaceAll(ip, ".", "-")
	if region == "us-east-1" {
		return host + ".ec2.internal"
	}
	return host + "." + region + ".compute.internal"
}

// PublicDNSName is the public DNS name of an instance whose public address is ip: ec2-a-b-c-d.<suffix>
// (AWS's ec2-a-b-c-d.compute-1.amazonaws.com, on a suffix that resolves where the address is reachable),
// or "" when the install configures no suffix or ip is not an IPv4 address.
func (i Identity) PublicDNSName(ip string) string {
	if i.PublicDNSSuffix == "" || !ipv4Re.MatchString(ip) {
		return ""
	}
	return "ec2-" + strings.ReplaceAll(ip, ".", "-") + "." + i.PublicDNSSuffix
}

// FromEnv reads ACCOUNT_ID, AWS_REGION (else AWS_DEFAULT_REGION), CFN_NAMESPACE and PUBLIC_DNS_SUFFIX through getenv,
// defaulting each. It returns a warning for each value AWS would reject (an account id that is not 12
// digits), so the caller can log it; the value is still used.
func FromEnv(getenv func(string) string) (Identity, []string) {
	id := Default()
	var warns []string
	if v := strings.TrimSpace(getenv("ACCOUNT_ID")); v != "" {
		id.AccountID = v
	}
	if !accountRe.MatchString(id.AccountID) {
		warns = append(warns, "ACCOUNT_ID "+id.AccountID+" is not a 12-digit AWS account id: ARNs that templates build with ${AWS::AccountId} will not look like AWS's")
	}
	if v := strings.TrimSpace(getenv("AWS_REGION")); v != "" {
		id.Region = v
	} else if v := strings.TrimSpace(getenv("AWS_DEFAULT_REGION")); v != "" {
		id.Region = v
	}
	if v := strings.TrimSpace(getenv("CFN_NAMESPACE")); v != "" {
		id.StackNamespace = v
	}
	if v := strings.ToLower(strings.Trim(strings.TrimSpace(getenv("PUBLIC_DNS_SUFFIX")), ".")); v != "" {
		if dnsSuffixRe.MatchString(v) {
			id.PublicDNSSuffix = v
		} else {
			warns = append(warns, "PUBLIC_DNS_SUFFIX "+v+" is not a DNS name: instances get no public DNS name")
		}
	}
	return id, warns
}

var (
	mu      sync.RWMutex
	current = Default()
)

// Set makes id the identity Current returns. The aws-shim calls it once at start-up, before serving.
func Set(id Identity) {
	mu.Lock()
	defer mu.Unlock()
	current = id
}

// Current returns the identity Set last, or Default.
func Current() Identity {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// ForAccount is the identity of account accountID within this install: the install's region, partition
// and public DNS suffix, with accountID as the account and homeNamespace (the account's home, where its
// stacks are kept) as the stack namespace. The install's own account — the management account — is i
// unchanged, so its ARNs, StackIds and stack namespace are exactly what they were before accounts. An empty
// accountID is the management account; an empty homeNamespace keeps i's stack namespace.
func (i Identity) ForAccount(accountID, homeNamespace string) Identity {
	if accountID == "" || accountID == i.AccountID {
		return i
	}
	out := i
	out.AccountID = accountID
	if homeNamespace != "" {
		out.StackNamespace = homeNamespace
	}
	return out
}

// IsManagement reports whether accountID is this identity's own account (the install's, the management
// account), or empty.
func (i Identity) IsManagement(accountID string) bool {
	return accountID == "" || accountID == i.AccountID
}

// AccountOfARN is the account field of an ARN (arn:<partition>:<service>:<region>:<account>:<resource>), or
// "" when s is not an ARN or carries no account (an S3 bucket ARN, an AWS managed policy's "aws").
func AccountOfARN(s string) string {
	if !strings.HasPrefix(s, "arn:") {
		return ""
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) < 6 || !accountRe.MatchString(parts[4]) {
		return ""
	}
	return parts[4]
}

type ctxKey struct{}

// WithIdentity carries id on ctx: the identity of the account a request acts in (the caller's). Code that
// builds ARNs or resolves pseudo-parameters for that request reads it with FromContext.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext is the identity WithIdentity put on ctx, else Current (the management account).
func FromContext(ctx context.Context) Identity {
	if ctx != nil {
		if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
			return id
		}
	}
	return Current()
}

// ARN builds arn:aws:<service>:<region>:<account>:<resource>. region is "" for a global service (IAM,
// STS) and for S3, whose bucket ARNs carry neither region nor account (use S3BucketARN).
func (i Identity) ARN(service, region, resource string) string {
	return "arn:" + Partition + ":" + service + ":" + region + ":" + i.AccountID + ":" + resource
}

// RegionalARN builds an ARN in the identity's region: arn:aws:<service>:<region>:<account>:<resource>.
func (i Identity) RegionalARN(service, resource string) string {
	return i.ARN(service, i.Region, resource)
}

// IAMARN builds an IAM ARN: arn:aws:iam::<account>:<resource> (e.g. "role/x", "user/y").
func (i Identity) IAMARN(resource string) string { return i.ARN("iam", "", resource) }

// STSARN builds an STS ARN: arn:aws:sts::<account>:<resource> (e.g. "assumed-role/r/session").
func (i Identity) STSARN(resource string) string { return i.ARN("sts", "", resource) }

// S3BucketARN builds arn:aws:s3:::<bucket>.
func S3BucketARN(bucket string) string { return "arn:" + Partition + ":s3:::" + bucket }

// StackID is the derived StackId of stack name: arn:aws:cloudformation:<region>:<account>:stack/<name>/<id>,
// where <id> is derived from the stack namespace and name. Stacks created before StackIds were per stack
// instance keep it for their life (their record names no StackId of its own), and AWS::StackId resolves
// to it for them; a stack created since has its own, from NewStackID.
func (i Identity) StackID(name string) string {
	sum := sha256.Sum256([]byte(i.StackNamespace + "/" + name))
	return i.RegionalARN("cloudformation", "stack/"+name+"/"+hex.EncodeToString(sum[:])[:32])
}

// NewStackID is a new stack instance's StackId, as AWS gives each stack it creates:
// arn:aws:cloudformation:<region>:<account>:stack/<name>/<uuid>, the uuid random. A stack re-created
// under a deleted stack's name gets a new one, so the deleted stack stays known by its own.
func (i Identity) NewStackID(name string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// No randomness: the name and the time still make the id unique to this instance.
		sum := sha256.Sum256([]byte(i.StackNamespace + "/" + name + "/" + time.Now().UTC().Format(time.RFC3339Nano)))
		copy(b[:], sum[:16])
	}
	b[6] = (b[6] & 0x0f) | 0x40 // a version 4 UUID, the form AWS's StackIds take
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return i.RegionalARN("cloudformation", "stack/"+name+"/"+h[0:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:32])
}

// StackIDName is the stack name a StackId names (arn:…:stack/<name>/<id>); ok=false when s is not one.
func StackIDName(s string) (name string, ok bool) {
	if !strings.HasPrefix(s, "arn:") || !strings.Contains(s, ":cloudformation:") {
		return "", false
	}
	i := strings.Index(s, ":stack/")
	if i < 0 {
		return "", false
	}
	rest := s[i+len(":stack/"):]
	name, id, found := strings.Cut(rest, "/")
	if !found || name == "" || id == "" {
		return "", false
	}
	return name, true
}

// SameStackID reports whether two StackIds name the same stack instance: the same name and the same
// unique part. The account, region and partition are not compared, so a StackId kept from before the
// install's identity changed (the legacy partition or account) still matches.
func SameStackID(a, b string) bool {
	an, aok := StackIDName(a)
	bn, bok := StackIDName(b)
	if !aok || !bok || an != bn {
		return false
	}
	return a[strings.LastIndex(a, "/")+1:] == b[strings.LastIndex(b, "/")+1:]
}

// Canonical rewrites an ARN or a URL from the legacy form to this identity: the "openinfra" partition
// becomes "aws", and the "open-infra" account becomes AccountID (in an ARN's account field, or as the
// first path segment of an SQS queue URL). Anything else is returned unchanged.
func (i Identity) Canonical(s string) string {
	return i.swap(s, LegacyAccountID, i.AccountID, true)
}

// Legacy is Canonical's inverse for the account: it rewrites AccountID back to "open-infra", so a value
// can be matched against rows stored before the identity changed. The partition stays "aws" (stored
// service ARNs always used it; only STS ARNs used the legacy partition, and none is stored).
func (i Identity) Legacy(s string) string {
	return i.swap(s, i.AccountID, LegacyAccountID, false)
}

// Equivalents returns s and the other forms the same resource may be stored or presented under — the
// canonical form and the legacy form — de-duplicated, s first.
func (i Identity) Equivalents(s string) []string {
	out := []string{s}
	for _, v := range []string{i.Canonical(s), i.Legacy(i.Canonical(s))} {
		if v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func (i Identity) swap(s, from, to string, fixPartition bool) string {
	if from == "" || from == to {
		if fixPartition {
			return fixLegacyPartition(s)
		}
		return s
	}
	if strings.HasPrefix(s, "arn:") {
		parts := strings.SplitN(s, ":", 6)
		if len(parts) < 6 {
			return s
		}
		if fixPartition && parts[1] == legacyPartition {
			parts[1] = Partition
		}
		if parts[4] == from {
			parts[4] = to
		}
		return strings.Join(parts, ":")
	}
	// A queue URL: <scheme>://<host>/<account>/<name>.
	if scheme, rest, ok := strings.Cut(s, "://"); ok && (scheme == "http" || scheme == "https") {
		host, path, ok := strings.Cut(rest, "/")
		if !ok {
			return s
		}
		seg, tail, hasTail := strings.Cut(path, "/")
		if seg == from && hasTail && tail != "" {
			return scheme + "://" + host + "/" + to + "/" + tail
		}
	}
	return s
}

func fixLegacyPartition(s string) string {
	if strings.HasPrefix(s, "arn:"+legacyPartition+":") {
		return "arn:" + Partition + ":" + strings.TrimPrefix(s, "arn:"+legacyPartition+":")
	}
	return s
}

func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}
