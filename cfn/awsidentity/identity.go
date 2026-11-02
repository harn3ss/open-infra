// Package awsidentity is the one AWS identity an open-infra install presents: a 12-digit account id,
// a region and the `aws` partition. The aws-shim reports it (STS, ARNs, queue URLs, the StackId), the
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
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
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

// StackID is the StackId of stack name: arn:aws:cloudformation:<region>:<account>:stack/<name>/<id>,
// where <id> is derived from the stack namespace and name, so it is stable for the stack's life.
// AWS::StackId resolves to the same value.
func (i Identity) StackID(name string) string {
	sum := sha256.Sum256([]byte(i.StackNamespace + "/" + name))
	return i.RegionalARN("cloudformation", "stack/"+name+"/"+hex.EncodeToString(sum[:])[:32])
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
