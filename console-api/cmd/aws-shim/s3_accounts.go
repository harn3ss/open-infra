// Each account's S3 buckets.
//
// On AWS a bucket name is global — CreateBucket of a name any account owns is BucketAlreadyExists — and
// the bucket belongs to the account that made it: ListBuckets lists the caller's account's buckets alone,
// and a request on a bucket is decided in the bucket's account (within it the caller's identity policy or
// the bucket policy allows it; from another account both must). Here a bucket made through CreateBucket is
// a kind: Bucket claim: the management account's in S3_BUCKET_NAMESPACE as before accounts, a member
// account's in its home (written by the shim once IAM has allowed the call). A bucket belongs to the account
// of the namespace of the kind: Bucket claim that made it.
//
// "Made it" is decided on facts no claimant can forge, in this order:
//   - A claim whose setup has succeeded (its composite's status.ready): the setup succeeds only when the
//     platform's owner record for the bucket names that claim's namespace. The record is written by the
//     setup itself, in a platform namespace. So a bucket an account's claim adopted with an operator's
//     record, or took over from an earlier instance of the same claim, is that account's, as a bucket a
//     stack kept stays its account's on AWS.
//   - Otherwise (a claim whose setup has not finished yet, as when CreateBucket answers), a claim whose
//     composite was created no later than the bucket itself: the setup creates the bucket after its claim,
//     and refuses a claim naming a bucket that already exists and is another's.
//
// A claim naming an existing bucket it does not own (another account's, a StaticSite's or an Application's
// own) never makes that bucket its account's. A bucket no claim made — a platform bucket, another kind's,
// one from before claims — is the management account's, as every bucket was before accounts; so is every
// bucket while no member account exists (nothing is looked up then). If claims of two accounts both qualify
// the bucket is no account's: neither reaches it as its own.
//
// Requests where accounts meet — a member account's principal, or a member account's bucket — are decided
// by s3authz.Gate.AllowAccount with the bucket's account and its policy; the management account's
// principals on the management account's buckets keep the gate they always had (s3authz.Gate.Allow).
package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() { accountScopedServices["s3"] = true }

// s3Accounts is what the S3 door needs of the account directory (internal/accounts.Directory).
type s3Accounts interface {
	// AccountOf is the account namespace ns belongs to ("" for a platform namespace).
	AccountOf(ns string) string
	// Accounts lists the accounts the directory knows, the management account first.
	Accounts() []string
}

// bucketContested is the owner of a bucket that claims of two accounts each could have made: no account's.
const bucketContested = "\x00contested"

// bucketOwnersTTL is how long the bucket → account index is trusted before it is built again (a
// CreateBucket or DeleteBucket through this door rebuilds it at once).
const bucketOwnersTTL = 5 * time.Second

// bucketOwners is the bucket → account index of the member accounts' buckets (a bucket absent from it is
// the management account's).
type bucketOwners struct {
	mu    sync.Mutex
	at    time.Time
	owner map[string]string
}

func (o *bucketOwners) forget() {
	o.mu.Lock()
	o.at = time.Time{}
	o.mu.Unlock()
}

// claimsAccount is the account a principal acts in: its member account, else the management account.
func claimsAccount(claims iam.Claims) string {
	if memberAccount(claims) {
		return claims.Account
	}
	return awsidentity.Current().AccountID
}

// accountsInPlay reports whether any member account exists: until one does, every bucket is the
// management account's and nothing is looked up.
func (h *s3Handler) accountsInPlay() bool {
	return h.accounts != nil && len(h.accounts.Accounts()) > 1 && h.dyn != nil && h.mc != nil
}

// namespaceAccount is the account namespace ns belongs to (a platform namespace is the management
// account's).
func (h *s3Handler) namespaceAccount(ns string) string {
	if h.accounts != nil {
		if a := h.accounts.AccountOf(ns); a != "" {
			return a
		}
	}
	return awsidentity.Current().AccountID
}

// bucketOwner is the account bucket belongs to (bucketContested for one no account clearly made).
func (h *s3Handler) bucketOwner(ctx context.Context, bucket string) string {
	mgmt := awsidentity.Current().AccountID
	if bucket == "" || isPlatformBucket(bucket) || !h.accountsInPlay() {
		return mgmt
	}
	h.owners.mu.Lock()
	defer h.owners.mu.Unlock()
	if h.owners.owner == nil || time.Since(h.owners.at) > bucketOwnersTTL {
		if idx, err := h.buildBucketOwners(ctx); err != nil {
			// The last index stays (none yet: every bucket is the management account's, as before accounts).
			h.logger.Warn("s3: could not index the buckets' accounts", "err", err)
		} else {
			h.owners.owner = idx
		}
		h.owners.at = time.Now()
	}
	if a, ok := h.owners.owner[bucket]; ok {
		return a
	}
	return mgmt
}

// buildBucketOwners indexes the buckets a member account's claim made (and those contested).
func (h *s3Handler) buildBucketOwners(ctx context.Context) (map[string]string, error) {
	xl, err := h.dyn.Resource(xbucketGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	made, err := h.mc.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	created := make(map[string]time.Time, len(made))
	for _, b := range made {
		created[b.Name] = b.CreationDate
	}
	// bucket → the account of the claims that could have made it: those whose setup succeeded (recorded),
	// else those created no later than the bucket (dated).
	recorded, dated := map[string]string{}, map[string]string{}
	add := func(m map[string]string, b, acct string) {
		if prev, seen := m[b]; !seen {
			m[b] = acct
		} else if prev != acct {
			m[b] = bucketContested
		}
	}
	for _, x := range xl.Items {
		b, _, _ := unstructuredString(x.Object, "status", "bucket")
		if b == "" {
			b, _, _ = unstructuredString(x.Object, "spec", "bucketName")
		}
		ns := x.GetLabels()["crossplane.io/claim-namespace"]
		bt, exists := created[b]
		if b == "" || ns == "" || !exists {
			continue // no bucket: no claim's account's
		}
		acct := h.namespaceAccount(ns)
		if ready, _, _ := unstructured.NestedBool(x.Object, "status", "ready"); ready {
			add(recorded, b, acct)
			continue
		}
		if bt.Year() < 1971 || x.GetCreationTimestamp().Time.After(bt) {
			continue // no creation time to tell its maker by, or the claim came after the bucket: it did not make it
		}
		add(dated, b, acct)
	}
	makers := dated
	for b, acct := range recorded {
		makers[b] = acct // the platform's record decides where it exists
	}
	mgmt := awsidentity.Current().AccountID
	for b, acct := range makers {
		if acct == mgmt {
			delete(makers, b) // the management account's, as a bucket absent from the index is
		}
	}
	return makers, nil
}

// accountBucketClaim is the kind: Bucket claim of bucket in the caller's account (found), or whether
// another account's claim names it (taken). Without member accounts it is bucketClaimFor.
func (h *s3Handler) accountBucketClaim(ctx context.Context, claims iam.Claims, bucket string) (claim bucketClaim, found, taken bool, err error) {
	if !h.accountsInPlay() && !memberAccount(claims) {
		claim, found, err = bucketClaimFor(ctx, h.dyn, bucket)
		return claim, found, false, err
	}
	l, err := h.dyn.Resource(xbucketGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return bucketClaim{}, false, false, err
	}
	acct := claimsAccount(claims)
	for _, x := range l.Items {
		b, _, _ := unstructuredString(x.Object, "status", "bucket")
		if b == "" {
			b, _, _ = unstructuredString(x.Object, "spec", "bucketName")
		}
		lbl := x.GetLabels()
		ns, cn := lbl["crossplane.io/claim-namespace"], lbl["crossplane.io/claim-name"]
		if b != bucket || ns == "" || cn == "" {
			continue
		}
		if h.namespaceAccount(ns) == acct {
			return bucketClaim{namespace: ns, name: cn}, true, false, nil
		}
		taken = true
	}
	return bucketClaim{}, false, taken, nil
}

// bucketNamespace is where the caller's account's CreateBucket makes its claim: S3_BUCKET_NAMESPACE for
// the management account, its home for a member account.
func (h *s3Handler) bucketNamespace(ctx context.Context, claims iam.Claims) string {
	if memberAccount(claims) {
		return accountNamespace(ctx, h.bucketNS)
	}
	return h.bucketNS
}

// s3Owner is ListBuckets' Owner for the caller's account: the management account's as before accounts,
// a member account's its account id.
func s3Owner(claims iam.Claims) canonicalUser {
	if memberAccount(claims) {
		return canonicalUser{ID: claims.Account}
	}
	return canonicalUser{ID: "open-infra"}
}

// allowedAcrossAccounts decides op where accounts meet (s3authz.Gate.AllowAccount): the caller as its
// account's principal, the bucket's account, the bucket's policy.
func (h *s3Handler) allowedAcrossAccounts(r *http.Request, claims iam.Claims, op s3op, owner string) (bool, string) {
	ctx := r.Context()
	return h.gate().AllowAccount(ctx, op.authzRequest(), s3authz.Account{
		Principal: principalOf(ctx, claims),
		Owner:     owner,
		Policy:    func() string { return h.bucketPolicyDoc(ctx, op.bucket) },
	}, requestContext(claims, r))
}

// bucketPolicyDoc is the bucket's policy document as MinIO holds it ("" for none, or none readable).
func (h *s3Handler) bucketPolicyDoc(ctx context.Context, bucket string) string {
	if h.mc == nil || bucket == "" {
		return ""
	}
	h.policies.mu.Lock()
	if e, ok := h.policies.docs[bucket]; ok && time.Since(e.at) < bucketPolicyTTL {
		h.policies.mu.Unlock()
		return e.doc
	}
	h.policies.mu.Unlock()
	doc, err := h.mc.GetBucketPolicy(ctx, bucket)
	if err != nil {
		doc = ""
	}
	doc = strings.TrimSpace(doc)
	h.policies.mu.Lock()
	if h.policies.docs == nil || len(h.policies.docs) > 4096 {
		h.policies.docs = map[string]policyDoc{}
	}
	h.policies.docs[bucket] = policyDoc{doc: doc, at: time.Now()}
	h.policies.mu.Unlock()
	return doc
}

// bucketPolicyTTL is how long a bucket's policy is remembered between requests (a DeleteObjects of a
// thousand keys reads it once).
const bucketPolicyTTL = 2 * time.Second

type policyDoc struct {
	doc string
	at  time.Time
}

type bucketPolicies struct {
	mu   sync.Mutex
	docs map[string]policyDoc
}
