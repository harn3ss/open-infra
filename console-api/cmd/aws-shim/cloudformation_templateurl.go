// TemplateURL and nested stacks (#347 item I).
//
// AWS takes a template either inline (TemplateBody, up to 51,200 bytes) or as an S3 object (TemplateURL,
// up to 1 MB) — `aws cloudformation deploy --s3-bucket` uploads it there for anything larger, and a nested
// stack (AWS::CloudFormation::Stack) names its child template the same way. This front door accepts a
// TemplateURL that names an object in ITS OWN S3: the URL is only ever parsed into a bucket and key, never
// fetched over the network (no SSRF), and the object is read as the CALLER is allowed to read it (the S3
// front door's own authorization). A nested stack's child template is read the same way, when the child is
// created as a stack of its own (cfn_nested.go).
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	"github.com/minio/minio-go/v7"
)

// maxTemplateURLBytes is AWS's limit for a template read from S3.
const maxTemplateURLBytes = 1 << 20

type cfnClaimsKey struct{}

// withCallerClaims carries the caller's identity on the request, for steps that read on its behalf.
func withCallerClaims(r *http.Request, c iam.Claims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), cfnClaimsKey{}, c))
}

func callerClaimsOf(r *http.Request) (iam.Claims, bool) {
	c, ok := r.Context().Value(cfnClaimsKey{}).(iam.Claims)
	return c, ok
}

// onBehalfOf is r cloned onto ctx (an operation that outlives r: a deploy's package read, a nested stack's
// template read) as the caller of r, in the caller's account. A member account's caller is decided as that
// account's principal, whose id principalOf qualifies by the account's IAM home, read from the context: a
// bare ctx carries none, and the caller would be decided as no principal at all (#419).
func onBehalfOf(ctx context.Context, r *http.Request, claims iam.Claims) *http.Request {
	if home, _ := r.Context().Value(accountHomeKey{}).(string); home != "" && memberAccount(claims) {
		ctx = inAccount(ctx, claims.Account, home)
	}
	return withCallerClaims(r.Clone(ctx), claims)
}

// awsS3VhostRe / awsS3HostRe are AWS's S3 hostnames (virtual-hosted and path-style): on open-infra the
// shim's S3 stands in for them.
var (
	awsS3VhostRe = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-](?:dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com$`)
	awsS3HostRe  = regexp.MustCompile(`^s3(?:[.-](?:dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com$`)
)

// templateObject maps a TemplateURL onto a bucket and key of this shim's S3, or refuses it.
func (h *cfnDoorway) templateObject(raw string, r *http.Request) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", "", fmt.Errorf("TemplateURL %q is not an http(s) URL of an S3 object", raw)
	}
	host := hostNoPort(u.Host)
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	unescape := func(s string) string {
		if v, err := url.PathUnescape(s); err == nil {
			return v
		}
		return s
	}
	var suffixes []string
	if h.s3 != nil {
		suffixes = h.s3.vhostSuffixes
	}
	// Virtual-hosted: the bucket is the host's first label.
	if b := vhostBucket(host, suffixes); b != "" {
		return b, unescape(path), nil
	}
	if m := awsS3VhostRe.FindStringSubmatch(host); m != nil {
		return m[1], unescape(path), nil
	}
	// Path-style: /<bucket>/<key> on this endpoint, an S3 hostname of this site, or AWS's.
	own := r != nil && hostNoPort(r.Host) == host
	for _, s := range suffixes {
		if host == strings.ToLower(s) {
			own = true
		}
	}
	if own || awsS3HostRe.MatchString(host) {
		bucket, key, ok := strings.Cut(path, "/")
		if !ok || bucket == "" || key == "" {
			return "", "", fmt.Errorf("TemplateURL %q does not name an object (/<bucket>/<key>)", raw)
		}
		return unescape(bucket), unescape(key), nil
	}
	return "", "", fmt.Errorf("TemplateURL %q is not an object in this endpoint's S3 — open-infra reads templates only from its own S3 (upload the template there, e.g. `aws cloudformation deploy --s3-bucket` with AWS_ENDPOINT_URL set)", raw)
}

// readTemplateURL reads a TemplateURL's object as the caller.
func (h *cfnDoorway) readTemplateURL(r *http.Request, raw string) (string, error) {
	if h.s3 == nil || h.s3.mc == nil {
		return "", fmt.Errorf("TemplateURL is not available on this shim (no S3 front door) — pass the template inline as TemplateBody")
	}
	bucket, key, err := h.templateObject(raw, r)
	if err != nil {
		return "", err
	}
	claims, ok := callerClaimsOf(r)
	if !ok {
		return "", fmt.Errorf("TemplateURL: no caller identity")
	}
	if denied, reason := h.s3ReadDenied(r, claims, bucket, key); denied {
		return "", fmt.Errorf("TemplateURL: access denied reading s3://%s/%s (%s)", bucket, key, reason)
	}
	obj, err := h.s3.mc.GetObject(r.Context(), bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("TemplateURL: reading s3://%s/%s: %v", bucket, key, err)
	}
	defer obj.Close()
	b, err := io.ReadAll(io.LimitReader(obj, maxTemplateURLBytes+1))
	if err != nil {
		return "", fmt.Errorf("TemplateURL: reading s3://%s/%s: %s", bucket, key, minioErrToS3(err))
	}
	if len(b) > maxTemplateURLBytes {
		return "", fmt.Errorf("TemplateURL: the template exceeds 1 MB, the limit for a template in S3")
	}
	return string(b), nil
}

// s3ReadDenied is the S3 front door's authorization of a GetObject on the template's object, for a
// template read on the caller's behalf (s3authz.Gate, exactly as the S3 API authorizes the same read): the
// platform-bucket fence, then an assumed role default-deny under its data-plane policy, a User the coarse
// read right and no data-plane deny. Where accounts meet — a member account's caller, or a member
// account's bucket — it is decided as the S3 front door decides one (s3_accounts.go): in the bucket's
// account with the bucket's own policy, so a stack reads a template from its own account's bucket, or from
// another account's that its bucket policy opens to it, as on AWS.
func (h *cfnDoorway) s3ReadDenied(r *http.Request, claims iam.Claims, bucket, key string) (bool, string) {
	ctx := r.Context()
	g := s3authz.Gate{CS: h.s3.cs, Authz: h.authz, NS: h.s3.authzNS}
	q := s3authz.Request{Action: "s3:GetObject", Verb: "get", Bucket: bucket, Key: key, Object: true}
	if owner := h.s3.bucketOwner(ctx, bucket); memberAccount(claims) || !awsidentity.Current().IsManagement(owner) {
		ok, reason := g.AllowAccount(ctx, q, s3authz.Account{
			Principal: principalOf(ctx, claims),
			Owner:     owner,
			Policy:    func() string { return h.s3.bucketPolicyDoc(ctx, bucket) },
		}, requestContext(claims, r))
		return !ok, reason
	}
	ok, reason := g.Allow(ctx, claims, q, requestContext(claims, r))
	return !ok, reason
}
