// TemplateURL and nested stacks (#347 item I).
//
// AWS takes a template either inline (TemplateBody, up to 51,200 bytes) or as an S3 object (TemplateURL,
// up to 1 MB) — `aws cloudformation deploy --s3-bucket` uploads it there for anything larger, and a nested
// stack (AWS::CloudFormation::Stack) names its child template the same way. This front door accepts a
// TemplateURL that names an object in ITS OWN S3: the URL is only ever parsed into a bucket and key, never
// fetched over the network (no SSRF), and the object is read as the CALLER is allowed to read it (the S3
// front door's own authorization). Nested stacks are then flattened into one stack (cfn.FlattenNested)
// with the same resolver.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
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

// s3ReadDenied is the S3 front door's authorization of a GetObject, for a template read on the caller's
// behalf: an assumed role is default-deny under its data-plane policy; a User needs the coarse read right
// and no data-plane deny.
func (h *cfnDoorway) s3ReadDenied(r *http.Request, claims iam.Claims, bucket, key string) (bool, string) {
	if claims.PrincipalType() == "Role" {
		if h.authz == nil {
			return true, "no data-plane policy engine: an assumed role is denied"
		}
		allowed, governed, reason := h.authz.Authorize(r.Context(), "Role", claims.PrincipalID(), claims.Groups,
			"s3:GetObject", "Bucket", scopeFor(claims, bucket), requestContext(claims, r))
		if !governed || !allowed {
			if reason == "" {
				reason = "the assumed role has no data-plane policy allowing s3:GetObject (default deny)"
			}
			return true, reason
		}
		return false, ""
	}
	if allowed, reason := h.s3.authorizeS3(r.Context(), claims, s3op{kind: "get", bucket: bucket, key: key}); !allowed {
		return true, reason
	}
	return deniedByDataPlane(r.Context(), h.authz, claims, "s3:GetObject", "Bucket", bucket, r)
}

// templateURLResolver resolves a nested stack's child TemplateURL the same way (cfn.TemplateResolver).
type templateURLResolver struct {
	h *cfnDoorway
	r *http.Request
}

func (t templateURLResolver) Resolve(u string) ([]byte, error) {
	s, err := t.h.readTemplateURL(t.r, u)
	return []byte(s), err
}

// withNestedFlattened inlines a template's nested stacks (AWS::CloudFormation::Stack, children from this
// shim's S3) into one stack; a template with none is returned unchanged.
func (h *cfnDoorway) withNestedFlattened(r *http.Request, body string) (string, error) {
	if !strings.Contains(body, "AWS::CloudFormation::Stack") {
		return body, nil
	}
	out, err := cfn.FlattenNested([]byte(body), templateURLResolver{h: h, r: r})
	if err != nil {
		return "", err
	}
	return string(out), nil
}
