// CloudFront for the CFN engine — a narrow, static-site subset (#347 item 1.9).
//
// A CloudFront distribution in front of a private S3 bucket is, on open-infra, a kind: StaticSite: an
// nginx server that syncs the bucket from MinIO and serves it behind a Traefik Ingress with
// cert-manager TLS. There is no edge tier — no PoPs, no cache — so the translator accepts exactly the
// shape a single-origin static site needs and refuses everything else with a precise reason:
//
//	accepted   one S3 REST origin over an in-stack AWS::S3::Bucket, read via an in-stack OAC or OAI
//	           (or neither); the S3 BucketPolicy statements that grant CloudFront read; SPA fallback
//	           (CustomErrorResponses 403/404 -> /index.html, 200) or an error document; a response
//	           headers policy (in-stack, or the AWS managed SecurityHeadersPolicy); TLS on the Aliases
//	           (ViewerCertificate.AcmCertificateArn, typically an in-stack ACM certificate).
//	caveated   everything accepted but not emulated: caching (cache/origin-request policies, TTLs,
//	           Compress), PriceClass/HttpVersion/IPV6Enabled/Comment/Tags, access Logging, ViewerProtocol
//	           Policy (the site answers HTTPS only), origin timeouts/shield, ACM validation, OAC signing.
//	refused    a second origin or an origin group, a custom (non-S3) origin, OriginPath, path-pattern
//	           CacheBehaviors, Lambda@Edge / CloudFront Functions, signed URLs (trusted key groups/
//	           signers), field-level encryption, real-time logs, geo restriction, WAF (WebACLId), a
//	           continuous-deployment/staging distribution, write methods, CORS / remove-headers policy
//	           config, a distribution with no Aliases (open-infra has no *.cloudfront.net hostname), and
//	           a disabled distribution.
//
// The mapping: the template's bucket stays a kind: Bucket (its versioning/lifecycle/policy translate as
// before) and the distribution becomes a kind: StaticSite whose spec.bucket names that same MinIO bucket.
// The site's bucket-setup Job is idempotent on an existing bucket and mints the site its own scoped,
// read-capable MinIO user — that IS the OAC/OAI analog, so the bucket stays private and the template's
// CloudFront read grant is realized by the site rather than stored as a MinIO bucket policy (MinIO can't
// resolve a CloudFront principal). OAC/OAI, response-headers/cache/origin-request policies and the ACM
// certificate provision nothing on their own: each validates its own properties (fail-closed) and is
// read by the distribution that references it.
package cfn

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	cfDistributionType = "AWS::CloudFront::Distribution"
	cfOACType          = "AWS::CloudFront::OriginAccessControl"
	cfOAIType          = "AWS::CloudFront::CloudFrontOriginAccessIdentity"
	cfRHPType          = "AWS::CloudFront::ResponseHeadersPolicy"
	cfCachePolicyType  = "AWS::CloudFront::CachePolicy"
	cfORPType          = "AWS::CloudFront::OriginRequestPolicy"
	acmCertificateType = "AWS::CertificateManager::Certificate"
)

var (
	// cfPlaceholderRe matches a resolver placeholder for an in-stack reference: <ref:X> (Ref) or <X.Attr>
	// (Fn::GetAtt). The distribution reads references off its RESOLVED properties, so a reference nested
	// in Fn::If / Fn::Sub / Fn::Join is seen exactly as the resolver produced it.
	cfPlaceholderRe = regexp.MustCompile(`^<(?:ref:([A-Za-z0-9]+)|([A-Za-z0-9]+)\.([A-Za-z0-9.]+))>$`)
	// cfOriginDomainRe recognizes an S3 REST origin DomainName: <Bucket.RegionalDomainName|DomainName|
	// DualStackDomainName>, or <ref:Bucket> / a literal bucket name followed by an S3 endpoint suffix
	// (.s3.amazonaws.com, .s3.<region>.amazonaws.com, .s3-<region>…, .s3.dualstack.<region>…; the region
	// is an AWS region name or the engine's AWS::Region pseudo value). An S3 *website* endpoint
	// (s3-website…) does not match — that is a custom origin.
	cfOriginDomainRe = regexp.MustCompile(`^(?:<ref:([A-Za-z0-9]+)>|<([A-Za-z0-9]+)\.(?:RegionalDomainName|DomainName|DualStackDomainName)>|([a-z0-9][a-z0-9.-]*?[a-z0-9]))(\.s3(?:\.dualstack)?(?:[.-](?:[a-z]{2}(?:-[a-z]+)+-[0-9]+|openinfra))?\.amazonaws\.com(?:\.cn)?)?$`)
	cfOAIPathRe      = regexp.MustCompile(`^origin-access-identity/cloudfront/(.+)$`)
	cfOAIArnRe       = regexp.MustCompile(`^arn:aws[a-z-]*:iam::cloudfront:user/CloudFront Origin Access Identity (.+)$`)
	// cfHostnameRe is a lowercase DNS name with at least two labels (the StaticSite domains pattern).
	cfHostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	// cfPagePathRe is a safe object path for an index/error document (it lands in the nginx config).
	cfPagePathRe = regexp.MustCompile(`^/?[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$`)
	// cfHeaderNameRe / cfHeaderValueRe mirror the StaticSite XRD's responseHeaders patterns: a header
	// name is one nginx token; a value is printable ASCII without " \ or $ (one double-quoted nginx
	// string, no variable interpolation) — its 4096 cap is checked separately (RE2 caps {n,m} at 1000).
	cfHeaderNameRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
	cfHeaderValueRe = regexp.MustCompile(`^[ !#%-\[\]-~]+$`)
	// cfEmbeddedRefRe finds a <ref:X> / <X.Id> reference inside a built string (an ARN from !Sub/!Join).
	cfEmbeddedRefRe = regexp.MustCompile(`<ref:([A-Za-z0-9]+)>|<([A-Za-z0-9]+)\.Id>`)
	// staticSiteBucketRe is the StaticSite XRD's spec.bucket pattern.
	staticSiteBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// cfServerHeaders are headers nginx sets itself; add_header would DUPLICATE them, not replace them, so a
// response-headers policy naming one refuses rather than emitting two conflicting values.
var cfServerHeaders = map[string]bool{
	"content-type": true, "content-length": true, "content-range": true, "content-encoding": true,
	"server": true, "date": true, "last-modified": true, "etag": true, "accept-ranges": true,
	"connection": true, "keep-alive": true, "location": true, "transfer-encoding": true,
}

// cfHeader is one response header a StaticSite adds.
type cfHeader struct{ name, value string }

// cfManagedResponseHeaders is the AWS managed response headers policies, by policy id. Only
// Managed-SecurityHeadersPolicy maps (its fixed header set, per the CloudFront developer guide's
// "Use managed response headers policies"); the CORS ones refuse like an in-stack CorsConfig does.
var cfManagedResponseHeaders = map[string]struct {
	name    string
	headers []cfHeader
}{
	"67f7725c-6f97-4210-82d7-5512b31e9d03": {name: "Managed-SecurityHeadersPolicy", headers: []cfHeader{
		{"Strict-Transport-Security", "max-age=31536000"},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "SAMEORIGIN"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"X-XSS-Protection", "1; mode=block"},
	}},
	"60669652-455b-4ae9-85a4-c4c02393f86c": {name: "Managed-SimpleCORS"},
	"5cc3b908-e619-4b99-88e5-2cf7f45965bd": {name: "Managed-CORS-With-Preflight"},
	"e61eb60c-9c35-4d20-a928-2b84e02af89c": {name: "Managed-CORS-and-SecurityHeadersPolicy"},
	"eaab4381-ed33-4a86-88ca-d9558dc6cd63": {name: "Managed-CORS-with-preflight-and-SecurityHeadersPolicy"},
}

var cfDistributionConfigKeys = map[string]bool{
	"Aliases": true, "CacheBehaviors": true, "Comment": true, "ContinuousDeploymentPolicyId": true,
	"CustomErrorResponses": true, "DefaultCacheBehavior": true, "DefaultRootObject": true, "Enabled": true,
	"HttpVersion": true, "IPV6Enabled": true, "Logging": true, "OriginGroups": true, "Origins": true,
	"PriceClass": true, "Restrictions": true, "Staging": true, "ViewerCertificate": true, "WebACLId": true,
}

var cfOriginKeys = map[string]bool{
	"Id": true, "DomainName": true, "S3OriginConfig": true, "OriginAccessControlId": true, "OriginPath": true,
	"CustomOriginConfig": true, "OriginCustomHeaders": true, "OriginShield": true,
	"ConnectionAttempts": true, "ConnectionTimeout": true, "ResponseCompletionTimeout": true,
}

var cfCacheBehaviorKeys = map[string]bool{
	"AllowedMethods": true, "CachedMethods": true, "CachePolicyId": true, "Compress": true,
	"DefaultTTL": true, "MaxTTL": true, "MinTTL": true, "FieldLevelEncryptionId": true,
	"ForwardedValues": true, "FunctionAssociations": true, "GrpcConfig": true,
	"LambdaFunctionAssociations": true, "OriginRequestPolicyId": true, "RealtimeLogConfigArn": true,
	"ResponseHeadersPolicyId": true, "SmoothStreaming": true, "TargetOriginId": true,
	"TrustedKeyGroups": true, "TrustedSigners": true, "ViewerProtocolPolicy": true,
}

// ---- AWS::CloudFront::Distribution -> kind: StaticSite ----

func translateCloudFrontDistribution(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	var f []Finding
	refuse := func(format string, a ...any) {
		f = append(f, Finding{"Resource " + id, fmt.Sprintf(format, a...)})
	}
	var cav []string
	f = append(f, blockUnknownProps(id, props, map[string]bool{"DistributionConfig": true, "Tags": true})...)
	if ctx == nil {
		refuse("a CloudFront distribution needs stack context to resolve its origin bucket")
		return nil, f
	}
	dc, ok := props["DistributionConfig"].(map[string]any)
	if !ok {
		refuse("AWS::CloudFront::Distribution requires a DistributionConfig")
		return nil, f
	}
	reportKnown(id+".DistributionConfig", cfDistributionConfigKeys)
	for _, k := range sortedKeys(dc) {
		if !cfDistributionConfigKeys[k] {
			refuse("DistributionConfig.%s is not translatable to kind: StaticSite — refusing rather than silently dropping it", k)
		}
	}

	// --- out-of-subset distribution features: refused with the reason, never approximated ---
	if cfNonEmpty(dc["CacheBehaviors"]) {
		refuse("DistributionConfig.CacheBehaviors (path-pattern cache behaviors) are not translatable — kind: StaticSite serves the whole site under one behavior (the DefaultCacheBehavior); refusing rather than serving every path the same way")
	}
	if cfNonEmpty(dc["OriginGroups"]) {
		refuse("DistributionConfig.OriginGroups (origin failover) are not translatable — kind: StaticSite serves one bucket from one in-cluster server; there is no second origin to fail over to")
	}
	if cfNonEmpty(dc["WebACLId"]) {
		refuse("DistributionConfig.WebACLId (an AWS WAF web ACL) is not translatable — kind: StaticSite has no WAF attachment; refusing rather than serving the site unprotected")
	}
	if cfNonEmpty(dc["ContinuousDeploymentPolicyId"]) || cfTrue(dc["Staging"]) {
		refuse("CloudFront continuous deployment (ContinuousDeploymentPolicyId / Staging) is not translatable — there is no staging distribution or traffic split for a kind: StaticSite")
	}
	if r, ok := dc["Restrictions"].(map[string]any); ok {
		geo, _ := r["GeoRestriction"].(map[string]any)
		if rt, _ := concrete(geo["RestrictionType"]); rt != "" && rt != "none" {
			refuse("DistributionConfig.Restrictions.GeoRestriction %s is not translatable — kind: StaticSite has no viewer-geolocation filter; refusing rather than serving the site to every country", rt)
		}
	}
	switch en, ok := cfBool(dc["Enabled"]); {
	case !ok:
		refuse("DistributionConfig.Enabled is required (true)")
	case !en:
		refuse("DistributionConfig.Enabled is false — a disabled distribution serves nothing, and kind: StaticSite has no disabled state; remove the distribution or enable it")
	}

	// --- Aliases -> spec.domain (+ spec.domains) ---
	var hosts []string
	seen := map[string]bool{}
	for _, a := range cfStringList(dc["Aliases"]) {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
		switch {
		case strings.HasPrefix(h, "*."):
			refuse("Alias %q is a wildcard — kind: StaticSite serves explicit hostnames; list each hostname in Aliases", a)
		case !cfHostnameRe.MatchString(h):
			refuse("Alias %q is not a concrete DNS hostname (an unresolved reference, or an invalid name)", a)
		case !seen[h]:
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(cfStringList(dc["Aliases"])) == 0 {
		refuse("DistributionConfig.Aliases is empty — a distribution without Aliases is served on an AWS-generated *.cloudfront.net hostname, which has no open-infra analog; declare the site's hostname in Aliases (with ViewerCertificate.AcmCertificateArn for its TLS certificate)")
	}

	// --- ViewerCertificate -> spec.tls (cert-manager issues the alias certificate) ---
	vc, hasVC := dc["ViewerCertificate"].(map[string]any)
	if !hasVC {
		refuse("DistributionConfig.ViewerCertificate is required with Aliases — name the certificate for them (AcmCertificateArn)")
	} else {
		for _, k := range sortedKeys(vc) {
			switch k {
			case "AcmCertificateArn", "IamCertificateId", "CloudFrontDefaultCertificate", "SslSupportMethod", "MinimumProtocolVersion":
			default:
				refuse("ViewerCertificate.%s is not translatable — refusing rather than silently dropping it", k)
			}
		}
		if cfTrue(vc["CloudFrontDefaultCertificate"]) {
			refuse("ViewerCertificate.CloudFrontDefaultCertificate covers only *.cloudfront.net, never the distribution's Aliases — name the alias certificate (AcmCertificateArn)")
		}
		switch acm, iam := vc["AcmCertificateArn"], vc["IamCertificateId"]; {
		case cfNonEmpty(acm):
			if certID, attr, ok := cfPlaceholder(acm); ok && attr == "" && ctx.isType(certID, acmCertificateType) {
				if !ctx.includedID(certID) {
					refuse("ViewerCertificate.AcmCertificateArn references %s, which its Condition excludes", certID)
				} else if cp, ok := ctx.resolveProps(certID); ok {
					names, notes, _ := cfCertificate(certID, cp) // the certificate reports its own refusals
					cav = append(cav, notes...)
					if uncovered := cfUncovered(names, hosts); len(uncovered) > 0 {
						refuse("certificate %s (%s) does not cover Alias(es) %s — CloudFront refuses a distribution whose certificate doesn't cover its Aliases", certID, strings.Join(names, ", "), strings.Join(uncovered, ", "))
					}
				}
			} else {
				arn, _ := concrete(acm)
				cav = append(cav, fmt.Sprintf("ViewerCertificate.AcmCertificateArn names a certificate outside this stack (%s); it is not used — the site's certificate for %s is issued in-cluster (see the TLS caveat)", cfOr(arn, "unresolved"), strings.Join(hosts, ", ")))
			}
		case cfNonEmpty(iam):
			cav = append(cav, "ViewerCertificate.IamCertificateId (an IAM server certificate) is not used — the site's certificate is issued in-cluster (see the TLS caveat)")
		default:
			refuse("ViewerCertificate must name a certificate for the Aliases (AcmCertificateArn)")
		}
		switch m, _ := concrete(vc["SslSupportMethod"]); m {
		case "", "sni-only":
		default:
			refuse("ViewerCertificate.SslSupportMethod %s (a dedicated-IP certificate) is not translatable — Traefik serves TLS by SNI only", m)
		}
		if v, ok := concrete(vc["MinimumProtocolVersion"]); ok && v != "" {
			cav = append(cav, "ViewerCertificate.MinimumProtocolVersion "+v+" is not applied per site — Traefik's TLS defaults (TLS 1.2+) govern the handshake")
		}
	}
	cav = append(cav, fmt.Sprintf("TLS for %s is terminated by Traefik with a certificate cert-manager issues from the cluster ClusterIssuer openinfra-issuer (self-signed unless the operator configured an ACME issuer) — not an ACM certificate, so a browser trusts it only if it trusts that issuer", cfOr(strings.Join(hosts, ", "), "the Aliases")))

	// --- the single S3 origin -> spec.bucket ---
	origins, _ := dc["Origins"].([]any)
	originID, bucket := "", ""
	if len(origins) != 1 {
		refuse("DistributionConfig.Origins: exactly one S3 origin translates (got %d) — multiple origins, and routing between them, are outside the CloudFront subset kind: StaticSite models", len(origins))
	} else if o, ok := origins[0].(map[string]any); !ok {
		refuse("DistributionConfig.Origins[0] is not an object")
	} else {
		reportKnown(id+".DistributionConfig.Origins[0]", cfOriginKeys)
		originID, bucket, cav = cfOrigin(o, ctx, refuse, cav)
	}

	// --- DefaultCacheBehavior: the one behavior; edge features refuse, caching is a caveat ---
	var headers []cfHeader
	var headerNotes []string
	dcb, ok := dc["DefaultCacheBehavior"].(map[string]any)
	if !ok {
		refuse("DistributionConfig.DefaultCacheBehavior is required")
	} else {
		reportKnown(id+".DistributionConfig.DefaultCacheBehavior", cfCacheBehaviorKeys)
		headers, headerNotes, cav = cfDefaultBehavior(dcb, originID, ctx, refuse, cav)
	}

	// --- CustomErrorResponses + DefaultRootObject -> spa / indexDocument / errorDocument ---
	spa, index, errorDoc, ecav := cfErrorResponses(dc, refuse)
	cav = append(cav, ecav...)

	// --- accepted, no open-infra effect ---
	var inert []string
	for _, k := range []string{"PriceClass", "HttpVersion", "IPV6Enabled", "Comment"} {
		if _, ok := dc[k]; ok {
			inert = append(inert, k)
		}
	}
	if _, ok := props["Tags"]; ok {
		inert = append(inert, "Tags")
	}
	if len(inert) > 0 {
		cav = append(cav, strings.Join(inert, "/")+" have no open-infra effect — one cluster ingress has no price classes or edge locations, Traefik negotiates HTTP/2 over TLS, IPv6 follows the cluster network, and comments/tags are not carried")
	}
	if _, ok := dc["Logging"]; ok {
		cav = append(cav, "DistributionConfig.Logging is not emulated — standard access logs are not delivered to the logging bucket; the site's nginx access log goes to the pod's stdout (collected by the cluster's log pipeline)")
	}
	cav = append(cav,
		"CloudFront edge caching is not emulated: one in-cluster nginx serves the origin bucket, re-synced from MinIO every 30s — an upload goes live within ~30s and a deleted object disappears on the next sync; there are no edge locations and no CreateInvalidation",
		"S3 object metadata set at upload (Content-Type, Cache-Control, Content-Encoding, x-amz-meta-*) is not served — nginx serves the synced files with a Content-Type inferred from the file extension, so a pre-compressed object uploaded with Content-Encoding is served as raw bytes",
		"directory paths differ: nginx serves "+index+" inside a sub-directory (e.g. /docs/ -> /docs/"+index+") and answers a directory with no index document with 403 — CloudFront applies DefaultRootObject to / only",
	)
	if len(hosts) > 0 {
		cav = append(cav, fmt.Sprintf("Fn::GetAtt %s.DomainName resolves to %s, the site's primary hostname (there is no *.cloudfront.net name); Ref / Fn::GetAtt .Id have no value here (no distribution id exists)", id, hosts[0]))
	}
	cav = append(cav, headerNotes...)

	if len(f) > 0 {
		return nil, f
	}
	spec := map[string]any{
		"domain":        hosts[0],
		"bucket":        bucket,
		"tls":           true,
		"spa":           spa,
		"indexDocument": index,
	}
	if len(hosts) > 1 {
		spec["domains"] = toAnySlice(hosts[1:])
	}
	if errorDoc != "" {
		spec["errorDocument"] = errorDoc
	}
	if len(headers) > 0 {
		hs := make([]any, 0, len(headers))
		for _, h := range headers {
			hs = append(hs, map[string]any{"name": h.name, "value": h.value})
		}
		spec["responseHeaders"] = hs
	}
	return &Manifest{APIVersion: "openinfra.dev/v1", Kind: "StaticSite", Name: ctx.name(id), Spec: spec, Caveats: cav}, nil
}

// cfOrigin validates the distribution's single origin and returns its Id and the MinIO bucket the site
// serves. It must be an S3 REST origin over an included in-stack AWS::S3::Bucket, read via an in-stack
// OAC or OAI (or neither).
func cfOrigin(o map[string]any, ctx *stackCtx, refuse func(string, ...any), cav []string) (originID, bucket string, _ []string) {
	for _, k := range sortedKeys(o) {
		if !cfOriginKeys[k] {
			refuse("origin property %s is not translatable — refusing rather than silently dropping it", k)
		}
	}
	originID, _ = concrete(o["Id"])
	if originID == "" {
		refuse("the origin requires an Id")
	}
	if _, ok := o["CustomOriginConfig"]; ok {
		refuse("origin %s uses CustomOriginConfig (a custom HTTP origin — an S3 website endpoint, a load balancer, an API) — only an S3 REST origin over an in-stack AWS::S3::Bucket translates (to kind: StaticSite)", originID)
		return originID, "", cav
	}
	s3cfg, hasS3 := o["S3OriginConfig"].(map[string]any)
	if !hasS3 {
		refuse("origin %s has no S3OriginConfig — only an S3 REST origin translates (CloudFront itself requires S3OriginConfig, possibly with an empty OriginAccessIdentity, for an S3 origin)", originID)
	}
	for _, k := range sortedKeys(s3cfg) {
		if k != "OriginAccessIdentity" && k != "OriginReadTimeout" {
			refuse("S3OriginConfig.%s is not translatable — refusing rather than silently dropping it", k)
		}
	}
	if p, _ := concrete(o["OriginPath"]); p != "" && p != "/" {
		refuse("origin %s OriginPath %q (serving a key prefix of the bucket) is not translatable — kind: StaticSite serves the bucket root; publish the site at the bucket root", originID, p)
	}

	// The bucket.
	bucketID, why := ctx.cloudFrontOriginBucket(o["DomainName"])
	if bucketID == "" {
		refuse("origin %s: %s", originID, why)
	} else {
		bp, _ := ctx.resolveProps(bucketID)
		if _, lock := bp["ObjectLockEnabled"]; lock || bp["ObjectLockConfiguration"] != nil {
			refuse("origin bucket %s has Object Lock — Object Lock must be set when the bucket is created, and the site's own bucket setup may create the bucket first; a WORM-locked origin is outside the static-site subset", bucketID)
		}
		bucket = s3BucketMinIOName(bucketID, ctx)
		if !staticSiteBucketRe.MatchString(bucket) {
			refuse("origin bucket name %q is not a valid kind: StaticSite bucket (3-63 lowercase letters, digits, dots, hyphens)", bucket)
		}
	}

	// Origin access: an in-stack OAC (OriginAccessControlId) or OAI (S3OriginConfig.OriginAccessIdentity).
	access := ""
	if v := o["OriginAccessControlId"]; cfNonEmpty(v) {
		if oac, attr, ok := cfPlaceholder(v); ok && (attr == "" || attr == "Id") && ctx.isType(oac, cfOACType) {
			if !ctx.includedID(oac) {
				refuse("origin %s OriginAccessControlId references %s, which its Condition excludes", originID, oac)
			}
			access = "OAC"
			if op, ok := ctx.resolveProps(oac); ok {
				notes, _ := cfOriginAccessControl(oac, op) // the OAC reports its own refusals
				cav = append(cav, notes...)
			}
		} else {
			refuse("origin %s OriginAccessControlId must !Ref / !GetAtt <OAC>.Id an in-stack AWS::CloudFront::OriginAccessControl — an origin access control outside this stack can't be read", originID)
		}
	}
	if v := s3cfg["OriginAccessIdentity"]; cfNonEmpty(v) {
		s := fmt.Sprint(v)
		m := cfOAIPathRe.FindStringSubmatch(s)
		oai := ""
		if m != nil {
			if id, attr, ok := cfPlaceholder(m[1]); ok && attr == "" && ctx.isType(id, cfOAIType) {
				oai = id
			}
		}
		switch {
		case oai == "":
			refuse("origin %s S3OriginConfig.OriginAccessIdentity %q must be origin-access-identity/cloudfront/${OAI} for an in-stack AWS::CloudFront::CloudFrontOriginAccessIdentity — an identity outside this stack can't be read", originID, s)
		case !ctx.includedID(oai):
			refuse("origin %s OriginAccessIdentity references %s, which its Condition excludes", originID, oai)
		case access != "":
			refuse("origin %s sets both an OriginAccessControlId and an OriginAccessIdentity — CloudFront accepts one", originID)
		default:
			access = "OAI"
		}
	}
	if access != "" {
		cav = append(cav, "origin access ("+access+") is realized by the site's own scoped MinIO credentials (the <site>-minio secret its bucket setup mints) — the bucket stays private; CloudFront's request signing is not emulated")
	} else {
		cav = append(cav, "the origin has no OAC/OAI, so on AWS CloudFront reads it anonymously (the bucket must allow public read); on open-infra the site reads it with its own scoped MinIO credentials either way")
	}

	var inert []string
	if sh, ok := o["OriginShield"].(map[string]any); ok && cfTrue(sh["Enabled"]) {
		inert = append(inert, "OriginShield")
	}
	if cfNonEmpty(o["OriginCustomHeaders"]) {
		inert = append(inert, "OriginCustomHeaders")
	}
	for _, k := range []string{"ConnectionAttempts", "ConnectionTimeout", "ResponseCompletionTimeout"} {
		if _, ok := o[k]; ok {
			inert = append(inert, k)
		}
	}
	if _, ok := s3cfg["OriginReadTimeout"]; ok {
		inert = append(inert, "S3OriginConfig.OriginReadTimeout")
	}
	if len(inert) > 0 {
		cav = append(cav, strings.Join(inert, "/")+" have no effect — the site serves synced files locally; there is no per-request origin fetch to shield, time out, or add headers to")
	}
	return originID, bucket, cav
}

// cfDefaultBehavior validates the DefaultCacheBehavior and returns the response headers it adds.
func cfDefaultBehavior(b map[string]any, originID string, ctx *stackCtx, refuse func(string, ...any), cav []string) ([]cfHeader, []string, []string) {
	for _, k := range sortedKeys(b) {
		if !cfCacheBehaviorKeys[k] {
			refuse("DefaultCacheBehavior.%s is not translatable — refusing rather than silently dropping it", k)
		}
	}
	if t, _ := concrete(b["TargetOriginId"]); originID != "" && t != originID {
		refuse("DefaultCacheBehavior.TargetOriginId %q does not name the origin (%s)", t, originID)
	}
	if cfNonEmpty(b["LambdaFunctionAssociations"]) {
		refuse("DefaultCacheBehavior.LambdaFunctionAssociations (Lambda@Edge) are not translatable — kind: StaticSite runs no code at the edge; refusing rather than serving responses the functions would have rewritten")
	}
	if cfNonEmpty(b["FunctionAssociations"]) {
		refuse("DefaultCacheBehavior.FunctionAssociations (CloudFront Functions) are not translatable — kind: StaticSite runs no viewer-request/response code; refusing rather than serving requests the functions would have rewritten")
	}
	if cfNonEmpty(b["TrustedKeyGroups"]) || cfNonEmpty(b["TrustedSigners"]) {
		refuse("DefaultCacheBehavior.TrustedKeyGroups/TrustedSigners (signed URLs / signed cookies) are not translatable — kind: StaticSite has no signed-request check; refusing rather than serving restricted content to anyone")
	}
	if cfNonEmpty(b["FieldLevelEncryptionId"]) {
		refuse("DefaultCacheBehavior.FieldLevelEncryptionId (field-level encryption) is not translatable — refusing rather than passing those fields through unencrypted")
	}
	if cfNonEmpty(b["RealtimeLogConfigArn"]) {
		refuse("DefaultCacheBehavior.RealtimeLogConfigArn (real-time logs to Kinesis) is not translatable — kind: StaticSite has no real-time log stream")
	}
	if cfTrue(b["SmoothStreaming"]) {
		refuse("DefaultCacheBehavior.SmoothStreaming (Microsoft Smooth Streaming) is not translatable")
	}
	if g, ok := b["GrpcConfig"].(map[string]any); ok && cfTrue(g["Enabled"]) {
		refuse("DefaultCacheBehavior.GrpcConfig (gRPC) is not translatable — a static site serves no gRPC")
	}
	writes := false
	for _, m := range cfStringList(b["AllowedMethods"]) {
		switch strings.ToUpper(m) {
		case "GET", "HEAD":
		case "OPTIONS":
			cav = append(cav, "AllowedMethods includes OPTIONS: an OPTIONS request is answered by nginx without a CORS preflight response (S3 CORS is not modeled)")
		default:
			writes = true
		}
	}
	if writes {
		refuse("DefaultCacheBehavior.AllowedMethods %v include write methods (POST/PUT/PATCH/DELETE) — kind: StaticSite serves the bucket read-only (GET/HEAD/OPTIONS); refusing rather than dropping writes", cfStringList(b["AllowedMethods"]))
	}

	switch p, _ := concrete(b["ViewerProtocolPolicy"]); p {
	case "https-only":
	case "redirect-to-https", "allow-all":
		cav = append(cav, "ViewerProtocolPolicy "+p+": the site answers on HTTPS only (Traefik's websecure entrypoint) — a plain-HTTP request is neither served nor redirected to HTTPS, so http:// links fail rather than redirect")
	case "":
		refuse("DefaultCacheBehavior.ViewerProtocolPolicy is required")
	default:
		refuse("DefaultCacheBehavior.ViewerProtocolPolicy %q is not a CloudFront viewer protocol policy", p)
	}

	// In-stack policy references must be included (a reference to a conditioned-off resource has no value).
	for _, k := range []string{"CachePolicyId", "OriginRequestPolicyId"} {
		if pid, _, ok := cfPlaceholder(b[k]); ok && !ctx.includedID(pid) {
			refuse("DefaultCacheBehavior.%s references %s, which its Condition excludes", k, pid)
		}
	}
	var caching []string
	for _, k := range []string{"CachePolicyId", "OriginRequestPolicyId", "CachedMethods", "DefaultTTL", "MaxTTL", "MinTTL", "ForwardedValues"} {
		if _, ok := b[k]; ok {
			caching = append(caching, k)
		}
	}
	if cfTrue(b["Compress"]) {
		caching = append(caching, "Compress")
	}
	if len(caching) > 0 {
		cav = append(cav, "DefaultCacheBehavior "+strings.Join(caching, "/")+" are accepted but not emulated — there is no cache tier (every request is served from the synced copy of the bucket), no cache key, and responses are not compressed")
	}

	// Response headers: an in-stack AWS::CloudFront::ResponseHeadersPolicy, or an AWS managed policy id.
	var headers []cfHeader
	var notes []string
	if v := b["ResponseHeadersPolicyId"]; cfNonEmpty(v) {
		if rhp, attr, ok := cfPlaceholder(v); ok {
			switch {
			case (attr != "" && attr != "Id") || !ctx.isType(rhp, cfRHPType):
				refuse("DefaultCacheBehavior.ResponseHeadersPolicyId must !Ref / !GetAtt <Policy>.Id an AWS::CloudFront::ResponseHeadersPolicy (got a reference to %s)", rhp)
			case !ctx.includedID(rhp):
				refuse("DefaultCacheBehavior.ResponseHeadersPolicyId references %s, which its Condition excludes", rhp)
			default:
				rp, _ := ctx.resolveProps(rhp)
				headers, notes, _ = cfResponseHeadersConfig(rhp, rp) // the policy reports its own refusals
			}
		} else {
			pid, _ := concrete(v)
			mp, known := cfManagedResponseHeaders[pid]
			switch {
			case !known:
				refuse("DefaultCacheBehavior.ResponseHeadersPolicyId %q names a response headers policy outside this stack, whose headers can't be read — define it in the stack (AWS::CloudFront::ResponseHeadersPolicy) or use the AWS managed SecurityHeadersPolicy", pid)
			case mp.headers == nil:
				refuse("DefaultCacheBehavior.ResponseHeadersPolicyId is the AWS managed %s, whose CORS headers (and preflight handling) are not emulated — set a static Access-Control-Allow-Origin with an in-stack policy's CustomHeadersConfig if a fixed origin suffices", mp.name)
			default:
				headers = mp.headers
				notes = append(notes, "the AWS managed "+mp.name+" is applied as its fixed header set")
			}
		}
	}
	if len(headers) > 0 {
		names := make([]string, len(headers))
		for i, h := range headers {
			names[i] = h.name
		}
		notes = append(notes, "response headers "+strings.Join(names, ", ")+" are added by nginx to every response, error responses included; each policy entry's Override is moot (the origin never sets these headers)")
	}
	return headers, notes, cav
}

// cfErrorResponses maps CustomErrorResponses + DefaultRootObject to the StaticSite's spa /
// indexDocument / errorDocument. Accepted: every mapping is a 403/404 to ONE page — with ResponseCode
// 200 it is the SPA history fallback (the page must be the index document), with a 404 response it is
// an error document. The nginx origin reports a missing object as 404 (an S3 origin without
// s3:ListBucket says 403), so the 403 and 404 rules collapse into the one missing-object behavior.
func cfErrorResponses(dc map[string]any, refuse func(string, ...any)) (spa bool, index, errorDoc string, cav []string) {
	index = "index.html"
	dro, _ := concrete(dc["DefaultRootObject"])
	dro = strings.TrimPrefix(dro, "/")
	if dro != "" {
		if !cfSafePagePath(dro) {
			refuse("DefaultRootObject %q is not a plain object path", dro)
		} else {
			index = dro
		}
	}
	// Without a DefaultRootObject CloudFront answers / with the origin's error (or, with a SPA mapping,
	// the fallback page); the site serves index.html at / whenever the bucket has one.
	noRoot := func() {
		if dro == "" {
			cav = append(cav, "DefaultRootObject is not set: CloudFront would answer / with an error, while the site serves index.html at / when the bucket has one")
		}
	}
	type mapping struct {
		code       int
		page, resp string
	}
	var maps []mapping
	cachingOnly := false
	list, _ := dc["CustomErrorResponses"].([]any)
	for i, e := range list {
		em, _ := e.(map[string]any)
		for _, k := range sortedKeys(em) {
			switch k {
			case "ErrorCode", "ResponseCode", "ResponsePagePath", "ErrorCachingMinTTL":
			default:
				refuse("CustomErrorResponses[%d].%s is not translatable", i, k)
			}
		}
		code, cok := cfInt(em["ErrorCode"])
		page, _ := concrete(em["ResponsePagePath"])
		resp := ""
		if rc, ok := cfInt(em["ResponseCode"]); ok {
			resp = strconv.Itoa(rc)
		} else if s, _ := concrete(em["ResponseCode"]); strings.TrimSpace(s) != "" {
			resp = strings.TrimSpace(s) // not a number: refused below as a non-200/404 response
		}
		switch {
		case !cok:
			refuse("CustomErrorResponses[%d].ErrorCode is required", i)
			continue
		case page == "" && resp == "":
			cachingOnly = true // only ErrorCachingMinTTL: a caching knob
			continue
		case page == "":
			refuse("CustomErrorResponses[%d] sets ResponseCode %s without a ResponsePagePath (CloudFront requires both)", i, resp)
			continue
		case code != 403 && code != 404:
			refuse("CustomErrorResponses ErrorCode %d is not translatable — only 403/404 (a missing object) map, as the SPA fallback or an error document; the nginx origin produces no other error a custom page could replace", code)
			continue
		case !cfSafePagePath(page):
			refuse("CustomErrorResponses ResponsePagePath %q is not a plain object path", page)
			continue
		}
		if _, ok := em["ErrorCachingMinTTL"]; ok {
			cachingOnly = true
		}
		maps = append(maps, mapping{code, "/" + strings.TrimPrefix(page, "/"), resp})
	}
	if cachingOnly {
		cav = append(cav, "CustomErrorResponses ErrorCachingMinTTL is not emulated (error responses are not cached)")
	}
	if len(maps) == 0 {
		cav = append(cav, "no CustomErrorResponses: a missing object returns nginx's 404 page (an S3 origin without s3:ListBucket returns 403)")
		noRoot()
		return false, index, "", cav
	}
	page := maps[0].page
	for _, m := range maps[1:] {
		if m.page != page {
			refuse("CustomErrorResponses map 403 and 404 to different pages (%s, %s) — the site has one missing-object behavior, so both must name the same page", page, m.page)
			return false, index, "", cav
		}
	}
	all := func(want string, def bool) bool {
		for _, m := range maps {
			r := m.resp
			if r == "" && def {
				r = strconv.Itoa(m.code) // no ResponseCode: CloudFront returns the original error code
			}
			if r != want {
				return false
			}
		}
		return true
	}
	codes := make([]string, len(maps))
	for i, m := range maps {
		codes[i] = strconv.Itoa(m.code)
	}
	switch {
	case all("200", false):
		want := "/" + index
		if dro == "" {
			index = strings.TrimPrefix(page, "/")
			want = page
		}
		if page != want {
			refuse("the SPA fallback page %s is not the DefaultRootObject (%s) — the site falls back to its index document, so the two must be the same object", page, want)
			return false, index, "", cav
		}
		cav = append(cav, "CustomErrorResponses "+strings.Join(codes, "/")+" -> "+page+" (200) map to SPA history fallback: any path with no object serves "+index+" with 200")
		return true, index, "", cav
	case all("404", true):
		cav = append(cav, "CustomErrorResponses "+strings.Join(codes, "/")+" -> "+page+" (404) map to the site's error document: a missing object returns "+page+" with 404")
		noRoot()
		return false, index, strings.TrimPrefix(page, "/"), cav
	default:
		refuse("CustomErrorResponses for %s must all answer 200 (SPA fallback) or all answer 404 (an error document) — the nginx origin reports a missing object one way, so a 403 with a different ResponseCode than the 404 can't be reproduced", strings.Join(codes, "/"))
		return false, index, "", cav
	}
}

// ---- OAC / OAI / response-headers / cache / origin-request policies: no standalone form ----
//
// Each provisions nothing on its own — the distribution that references it reads it. Its translator
// validates its own properties (fail-closed) so an untranslatable one refuses exactly once, wherever it
// is referenced from.
func translateCloudFrontChild(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx == nil {
		return nil, nil
	}
	switch ctx.template.Resources[id].Type {
	case cfOACType:
		_, f := cfOriginAccessControl(id, props)
		return nil, f
	case cfOAIType:
		f := blockUnknownProps(id, props, map[string]bool{"CloudFrontOriginAccessIdentityConfig": true})
		if c, ok := props["CloudFrontOriginAccessIdentityConfig"].(map[string]any); ok {
			f = append(f, blockUnknownProps(id+".CloudFrontOriginAccessIdentityConfig", c, map[string]bool{"Comment": true})...)
		}
		return nil, f
	case cfRHPType:
		_, _, f := cfResponseHeadersConfig(id, props)
		return nil, f
	case cfCachePolicyType:
		return nil, blockUnknownProps(id, props, map[string]bool{"CachePolicyConfig": true})
	case cfORPType:
		return nil, blockUnknownProps(id, props, map[string]bool{"OriginRequestPolicyConfig": true})
	}
	return nil, nil
}

// cfOriginAccessControl validates an OAC's config: an S3 origin type only. SigningBehavior never (no
// signing — the bucket must be public on AWS) is a caveat: the site reads with credentials either way.
func cfOriginAccessControl(id string, props map[string]any) (notes []string, f []Finding) {
	f = blockUnknownProps(id, props, map[string]bool{"OriginAccessControlConfig": true})
	c, ok := props["OriginAccessControlConfig"].(map[string]any)
	if !ok {
		return nil, append(f, Finding{"Resource " + id, "AWS::CloudFront::OriginAccessControl requires an OriginAccessControlConfig"})
	}
	f = append(f, blockUnknownProps(id+".OriginAccessControlConfig", c, map[string]bool{
		"Name": true, "Description": true, "OriginAccessControlOriginType": true, "SigningBehavior": true, "SigningProtocol": true,
	})...)
	if t, _ := concrete(c["OriginAccessControlOriginType"]); t != "s3" {
		f = append(f, Finding{"Resource " + id, "OriginAccessControlOriginType " + cfOr(t, "(unset)") + " is not translatable — only an s3 origin access control maps (to the site's scoped bucket credentials)"})
	}
	if sb, _ := concrete(c["SigningBehavior"]); sb == "never" {
		notes = append(notes, "origin access control "+id+" has SigningBehavior never (CloudFront sends unsigned requests, so on AWS the bucket must be public); the site reads it with its own credentials either way")
	}
	return notes, f
}

// cfResponseHeadersConfig maps an AWS::CloudFront::ResponseHeadersPolicy's resolved Properties to the
// headers a StaticSite adds. Security headers map to their header values; CustomHeadersConfig items map
// verbatim. CorsConfig and RemoveHeadersConfig refuse (dynamic CORS / header removal aren't emulated).
func cfResponseHeadersConfig(id string, props map[string]any) (hs []cfHeader, notes []string, f []Finding) {
	fin := func(format string, a ...any) { f = append(f, Finding{"Resource " + id, fmt.Sprintf(format, a...)}) }
	f = blockUnknownProps(id, props, map[string]bool{"ResponseHeadersPolicyConfig": true})
	c, ok := props["ResponseHeadersPolicyConfig"].(map[string]any)
	if !ok {
		fin("AWS::CloudFront::ResponseHeadersPolicy requires a ResponseHeadersPolicyConfig")
		return nil, nil, f
	}
	for _, k := range sortedKeys(c) {
		switch k {
		case "Name", "Comment", "CorsConfig", "CustomHeadersConfig", "RemoveHeadersConfig", "SecurityHeadersConfig", "ServerTimingHeadersConfig":
		default:
			fin("ResponseHeadersPolicyConfig.%s is not translatable — refusing rather than silently dropping it", k)
		}
	}
	if _, ok := c["CorsConfig"]; ok {
		fin("ResponseHeadersPolicyConfig.CorsConfig (CloudFront-generated CORS headers and preflight handling) is not emulated — refusing rather than serving without the CORS headers the policy promises; a fixed Access-Control-Allow-Origin can be a CustomHeadersConfig item")
	}
	if rh, ok := c["RemoveHeadersConfig"].(map[string]any); ok && cfNonEmpty(rh["Items"]) {
		fin("ResponseHeadersPolicyConfig.RemoveHeadersConfig is not translatable — nginx can't strip response headers per site; refusing rather than leaving headers the policy removes")
	}
	if st, ok := c["ServerTimingHeadersConfig"].(map[string]any); ok && cfTrue(st["Enabled"]) {
		notes = append(notes, "ServerTimingHeadersConfig (CloudFront's Server-Timing diagnostics) is not emulated — it reports CloudFront-internal timings that have no analog here")
	}

	if sec, ok := c["SecurityHeadersConfig"].(map[string]any); ok {
		for _, k := range sortedKeys(sec) {
			switch k {
			case "StrictTransportSecurity", "ContentSecurityPolicy", "ContentTypeOptions", "FrameOptions", "ReferrerPolicy", "XSSProtection":
			default:
				fin("SecurityHeadersConfig.%s is not translatable", k)
			}
		}
		if h, ok := sec["StrictTransportSecurity"].(map[string]any); ok {
			age, ok := cfInt(h["AccessControlMaxAgeSec"])
			if !ok || age < 0 {
				fin("StrictTransportSecurity.AccessControlMaxAgeSec must be a non-negative integer")
			} else {
				v := "max-age=" + strconv.Itoa(age)
				if cfTrue(h["IncludeSubdomains"]) {
					v += "; includeSubDomains"
				}
				if cfTrue(h["Preload"]) {
					v += "; preload"
				}
				hs = append(hs, cfHeader{"Strict-Transport-Security", v})
			}
		}
		if h, ok := sec["ContentSecurityPolicy"].(map[string]any); ok {
			v, _ := concrete(h["ContentSecurityPolicy"])
			hs = append(hs, cfHeader{"Content-Security-Policy", v})
		}
		if _, ok := sec["ContentTypeOptions"].(map[string]any); ok {
			hs = append(hs, cfHeader{"X-Content-Type-Options", "nosniff"})
		}
		if h, ok := sec["FrameOptions"].(map[string]any); ok {
			switch v, _ := concrete(h["FrameOption"]); v {
			case "DENY", "SAMEORIGIN":
				hs = append(hs, cfHeader{"X-Frame-Options", v})
			default:
				fin("FrameOptions.FrameOption must be DENY or SAMEORIGIN (got %q)", v)
			}
		}
		if h, ok := sec["ReferrerPolicy"].(map[string]any); ok {
			switch v, _ := concrete(h["ReferrerPolicy"]); v {
			case "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url":
				hs = append(hs, cfHeader{"Referrer-Policy", v})
			default:
				fin("ReferrerPolicy.ReferrerPolicy %q is not a referrer policy CloudFront accepts", v)
			}
		}
		if h, ok := sec["XSSProtection"].(map[string]any); ok {
			prot, pok := cfBool(h["Protection"])
			uri, _ := concrete(h["ReportUri"])
			switch {
			case !pok:
				fin("XSSProtection.Protection is required")
			case !prot:
				hs = append(hs, cfHeader{"X-XSS-Protection", "0"})
			case cfTrue(h["ModeBlock"]) && uri != "":
				fin("XSSProtection sets both ModeBlock and ReportUri (CloudFront accepts one)")
			case cfTrue(h["ModeBlock"]):
				hs = append(hs, cfHeader{"X-XSS-Protection", "1; mode=block"})
			case uri != "":
				hs = append(hs, cfHeader{"X-XSS-Protection", "1; report=" + uri})
			default:
				hs = append(hs, cfHeader{"X-XSS-Protection", "1"})
			}
		}
	}
	if ch, ok := c["CustomHeadersConfig"].(map[string]any); ok {
		items, _ := ch["Items"].([]any)
		for i, it := range items {
			im, _ := it.(map[string]any)
			for _, k := range sortedKeys(im) {
				if k != "Header" && k != "Value" && k != "Override" {
					fin("CustomHeadersConfig.Items[%d].%s is not translatable", i, k)
				}
			}
			n, _ := concrete(im["Header"])
			v, _ := concrete(im["Value"])
			hs = append(hs, cfHeader{n, v})
		}
	}

	seen := map[string]bool{}
	for _, h := range hs {
		lc := strings.ToLower(h.name)
		switch {
		case !cfHeaderNameRe.MatchString(h.name):
			fin("response header name %q is not translatable — letters, digits and hyphens only", h.name)
		case cfServerHeaders[lc]:
			fin("response header %s is set by the site's server itself; adding it would duplicate it rather than replace it — refusing", h.name)
		case seen[lc]:
			fin("response header %s is set twice", h.name)
		case !cfHeaderValueRe.MatchString(h.value) || len(h.value) > 4096:
			fin("response header %s value %q is not translatable — 1-4096 printable ASCII characters without double quotes, backslashes or dollar signs (it is served verbatim by nginx)", h.name, h.value)
		}
		seen[lc] = true
	}
	return hs, notes, f
}

// ---- AWS::CertificateManager::Certificate -> the StaticSite's cert-manager TLS ----
//
// The viewer certificate of an in-stack distribution: the site's certificate for its Aliases is issued by
// the cluster's cert-manager ClusterIssuer, so this provisions nothing. A certificate no in-stack
// distribution uses (an ELB listener's, an API Gateway domain's) has no open-infra consumer and refuses.
func translateACMCertificate(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	_, _, f := cfCertificate(id, props)
	if ctx != nil && len(ctx.cloudFrontCertificateUsers(id)) == 0 {
		f = append(f, Finding{"Resource " + id, "an AWS::CertificateManager::Certificate translates only as the ViewerCertificate of an in-stack AWS::CloudFront::Distribution (the site's certificate is issued in-cluster by cert-manager for the distribution's Aliases); no included distribution references this one, and a standalone certificate (for a load balancer or an API domain) has no open-infra consumer"})
	}
	return nil, f
}

// cfCertificate validates an ACM certificate's properties and returns the names it covers (DomainName +
// SubjectAlternativeNames, when concrete) and its caveats.
func cfCertificate(id string, props map[string]any) (names, notes []string, f []Finding) {
	f = blockUnknownProps(id, props, map[string]bool{
		"DomainName": true, "SubjectAlternativeNames": true, "ValidationMethod": true, "DomainValidationOptions": true,
		"CertificateTransparencyLoggingPreference": true, "KeyAlgorithm": true, "Tags": true, "CertificateAuthorityArn": true,
	})
	if cfNonEmpty(props["CertificateAuthorityArn"]) {
		f = append(f, Finding{"Resource " + id, "CertificateAuthorityArn (a private-CA certificate) is not translatable — the site's certificate is issued by the cluster's openinfra-issuer, not a private CA you named"})
	}
	all := []string{}
	concreteNames := true
	if d, ok := concrete(props["DomainName"]); ok && d != "" {
		all = append(all, strings.ToLower(d))
	} else {
		concreteNames = false
		f = append(f, Finding{"Resource " + id, "AWS::CertificateManager::Certificate requires a concrete DomainName"})
	}
	for _, s := range cfStringList(props["SubjectAlternativeNames"]) {
		if _, ok := concrete(s); !ok {
			concreteNames = false
			continue
		}
		all = append(all, strings.ToLower(s))
	}
	if concreteNames {
		names = all
	}
	var dropped []string
	for _, k := range []string{"ValidationMethod", "DomainValidationOptions", "CertificateTransparencyLoggingPreference", "KeyAlgorithm", "Tags"} {
		if _, ok := props[k]; ok {
			dropped = append(dropped, k)
		}
	}
	msg := "certificate " + id + " is not requested from ACM — the site's certificate is issued in-cluster for the Aliases, so no DNS/email validation record is needed or created"
	if len(dropped) > 0 {
		msg += "; the template's " + strings.Join(dropped, "/") + " not applied (cert-manager's issuance and key defaults apply)"
	}
	return names, append(notes, msg), f
}

// cfUncovered returns the hosts a certificate's names don't cover (exact match, or a one-label
// *.domain wildcard). An unknown name set (a non-concrete SAN) covers everything — nothing to check.
func cfUncovered(names, hosts []string) []string {
	if names == nil {
		return nil
	}
	var out []string
	for _, h := range hosts {
		ok := false
		for _, n := range names {
			if n == h || (strings.HasPrefix(n, "*.") && strings.Count(h, ".") == strings.Count(n, ".") && strings.HasSuffix(h, n[1:])) {
				ok = true
				break
			}
		}
		if !ok {
			out = append(out, h)
		}
	}
	return out
}

// ---- the S3 bucket side: CloudFront read grants in the bucket policy ----

// cloudFrontBucketGrants filters the CloudFront read grants (OAC: Principal Service cloudfront.amazonaws.com;
// OAI: the identity's CanonicalUser / IAM ARN) out of a bucket's resolved policy document. A grant that an
// in-stack distribution serving this bucket honors is realized by that distribution's kind: StaticSite (its
// scoped reader), not stored as a MinIO policy MinIO couldn't resolve — so it is dropped with a note. A
// CloudFront statement that can't be honored that way refuses. Every other statement is left for the
// bucket's own public-principal rules. It returns the document unchanged when it holds no CloudFront
// statement, and nil when every statement was an honored grant.
func (c *stackCtx) cloudFrontBucketGrants(bucketID, policyID string, doc any) (any, []string, []Finding) {
	m, ok := doc.(map[string]any)
	if !ok || c == nil {
		return doc, nil, nil
	}
	var stmts []any
	switch s := m["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	var keep []any
	var f []Finding
	kinds := map[string]bool{}
	honored := 0
	var serving []string
	looked := false
	for i, s := range stmts {
		sm, _ := s.(map[string]any)
		kind := c.cloudFrontPrincipal(sm["Principal"])
		if kind == "" {
			keep = append(keep, s)
			continue
		}
		if !looked { // only a policy that names CloudFront pays for the distribution walk
			serving, looked = c.cloudFrontDistributionsServing(bucketID), true
		}
		if why := c.cloudFrontGrantProblem(sm, kind, serving); why != "" {
			f = append(f, Finding{"Resource " + policyID, fmt.Sprintf("BucketPolicy Statement %d %s", i, why)})
			continue
		}
		honored++
		kinds[strings.ToUpper(kind)] = true
	}
	if honored == 0 && len(f) == 0 {
		return doc, nil, nil
	}
	var notes []string
	if honored > 0 {
		names := make([]string, len(serving))
		for i, d := range serving {
			names[i] = c.name(d)
		}
		ks := make([]string, 0, len(kinds))
		for k := range kinds {
			ks = append(ks, k)
		}
		sortStrs(ks)
		notes = append(notes, fmt.Sprintf("BucketPolicy %s: %d statement(s) granting CloudFront read (%s) are realized by the kind: StaticSite serving this bucket (%s), which reads it with its own scoped MinIO credentials — they are not stored as a bucket policy (MinIO can't resolve a CloudFront principal), and the bucket stays private", policyID, honored, strings.Join(ks, "/"), strings.Join(names, ", ")))
	}
	if len(keep) == 0 {
		return nil, notes, f
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	out["Statement"] = keep
	return out, notes, f
}

// cloudFrontPrincipal classifies a bucket-policy Principal: "oac" (the cloudfront.amazonaws.com service),
// "oai" (an in-stack origin access identity), "oai-external" (an identity outside this stack), "mixed"
// (a CloudFront principal alongside others), or "" (not a CloudFront principal).
func (c *stackCtx) cloudFrontPrincipal(p any) string {
	pm, ok := p.(map[string]any)
	if !ok {
		return ""
	}
	cf, other, external := 0, 0, false
	kind := ""
	for k, v := range pm {
		for _, s := range cfStringList(v) {
			switch {
			case k == "Service" && s == "cloudfront.amazonaws.com":
				cf++
				kind = "oac"
			case k == "CanonicalUser":
				if id, attr, ok := cfPlaceholder(s); ok && attr == "S3CanonicalUserId" && c.isType(id, cfOAIType) {
					cf++
					kind = "oai"
				} else {
					other++
				}
			case k == "AWS" && cfOAIArnRe.MatchString(s):
				cf++
				kind = "oai"
				if id, attr, ok := cfPlaceholder(cfOAIArnRe.FindStringSubmatch(s)[1]); !ok || attr != "" || !c.isType(id, cfOAIType) {
					external = true
				}
			default:
				other++
			}
		}
	}
	switch {
	case cf == 0:
		return ""
	case other > 0 || cf > 1:
		return "mixed"
	case external:
		return "oai-external"
	}
	return kind
}

// cloudFrontGrantProblem returns why a CloudFront-principal statement can't be realized by the serving
// StaticSite, or "" when it can: an Allow of read actions, conditioned at most on aws:SourceArn naming an
// in-stack distribution (or aws:SourceAccount), on a bucket an included in-stack distribution serves.
func (c *stackCtx) cloudFrontGrantProblem(sm map[string]any, kind string, serving []string) string {
	switch kind {
	case "mixed":
		return "mixes a CloudFront principal with other principals — split it into a CloudFront read grant and a separate statement"
	case "oai-external":
		return "grants read to a CloudFront origin access identity outside this stack, which doesn't exist on open-infra"
	}
	if len(serving) == 0 {
		return "grants CloudFront read, but no included in-stack AWS::CloudFront::Distribution serves this bucket — nothing on open-infra would hold the grant"
	}
	if e, _ := concrete(sm["Effect"]); e != "Allow" {
		return "is a " + cfOr(e, "statement without an Effect") + " for a CloudFront principal, which has no open-infra form"
	}
	for _, k := range []string{"NotAction", "NotPrincipal", "NotResource"} {
		if _, ok := sm[k]; ok {
			return "uses " + k + " with a CloudFront principal, which has no open-infra form"
		}
	}
	for _, a := range cfStringList(sm["Action"]) {
		if a != "s3:GetObject" && a != "s3:ListBucket" {
			return "grants CloudFront " + a + " — only read (s3:GetObject / s3:ListBucket) is served by the static site"
		}
	}
	cond, _ := sm["Condition"].(map[string]any)
	for _, op := range sortedKeys(cond) {
		km, _ := cond[op].(map[string]any)
		for _, key := range sortedKeys(km) {
			val := km[key]
			switch strings.ToLower(key) {
			case "aws:sourceaccount":
				continue
			case "aws:sourcearn":
				if op != "StringEquals" && op != "StringLike" && op != "ArnEquals" && op != "ArnLike" {
					return "conditions on aws:SourceArn with " + op + ", which has no open-infra form"
				}
				for _, s := range cfStringList(val) {
					if d := cfRefIn(s); d == "" || !c.isType(d, cfDistributionType) || !c.includedID(d) {
						return "limits the grant (aws:SourceArn " + s + ") to a distribution that isn't an included one in this stack"
					}
				}
			default:
				return "conditions on " + key + ", which has no open-infra form for a CloudFront grant"
			}
		}
	}
	return ""
}

// ---- stack lookups ----

// cloudFrontOriginBucket resolves a (resolved) origin DomainName to the logical id of the INCLUDED in-stack
// AWS::S3::Bucket it names, or "" and why not.
func (c *stackCtx) cloudFrontOriginBucket(domain any) (string, string) {
	s, _ := domain.(string)
	m := cfOriginDomainRe.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Sprintf("DomainName %q is not an S3 REST endpoint of an in-stack bucket (use !GetAtt <Bucket>.RegionalDomainName, or ${Bucket}.s3.amazonaws.com) — an S3 website endpoint is a custom origin, and an out-of-stack bucket isn't managed by this stack", s)
	}
	id := ""
	switch {
	case m[1] != "" && m[4] != "": // <ref:Bucket>.s3…
		id = m[1]
	case m[2] != "" && m[4] == "": // <Bucket.RegionalDomainName>
		id = m[2]
	case m[3] != "" && m[4] != "": // literal-bucket-name.s3…
		for _, bid := range c.template.rawOrder {
			if c.isType(bid, "AWS::S3::Bucket") && c.includedID(bid) && s3BucketMinIOName(bid, c) == m[3] {
				id = bid
				break
			}
		}
		if id == "" {
			return "", fmt.Sprintf("DomainName %q names bucket %s, which is not an in-stack AWS::S3::Bucket — an out-of-stack bucket isn't managed by this stack", s, m[3])
		}
	default:
		return "", fmt.Sprintf("DomainName %q is not an S3 REST endpoint of an in-stack bucket (use !GetAtt <Bucket>.RegionalDomainName)", s)
	}
	if !c.isType(id, "AWS::S3::Bucket") {
		return "", fmt.Sprintf("DomainName %q references %s, which is not an AWS::S3::Bucket", s, id)
	}
	if !c.includedID(id) {
		return "", fmt.Sprintf("the origin bucket %s is excluded by its Condition", id)
	}
	return id, ""
}

// cloudFrontDistributionsServing returns the INCLUDED in-stack distributions whose (single) origin is
// bucketID, sorted — the StaticSites that hold the bucket's CloudFront read grant.
func (c *stackCtx) cloudFrontDistributionsServing(bucketID string) []string {
	var out []string
	for _, did := range c.template.rawOrder {
		if !c.isType(did, cfDistributionType) || !c.includedID(did) {
			continue
		}
		p, _ := c.resolveProps(did)
		dc, _ := p["DistributionConfig"].(map[string]any)
		for _, o := range cfAnyList(dc["Origins"]) {
			om, _ := o.(map[string]any)
			if b, _ := c.cloudFrontOriginBucket(om["DomainName"]); b == bucketID {
				out = append(out, did)
				break
			}
		}
	}
	sortStrs(out)
	return out
}

// cloudFrontCertificateUsers returns the INCLUDED in-stack distributions whose ViewerCertificate
// AcmCertificateArn references certID.
func (c *stackCtx) cloudFrontCertificateUsers(certID string) []string {
	var out []string
	for _, did := range c.template.rawOrder {
		if !c.isType(did, cfDistributionType) || !c.includedID(did) {
			continue
		}
		p, _ := c.resolveProps(did)
		dc, _ := p["DistributionConfig"].(map[string]any)
		vc, _ := dc["ViewerCertificate"].(map[string]any)
		if id, attr, ok := cfPlaceholder(vc["AcmCertificateArn"]); ok && attr == "" && id == certID {
			out = append(out, did)
		}
	}
	return out
}

// includedID reports whether in-stack resource `id` is active under its Condition.
func (c *stackCtx) includedID(id string) bool {
	res, ok := c.template.Resources[id]
	return ok && c.included(res)
}

// s3BucketMinIOName is the MinIO bucket an in-stack AWS::S3::Bucket becomes — its concrete BucketName,
// else the k8s-safe logical id (exactly what translateS3Bucket + the Bucket composition produce).
func s3BucketMinIOName(bucketID string, c *stackCtx) string {
	p, _ := c.resolveProps(bucketID)
	if n, ok := concrete(p["BucketName"]); ok && n != "" {
		return n
	}
	return c.name(bucketID)
}

// ---- Fn::GetAtt <Distribution>.DomainName ----

// cloudFrontGetAtt resolves Fn::GetAtt <Distribution>.DomainName to the hostname the site is served on —
// the distribution's first Alias (on AWS it is the generated *.cloudfront.net name, which has no analog;
// the alias is the name a client reaches the site by). The Aliases are resolved in a sandbox so their
// references don't leak into the caller's dependencies or findings. ok=false (the attribute stays a
// placeholder) for any other attribute, a conditioned-off distribution, or an alias that doesn't resolve.
func (r *resolver) cloudFrontGetAtt(id, attr string) (string, bool) {
	if attr != "DomainName" {
		return "", false
	}
	res, ok := r.t.Resources[id]
	if !ok || res.Type != cfDistributionType || (res.Condition != "" && !r.conds[res.Condition]) {
		return "", false
	}
	dc, _ := res.Properties["DistributionConfig"].(map[string]any)
	raw, has := dc["Aliases"]
	if !has || r.cfResolving[id] { // a self-referential alias can't resolve
		return "", false
	}
	if r.cfResolving == nil {
		r.cfResolving = map[string]bool{}
	}
	r.cfResolving[id] = true
	where, refs, nf := r.where, r.refs, len(r.findings)
	r.refs = map[string]bool{}
	v := r.resolve(raw)
	r.where, r.refs, r.findings = where, refs, r.findings[:nf]
	delete(r.cfResolving, id)
	aliases := cfStringList(v)
	if len(aliases) == 0 {
		return "", false
	}
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(aliases[0])), ".")
	return h, cfHostnameRe.MatchString(h)
}

// ---- small value helpers ----

// cfPlaceholder parses a resolver placeholder for an in-stack reference: <ref:X> -> (X, "", true) and
// <X.Attr> -> (X, Attr, true).
func cfPlaceholder(v any) (id, attr string, ok bool) {
	s, isStr := v.(string)
	if !isStr {
		return "", "", false
	}
	m := cfPlaceholderRe.FindStringSubmatch(s)
	switch {
	case m == nil:
		return "", "", false
	case m[1] != "":
		return m[1], "", true
	}
	return m[2], m[3], true
}

// cfRefIn returns the logical id of the first <ref:X> or <X.Id> reference embedded in s (an ARN built with
// !Sub/!Join around a !Ref), or "".
func cfRefIn(s string) string {
	if m := cfEmbeddedRefRe.FindStringSubmatch(s); m != nil {
		return m[1] + m[2]
	}
	return ""
}

// cfStringList flattens a resolved value to its string elements: a list, a single string, or (for a
// CommaDelimitedList parameter, which resolves to its raw string) a comma-separated string.
func cfStringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	case []any:
		for _, e := range t {
			if s := strings.TrimSpace(fmt.Sprint(e)); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

// cfAnyList returns v as a list (a non-list is empty).
func cfAnyList(v any) []any {
	l, _ := v.([]any)
	return l
}

// cfNonEmpty reports whether a resolved property carries a value: a non-empty string/list/map, a true
// bool, or (the legacy {Quantity, Items} shape) non-empty Items.
func cfNonEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case bool:
		return t
	case []any:
		return len(t) > 0
	case map[string]any:
		if items, ok := t["Items"]; ok {
			return cfNonEmpty(items)
		}
		if q, ok := t["Quantity"]; ok {
			return toInt(q) > 0
		}
		if en, ok := t["Enabled"]; ok {
			return cfTrue(en)
		}
		return len(t) > 0
	}
	return true
}

// cfBool reads a resolved boolean (a bool, or the string "true"/"false" from a templated value).
func cfBool(v any) (b, ok bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func cfTrue(v any) bool { b, _ := cfBool(v); return b }

// cfInt reads a resolved integer — a JSON number (float64), a Go int, or a numeric string from a
// templated value. ok=false for anything else (a placeholder, a fraction, an empty value).
func cfInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		if t == float64(int(t)) {
			return int(t), true
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}

func cfOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// cfSafePagePath reports whether p is a plain object path (no traversal, no nginx-significant characters).
func cfSafePagePath(p string) bool {
	if !cfPagePathRe.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
