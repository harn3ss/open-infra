// CloudFront reads of a stack's distribution and of the policies, origin access control and origin
// access identity it uses: GetDistribution, GetDistributionConfig, ListDistributions, GetCachePolicy,
// GetOriginRequestPolicy, GetResponseHeadersPolicy, GetOriginAccessControl and
// GetCloudFrontOriginAccessIdentity, in CloudFront's REST-XML shapes.
//
// A distribution is a kind: StaticSite the stack record lists under its Ref (cloudfront.go). Its
// configuration is the one the stack deployed — the template's DistributionConfig resolved as the stack
// resolved it (cfn.TemplateResources), so the ids it names are the ids of the stack's own policies and
// origin access control, and its ACM certificate's ARN — with Status Deployed once the stack is complete.
// A policy, an origin access control and an origin access identity provision nothing of their own (they
// compose into the distribution's StaticSite, or are accepted but not emulated: there is no edge cache),
// so the record keeps no entry for them; each is answered from its stack's template the same way, under the
// id its Ref gave the distribution. What the platform does with each is docs/cloudformation.md's.
//
// Authorization, as for the invalidations: cloudfront:<Action> on the resource (Distribution::<id>,
// CachePolicy::<id>, OriginRequestPolicy::<id>, ResponseHeadersPolicy::<id>, OriginAccessControl::<id>,
// OriginAccessIdentity::<id>; ListDistributions on Distribution::*), and for a User the coarse RBAC gate of
// what it is: get on the distribution's StaticSite, or — for a policy, which is part of a stack and nothing
// else — get on the stack, as DescribeStackResources needs. ListDistributions lists only the
// distributions whose StaticSite the caller may get.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The CloudFormation types of the configuration objects a distribution names.
const (
	cfCachePolicyType = "AWS::CloudFront::CachePolicy"
	cfORPType         = "AWS::CloudFront::OriginRequestPolicy"
	cfRHPType         = "AWS::CloudFront::ResponseHeadersPolicy"
	cfOACType         = "AWS::CloudFront::OriginAccessControl"
	cfOAIType         = "AWS::CloudFront::CloudFrontOriginAccessIdentity"
)

// cfResourceIDRe matches a policy's id (a UUID) or an origin access control's or identity's (E…).
var cfResourceIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// cfReadKinds maps a configuration read to its CloudFormation type, the data-plane resource type its
// authorization names, and the XML element it answers.
var cfReadKinds = map[string]struct{ typ, resType, elem string }{
	"GetCachePolicy":                    {cfCachePolicyType, "CachePolicy", "CachePolicy"},
	"GetOriginRequestPolicy":            {cfORPType, "OriginRequestPolicy", "OriginRequestPolicy"},
	"GetResponseHeadersPolicy":          {cfRHPType, "ResponseHeadersPolicy", "ResponseHeadersPolicy"},
	"GetOriginAccessControl":            {cfOACType, "OriginAccessControl", "OriginAccessControl"},
	"GetCloudFrontOriginAccessIdentity": {cfOAIType, "OriginAccessIdentity", "CloudFrontOriginAccessIdentity"},
}

// parseCFReadRoute matches the read paths after the API version (GET only).
func parseCFReadRoute(parts []string) (cfRoute, bool) {
	switch {
	case len(parts) == 1 && parts[0] == "distribution":
		return cfRoute{op: "ListDistributions"}, true
	case len(parts) == 2 && parts[0] == "distribution":
		return cfRoute{op: "GetDistribution", distID: parts[1]}, true
	case len(parts) == 3 && parts[0] == "distribution" && parts[2] == "config":
		return cfRoute{op: "GetDistributionConfig", distID: parts[1]}, true
	case len(parts) == 2 && parts[0] == "cache-policy":
		return cfRoute{op: "GetCachePolicy", resID: parts[1]}, true
	case len(parts) == 2 && parts[0] == "origin-request-policy":
		return cfRoute{op: "GetOriginRequestPolicy", resID: parts[1]}, true
	case len(parts) == 2 && parts[0] == "response-headers-policy":
		return cfRoute{op: "GetResponseHeadersPolicy", resID: parts[1]}, true
	case len(parts) == 2 && parts[0] == "origin-access-control":
		return cfRoute{op: "GetOriginAccessControl", resID: parts[1]}, true
	case len(parts) == 3 && parts[0] == "origin-access-identity" && parts[1] == "cloudfront":
		return cfRoute{op: "GetCloudFrontOriginAccessIdentity", resID: parts[2]}, true
	}
	return cfRoute{}, false
}

func cfReadOp(op string) bool {
	switch op {
	case "ListDistributions", "GetDistribution", "GetDistributionConfig":
		return true
	}
	_, ok := cfReadKinds[op]
	return ok
}

// cfStackResource is a template resource of a stack, with the stack it is in.
type cfStackResource struct {
	rec *cfn.StackRecord
	res cfn.TemplateResource
}

// stackRecords is every stack record.
func (h *cloudFrontHandler) stackRecords(ctx context.Context) ([]*cfn.StackRecord, error) {
	st := h.cfn.recs()
	list, err := st.client().List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cfn"})
	if err != nil {
		return nil, err
	}
	var out []*cfn.StackRecord
	for i := range list.Items {
		if !strings.HasPrefix(list.Items[i].GetName(), "cfn-stack-") {
			continue
		}
		if rec, ok := st.stackRecord(&list.Items[i]); ok {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// templateResources resolves the resources of the given types in rec's template as the stack resolved
// them (nil when the record keeps no template, or it no longer parses).
func templateResources(rec *cfn.StackRecord, all []*cfn.StackRecord, types ...string) []cfn.TemplateResource {
	if rec.Template == "" {
		return nil
	}
	res, err := cfn.TemplateResourcesOf(rec, exportsFrom(all, rec.Name).values, types...)
	if err != nil {
		return nil
	}
	return res
}

func (h *cloudFrontHandler) serveRead(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string, rt cfRoute) {
	ctx := r.Context()
	if h.cfn.cs == nil && claims.AssumedRole == "" {
		writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, "CloudFront authorization is not configured on this shim")
		return
	}
	switch rt.op {
	case "ListDistributions":
		h.listDistributions(w, r, claims, requestID)
		return
	case "GetDistribution", "GetDistributionConfig":
		// Authorized before anything about the id is looked at, as AWS does: a caller not allowed the
		// action is denied whether or not the distribution exists, or could.
		if ok, reason := decide(ctx, r, h.cfn.authz, claims, "cloudfront:"+rt.op, "Distribution", rt.distID,
			scopedDataPlaneOnly(ctx, r, h.cfn.authz, claims, "cloudfront:"+rt.op, "Distribution", rt.distID)); !ok {
			writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
			return
		}
		if !cfDistributionIDRe.MatchString(rt.distID) {
			writeCFError(w, http.StatusNotFound, "NoSuchDistribution", requestID, "The specified distribution does not exist.")
			return
		}
		recs, err := h.stackRecords(ctx)
		if err != nil {
			h.unavailable(w, requestID, err)
			return
		}
		for _, rec := range recs {
			d := distributionIn(rec, rt.distID, h.cfn.ns)
			if d == nil {
				continue
			}
			if !enforcing(ctx, h.cfn.authz, claims) {
				if allowed, reason := coarseOnly(ctx, h.cfn.cs, claims, "get", "openinfra.dev", "staticsites", d.ns, d.site)(); !allowed {
					writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
					return
				}
			}
			config := h.distributionConfigXML(rec, recs, rt.distID)
			w.Header().Set("ETag", cfETag(config))
			if rt.op == "GetDistributionConfig" {
				writeCFRawXML(w, requestID, `<DistributionConfig xmlns="`+cloudFrontXMLNS+`">`+config+`</DistributionConfig>`)
				return
			}
			writeCFRawXML(w, requestID, `<Distribution xmlns="`+cloudFrontXMLNS+`">`+h.distributionHead(ctx, rec, d, recs)+
				`<DistributionConfig>`+config+`</DistributionConfig></Distribution>`)
			return
		}
		writeCFError(w, http.StatusNotFound, "NoSuchDistribution", requestID, "The specified distribution does not exist.")
		return
	}
	kind := cfReadKinds[rt.op]
	if ok, reason := decide(ctx, r, h.cfn.authz, claims, "cloudfront:"+rt.op, kind.resType, rt.resID,
		scopedDataPlaneOnly(ctx, r, h.cfn.authz, claims, "cloudfront:"+rt.op, kind.resType, rt.resID)); !ok {
		writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
		return
	}
	if !cfResourceIDRe.MatchString(rt.resID) {
		writeCFError(w, http.StatusNotFound, "NoSuch"+kind.elem, requestID, "The specified "+kind.elem+" does not exist.")
		return
	}
	recs, err := h.stackRecords(ctx)
	if err != nil {
		h.unavailable(w, requestID, err)
		return
	}
	for _, rec := range recs {
		for _, tr := range templateResources(rec, recs, kind.typ) {
			if tr.Ref != rt.resID {
				continue
			}
			if allowed, reason := h.cfn.canDo(ctx, claims, "get", rec.Name); !allowed {
				writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
				return
			}
			body := cfConfigXML(rt.op, rec, tr)
			w.Header().Set("ETag", cfETag(body))
			writeCFRawXML(w, requestID, body)
			return
		}
	}
	writeCFError(w, http.StatusNotFound, "NoSuch"+kind.elem, requestID, "The specified "+kind.elem+" does not exist.")
}

func (h *cloudFrontHandler) unavailable(w http.ResponseWriter, requestID string, err error) {
	h.logger.Warn("cloudfront: reading the stack records failed", "error", err.Error())
	writeCFError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "The distribution could not be read; retry.")
}

// listDistributions lists the stacks' distributions in id order, paged by Marker (the last id answered) and
// MaxItems (default and ceiling 100), keeping those whose StaticSite the caller may get.
func (h *cloudFrontHandler) listDistributions(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	ctx := r.Context()
	if ok, reason := decide(ctx, r, h.cfn.authz, claims, "cloudfront:ListDistributions", "Distribution", "",
		dataPlaneOnly(ctx, r, h.cfn.authz, claims, "cloudfront:ListDistributions", "Distribution", "")); !ok {
		writeCFError(w, http.StatusForbidden, "AccessDenied", requestID, reason)
		return
	}
	q := r.URL.Query()
	max := 100
	if s := q.Get("MaxItems"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeCFError(w, http.StatusBadRequest, "InvalidArgument", requestID, "MaxItems must be a positive integer.")
			return
		}
		if n < max {
			max = n
		}
	}
	marker := q.Get("Marker")
	recs, err := h.stackRecords(ctx)
	if err != nil {
		h.unavailable(w, requestID, err)
		return
	}
	type entry struct {
		rec *cfn.StackRecord
		d   *cfDistribution
	}
	var all []entry
	for _, rec := range recs {
		for _, res := range rec.Resources {
			if res.Type == cloudFrontDistributionType && res.Kind == "StaticSite" && res.PhysicalID != "" && res.PhysicalID > marker {
				if d := distributionIn(rec, res.PhysicalID, h.cfn.ns); d != nil {
					all = append(all, entry{rec, d})
				}
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].d.id < all[j].d.id })
	var items strings.Builder
	n, last, truncated := 0, "", false
	// In enforce IAM policy allowed cloudfront:ListDistributions above: the account's distributions are
	// listed. In legacy only those whose StaticSite the caller may get.
	enforce := enforcing(ctx, h.cfn.authz, claims)
	for _, e := range all {
		if !enforce {
			if allowed, _ := coarseOnly(ctx, h.cfn.cs, claims, "get", "openinfra.dev", "staticsites", e.d.ns, e.d.site)(); !allowed {
				continue
			}
		}
		if n == max {
			truncated = true
			break
		}
		items.WriteString("<DistributionSummary>" + h.distributionHead(ctx, e.rec, e.d, recs) + h.summaryFields(e.rec, recs, e.d.id) + "</DistributionSummary>")
		n, last = n+1, e.d.id
	}
	var b strings.Builder
	b.WriteString(`<DistributionList xmlns="` + cloudFrontXMLNS + `"><Marker>` + xesc(marker) + `</Marker>`)
	if truncated {
		b.WriteString("<NextMarker>" + xesc(last) + "</NextMarker>") // the next page lists the ids after it
	}
	b.WriteString(fmt.Sprintf("<MaxItems>%d</MaxItems><IsTruncated>%t</IsTruncated><Quantity>%d</Quantity>", max, truncated, n))
	if n > 0 {
		b.WriteString("<Items>" + items.String() + "</Items>")
	}
	b.WriteString("</DistributionList>")
	writeCFRawXML(w, requestID, b.String())
}

// distributionHead is the Distribution / DistributionSummary fields that are not its configuration.
func (h *cloudFrontHandler) distributionHead(ctx context.Context, rec *cfn.StackRecord, d *cfDistribution, recs []*cfn.StackRecord) string {
	status := "InProgress"
	if strings.HasSuffix(rec.Status, "_COMPLETE") && !strings.HasPrefix(rec.Status, "DELETE") && !strings.Contains(rec.Status, "ROLLBACK") {
		status = "Deployed"
	}
	inProgress := 0
	if list, err := h.load(ctx, d); err == nil {
		for _, inv := range list {
			if inv.Status != "Completed" {
				inProgress++
			}
		}
	}
	domain := ""
	for _, tr := range templateResources(rec, recs, cloudFrontDistributionType) {
		if tr.Ref == d.id {
			domain = tr.Attrs["DomainName"]
		}
	}
	if domain == "" {
		domain = h.siteDomain(rec, d)
	}
	return "<Id>" + xesc(d.id) + "</Id><ARN>" + xesc("arn:aws:cloudfront::"+h.cfn.account+":distribution/"+d.id) + "</ARN>" +
		"<Status>" + status + "</Status><LastModifiedTime>" + xesc(cfRecordTime(rec.UpdatedAt, rec.CreatedAt)) + "</LastModifiedTime>" +
		fmt.Sprintf("<InProgressInvalidationBatches>%d</InProgressInvalidationBatches>", inProgress) +
		"<DomainName>" + xesc(domain) + "</DomainName>" +
		"<ActiveTrustedSigners><Enabled>false</Enabled><Quantity>0</Quantity></ActiveTrustedSigners>" +
		"<ActiveTrustedKeyGroups><Enabled>false</Enabled><Quantity>0</Quantity></ActiveTrustedKeyGroups>"
}

// summaryFields are the configuration fields a DistributionSummary carries beside its head.
func (h *cloudFrontHandler) summaryFields(rec *cfn.StackRecord, recs []*cfn.StackRecord, id string) string {
	dc := h.deployedConfig(rec, recs, id)
	return cfAliasesXML(dc) + cfOriginsXML(dc) + cfDefaultCacheBehaviorXML(dc) + cfCustomErrorsXML(dc) +
		"<Comment>" + xesc(fnStr(dc["Comment"])) + "</Comment><PriceClass>" + xesc(cfOrDefault(fnStr(dc["PriceClass"]), "PriceClass_All")) + "</PriceClass>" +
		"<Enabled>true</Enabled>" + cfViewerCertificateXML(dc) +
		"<WebACLId></WebACLId><HttpVersion>" + xesc(cfOrDefault(fnStr(dc["HttpVersion"]), "http2")) + "</HttpVersion>" +
		"<IsIPV6Enabled>" + strconv.FormatBool(fnBool(dc["IPV6Enabled"])) + "</IsIPV6Enabled><Staging>false</Staging>"
}

// siteDomain is the StaticSite's primary hostname, as recorded.
func (h *cloudFrontHandler) siteDomain(rec *cfn.StackRecord, d *cfDistribution) string {
	for _, res := range rec.Resources {
		if res.Type == cloudFrontDistributionType && res.Name == d.site {
			return fnStr(res.Spec["domain"])
		}
	}
	return ""
}

// deployedConfig is the distribution's DistributionConfig as the stack resolved it; one whose template no
// longer resolves is described from its StaticSite (its hostnames, index and error documents).
func (h *cloudFrontHandler) deployedConfig(rec *cfn.StackRecord, recs []*cfn.StackRecord, id string) map[string]any {
	for _, tr := range templateResources(rec, recs, cloudFrontDistributionType) {
		if tr.Ref == id {
			if dc, ok := tr.Properties["DistributionConfig"].(map[string]any); ok {
				return dc
			}
		}
	}
	dc := map[string]any{}
	for _, res := range rec.Resources {
		if res.Type != cloudFrontDistributionType || res.PhysicalID != id {
			continue
		}
		aliases := []any{res.Spec["domain"]}
		if more, ok := res.Spec["domains"].([]any); ok {
			aliases = append(aliases, more...)
		}
		dc["Aliases"] = aliases
		dc["DefaultRootObject"] = res.Spec["indexDocument"]
		dc["Origins"] = []any{map[string]any{"Id": fnStr(res.Spec["bucket"]), "DomainName": fnStr(res.Spec["bucket"]) + ".s3.amazonaws.com"}}
		dc["DefaultCacheBehavior"] = map[string]any{"TargetOriginId": fnStr(res.Spec["bucket"]), "ViewerProtocolPolicy": "redirect-to-https"}
		if spa, _ := res.Spec["spa"].(bool); spa {
			dc["CustomErrorResponses"] = []any{
				map[string]any{"ErrorCode": 403, "ResponseCode": 200, "ResponsePagePath": "/" + strings.TrimPrefix(fnStr(res.Spec["indexDocument"]), "/")},
				map[string]any{"ErrorCode": 404, "ResponseCode": 200, "ResponsePagePath": "/" + strings.TrimPrefix(fnStr(res.Spec["indexDocument"]), "/")},
			}
		}
	}
	return dc
}

// distributionConfigXML is the DistributionConfig body (without its element).
func (h *cloudFrontHandler) distributionConfigXML(rec *cfn.StackRecord, recs []*cfn.StackRecord, id string) string {
	dc := h.deployedConfig(rec, recs, id)
	return "<CallerReference>" + xesc(rec.Name+"/"+id) + "</CallerReference>" + cfAliasesXML(dc) +
		"<DefaultRootObject>" + xesc(fnStr(dc["DefaultRootObject"])) + "</DefaultRootObject>" +
		cfOriginsXML(dc) + cfDefaultCacheBehaviorXML(dc) + cfCustomErrorsXML(dc) +
		"<Comment>" + xesc(fnStr(dc["Comment"])) + "</Comment>" +
		"<PriceClass>" + xesc(cfOrDefault(fnStr(dc["PriceClass"]), "PriceClass_All")) + "</PriceClass>" +
		"<Enabled>true</Enabled>" + cfViewerCertificateXML(dc) +
		"<HttpVersion>" + xesc(cfOrDefault(fnStr(dc["HttpVersion"]), "http2")) + "</HttpVersion>" +
		"<IsIPV6Enabled>" + strconv.FormatBool(fnBool(dc["IPV6Enabled"])) + "</IsIPV6Enabled>"
}

func cfAliasesXML(dc map[string]any) string {
	names := cfStrings(dc["Aliases"])
	var b strings.Builder
	b.WriteString(fmt.Sprintf("<Aliases><Quantity>%d</Quantity>", len(names)))
	if len(names) > 0 {
		b.WriteString("<Items>")
		for _, n := range names {
			b.WriteString("<CNAME>" + xesc(n) + "</CNAME>")
		}
		b.WriteString("</Items>")
	}
	b.WriteString("</Aliases>")
	return b.String()
}

func cfOriginsXML(dc map[string]any) string {
	origins, _ := dc["Origins"].([]any)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("<Origins><Quantity>%d</Quantity><Items>", len(origins)))
	for _, o := range origins {
		m, _ := o.(map[string]any)
		b.WriteString("<Origin><Id>" + xesc(fnStr(m["Id"])) + "</Id><DomainName>" + xesc(fnStr(m["DomainName"])) + "</DomainName>" +
			"<OriginPath></OriginPath><CustomHeaders><Quantity>0</Quantity></CustomHeaders>")
		oai := ""
		if s3, ok := m["S3OriginConfig"].(map[string]any); ok {
			oai = fnStr(s3["OriginAccessIdentity"])
		}
		b.WriteString("<S3OriginConfig><OriginAccessIdentity>" + xesc(oai) + "</OriginAccessIdentity></S3OriginConfig>")
		b.WriteString("<ConnectionAttempts>3</ConnectionAttempts><ConnectionTimeout>10</ConnectionTimeout>")
		if oac := fnStr(m["OriginAccessControlId"]); oac != "" {
			b.WriteString("<OriginAccessControlId>" + xesc(oac) + "</OriginAccessControlId>")
		}
		b.WriteString("</Origin>")
	}
	b.WriteString("</Items></Origins>")
	return b.String()
}

func cfDefaultCacheBehaviorXML(dc map[string]any) string {
	m, _ := dc["DefaultCacheBehavior"].(map[string]any)
	var b strings.Builder
	b.WriteString("<DefaultCacheBehavior><TargetOriginId>" + xesc(fnStr(m["TargetOriginId"])) + "</TargetOriginId>" +
		"<TrustedSigners><Enabled>false</Enabled><Quantity>0</Quantity></TrustedSigners>" +
		"<TrustedKeyGroups><Enabled>false</Enabled><Quantity>0</Quantity></TrustedKeyGroups>" +
		"<ViewerProtocolPolicy>" + xesc(cfOrDefault(fnStr(m["ViewerProtocolPolicy"]), "redirect-to-https")) + "</ViewerProtocolPolicy>" +
		"<AllowedMethods><Quantity>2</Quantity><Items><Method>HEAD</Method><Method>GET</Method></Items>" +
		"<CachedMethods><Quantity>2</Quantity><Items><Method>HEAD</Method><Method>GET</Method></Items></CachedMethods></AllowedMethods>" +
		"<Compress>" + strconv.FormatBool(fnBool(m["Compress"])) + "</Compress>")
	for _, k := range []string{"CachePolicyId", "OriginRequestPolicyId", "ResponseHeadersPolicyId"} {
		if v := fnStr(m[k]); v != "" {
			b.WriteString("<" + k + ">" + xesc(v) + "</" + k + ">")
		}
	}
	b.WriteString("</DefaultCacheBehavior>")
	return b.String()
}

func cfCustomErrorsXML(dc map[string]any) string {
	l, _ := dc["CustomErrorResponses"].([]any)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("<CustomErrorResponses><Quantity>%d</Quantity>", len(l)))
	if len(l) > 0 {
		b.WriteString("<Items>")
		for _, e := range l {
			m, _ := e.(map[string]any)
			b.WriteString("<CustomErrorResponse><ErrorCode>" + xesc(fmt.Sprint(m["ErrorCode"])) + "</ErrorCode>")
			if p := fnStr(m["ResponsePagePath"]); p != "" {
				b.WriteString("<ResponsePagePath>" + xesc(p) + "</ResponsePagePath>")
			}
			if c, ok := m["ResponseCode"]; ok {
				b.WriteString("<ResponseCode>" + xesc(fmt.Sprint(c)) + "</ResponseCode>")
			}
			b.WriteString("</CustomErrorResponse>")
		}
		b.WriteString("</Items>")
	}
	b.WriteString("</CustomErrorResponses>")
	return b.String()
}

func cfViewerCertificateXML(dc map[string]any) string {
	vc, _ := dc["ViewerCertificate"].(map[string]any)
	arn := fnStr(vc["AcmCertificateArn"])
	if arn == "" {
		return "<ViewerCertificate><CloudFrontDefaultCertificate>true</CloudFrontDefaultCertificate><MinimumProtocolVersion>TLSv1</MinimumProtocolVersion><CertificateSource>cloudfront</CertificateSource></ViewerCertificate>"
	}
	return "<ViewerCertificate><CloudFrontDefaultCertificate>false</CloudFrontDefaultCertificate><ACMCertificateArn>" + xesc(arn) + "</ACMCertificateArn>" +
		"<SSLSupportMethod>" + xesc(cfOrDefault(fnStr(vc["SslSupportMethod"]), "sni-only")) + "</SSLSupportMethod>" +
		"<MinimumProtocolVersion>" + xesc(cfOrDefault(fnStr(vc["MinimumProtocolVersion"]), "TLSv1.2_2021")) + "</MinimumProtocolVersion>" +
		"<Certificate>" + xesc(arn) + "</Certificate><CertificateSource>acm</CertificateSource></ViewerCertificate>"
}

// cfConfigXML answers a configuration read: the object's element with its id, last-modified time and
// config, CloudFormation's property shapes in CloudFront's XML ones.
func cfConfigXML(op string, rec *cfn.StackRecord, tr cfn.TemplateResource) string {
	kind := cfReadKinds[op]
	head := `<` + kind.elem + ` xmlns="` + cloudFrontXMLNS + `"><Id>` + xesc(tr.Ref) + `</Id>`
	modified := "<LastModifiedTime>" + xesc(cfRecordTime(rec.UpdatedAt, rec.CreatedAt)) + "</LastModifiedTime>"
	tail := `</` + kind.elem + `>`
	switch op {
	case "GetCachePolicy":
		c, _ := tr.Properties["CachePolicyConfig"].(map[string]any)
		p, _ := c["ParametersInCacheKeyAndForwardedToOrigin"].(map[string]any)
		body := "<Comment>" + xesc(fnStr(c["Comment"])) + "</Comment><Name>" + xesc(fnStr(c["Name"])) + "</Name>" +
			"<DefaultTTL>" + xesc(cfNum(c["DefaultTTL"], "86400")) + "</DefaultTTL><MaxTTL>" + xesc(cfNum(c["MaxTTL"], "31536000")) + "</MaxTTL>" +
			"<MinTTL>" + xesc(cfNum(c["MinTTL"], "0")) + "</MinTTL>" +
			"<ParametersInCacheKeyAndForwardedToOrigin><EnableAcceptEncodingGzip>" + strconv.FormatBool(fnBool(p["EnableAcceptEncodingGzip"])) + "</EnableAcceptEncodingGzip>" +
			"<EnableAcceptEncodingBrotli>" + strconv.FormatBool(fnBool(p["EnableAcceptEncodingBrotli"])) + "</EnableAcceptEncodingBrotli>" +
			cfForwarded(p) + "</ParametersInCacheKeyAndForwardedToOrigin>"
		return head + modified + "<CachePolicyConfig>" + body + "</CachePolicyConfig>" + tail
	case "GetOriginRequestPolicy":
		c, _ := tr.Properties["OriginRequestPolicyConfig"].(map[string]any)
		body := "<Comment>" + xesc(fnStr(c["Comment"])) + "</Comment><Name>" + xesc(fnStr(c["Name"])) + "</Name>" + cfForwarded(c)
		return head + modified + "<OriginRequestPolicyConfig>" + body + "</OriginRequestPolicyConfig>" + tail
	case "GetResponseHeadersPolicy":
		c, _ := tr.Properties["ResponseHeadersPolicyConfig"].(map[string]any)
		var b strings.Builder
		b.WriteString("<Comment>" + xesc(fnStr(c["Comment"])) + "</Comment><Name>" + xesc(fnStr(c["Name"])) + "</Name>")
		if s, ok := c["SecurityHeadersConfig"].(map[string]any); ok {
			b.WriteString("<SecurityHeadersConfig>" + cfScalarsXML(s) + "</SecurityHeadersConfig>")
		}
		if ch, ok := c["CustomHeadersConfig"].(map[string]any); ok {
			items, _ := ch["Items"].([]any)
			b.WriteString(fmt.Sprintf("<CustomHeadersConfig><Quantity>%d</Quantity>", len(items)))
			if len(items) > 0 {
				b.WriteString("<Items>")
				for _, it := range items {
					m, _ := it.(map[string]any)
					b.WriteString("<ResponseHeadersPolicyCustomHeader><Header>" + xesc(fnStr(m["Header"])) + "</Header><Value>" + xesc(fnStr(m["Value"])) +
						"</Value><Override>" + strconv.FormatBool(fnBool(m["Override"])) + "</Override></ResponseHeadersPolicyCustomHeader>")
				}
				b.WriteString("</Items>")
			}
			b.WriteString("</CustomHeadersConfig>")
		}
		return head + modified + "<ResponseHeadersPolicyConfig>" + b.String() + "</ResponseHeadersPolicyConfig>" + tail
	case "GetOriginAccessControl":
		c, _ := tr.Properties["OriginAccessControlConfig"].(map[string]any)
		return head + "<OriginAccessControlConfig>" + cfScalarsXML(c) + "</OriginAccessControlConfig>" + tail
	case "GetCloudFrontOriginAccessIdentity":
		c, _ := tr.Properties["CloudFrontOriginAccessIdentityConfig"].(map[string]any)
		return head + "<S3CanonicalUserId>" + xesc(tr.Attrs["S3CanonicalUserId"]) + "</S3CanonicalUserId>" +
			"<CloudFrontOriginAccessIdentityConfig><CallerReference>" + xesc(rec.Name+"/"+tr.LogicalID) + "</CallerReference>" +
			"<Comment>" + xesc(fnStr(c["Comment"])) + "</Comment></CloudFrontOriginAccessIdentityConfig>" + tail
	}
	return head + tail
}

// cfForwarded is a policy's HeadersConfig, CookiesConfig and QueryStringsConfig, in CloudFront's shape (a
// list is Quantity + Items).
func cfForwarded(p map[string]any) string {
	var b strings.Builder
	for _, f := range []struct{ cfg, behavior, list, wrap string }{
		{"HeadersConfig", "HeaderBehavior", "Headers", "Headers"},
		{"CookiesConfig", "CookieBehavior", "Cookies", "Cookies"},
		{"QueryStringsConfig", "QueryStringBehavior", "QueryStrings", "QueryStrings"},
	} {
		c, _ := p[f.cfg].(map[string]any)
		b.WriteString("<" + f.cfg + "><" + f.behavior + ">" + xesc(cfOrDefault(fnStr(c[f.behavior]), "none")) + "</" + f.behavior + ">")
		if names := cfStrings(c[f.list]); len(names) > 0 {
			b.WriteString(fmt.Sprintf("<%s><Quantity>%d</Quantity><Items>", f.wrap, len(names)))
			for _, n := range names {
				b.WriteString("<Name>" + xesc(n) + "</Name>")
			}
			b.WriteString("</Items></" + f.wrap + ">")
		}
		b.WriteString("</" + f.cfg + ">")
	}
	return b.String()
}

// cfScalarsXML writes a CloudFormation property object whose CloudFront XML form has the same element names
// (nested objects of scalars), in key order.
func cfScalarsXML(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := m[k].(type) {
		case map[string]any:
			b.WriteString("<" + k + ">" + cfScalarsXML(v) + "</" + k + ">")
		case nil:
		default:
			b.WriteString("<" + k + ">" + xesc(fmt.Sprint(v)) + "</" + k + ">")
		}
	}
	return b.String()
}

func cfStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		if s := fnStr(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cfNum(v any, def string) string {
	if v == nil {
		return def
	}
	return fmt.Sprint(v)
}

func fnBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true"
	}
	return false
}

func cfOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// cfRecordTime is a record time in CloudFront's form (RFC 3339, UTC); the first that parses.
func cfRecordTime(ts ...string) string {
	for _, s := range ts {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	return time.Unix(0, 0).UTC().Format("2006-01-02T15:04:05.000Z")
}

// cfETag is an object's version tag: a hash of what it answers (it changes when the configuration does).
func cfETag(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "E" + strings.ToUpper(hex.EncodeToString(sum[:]))[:13]
}

func writeCFRawXML(w http.ResponseWriter, requestID, body string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + body))
}
