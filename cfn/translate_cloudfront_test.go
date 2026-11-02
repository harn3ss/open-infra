package cfn

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// cfSiteTemplate is the CloudFront static-site subset in full: a private bucket + OAC + the bucket policy
// granting CloudFront read + an in-stack ACM certificate + a response headers policy + a distribution
// with SPA 403/404 fallback on two Aliases, plus an SSM parameter consuming GetAtt DomainName. Built as
// a Go map (and marshaled to JSON, which the engine parses as a template) so each refusal case can
// mutate exactly one property.
func cfSiteTemplate() map[string]any {
	ref := func(id string) map[string]any { return map[string]any{"Ref": id} }
	getAtt := func(id, attr string) map[string]any { return map[string]any{"Fn::GetAtt": []any{id, attr}} }
	sub := func(s string) map[string]any { return map[string]any{"Fn::Sub": s} }
	return map[string]any{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Parameters": map[string]any{
			"SiteDomain": map[string]any{"Type": "String", "Default": "app.example.com"},
		},
		"Resources": map[string]any{
			"SiteBucket": map[string]any{"Type": "AWS::S3::Bucket", "Properties": map[string]any{
				"BucketName":              "example-site-assets",
				"VersioningConfiguration": map[string]any{"Status": "Enabled"},
				"PublicAccessBlockConfiguration": map[string]any{
					"BlockPublicAcls": true, "BlockPublicPolicy": true, "IgnorePublicAcls": true, "RestrictPublicBuckets": true,
				},
			}},
			"SiteOAC": map[string]any{"Type": "AWS::CloudFront::OriginAccessControl", "Properties": map[string]any{
				"OriginAccessControlConfig": map[string]any{
					"Name": "site-oac", "OriginAccessControlOriginType": "s3", "SigningBehavior": "always", "SigningProtocol": "sigv4",
				},
			}},
			"SiteBucketPolicy": map[string]any{"Type": "AWS::S3::BucketPolicy", "Properties": map[string]any{
				"Bucket": ref("SiteBucket"),
				"PolicyDocument": map[string]any{
					"Version": "2012-10-17",
					"Statement": []any{map[string]any{
						"Sid":       "AllowCloudFrontRead",
						"Effect":    "Allow",
						"Principal": map[string]any{"Service": "cloudfront.amazonaws.com"},
						"Action":    "s3:GetObject",
						"Resource":  sub("${SiteBucket.Arn}/*"),
						"Condition": map[string]any{"StringEquals": map[string]any{
							"AWS:SourceArn": sub("arn:aws:cloudfront::${AWS::AccountId}:distribution/${SiteDistribution}"),
						}},
					}},
				},
			}},
			"SiteCertificate": map[string]any{"Type": "AWS::CertificateManager::Certificate", "Properties": map[string]any{
				"DomainName":              ref("SiteDomain"),
				"SubjectAlternativeNames": []any{sub("www.${SiteDomain}")},
				"ValidationMethod":        "DNS",
			}},
			"SecurityHeaders": map[string]any{"Type": "AWS::CloudFront::ResponseHeadersPolicy", "Properties": map[string]any{
				"ResponseHeadersPolicyConfig": map[string]any{
					"Name": "site-security-headers",
					"SecurityHeadersConfig": map[string]any{
						"StrictTransportSecurity": map[string]any{"AccessControlMaxAgeSec": 63072000, "IncludeSubdomains": true, "Preload": true, "Override": true},
						"ContentTypeOptions":      map[string]any{"Override": true},
						"FrameOptions":            map[string]any{"FrameOption": "DENY", "Override": true},
						"ReferrerPolicy":          map[string]any{"ReferrerPolicy": "strict-origin-when-cross-origin", "Override": true},
						"ContentSecurityPolicy":   map[string]any{"ContentSecurityPolicy": "default-src 'self'; img-src 'self' data:", "Override": true},
						"XSSProtection":           map[string]any{"Protection": true, "ModeBlock": true, "Override": true},
					},
					"CustomHeadersConfig": map[string]any{"Items": []any{
						map[string]any{"Header": "Permissions-Policy", "Value": "camera=(), microphone=()", "Override": true},
					}},
				},
			}},
			"SiteDistribution": map[string]any{"Type": "AWS::CloudFront::Distribution", "Properties": map[string]any{
				"DistributionConfig": map[string]any{
					"Enabled":           true,
					"Comment":           "example SPA",
					"Aliases":           []any{ref("SiteDomain"), sub("www.${SiteDomain}")},
					"DefaultRootObject": "index.html",
					"HttpVersion":       "http2",
					"PriceClass":        "PriceClass_100",
					"IPV6Enabled":       true,
					"Origins": []any{map[string]any{
						"Id":                    "s3-site",
						"DomainName":            getAtt("SiteBucket", "RegionalDomainName"),
						"S3OriginConfig":        map[string]any{"OriginAccessIdentity": ""},
						"OriginAccessControlId": getAtt("SiteOAC", "Id"),
					}},
					"DefaultCacheBehavior": map[string]any{
						"TargetOriginId":          "s3-site",
						"ViewerProtocolPolicy":    "redirect-to-https",
						"AllowedMethods":          []any{"GET", "HEAD", "OPTIONS"},
						"CachedMethods":           []any{"GET", "HEAD"},
						"Compress":                true,
						"CachePolicyId":           "658327ea-f89d-4fab-a63d-7e88639e58f6", // managed CachingOptimized
						"ResponseHeadersPolicyId": ref("SecurityHeaders"),
					},
					"CustomErrorResponses": []any{
						map[string]any{"ErrorCode": 403, "ResponseCode": 200, "ResponsePagePath": "/index.html", "ErrorCachingMinTTL": 10},
						map[string]any{"ErrorCode": 404, "ResponseCode": 200, "ResponsePagePath": "/index.html"},
					},
					"ViewerCertificate": map[string]any{
						"AcmCertificateArn":      ref("SiteCertificate"),
						"SslSupportMethod":       "sni-only",
						"MinimumProtocolVersion": "TLSv1.2_2021",
					},
				},
			}},
			"SiteUrl": map[string]any{"Type": "AWS::SSM::Parameter", "Properties": map[string]any{
				"Name":  "/example/site/url",
				"Type":  "String",
				"Value": sub("https://${SiteDistribution.DomainName}"),
			}},
		},
		"Outputs": map[string]any{
			"DistributionId":     map[string]any{"Value": ref("SiteDistribution")},
			"DistributionDomain": map[string]any{"Value": getAtt("SiteDistribution", "DomainName")},
		},
	}
}

func cfJSON(t *testing.T, tmpl map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatalf("marshal template: %v", err)
	}
	return b
}

// cfRes / cfDC / cfDCB / cfOrigin0 reach into the template map for a mutation.
func cfRes(tmpl map[string]any, id string) map[string]any {
	return tmpl["Resources"].(map[string]any)[id].(map[string]any)
}
func cfProps(tmpl map[string]any, id string) map[string]any {
	return cfRes(tmpl, id)["Properties"].(map[string]any)
}
func cfDC(tmpl map[string]any) map[string]any {
	return cfProps(tmpl, "SiteDistribution")["DistributionConfig"].(map[string]any)
}
func cfDCB(tmpl map[string]any) map[string]any {
	return cfDC(tmpl)["DefaultCacheBehavior"].(map[string]any)
}
func cfOrigin0(tmpl map[string]any) map[string]any {
	return cfDC(tmpl)["Origins"].([]any)[0].(map[string]any)
}
func cfRHPConfig(tmpl map[string]any) map[string]any {
	return cfProps(tmpl, "SecurityHeaders")["ResponseHeadersPolicyConfig"].(map[string]any)
}

func cfBuilt(t *testing.T, data []byte) map[string]builtResource {
	t.Helper()
	built, err := buildManifests(data, DeployOptions{StackName: "site", Namespace: "web"})
	if err != nil {
		t.Fatalf("buildManifests refused the happy path: %v", err)
	}
	out := map[string]builtResource{}
	for _, b := range built {
		out[b.res.LogicalID] = b
	}
	return out
}

func cfHasCaveat(cavs []string, sub string) bool {
	for _, c := range cavs {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// The happy path: plan is PROVISIONABLE (with caveats — the mappings are partial), every resource is
// create-deployable, and the distribution becomes exactly this kind: StaticSite over the template's
// bucket, with the SPA fallback, both Aliases, the response headers, and TLS.
func TestCloudFront_SiteSubset_Provisionable(t *testing.T) {
	data := cfJSON(t, cfSiteTemplate())
	p := mustPlan(t, data, nil, "site")
	if p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict = %s, want PROVISIONABLE_WITH_CAVEATS; blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	for _, r := range p.Resources {
		if !r.Deployable {
			t.Errorf("%s (%s) must be create-deployable", r.LogicalID, r.CFNType)
		}
	}
	if idx(p.Order, "SiteBucket") > idx(p.Order, "SiteDistribution") {
		t.Errorf("the bucket must be provisioned before the distribution's StaticSite: %v", p.Order)
	}

	built := cfBuilt(t, data)
	site, ok := built["SiteDistribution"]
	if !ok {
		t.Fatalf("no StaticSite built for the distribution; built: %v", built)
	}
	if site.res.Kind != "StaticSite" || site.res.APIVersion != "openinfra.dev/v1" || site.res.Name != "site-sitedistribution" {
		t.Fatalf("bad manifest head: %+v", site.res)
	}
	want := map[string]any{
		"domain":        "app.example.com",
		"domains":       []any{"www.app.example.com"},
		"bucket":        "example-site-assets",
		"tls":           true,
		"spa":           true,
		"indexDocument": "index.html",
		"responseHeaders": []any{
			map[string]any{"name": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"},
			map[string]any{"name": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data:"},
			map[string]any{"name": "X-Content-Type-Options", "value": "nosniff"},
			map[string]any{"name": "X-Frame-Options", "value": "DENY"},
			map[string]any{"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
			map[string]any{"name": "X-XSS-Protection", "value": "1; mode=block"},
			map[string]any{"name": "Permissions-Policy", "value": "camera=(), microphone=()"},
		},
	}
	if !reflect.DeepEqual(site.res.Spec, want) {
		gotJ, _ := json.MarshalIndent(site.res.Spec, "", "  ")
		wantJ, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("StaticSite spec mismatch\n got: %s\nwant: %s", gotJ, wantJ)
	}
	// Every accepted-but-not-emulated property is in the fidelity summary.
	for _, c := range []string{
		"edge caching is not emulated",
		"CachePolicyId/CachedMethods/Compress", // the caching group, in template-key order
		"PriceClass/HttpVersion/IPV6Enabled/Comment have no open-infra effect",
		"ViewerProtocolPolicy redirect-to-https: the site answers on HTTPS only",
		"openinfra-issuer",
		"MinimumProtocolVersion TLSv1.2_2021",
		"certificate SiteCertificate is not requested from ACM",
		"origin access (OAC) is realized by the site's own scoped MinIO credentials",
		"CustomErrorResponses 403/404 -> /index.html (200) map to SPA history fallback",
		"ErrorCachingMinTTL is not emulated",
		"S3 object metadata",
		"AllowedMethods includes OPTIONS",
		"Fn::GetAtt SiteDistribution.DomainName resolves to app.example.com",
		"response headers Strict-Transport-Security, Content-Security-Policy",
	} {
		if !cfHasCaveat(site.cav, c) {
			t.Errorf("StaticSite caveats missing %q; got:\n  %s", c, strings.Join(site.cav, "\n  "))
		}
	}

	// The bucket stays a kind: Bucket; its CloudFront grant is realized by the site, not stored.
	bucket := built["SiteBucket"]
	if bucket.res.Kind != "Bucket" || bucket.res.Spec["bucketName"] != "example-site-assets" {
		t.Fatalf("bucket should stay a kind: Bucket: %+v", bucket.res)
	}
	if _, has := bucket.res.Spec["policy"]; has {
		t.Fatalf("a CloudFront-only bucket policy must not be stored as a MinIO policy, got %v", bucket.res.Spec["policy"])
	}
	if !cfHasCaveat(bucket.cav, "granting CloudFront read (OAC) are realized by the kind: StaticSite serving this bucket (site-sitedistribution)") {
		t.Errorf("bucket caveats should explain the realized grant; got:\n  %s", strings.Join(bucket.cav, "\n  "))
	}
	// OAC / certificate / headers policy / bucket policy provision nothing on their own.
	for _, id := range []string{"SiteOAC", "SiteCertificate", "SecurityHeaders", "SiteBucketPolicy"} {
		if _, has := built[id]; has {
			t.Errorf("%s must compose into the site, not provision on its own", id)
		}
	}
	// GetAtt DomainName resolves to the site's primary hostname for a consumer.
	if v := built["SiteUrl"].res.Spec["value"]; v != "https://app.example.com" {
		t.Errorf("SSM parameter consuming GetAtt DomainName = %v, want https://app.example.com", v)
	}
}

// Deploy applies the bucket before the StaticSite (dependency order) and records the composed children
// as nothing.
func TestCloudFront_DeployOrder(t *testing.T) {
	ap := &fakeApplier{}
	rec, err := Deploy(context.Background(), cfJSON(t, cfSiteTemplate()), DeployOptions{StackName: "site", Namespace: "web"}, ap)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("status %s", rec.Status)
	}
	bi, si := -1, -1
	for i, a := range ap.applied {
		switch a {
		case "Bucket/site-sitebucket":
			bi = i
		case "StaticSite/site-sitedistribution":
			si = i
		}
	}
	if bi < 0 || si < 0 || bi > si {
		t.Fatalf("want Bucket/sitebucket applied before StaticSite/sitedistribution, got %v", ap.applied)
	}
}

// Fn::GetAtt <Distribution>.DomainName resolves to the first Alias (and still orders the consumer after
// the distribution); Ref / Fn::GetAtt .Id stay placeholders (no distribution id exists here).
func TestCloudFront_GetAttDomainNameAndRef(t *testing.T) {
	data := cfJSON(t, cfSiteTemplate())
	tt, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(tt, resolveParams(tt, nil), nil, pseudoParams("site"))
	r.evalConditions()
	if v := r.resolve(map[string]any{"Fn::GetAtt": []any{"SiteDistribution", "DomainName"}}); v != "app.example.com" {
		t.Errorf("GetAtt DomainName = %v, want app.example.com", v)
	}
	if v := r.resolve(map[string]any{"Fn::Sub": "https://${SiteDistribution.DomainName}/app"}); v != "https://app.example.com/app" {
		t.Errorf("Sub ${Dist.DomainName} = %v", v)
	}
	if v := r.resolve(map[string]any{"Ref": "SiteDistribution"}); v != "<ref:SiteDistribution>" {
		t.Errorf("Ref Distribution must stay a placeholder, got %v", v)
	}
	if v := r.resolve(map[string]any{"Fn::GetAtt": []any{"SiteDistribution", "Id"}}); v != "<SiteDistribution.Id>" {
		t.Errorf("GetAtt Id must stay a placeholder, got %v", v)
	}
	if len(r.findings) != 0 {
		t.Errorf("resolving the alias in a sandbox must not leak findings: %v", r.findings)
	}
	// With a parameter override, the attribute follows the alias.
	r2 := newResolver(tt, resolveParams(tt, map[string]string{"SiteDomain": "shop.example.com"}), nil, pseudoParams("site"))
	r2.evalConditions()
	if v := r2.resolve(map[string]any{"Fn::GetAtt": []any{"SiteDistribution", "DomainName"}}); v != "shop.example.com" {
		t.Errorf("GetAtt DomainName with SiteDomain=shop.example.com = %v", v)
	}
	// The consumer still depends on the distribution (ordering is preserved).
	p := mustPlan(t, data, nil, "site")
	for _, pr := range p.Resources {
		if pr.LogicalID == "SiteUrl" && !strings.Contains(strings.Join(pr.DependsOn, ","), "SiteDistribution") {
			t.Errorf("SiteUrl must depend on SiteDistribution, got %v", pr.DependsOn)
		}
	}
}

// A distribution whose Alias references its own DomainName can't resolve (and must not recurse forever).
func TestCloudFront_SelfReferentialAliasRefuses(t *testing.T) {
	tmpl := cfSiteTemplate()
	cfDC(tmpl)["Aliases"] = []any{map[string]any{"Fn::GetAtt": []any{"SiteDistribution", "DomainName"}}}
	p := mustPlan(t, cfJSON(t, tmpl), nil, "site")
	if p.Verdict != Rejected || !strings.Contains(blockersJoined(p), "is not a concrete DNS hostname") {
		t.Fatalf("a self-referential alias must refuse, got %s:\n%s", p.Verdict, blockersJoined(p))
	}
}

// Every out-of-subset feature is refused at plan with a precise message (never approximated).
func TestCloudFront_OutOfSubsetRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"second origin", func(m map[string]any) {
			o := cfOrigin0(m)
			cfDC(m)["Origins"] = []any{o, map[string]any{"Id": "api", "DomainName": "api.example.com", "CustomOriginConfig": map[string]any{"OriginProtocolPolicy": "https-only"}}}
		}, "exactly one S3 origin translates (got 2)"},
		{"custom origin", func(m map[string]any) {
			cfDC(m)["Origins"] = []any{map[string]any{"Id": "s3-site", "DomainName": "api.example.com", "CustomOriginConfig": map[string]any{"OriginProtocolPolicy": "https-only"}}}
		}, "uses CustomOriginConfig"},
		{"S3 website endpoint", func(m map[string]any) {
			cfOrigin0(m)["DomainName"] = "example-site-assets.s3-website-us-east-1.amazonaws.com"
		}, "is not an S3 REST endpoint"},
		// An out-of-stack origin bucket is served (TestCloudFront_BucketFromAnotherStack); the stack's own
		// bucket's CloudFront grant then has no distribution serving it, which refuses.
		{"out-of-stack bucket", func(m map[string]any) {
			cfOrigin0(m)["DomainName"] = "someone-elses-bucket.s3.amazonaws.com"
		}, "no included in-stack AWS::CloudFront::Distribution serves this bucket"},
		{"origin path", func(m map[string]any) { cfOrigin0(m)["OriginPath"] = "/build" }, "OriginPath \"/build\""},
		{"origin groups", func(m map[string]any) {
			cfDC(m)["OriginGroups"] = map[string]any{"Quantity": 1, "Items": []any{map[string]any{"Id": "g"}}}
		}, "OriginGroups (origin failover)"},
		{"path-pattern cache behaviors", func(m map[string]any) {
			cfDC(m)["CacheBehaviors"] = []any{map[string]any{"PathPattern": "/api/*", "TargetOriginId": "s3-site", "ViewerProtocolPolicy": "https-only"}}
		}, "path-pattern cache behaviors"},
		{"lambda@edge", func(m map[string]any) {
			cfDCB(m)["LambdaFunctionAssociations"] = []any{map[string]any{"EventType": "origin-request", "LambdaFunctionARN": "arn:aws:lambda:us-east-1:111122223333:function:rewrite:1"}}
		}, "Lambda@Edge"},
		{"cloudfront functions", func(m map[string]any) {
			cfDCB(m)["FunctionAssociations"] = []any{map[string]any{"EventType": "viewer-request", "FunctionARN": "arn:aws:cloudfront::111122223333:function/rewrite"}}
		}, "CloudFront Functions"},
		{"signed urls", func(m map[string]any) { cfDCB(m)["TrustedKeyGroups"] = []any{"kg-1"} }, "signed URLs"},
		{"field-level encryption", func(m map[string]any) { cfDCB(m)["FieldLevelEncryptionId"] = "fle-1" }, "field-level encryption"},
		{"real-time logs", func(m map[string]any) {
			cfDCB(m)["RealtimeLogConfigArn"] = "arn:aws:cloudfront::111122223333:realtime-log-config/rt"
		}, "real-time logs"},
		{"geo restriction", func(m map[string]any) {
			cfDC(m)["Restrictions"] = map[string]any{"GeoRestriction": map[string]any{"RestrictionType": "whitelist", "Locations": []any{"US"}}}
		}, "GeoRestriction whitelist"},
		{"waf", func(m map[string]any) {
			cfDC(m)["WebACLId"] = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/site/abc"
		}, "WebACLId (an AWS WAF web ACL)"},
		{"continuous deployment", func(m map[string]any) { cfDC(m)["Staging"] = true }, "continuous deployment"},
		{"write methods", func(m map[string]any) {
			cfDCB(m)["AllowedMethods"] = []any{"GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"}
		}, "include write methods"},
		{"no aliases", func(m map[string]any) {
			delete(cfDC(m), "Aliases")
			cfDC(m)["ViewerCertificate"] = map[string]any{"CloudFrontDefaultCertificate": true}
			delete(m["Resources"].(map[string]any), "SiteCertificate")
		}, "Aliases is empty — a distribution without Aliases is served on an AWS-generated *.cloudfront.net hostname"},
		{"wildcard alias", func(m map[string]any) {
			cfDC(m)["Aliases"] = []any{"*.example.com"}
			cfProps(m, "SiteCertificate")["DomainName"] = "*.example.com"
		}, "is a wildcard"},
		{"disabled", func(m map[string]any) { cfDC(m)["Enabled"] = false }, "a disabled distribution serves nothing"},
		{"dedicated-IP TLS", func(m map[string]any) {
			cfDC(m)["ViewerCertificate"].(map[string]any)["SslSupportMethod"] = "vip"
		}, "Traefik serves TLS by SNI only"},
		{"certificate does not cover an alias", func(m map[string]any) {
			cfDC(m)["Aliases"] = []any{"app.example.com", "other.example.org"}
		}, "does not cover Alias(es) other.example.org"},
		{"standalone certificate", func(m map[string]any) {
			m["Resources"].(map[string]any)["ApiCertificate"] = map[string]any{"Type": "AWS::CertificateManager::Certificate", "Properties": map[string]any{"DomainName": "api.example.com"}}
		}, "no included distribution references this one"},
		{"error code 500", func(m map[string]any) {
			cfDC(m)["CustomErrorResponses"] = []any{map[string]any{"ErrorCode": 500, "ResponseCode": 200, "ResponsePagePath": "/index.html"}}
		}, "ErrorCode 500 is not translatable"},
		{"spa page is not the root object", func(m map[string]any) { cfDC(m)["DefaultRootObject"] = "home.html" }, "is not the DefaultRootObject"},
		{"different error pages", func(m map[string]any) {
			cfDC(m)["CustomErrorResponses"] = []any{
				map[string]any{"ErrorCode": 403, "ResponseCode": 403, "ResponsePagePath": "/403.html"},
				map[string]any{"ErrorCode": 404, "ResponseCode": 404, "ResponsePagePath": "/404.html"},
			}
		}, "map 403 and 404 to different pages"},
		{"cors in headers policy", func(m map[string]any) {
			cfRHPConfig(m)["CorsConfig"] = map[string]any{"AccessControlAllowOrigins": map[string]any{"Items": []any{"https://app.example.com"}}}
		}, "CorsConfig (CloudFront-generated CORS headers"},
		{"remove headers", func(m map[string]any) {
			cfRHPConfig(m)["RemoveHeadersConfig"] = map[string]any{"Items": []any{map[string]any{"Header": "Server"}}}
		}, "RemoveHeadersConfig is not translatable"},
		{"server-set header", func(m map[string]any) {
			cfRHPConfig(m)["CustomHeadersConfig"] = map[string]any{"Items": []any{map[string]any{"Header": "Content-Type", "Value": "text/html", "Override": true}}}
		}, "is set by the site's server itself"},
		{"header value with $", func(m map[string]any) {
			cfRHPConfig(m)["CustomHeadersConfig"] = map[string]any{"Items": []any{map[string]any{"Header": "X-Build", "Value": "a$b", "Override": true}}}
		}, "without double quotes, backslashes or dollar signs"},
		{"managed CORS headers policy", func(m map[string]any) {
			cfDCB(m)["ResponseHeadersPolicyId"] = "5cc3b908-e619-4b99-88e5-2cf7f45965bd"
		}, "AWS managed Managed-CORS-With-Preflight"},
		{"out-of-stack headers policy", func(m map[string]any) {
			cfDCB(m)["ResponseHeadersPolicyId"] = "00000000-0000-0000-0000-000000000000"
		}, "names a response headers policy outside this stack"},
		{"non-s3 OAC", func(m map[string]any) {
			cfProps(m, "SiteOAC")["OriginAccessControlConfig"].(map[string]any)["OriginAccessControlOriginType"] = "mediastore"
		}, "OriginAccessControlOriginType mediastore is not translatable"},
		{"out-of-stack OAI", func(m map[string]any) {
			delete(cfOrigin0(m), "OriginAccessControlId")
			cfOrigin0(m)["S3OriginConfig"] = map[string]any{"OriginAccessIdentity": "origin-access-identity/cloudfront/E2EXAMPLE1234"}
		}, "an identity outside this stack can't be read"},
		{"grant to an out-of-stack distribution", func(m map[string]any) {
			st := cfProps(m, "SiteBucketPolicy")["PolicyDocument"].(map[string]any)["Statement"].([]any)[0].(map[string]any)
			st["Condition"] = map[string]any{"StringEquals": map[string]any{"AWS:SourceArn": "arn:aws:cloudfront::111122223333:distribution/E2EXAMPLE1234"}}
		}, "to a distribution that isn't an included one in this stack"},
		{"cloudfront write grant", func(m map[string]any) {
			st := cfProps(m, "SiteBucketPolicy")["PolicyDocument"].(map[string]any)["Statement"].([]any)[0].(map[string]any)
			st["Action"] = []any{"s3:GetObject", "s3:PutObject"}
		}, "grants CloudFront s3:PutObject"},
		{"object-lock origin bucket", func(m map[string]any) {
			cfProps(m, "SiteBucket")["ObjectLockEnabled"] = true
			cfProps(m, "SiteBucket")["ObjectLockConfiguration"] = map[string]any{"ObjectLockEnabled": "Enabled", "Rule": map[string]any{"DefaultRetention": map[string]any{"Mode": "GOVERNANCE", "Days": 1}}}
		}, "has Object Lock"},
		{"unknown distribution property", func(m map[string]any) { cfDC(m)["AnycastIpListId"] = "aip-1" }, "DistributionConfig.AnycastIpListId is not translatable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := cfSiteTemplate()
			tc.mutate(tmpl)
			p := mustPlan(t, cfJSON(t, tmpl), nil, "site")
			if p.Verdict != Rejected {
				t.Fatalf("want REJECTED, got %s", p.Verdict)
			}
			if !strings.Contains(blockersJoined(p), tc.want) {
				t.Fatalf("blockers should contain %q; got:\n%s", tc.want, blockersJoined(p))
			}
		})
	}
}

// The legacy OAI shape translates the same way: the identity composes into the site, and the bucket
// policy statement granting the identity's CanonicalUser read is realized by the site, not stored.
func TestCloudFront_OAI(t *testing.T) {
	tmpl := cfSiteTemplate()
	res := tmpl["Resources"].(map[string]any)
	delete(res, "SiteOAC")
	res["SiteOAI"] = map[string]any{"Type": "AWS::CloudFront::CloudFrontOriginAccessIdentity", "Properties": map[string]any{
		"CloudFrontOriginAccessIdentityConfig": map[string]any{"Comment": "site reader"},
	}}
	delete(cfOrigin0(tmpl), "OriginAccessControlId")
	cfOrigin0(tmpl)["S3OriginConfig"] = map[string]any{"OriginAccessIdentity": map[string]any{"Fn::Sub": "origin-access-identity/cloudfront/${SiteOAI}"}}
	cfProps(tmpl, "SiteBucketPolicy")["PolicyDocument"] = map[string]any{"Statement": []any{map[string]any{
		"Effect":    "Allow",
		"Principal": map[string]any{"CanonicalUser": map[string]any{"Fn::GetAtt": []any{"SiteOAI", "S3CanonicalUserId"}}},
		"Action":    []any{"s3:GetObject", "s3:ListBucket"},
		"Resource":  []any{"arn:aws:s3:::example-site-assets", "arn:aws:s3:::example-site-assets/*"},
	}}}
	built := cfBuilt(t, cfJSON(t, tmpl))
	if !cfHasCaveat(built["SiteDistribution"].cav, "origin access (OAI)") {
		t.Errorf("site caveats should name the OAI; got:\n  %s", strings.Join(built["SiteDistribution"].cav, "\n  "))
	}
	if _, has := built["SiteBucket"].res.Spec["policy"]; has {
		t.Fatalf("an OAI-only grant must not be stored as a MinIO policy")
	}
	if !cfHasCaveat(built["SiteBucket"].cav, "granting CloudFront read (OAI)") {
		t.Errorf("bucket caveats should explain the OAI grant; got:\n  %s", strings.Join(built["SiteBucket"].cav, "\n  "))
	}
	// The identity's IAM-ARN form is recognized too.
	cfProps(tmpl, "SiteBucketPolicy")["PolicyDocument"].(map[string]any)["Statement"].([]any)[0].(map[string]any)["Principal"] =
		map[string]any{"AWS": map[string]any{"Fn::Sub": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${SiteOAI}"}}
	built = cfBuilt(t, cfJSON(t, tmpl))
	if _, has := built["SiteBucket"].res.Spec["policy"]; has {
		t.Fatalf("an OAI IAM-ARN grant must not be stored as a MinIO policy")
	}
}

// A bucket policy mixing the CloudFront grant with a public statement keeps ONLY the public statement as
// spec.policy (the grant is realized by the site).
func TestCloudFront_BucketPolicyKeepsNonCloudFrontStatements(t *testing.T) {
	tmpl := cfSiteTemplate()
	doc := cfProps(tmpl, "SiteBucketPolicy")["PolicyDocument"].(map[string]any)
	doc["Statement"] = append(doc["Statement"].([]any), map[string]any{
		"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
		"Resource":  []any{"arn:aws:s3:::example-site-assets", "arn:aws:s3:::example-site-assets/*"},
		"Condition": map[string]any{"Bool": map[string]any{"aws:SecureTransport": "false"}},
	})
	built := cfBuilt(t, cfJSON(t, tmpl))
	pol, _ := built["SiteBucket"].res.Spec["policy"].(string)
	if !strings.Contains(pol, "DenyInsecureTransport") || strings.Contains(pol, "cloudfront") || strings.Contains(pol, "AllowCloudFrontRead") {
		t.Fatalf("spec.policy should hold only the public statement, got %q", pol)
	}
}

// The AWS managed SecurityHeadersPolicy (by id) maps to its fixed header set; an error-document mapping
// (403/404 -> /404.html, 404) is a plain site with errorDocument.
func TestCloudFront_ManagedHeadersAndErrorDocument(t *testing.T) {
	tmpl := cfSiteTemplate()
	delete(tmpl["Resources"].(map[string]any), "SecurityHeaders")
	cfDCB(tmpl)["ResponseHeadersPolicyId"] = "67f7725c-6f97-4210-82d7-5512b31e9d03"
	cfDC(tmpl)["CustomErrorResponses"] = []any{
		map[string]any{"ErrorCode": 403, "ResponseCode": 404, "ResponsePagePath": "/404.html"},
		map[string]any{"ErrorCode": 404, "ResponsePagePath": "/404.html"},
	}
	cfDCB(tmpl)["ViewerProtocolPolicy"] = "https-only"
	site := cfBuilt(t, cfJSON(t, tmpl))["SiteDistribution"]
	if site.res.Spec["spa"] != false || site.res.Spec["errorDocument"] != "404.html" || site.res.Spec["indexDocument"] != "index.html" {
		t.Fatalf("error-document mapping wrong: %v", site.res.Spec)
	}
	hs, _ := site.res.Spec["responseHeaders"].([]any)
	if len(hs) != 5 || hs[0].(map[string]any)["name"] != "Strict-Transport-Security" || hs[2].(map[string]any)["value"] != "SAMEORIGIN" {
		t.Fatalf("managed SecurityHeadersPolicy headers wrong: %v", hs)
	}
	if cfHasCaveat(site.cav, "ViewerProtocolPolicy") {
		t.Errorf("https-only needs no protocol caveat; got:\n  %s", strings.Join(site.cav, "\n  "))
	}
	// No error responses at all: a plain site, with the 404-vs-403 caveat.
	delete(cfDC(tmpl), "CustomErrorResponses")
	site = cfBuilt(t, cfJSON(t, tmpl))["SiteDistribution"]
	if site.res.Spec["spa"] != false {
		t.Fatalf("no CustomErrorResponses must be spa: false (StaticSite defaults spa to true), got %v", site.res.Spec["spa"])
	}
	if _, has := site.res.Spec["errorDocument"]; has || !cfHasCaveat(site.cav, "no CustomErrorResponses") {
		t.Fatalf("plain site wrong: %v / %v", site.res.Spec, site.cav)
	}
}

// The origin may name the bucket by ${Bucket}.s3.<region>.amazonaws.com, and a bucket without a
// BucketName serves under its k8s-safe logical id (the Bucket composition's default).
func TestCloudFront_SubOriginAndGeneratedBucketName(t *testing.T) {
	tmpl := cfSiteTemplate()
	delete(cfProps(tmpl, "SiteBucket"), "BucketName")
	cfOrigin0(tmpl)["DomainName"] = map[string]any{"Fn::Sub": "${SiteBucket}.s3.${AWS::Region}.amazonaws.com"}
	// The policy's Resource is an unresolvable !Sub, but it rides the CloudFront grant, which isn't stored.
	site := cfBuilt(t, cfJSON(t, tmpl))["SiteDistribution"]
	if site.res.Spec["bucket"] != "site-sitebucket" {
		t.Fatalf("bucket = %v, want sitebucket (the k8s-safe logical id)", site.res.Spec["bucket"])
	}
}

// A conditioned-OFF distribution provisions nothing, holds no bucket grant, and resolves no DomainName —
// the collation walks skip it like every other gated-off resource.
func TestCloudFront_ConditionedOffDistributionExcluded(t *testing.T) {
	tmpl := cfSiteTemplate()
	tmpl["Parameters"].(map[string]any)["WithCdn"] = map[string]any{"Type": "String", "Default": "false"}
	tmpl["Conditions"] = map[string]any{"CdnOn": map[string]any{"Fn::Equals": []any{map[string]any{"Ref": "WithCdn"}, "true"}}}
	for _, id := range []string{"SiteDistribution", "SiteBucketPolicy", "SiteCertificate", "SiteOAC", "SecurityHeaders", "SiteUrl"} {
		cfRes(tmpl, id)["Condition"] = "CdnOn"
	}
	data := cfJSON(t, tmpl)

	p := mustPlan(t, data, nil, "site")
	if p.Verdict == Rejected {
		t.Fatalf("a gated-off CDN must not block the stack:\n%s", blockersJoined(p))
	}
	built := cfBuilt(t, data)
	if _, has := built["SiteDistribution"]; has || len(built) != 1 {
		t.Fatalf("only the bucket should provision with the CDN gated off, got %v", built)
	}

	tt, _ := Parse(data)
	off := ecsCtx(t, string(data))
	if got := off.cloudFrontDistributionsServing("SiteBucket"); len(got) != 0 {
		t.Errorf("a conditioned-OFF distribution must not serve the bucket, got %v", got)
	}
	if got := off.cloudFrontCertificateUsers("SiteCertificate"); len(got) != 0 {
		t.Errorf("a conditioned-OFF distribution must not use the certificate, got %v", got)
	}
	r := newResolver(tt, resolveParams(tt, nil), nil, pseudoParams("site"))
	r.evalConditions()
	if v := r.resolve(map[string]any{"Fn::GetAtt": []any{"SiteDistribution", "DomainName"}}); v != "<SiteDistribution.DomainName>" {
		t.Errorf("GetAtt on a conditioned-OFF distribution must stay a placeholder, got %v", v)
	}

	// ON: the same walks see it (the skip is condition-driven, not a parse miss).
	on := ctxWithParams(t, string(data), map[string]string{"WithCdn": "true"})
	if got := on.cloudFrontDistributionsServing("SiteBucket"); len(got) != 1 || got[0] != "SiteDistribution" {
		t.Errorf("with the condition ON the distribution serves the bucket, got %v", got)
	}
	if got := on.cloudFrontCertificateUsers("SiteCertificate"); len(got) != 1 {
		t.Errorf("with the condition ON the distribution uses the certificate, got %v", got)
	}

	// A bucket grant whose only distribution is gated off (policy left ungated) refuses: nothing holds it.
	delete(cfRes(tmpl, "SiteBucketPolicy"), "Condition")
	p = mustPlan(t, cfJSON(t, tmpl), nil, "site")
	if !strings.Contains(blockersJoined(p), "no included in-stack AWS::CloudFront::Distribution serves this bucket") {
		t.Fatalf("a grant with no serving distribution must refuse, got %s:\n%s", p.Verdict, blockersJoined(p))
	}
}

// ACM's domain validation, as the operator configures it (certificates.validatedDomains): an alias under
// a validated domain gets the platform's ACM-style certificate; one outside every validated domain
// refuses, as its certificate would stay PENDING_VALIDATION on AWS; with no validated domains the site
// keeps the self-signed issuer, said so plainly.
func TestCloudFront_CertificateNeedsAValidatedDomain(t *testing.T) {
	data := cfJSON(t, cfSiteTemplate()) // Aliases app.example.com and www.app.example.com
	distCaveats := func(p *Plan) string {
		for _, r := range p.Resources {
			if r.LogicalID == "SiteDistribution" {
				return strings.Join(r.Caveats, "\n")
			}
		}
		return ""
	}
	for _, c := range []struct {
		name      string
		validated []string
		refuse    string
		caveat    string
	}{
		{"none validated", nil, "", "self-signed certificate (ClusterIssuer openinfra-issuer)"},
		{"the alias's own domain", []string{"example.com"}, "", "ClusterIssuer openinfra-acm"},
		{"a parent of the aliases", []string{"app.example.com"}, "", "ClusterIssuer openinfra-acm"},
		{"another domain", []string{"example.org"}, "app.example.com, www.app.example.com are not under a domain this environment has validated", ""},
		{"only one alias covered", []string{"www.app.example.com"}, "Alias(es) app.example.com are not under", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := BuildPlanWithCaps(data, nil, nil, "site", Capabilities{ValidatedDomains: c.validated})
			if err != nil {
				t.Fatal(err)
			}
			if c.refuse != "" {
				if p.Verdict != Rejected || !strings.Contains(blockersJoined(p), c.refuse) {
					t.Fatalf("want a refusal containing %q, got %s:\n%s", c.refuse, p.Verdict, blockersJoined(p))
				}
				if !strings.Contains(blockersJoined(p), "PENDING_VALIDATION") {
					t.Errorf("the refusal must say why (ACM would not validate it):\n%s", blockersJoined(p))
				}
				return
			}
			if p.Verdict == Rejected {
				t.Fatalf("must not refuse:\n%s", blockersJoined(p))
			}
			if got := distCaveats(p); !strings.Contains(got, c.caveat) {
				t.Errorf("distribution caveats must name %q:\n%s", c.caveat, got)
			}
		})
	}
	if !underValidatedDomain("App.Example.com.", []string{"*.example.com"}) || underValidatedDomain("badexample.com", []string{"example.com"}) {
		t.Error("underValidatedDomain: a subdomain (any case, trailing dot) is under its domain; a name merely ending in the same letters is not")
	}
}
