package cfn

import (
	"strings"
	"testing"
)

// A distribution (and its CloudFront read grant) over a bucket another stack created — its RegionalDomainName
// and name imported, as an app stack over a shared assets stack does — translates: the StaticSite serves that
// bucket by name, and the grant is realized by the site rather than written into the other stack's policy.
func TestCloudFront_BucketFromAnotherStack(t *testing.T) {
	order, err := buildManifests([]byte(`
Parameters:
  AssetsBucket: { Type: String }
Resources:
  Site:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Aliases: [ www.example.test ]
        DefaultRootObject: index.html
        ViewerCertificate: { AcmCertificateArn: !Ref Cert, SslSupportMethod: sni-only }
        Origins:
          - Id: s3
            DomainName: !ImportValue assets-RegionalDomainName
            S3OriginConfig: { OriginAccessIdentity: "" }
            OriginAccessControlId: !GetAtt OAC.Id
        DefaultCacheBehavior: { TargetOriginId: s3, ViewerProtocolPolicy: redirect-to-https }
  Cert: { Type: AWS::CertificateManager::Certificate, Properties: { DomainName: www.example.test, ValidationMethod: DNS } }
  OAC:
    Type: AWS::CloudFront::OriginAccessControl
    Properties: { OriginAccessControlConfig: { Name: oac, OriginAccessControlOriginType: s3, SigningBehavior: always, SigningProtocol: sigv4 } }
  Grant:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref AssetsBucket
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: { Service: cloudfront.amazonaws.com }
            Action: s3:GetObject
            Resource: !Sub "arn:aws:s3:::${AssetsBucket}/*"
            Condition: { StringEquals: { "AWS:SourceArn": !Sub "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Site}" } }
`), DeployOptions{StackName: "app", Namespace: "n", Params: map[string]string{"AssetsBucket": "shared-assets"},
		Exports: map[string]string{"assets-RegionalDomainName": "shared-assets.s3.us-east-1.amazonaws.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var site *StackResource
	var cav string
	for i := range order {
		if order[i].res.Kind == "StaticSite" {
			site = &order[i].res
			cav = strings.Join(order[i].cav, "\n")
		}
	}
	if site == nil || site.Spec["bucket"] != "shared-assets" {
		t.Fatalf("site = %+v, want a StaticSite serving shared-assets", site)
	}
	if !strings.Contains(cav, "not in this stack") {
		t.Fatalf("caveats = %s", cav)
	}
}
