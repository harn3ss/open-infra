package main

// S3 Block Public Access on a bucket: GetPublicAccessBlock, PutPublicAccessBlock, DeletePublicAccessBlock.
//
// A bucket here has no ACLs (its object ownership is always BucketOwnerEnforced, s3multipart.go), and it is
// public only through a bucket policy the platform applies: a kind: Bucket's spec.policy, or a stack's
// AWS::S3::BucketPolicy. So the configuration in force is the bucket's own:
//   - a bucket whose policy grants no one outside its own and named accounts blocks all public access: the
//     four settings true, AWS's default for a new bucket;
//   - a bucket whose policy allows any principal ("*") has public ACLs blocked and ignored, but its policy
//     public: BlockPublicPolicy and RestrictPublicBuckets false. Whatever the statement's conditions, such
//     a policy is counted public here (AWS counts some fixed-value conditions, a source IP or VPC, as not).
//
// GetPublicAccessBlock answers that configuration. PutPublicAccessBlock accepts it, and refuses one that would
// change it, with the reason, as PutBucketOwnershipControls refuses ACLs. A configuration is never accepted
// and then ignored: loosening a private bucket could not make it public through this API, and blocking a
// public policy here would leave the bucket public. DeletePublicAccessBlock, which on AWS turns all four
// settings off, is refused the same way.

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

// publicAccessBlock is the PublicAccessBlockConfiguration document, as GetPublicAccessBlock answers it and
// PutPublicAccessBlock takes it (a setting the request leaves out is false, as on AWS).
type publicAccessBlock struct {
	XMLName               xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ PublicAccessBlockConfiguration"`
	BlockPublicAcls       bool     `xml:"BlockPublicAcls"`
	IgnorePublicAcls      bool     `xml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool     `xml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool     `xml:"RestrictPublicBuckets"`
}

// publicAccessBlockIn is PutPublicAccessBlock's body, read without its namespace (the AWS CLI sends one, a
// hand-written request may not).
type publicAccessBlockIn struct {
	XMLName               xml.Name `xml:"PublicAccessBlockConfiguration"`
	BlockPublicAcls       bool     `xml:"BlockPublicAcls"`
	IgnorePublicAcls      bool     `xml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool     `xml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool     `xml:"RestrictPublicBuckets"`
}

// publicAccessInForce is a bucket's configuration in force: everything blocked, unless its policy is public.
func publicAccessInForce(policyPublic bool) publicAccessBlock {
	return publicAccessBlock{BlockPublicAcls: true, IgnorePublicAcls: true,
		BlockPublicPolicy: !policyPublic, RestrictPublicBuckets: !policyPublic}
}

// policyIsPublic reports whether a bucket policy document allows any principal: an Allow statement whose
// Principal is "*", {"AWS": "*"}, or a list holding "*". A statement naming accounts or roles is not public.
// A document that cannot be read is not assumed private.
func policyIsPublic(doc string) bool {
	if strings.TrimSpace(doc) == "" {
		return false
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil {
		return true
	}
	type stmt struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
	}
	var many []stmt
	if json.Unmarshal(p.Statement, &many) != nil {
		var one stmt
		if json.Unmarshal(p.Statement, &one) != nil {
			return true
		}
		many = []stmt{one}
	}
	for _, s := range many {
		if strings.EqualFold(s.Effect, "Allow") && principalIsAnyone(s.Principal) {
			return true
		}
	}
	return false
}

// principalIsAnyone reports whether a policy statement's Principal is everyone: "*", or "*" among its AWS
// principals.
func principalIsAnyone(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == "*"
	}
	var byType map[string]json.RawMessage
	if json.Unmarshal(raw, &byType) != nil {
		return false
	}
	aws, ok := byType["AWS"]
	if !ok {
		return false
	}
	if json.Unmarshal(aws, &one) == nil {
		return one == "*"
	}
	var list []string
	if json.Unmarshal(aws, &list) == nil {
		for _, v := range list {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

// bucketPublicAccess reads whether op's bucket exists and whether its policy is public, writing the error
// and returning ok=false when the answer cannot be given.
func (h *s3Handler) bucketPublicAccess(w http.ResponseWriter, r *http.Request, op s3op, requestID string) (public, ok bool) {
	exists, err := h.mc.BucketExists(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return false, false
	}
	if !exists {
		writeS3Error(w, "NoSuchBucket", requestID, r.URL.Path)
		return false, false
	}
	doc, err := h.mc.GetBucketPolicy(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return false, false
	}
	return policyIsPublic(doc), true
}

// getPublicAccessBlock answers the bucket's configuration in force.
func (h *s3Handler) getPublicAccessBlock(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	public, ok := h.bucketPublicAccess(w, r, op, requestID)
	if !ok {
		return
	}
	writeXML(w, http.StatusOK, requestID, publicAccessInForce(public))
}

// putPublicAccessBlock accepts the configuration in force and refuses any other, saying why.
func (h *s3Handler) putPublicAccessBlock(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	var in publicAccessBlockIn
	if err := xml.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	public, ok := h.bucketPublicAccess(w, r, op, requestID)
	if !ok {
		return
	}
	asked := publicAccessBlock{BlockPublicAcls: in.BlockPublicAcls, IgnorePublicAcls: in.IgnorePublicAcls,
		BlockPublicPolicy: in.BlockPublicPolicy, RestrictPublicBuckets: in.RestrictPublicBuckets}
	if asked != publicAccessInForce(public) {
		writeS3ErrorFull(w, "NotImplemented", http.StatusNotImplemented, requestID, publicAccessRefusal(asked, public), r.URL.Path)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

// deletePublicAccessBlock is refused: on AWS it turns every setting off, which a private bucket here cannot
// take, and a public one already has for its policy.
func (h *s3Handler) deletePublicAccessBlock(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	public, ok := h.bucketPublicAccess(w, r, op, requestID)
	if !ok {
		return
	}
	msg := "Removing the bucket's Block Public Access configuration would allow public ACLs and policies: " + publicAccessNotLoosened
	if public {
		msg = "Removing the bucket's Block Public Access configuration would allow public ACLs: " + aclsNotSupported + "."
	}
	writeS3ErrorFull(w, "NotImplemented", http.StatusNotImplemented, requestID, msg, r.URL.Path)
}

// publicAccessNotLoosened is why a private bucket's public access stays blocked.
const publicAccessNotLoosened = "a bucket here has no ACLs and is made public only by a bucket policy the platform applies (a kind: Bucket's spec.policy, or a stack's AWS::S3::BucketPolicy), so every public access setting stays on for a bucket without a public one."

// publicAccessRefusal says why a PutPublicAccessBlock that would change the configuration in force is refused.
func publicAccessRefusal(asked publicAccessBlock, public bool) string {
	if !asked.BlockPublicAcls || !asked.IgnorePublicAcls {
		return "BlockPublicAcls and IgnorePublicAcls are always true: " + aclsNotSupported + "."
	}
	if public {
		return "The bucket's policy grants public access, and it is set by the platform (a kind: Bucket's spec.policy, or a stack's AWS::S3::BucketPolicy): remove the public statements there, rather than blocking them here and leaving the bucket public."
	}
	return "BlockPublicPolicy and RestrictPublicBuckets are always true for this bucket: " + publicAccessNotLoosened
}
