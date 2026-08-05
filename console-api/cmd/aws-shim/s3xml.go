package main

import (
	"encoding/xml"
	"net/http"
)

// S3 wire encoding — the response and error shapes AWS SDKs parse. This is where most of the
// fidelity sweat lives (design handoff §2/§4): a wrong XML field name, a missing namespace, or a
// wrong error Code is a client-side SDK parse error even when the operation itself succeeded, so
// these shapes are pinned and unit-tested rather than hand-rolled per handler.

const s3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// s3ErrorBody is S3's error document. The SDKs key their ret/error handling off <Code>, so it must
// match S3's documented code exactly (e.g. "NoSuchKey", "SignatureDoesNotMatch").
type s3ErrorBody struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	Resource   string   `xml:"Resource,omitempty"`
	RequestID  string   `xml:"RequestId,omitempty"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
}

// s3ErrorInfo pairs an S3 error code with the HTTP status AWS returns for it and a default message.
type s3ErrorInfo struct {
	Status  int
	Message string
}

// s3Errors is the subset of S3 error codes the shim emits. Codes and statuses match S3 so an SDK's
// error-mapping (and its retry policy) behaves exactly as it would against real AWS.
var s3Errors = map[string]s3ErrorInfo{
	"SignatureDoesNotMatch": {http.StatusForbidden, "The request signature we calculated does not match the signature you provided."},
	"InvalidAccessKeyId":    {http.StatusForbidden, "The AWS access key ID you provided does not exist in our records."},
	"AccessDenied":          {http.StatusForbidden, "Access Denied."},
	"NoSuchKey":             {http.StatusNotFound, "The specified key does not exist."},
	"NoSuchBucket":          {http.StatusNotFound, "The specified bucket does not exist."},
	"MethodNotAllowed":      {http.StatusMethodNotAllowed, "The specified method is not allowed against this resource."},
	"NotImplemented":        {http.StatusNotImplemented, "A header or operation you provided implies functionality that is not implemented."},
	"InvalidRequest":        {http.StatusBadRequest, "Invalid Request."},
	"InternalError":         {http.StatusInternalServerError, "We encountered an internal error. Please try again."},
}

// writeS3Error writes an S3-faithful error response: the documented HTTP status, the XML error
// document with the exact <Code>, and the x-amz-request-id echoed for correlation. Any unknown
// code degrades to InternalError rather than inventing a shape a client can't parse.
func writeS3Error(w http.ResponseWriter, code, requestID, resource string) {
	info, ok := s3Errors[code]
	if !ok {
		code, info = "InternalError", s3Errors["InternalError"]
	}
	writeS3ErrorFull(w, code, info.Status, requestID, info.Message, resource)
}

// writeS3ErrorMsg writes an S3-shaped error with an explicit status and message (for codes not in
// the s3Errors table, e.g. the router's NotImplemented for an un-fronted service).
func writeS3ErrorMsg(w http.ResponseWriter, code string, status int, requestID, message string) {
	writeS3ErrorFull(w, code, status, requestID, message, "")
}

func writeS3ErrorFull(w http.ResponseWriter, code string, status int, requestID, message, resource string) {
	body := s3ErrorBody{Code: code, Message: message, Resource: resource, RequestID: requestID}
	out, err := xml.Marshal(body)
	if err != nil {
		http.Error(w, "InternalError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// listBucketResult is the ListObjectsV2 response body. The xmlns MUST be present or SDKs fail to
// unmarshal Contents; KeyCount/IsTruncated drive pagination.
type listBucketResult struct {
	XMLName     xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name        string         `xml:"Name"`
	Prefix      string         `xml:"Prefix"`
	KeyCount    int            `xml:"KeyCount"`
	MaxKeys     int            `xml:"MaxKeys"`
	IsTruncated bool           `xml:"IsTruncated"`
	Contents    []listObjectV2 `xml:"Contents"`
}

type listObjectV2 struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"` // ISO-8601, e.g. 2006-01-02T15:04:05.000Z
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// listAllMyBucketsResult is the ListBuckets (GET /) response body.
type listAllMyBucketsResult struct {
	XMLName xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   canonicalUser `xml:"Owner"`
	Buckets bucketList    `xml:"Buckets"`
}

type bucketList struct {
	Bucket []s3Bucket `xml:"Bucket"`
}

type s3Bucket struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type canonicalUser struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

// writeXML marshals v as an S3 XML response body with the XML declaration prepended.
func writeXML(w http.ResponseWriter, status int, requestID string, v any) {
	out, err := xml.Marshal(v)
	if err != nil {
		writeS3Error(w, "InternalError", requestID, "")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}
