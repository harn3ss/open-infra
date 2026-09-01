// DynamoDB front door for the aws-shim — Phase 0 skeleton.
//
// This handler recognizes DynamoDB requests (AWS JSON 1.0, the operation named in X-Amz-Target),
// authenticates them through the shared SigV4 path, authorizes them with the same impersonated
// SubjectAccessReview every other front door uses (one policy world), and speaks DynamoDB's own
// error dialect ({"__type","message"}). Operations are NOT yet executed: every recognized
// operation returns an honest 501 NotImplementedException — the same per-op graduation discipline
// the rest of the shim follows, never a silent fake. The backing store (the open-appsync
// Dynamo-shaped executor, extracted to a shared package) and the wire<->op adapter land in the
// next phase; this phase establishes the handler, the auth mapping, and the dialect.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type dynamoHandler struct {
	cs      kubernetes.Interface
	authzNS string
	logger  *slog.Logger
}

func newDynamoHandler(cs kubernetes.Interface, authzNS string, logger *slog.Logger) *dynamoHandler {
	return &dynamoHandler{cs: cs, authzNS: authzNS, logger: logger}
}

// dynamoErrType is the DynamoDB error __type namespace; SDKs key on the short name after '#'.
const dynamoErrType = "com.amazonaws.dynamodb.v20120810#"

// writeDynamoError writes DynamoDB's JSON-1.0 error shape: an HTTP status plus {"__type","message"}.
func writeDynamoError(w http.ResponseWriter, status int, errType, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"__type":  dynamoErrType + errType,
		"message": message,
	})
}

func (h *dynamoHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeDynamoError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForOp maps a DynamoDB operation to the coarse RBAC verb its SubjectAccessReview checks. Reads
// → get, writes → create/delete. This is bucket/table-agnostic in v1 — the same honestly-flagged
// coarseness S3 carries; a per-table kind: Table would tighten it later.
func verbForOp(op string) (verb string, known bool) {
	switch op {
	case "GetItem", "Query", "Scan", "BatchGetItem", "DescribeTable", "ListTables":
		return "get", true
	case "PutItem", "UpdateItem", "BatchWriteItem", "CreateTable":
		return "create", true
	case "DeleteItem", "DeleteTable":
		return "delete", true
	}
	return "", false
}

func (h *dynamoHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	// The operation is in the X-Amz-Target header, e.g. "DynamoDB_20120810.GetItem".
	target := r.Header.Get("X-Amz-Target")
	op := target
	if i := strings.LastIndex(target, "."); i >= 0 {
		op = target[i+1:]
	}
	if op == "" {
		writeDynamoError(w, http.StatusBadRequest, "MissingActionException", requestID,
			"No operation named in the X-Amz-Target header.")
		return
	}
	verb, known := verbForOp(op)
	if !known {
		writeDynamoError(w, http.StatusBadRequest, "UnknownOperationException", requestID,
			"Unrecognized DynamoDB operation "+op+".")
		return
	}

	// The table name (for authz scoping) is in the JSON body. Best-effort read; the body is not
	// forwarded in this phase.
	table := tableNameFromBody(r)

	// Authorize with the same impersonated SubjectAccessReview every front door uses — one policy
	// world. Coarse in v1: gated on openinfra.dev/applications.
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, table); !allowed {
		writeDynamoError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}

	// Recognized and authorized, but not yet executed — an honest 501, never a fake result.
	writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
		"DynamoDB "+op+" is recognized but not yet implemented by the open-infra shim.")
}

// tableNameFromBody best-effort-reads "TableName" from a DynamoDB JSON body, restoring the body so
// nothing downstream is disturbed.
func tableNameFromBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	var body struct{ TableName string }
	_ = json.Unmarshal(buf, &body)
	return body.TableName
}
