package main

import (
	"encoding/xml"
	"log/slog"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// stsHandler fronts a minimal, faithful slice of AWS STS. STS is the identity service SDKs and
// tooling probe first (`aws sts get-caller-identity` is the canonical "who am I / does auth work"
// check), so fronting it makes the shim feel real to standard tooling. It is also the cleanest
// possible service: GetCallerIdentity has NO backend — it simply reflects the identity the shim
// already proved via SigV4, so there is nothing to translate and nothing to get subtly wrong.
//
// Protocol: AWS Query (form-encoded `Action=…` POST, XML response). Only GetCallerIdentity is
// implemented; every other action returns a faithful query-protocol error rather than a guess.
type stsHandler struct {
	account string // the open-infra "account" id surfaced in the ARN/Account fields
	logger  *slog.Logger
}

func (h *stsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	action := stsAction(r)
	switch action {
	case "GetCallerIdentity":
		// AWS allows GetCallerIdentity for ANY authenticated principal (no extra authorization) —
		// it only reports who you are. We mirror that: the request is already authenticated.
		h.writeCallerIdentity(w, claims, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"The STS action '"+action+"' is not implemented by this open-infra shim", stsXMLNamespace)
	}
}

func (h *stsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	// STS's dialect: a query-protocol <ErrorResponse> with the SignatureDoesNotMatch code.
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", stsXMLNamespace)
}

const stsXMLNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"

// stsAction extracts the query-protocol Action. It is in the form body (POST) or the query string.
func stsAction(r *http.Request) string {
	if err := r.ParseForm(); err == nil {
		if a := r.PostFormValue("Action"); a != "" {
			return a
		}
	}
	return r.URL.Query().Get("Action")
}

// getCallerIdentityResponse is the STS GetCallerIdentity XML body. SDKs read Arn/UserId/Account.
type getCallerIdentityResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserId  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func (h *stsHandler) writeCallerIdentity(w http.ResponseWriter, claims iam.Claims, requestID string) {
	var resp getCallerIdentityResponse
	// An open-infra-shaped ARN: honest about the provider, parseable by tools that split on ':'.
	resp.Result.Arn = "arn:openinfra:iam::" + h.account + ":user/" + claims.Sub
	resp.Result.UserId = claims.Sub
	resp.Result.Account = h.account
	resp.ResponseMetadata.RequestId = requestID

	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// errorResponse is the AWS Query-protocol error envelope (STS, IAM, EC2, …).
type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	Error     queryError
	RequestId string `xml:"RequestId"`
}

type queryError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// writeQueryError writes an AWS Query-protocol <ErrorResponse> with the given code/status.
func writeQueryError(w http.ResponseWriter, status int, code, requestID, message, xmlns string) {
	body := errorResponse{Xmlns: xmlns, RequestId: requestID}
	body.Error = queryError{Type: "Sender", Code: code, Message: message}
	out, err := xml.Marshal(body)
	if err != nil {
		http.Error(w, "InternalFailure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}
