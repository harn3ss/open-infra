package main

import (
	"context"
	"encoding/xml"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
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
// roleResolver looks up a kind: Role's trust (who may assume it) and the groups an assumed session
// acts as. Backed by a dynamic k8s client in production and a fake in tests.
type roleResolver interface {
	Resolve(ctx context.Context, roleName string) (trust []string, groups []string, ok bool)
}

// tokenReviewer verifies a projected ServiceAccount token (the web-identity token) and returns the
// SA username ("system:serviceaccount:<ns>:<sa>"). Backed by a k8s TokenReview in production. nil
// disables AssumeRoleWithWebIdentity (workload identity).
type tokenReviewer interface {
	Review(ctx context.Context, token string) (username string, ok bool)
}

type stsHandler struct {
	account string         // the open-infra "account" id surfaced in the ARN/Account fields
	minter  *awssts.Minter // mints sts:AssumeRole session tokens; nil disables AssumeRole
	roles   roleResolver   // resolves a role's trust policy + session groups; nil disables AssumeRole
	webID   tokenReviewer  // verifies workload SA tokens; nil disables AssumeRoleWithWebIdentity
	logger  *slog.Logger
}

func (h *stsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	action := stsAction(r)
	switch action {
	case "GetCallerIdentity":
		// AWS allows GetCallerIdentity for ANY authenticated principal (no extra authorization) —
		// it only reports who you are. We mirror that: the request is already authenticated.
		h.writeCallerIdentity(w, claims, requestID)
	case "AssumeRole":
		h.assumeRole(w, r, claims, requestID)
	case "AssumeRoleWithWebIdentity":
		// Reachable pre-auth via the router (the web-identity token IS the credential); if it
		// arrives here it was SigV4-authenticated, which is fine too — the token still governs.
		h.assumeRoleWithWebIdentity(w, r, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"The STS action '"+action+"' is not implemented by this open-infra shim", stsXMLNamespace)
	}
}

// assumeRole implements a faithful sts:AssumeRole. It authorizes the caller against the target
// role's trust policy (who may assume), then mints a temporary credential (AccessKeyId +
// SecretAccessKey + SessionToken) that acts AS the role. Fails closed: assume disabled, an unknown
// role, or a caller not named by the trust policy all deny.
func (h *stsHandler) assumeRole(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.minter == nil || h.roles == nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"sts:AssumeRole is not enabled on this shim (no signing key configured)", stsXMLNamespace)
		return
	}
	_ = r.ParseForm()
	roleName := roleNameFromArn(r.PostFormValue("RoleArn"))
	sessionName := r.PostFormValue("RoleSessionName")
	if roleName == "" || sessionName == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"AssumeRole requires RoleArn and RoleSessionName", stsXMLNamespace)
		return
	}
	trust, groups, ok := h.roles.Resolve(r.Context(), roleName)
	if !ok {
		// AWS returns AccessDenied (not "not found") so a caller can't probe which roles exist.
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			"not authorized to perform sts:AssumeRole on role "+roleName, stsXMLNamespace)
		return
	}
	caller := callerName(claims)
	if !trusted(caller, trust) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			caller+" is not authorized to assume role "+roleName+" (not named by its trust policy)", stsXMLNamespace)
		return
	}
	ttl := awssts.DefaultDuration
	if d := r.PostFormValue("DurationSeconds"); d != "" {
		if secs, err := strconv.Atoi(d); err == nil {
			ttl = time.Duration(secs) * time.Second
		}
	}
	akid, sk, token, exp, err := h.minter.Mint(roleName, groups, sessionName, caller, ttl)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeAssumeRole(w, roleName, sessionName, akid, sk, token, exp, requestID)
}

// assumeRoleWithWebIdentity implements a faithful sts:AssumeRoleWithWebIdentity — the workload
// identity (IRSA) path. A pod presents its projected ServiceAccount token; the shim verifies it via
// a k8s TokenReview, then authorizes the SA against the role's trust policy and mints session
// credentials for the role. No static keys, no SigV4 on this call: the SA token IS the credential.
func (h *stsHandler) assumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request, requestID string) {
	if h.minter == nil || h.roles == nil || h.webID == nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"sts:AssumeRoleWithWebIdentity is not enabled on this shim", stsXMLNamespace)
		return
	}
	_ = r.ParseForm()
	roleName := roleNameFromArn(r.PostFormValue("RoleArn"))
	token := r.PostFormValue("WebIdentityToken")
	sessionName := r.PostFormValue("RoleSessionName")
	if roleName == "" || token == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"AssumeRoleWithWebIdentity requires RoleArn and WebIdentityToken", stsXMLNamespace)
		return
	}
	username, ok := h.webID.Review(r.Context(), token)
	if !ok {
		// STS's dialect for a bad web-identity token.
		writeQueryError(w, http.StatusBadRequest, "InvalidIdentityToken", requestID,
			"the web identity token could not be validated", stsXMLNamespace)
		return
	}
	trust, groups, ok := h.roles.Resolve(r.Context(), roleName)
	if !ok || !trusted(username, trust) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			username+" is not authorized to assume role "+roleName+" (not named by its trust policy)", stsXMLNamespace)
		return
	}
	if sessionName == "" {
		sessionName = saShortName(username)
	}
	ttl := awssts.DefaultDuration
	if d := r.PostFormValue("DurationSeconds"); d != "" {
		if secs, err := strconv.Atoi(d); err == nil {
			ttl = time.Duration(secs) * time.Second
		}
	}
	akid, sk, tok, exp, err := h.minter.Mint(roleName, groups, sessionName, username, ttl)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeWebIdentity(w, roleName, sessionName, username, akid, sk, tok, exp, requestID)
}

// saShortName turns "system:serviceaccount:ns:sa" into "sa" for a default session name.
func saShortName(username string) string {
	parts := strings.Split(username, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return username
}

// roleNameFromArn accepts an arn:openinfra:iam::<acct>:role/<name> or a bare role name.
func roleNameFromArn(arn string) string {
	arn = strings.TrimSpace(arn)
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return arn[i+len(":role/"):]
	}
	return arn
}

// callerName is the principal the trust policy is evaluated against: the User's name, or (for a
// chained assume) the already-assumed role's name.
func callerName(c iam.Claims) string {
	if c.AssumedRole != "" {
		return c.AssumedRole
	}
	return c.Sub
}

// trusted reports whether the caller is named by the trust policy. "*" trusts any authenticated
// principal (AWS's Principal:"*" trust); otherwise an exact name match.
func trusted(caller string, trust []string) bool {
	for _, t := range trust {
		if t == "*" || t == caller {
			return true
		}
	}
	return false
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

// assumeRoleResponse is the STS AssumeRole XML body — SDKs read Credentials + AssumedRoleUser.
type assumeRoleResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleId string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func (h *stsHandler) writeAssumeRole(w http.ResponseWriter, role, session, akid, sk, token string, exp time.Time, requestID string) {
	var resp assumeRoleResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.Result.AssumedRoleUser.Arn = "arn:openinfra:iam::" + h.account + ":assumed-role/" + role + "/" + session
	resp.Result.AssumedRoleUser.AssumedRoleId = role + ":" + session
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

// assumeRoleWithWebIdentityResponse is the STS AssumeRoleWithWebIdentity XML body.
type assumeRoleWithWebIdentityResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleId string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
		SubjectFromWebIdentityToken string `xml:"SubjectFromWebIdentityToken"`
		Provider                    string `xml:"Provider"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func (h *stsHandler) writeWebIdentity(w http.ResponseWriter, role, session, subject, akid, sk, token string, exp time.Time, requestID string) {
	var resp assumeRoleWithWebIdentityResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.Result.AssumedRoleUser.Arn = "arn:openinfra:iam::" + h.account + ":assumed-role/" + role + "/" + session
	resp.Result.AssumedRoleUser.AssumedRoleId = role + ":" + session
	resp.Result.SubjectFromWebIdentityToken = subject
	resp.Result.Provider = "openinfra:serviceaccount"
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

func (h *stsHandler) writeCallerIdentity(w http.ResponseWriter, claims iam.Claims, requestID string) {
	var resp getCallerIdentityResponse
	// An open-infra-shaped ARN: honest about the provider, parseable by tools that split on ':'.
	// An assumed-role session reports the assumed-role ARN (claims.Sub is "assumed-role/<role>/<sess>").
	if claims.AssumedRole != "" {
		resp.Result.Arn = "arn:openinfra:iam::" + h.account + ":" + claims.Sub
	} else {
		resp.Result.Arn = "arn:openinfra:iam::" + h.account + ":user/" + claims.Sub
	}
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
