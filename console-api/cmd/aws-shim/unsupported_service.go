package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// writeUnsupportedService reports a service this shim does not front (#350 item T): HTTP 501 and code
// NotImplemented, in the error shape of the protocol the client spoke, so an SDK or the CLI reports
// "NotImplemented" with the message rather than an error it cannot parse ("Unknown"). The protocol is read
// off the request: S3's REST-XML, EC2's own Query shape, the other Query services' <ErrorResponse> (a form
// with an Action), the JSON-RPC services' __type (an X-Amz-Target), REST-XML for Route 53 and the S3
// control plane, and REST-JSON (the X-Amzn-ErrorType header) for the rest.
func writeUnsupportedService(w http.ResponseWriter, r *http.Request, service, requestID string) {
	msg := "AWS service '" + service + "' is not fronted by this open-infra shim"
	const code, status = "NotImplemented", http.StatusNotImplemented
	switch serviceDialect(service, r) {
	case "s3":
		writeS3ErrorMsg(w, code, status, requestID, msg)
	case "ec2":
		writeEC2Error(w, status, code, requestID, msg)
	case "query":
		writeQueryError(w, status, code, requestID, msg, "https://"+service+".amazonaws.com/doc/")
	case "rest-xml":
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(xmlHeader + "<ErrorResponse><Error><Type>Sender</Type><Code>" + code + "</Code><Message>" + xesc(msg) +
			"</Message></Error><RequestId>" + xesc(requestID) + "</RequestId></ErrorResponse>"))
	case "json":
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/x-amz-json-") {
			ct = "application/x-amz-json-1.1"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": msg})
	default: // rest-json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-amzn-RequestId", requestID)
		w.Header().Set("X-Amzn-ErrorType", code)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": msg, "__type": code})
	}
}

// serviceDialect is the error protocol a request to service speaks.
func serviceDialect(service string, r *http.Request) string {
	switch service {
	case "s3", "s3-object-lambda", "s3-outposts", "s3express":
		return "s3"
	case "ec2":
		return "ec2"
	case "route53", "route53domains-rest", "s3control", "cloudfront":
		return "rest-xml"
	}
	if r.Header.Get("X-Amz-Target") != "" {
		return "json"
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") != "" {
			return "query"
		}
	}
	if r.URL.Query().Get("Action") != "" {
		return "query"
	}
	return "rest-json"
}
