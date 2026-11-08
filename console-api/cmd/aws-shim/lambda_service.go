// The Lambda service port (LAMBDA_SERVICE_LISTEN, default :4568): what a function's execution environment
// takes from Lambda itself, and nothing else — its stored deployment package (/v1/function-code, with its
// own identity token) and its execution role's credentials (sts:AssumeRoleWithWebIdentity, unsigned, the
// token in the form is the credential). On Lambda neither is the function's own network traffic, so no
// security group filters it: a function in a VPC is always allowed to this port (a security group in a VPC
// allows its members to it, securitygroup-composition.yaml), while the handler's own AWS calls go to the
// front door (:4566), which its security groups govern — as a function in an AWS VPC needs a NAT gateway or
// a VPC endpoint to call AWS. Every other request here is answered 404, as a path the port does not have.
package main

import (
	"net/http"
	"strings"
)

// lambdaServiceOnly passes next only the requests the Lambda service port serves.
func lambdaServiceOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == functionCodePath:
		case r.URL.Path == "/" && r.Header.Get("Authorization") == "" && !strings.Contains(r.URL.RawQuery, "X-Amz-Credential") &&
			isWebIdentityAssume(r):
		default:
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
