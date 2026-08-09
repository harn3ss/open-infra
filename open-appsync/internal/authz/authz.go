// Package authz is field-level authorization for open-appsync — the "one policy
// world, now at field granularity" story. It is deliberately a thin PORT with no Kubernetes
// dependency: the neutral core (the executor) consults an Authorizer before running a field's
// resolver, and the production Authorizer (internal/k8sauth) bottoms out in a Kubernetes
// SubjectAccessReview — the SAME RBAC + permission boundary the console, Terraform, and the aws-shim
// use. No parallel authz, and no auth vocabulary in the step/runtime contract: authorization is a
// lifecycle concern, exactly like a data-source call.
package authz

import (
	"context"
	"errors"
)

// ErrDenied is returned by an Authorizer when the boundary rejects the caller. It surfaces on the
// field as an "Unauthorized" GraphQL error; the resolver never runs.
var ErrDenied = errors.New("unauthorized")

// Requirement is what a field needs the caller to be allowed to do, expressed as a Kubernetes
// SubjectAccessReview (a verb on a resource) — so the check is the shared RBAC boundary, not a bespoke
// rule. A zero Requirement means the field is public (no check).
type Requirement struct {
	Group     string `json:"group"`     // API group, e.g. "openinfra.dev"; "" for core
	Resource  string `json:"resource"`  // resource plural, e.g. "graphqlapis"
	Verb      string `json:"verb"`      // e.g. "get", "create"
	Namespace string `json:"namespace"` // "" for cluster-scoped / all namespaces
	Name      string `json:"name"`      // optional specific object name
}

// IsZero reports whether no authorization is required (a public field).
func (r Requirement) IsZero() bool {
	return r.Group == "" && r.Resource == "" && r.Verb == "" && r.Namespace == "" && r.Name == ""
}

// Identity is the authenticated caller, established UPSTREAM (the aws-shim's SigV4→principal, conveyed
// as X-OpenInfra-User/-Groups; or console impersonation). Username + groups feed the impersonated SAR.
type Identity struct {
	Username string
	Groups   []string
}

// Authorizer decides whether an Identity may access a field with the given Requirement. Returning nil
// means allow; ErrDenied (or a wrapped error) means deny.
type Authorizer interface {
	Authorize(ctx context.Context, id Identity, need Requirement) error
}

// AllowAll is the no-op authorizer used when field auth is not wired (dev/test, or an engine that
// relies solely on the shim's coarse gate). It allows everything — so a field with a Requirement is
// only actually enforced once a real Authorizer (k8sauth) is wired; main logs which is in effect.
type AllowAll struct{}

func (AllowAll) Authorize(context.Context, Identity, Requirement) error { return nil }

// Auth modes — the AppSync auth mode a request was authenticated with, mirrored to the SDL auth
// directives. Set SERVER-SIDE at the HTTP boundary from a validated credential (never trusted from the
// client, exactly like the identity), and read by the executor to enforce a field's `@aws_*` mode gate.
const (
	ModeAPIKey  = "aws_api_key" // request presented a valid API key → impersonates the key's mapped identity
	ModeIAM     = "aws_iam"
	ModeOIDC    = "aws_oidc"
	ModeLambda  = "aws_lambda"
	ModeCognito = "aws_cognito_user_pools"
)

// --- carrying the caller's identity + auth mode through the request context ---

type ctxKey struct{}
type modeKey struct{}

// NewContext returns ctx carrying the caller's identity (set by the HTTP boundary from the request).
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the caller's identity, or the zero Identity (anonymous) if none was set.
func FromContext(ctx context.Context) Identity {
	if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return id
	}
	return Identity{}
}

// WithMode returns ctx tagged with the auth mode the request was authenticated with (e.g. ModeAPIKey).
// Set only server-side from a validated credential.
func WithMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, modeKey{}, mode)
}

// Mode returns the request's authenticated auth mode, or "" if none (anonymous / header-identity).
func Mode(ctx context.Context) string {
	if m, ok := ctx.Value(modeKey{}).(string); ok {
		return m
	}
	return ""
}
