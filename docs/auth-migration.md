# Migrating a Cognito-fronted AppSync app's auth

This is the honest auth-migration path for an app whose GraphQL API is fronted by **Amazon
Cognito** (or another OIDC IdP). The boundary, stated plainly:

- **Consume a JWT: yes.** open-infra's AppSync engine (open-appsync) verifies and enforces
  Cognito/OIDC bearer tokens on the request path, across all five AWS AppSync auth modes.
- **Manage a user pool: no.** open-infra does **not** host or manage a Cognito-equivalent user
  pool — no sign-up/sign-in flows, no hosted UI, no user-pool CRUD. Identity is supplied by an
  external IdP; open-infra is a relying party, not an identity provider.

## What open-infra consumes today

A request to the GraphQL API carries a bearer token; the [aws-shim](aws-shim.md) verifies it
(issuer, audience, expiry, signature) and stamps the request with the authenticated mode and the
mapped identity, which the engine then enforces. The five AppSync auth modes are all **enforced**
(not advisory):

- `@aws_api_key` — an API key from the API's mounted Secret.
- `@aws_iam` — a SigV4-signed request (service `appsync`).
- `@aws_cognito_user_pools` — a Cognito user-pool JWT; `@aws_cognito_user_pools(cognito_groups:)`
  additionally requires the caller to be in one of the listed groups, **fail-closed**.
- `@aws_oidc` — any OIDC-issued JWT.
- `@aws_lambda` — a Lambda-authorizer decision.

The token's subject and groups flow into the field's SubjectAccessReview authorization — **one
policy world**: the same impersonated, fail-closed check the rest of open-infra uses. A field
marked with an auth directive denies a request that does not satisfy it. (Enforcement is covered
by the engine's `auth_directives`, `oidc_auth`, `nested_auth`, and `lambda_auth` tests.)

## The two migration paths

**Path A — keep the external IdP (recommended, lowest-friction).**
Point the app at its existing Cognito user pool (or any OIDC IdP). The frontend authenticates
against Cognito exactly as it does on AWS and obtains a JWT; the GraphQL API on open-infra
verifies that JWT and enforces the `@aws_cognito_user_pools` / `@aws_oidc` directives. Nothing
about the pool changes — you are re-pointing the *relying party*, not migrating the identity
store. `cognito:groups` claims map straight onto the group-scoped field authorization.

**Path B — open-infra IAM + OIDC (when you want to leave Cognito).**
Issue tokens from an OIDC IdP you run (Keycloak/Dex, or the `kind: Directory` LDAP path), and
model authorization with open-infra IAM (`kind: User`/`Group`/`Policy`/`Role`). The app's fields
move from `@aws_cognito_user_pools` to `@aws_oidc`, and group membership comes from your IdP's
claims. This removes the Cognito dependency entirely, at the cost of standing up and operating an
IdP — which is identity-provider work open-infra does not do for you.

## Issuing tokens: `kind: UserPool` (experimental)

Beyond consuming tokens, open-infra can now **issue** them. `kind: UserPool` provisions a managed
OIDC identity provider (Keycloak) — a realm is the pool, a client is an app client — with sign-up /
sign-in, a hosted login UI, and OIDC JWT issuance: the open-source path to an AWS Cognito User Pool.
It emits a connection secret (`ISSUER_URL` / `REALM` / `CLIENT_ID` / `CLIENT_SECRET` / `ADMIN_*`);
pointing a consumer's OIDC issuer (e.g. the AWS-shim's `OIDC_ISSUER`) at that `ISSUER_URL` makes the
`@aws_oidc` / `@aws_cognito_user_pools` enforcement above verify its tokens — the loop closes with no
code change.

This is **experimental**: the first slice runs Keycloak in dev mode on an embedded database
persisted to a PVC — a real, functional issuer, not yet a hardened multi-replica, Postgres-backed
deployment. Programmatic user CRUD (a self-service management API) and a themed login UI are not yet
built. Prefer an external IdP where a hardened, HA identity provider is required.

## Honest status

The JWT-consumption and group-mapping mechanics above are verified by the engine's test suite and
its live slice-1 runs. The end-to-end observation against a representative app — its exact pool,
its exact directives, all three auth modes in one flow — is a separate live-verification step;
this note defines the path and the boundary, not that whole-flow observation.
