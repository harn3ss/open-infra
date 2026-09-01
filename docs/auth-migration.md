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

## Explicitly out of scope

**User-pool management** — creating pools, sign-up/sign-in/forgot-password flows, a hosted login
UI, or programmatic user CRUD against a managed pool — is **not** in scope. open-infra consumes
the tokens a pool issues; it is not a Cognito replacement. If a specific pilot genuinely requires
managed sign-up/sign-in hosted by open-infra, that is a separate, scoped build to be filed on its
own — not smuggled in here.

## Honest status

The JWT-consumption and group-mapping mechanics above are verified by the engine's test suite and
its live slice-1 runs. The end-to-end observation *against the pilot's own representative app*
(its exact pool, its exact directives, all three auth modes in one flow) belongs to the
pilot-readiness sweep and is tracked there — this note defines the path and the boundary; that
sweep is where it is watched working against the real app.
