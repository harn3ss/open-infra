# Cognito sign-in (real JWT-issuing user pool)

A minimal target app for the [Cognito doorway](../../docs/aws-shim.md) on the AWS-SDK shim: create a user
pool, sign up + confirm a user, and sign in to get **real RS256 JWTs** that verify against the pool's JWKS —
the same tokens an [API Gateway JWT authorizer](../apigw-lambda/) (or any app) validates. It uses **boto3
unmodified** — only `AWS_ENDPOINT_URL` points at the shim — and the end-user calls are unsigned, exactly as
on AWS.

```sh
export AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566

# control-plane (signed, an admin principal): create the pool + app client
AWS_ACCESS_KEY_ID=<admin key> AWS_SECRET_ACCESS_KEY=<secret> python signin.py setup
# → pool=us-east-1_xxxxxxxxx  client=xxxxxxxxxxxxxxxxxxxxxxxxxx

# end-user flow (unsigned): sign up + sign in
python signin.py signin us-east-1_xxxxxxxxx <client> alice 'Sup3r!Secret9'
# → real id/access/refresh JWTs
```

The pool's issuer is `${AWS_ENDPOINT_URL}/cognito/<pool-id>`, and its JWKS is served at
`…/cognito/<pool-id>/.well-known/jwks.json` — point an API Gateway JWT authorizer's `Issuer` there
(`Audience` = the app client id) and it admits these tokens.

## Notes

- **Supported flows:** `USER_PASSWORD_AUTH`, `ADMIN_USER_PASSWORD_AUTH`, `REFRESH_TOKEN_AUTH`. SRP and custom
  auth are refused (not half-implemented). Identity pools and the hosted UI are out of scope.
- **Password policy** is genuinely enforced at sign-up / `AdminSetUserPassword`.
- **`GlobalSignOut`** genuinely invalidates a user's already-issued tokens (a per-user cutoff).
- There is no email/SMS delivery, so `SignUp` confirmation codes aren't verified — use `AdminConfirmSignUp`
  (the reliable path). MFA is refused rather than advertised-and-not-enforced.
