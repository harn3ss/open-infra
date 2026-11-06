# Transactional email (Amazon SES)

open-infra sends email the way Amazon SES does. Every message goes through the aws-shim's SES front door —
the SES API (v1 `SendEmail` / `SendRawEmail`, v2 `SendEmail`) or the **SES SMTP interface** — which
authenticates the sender, authorizes every address the message is sent as with IAM policy, checks that the
sender's account has verified that identity, and hands the message to the platform's SMTP relay. The relay
accepts mail from the aws-shim only: no pod can submit to it directly, and no unauthenticated mail is
relayed.

Email rides the opt-in **`mail`** component, which deploys the relay and `kind: EmailSender`. Sending goes
through the aws-shim, so turn on both:

```yaml
components:
  awsShim: true
  mail: true
```

## `kind: EmailSender`: SMTP credentials for one sender

An `EmailSender` is a sending identity — a From address — and Amazon SES SMTP credentials that can send as
that address and nothing else:

```yaml
apiVersion: openinfra.dev/v1
kind: EmailSender
metadata: { name: notify, namespace: shop }
spec:
  fromAddress: noreply@shop.example.com
  fromName: "Shop Notifications"
```

In the AWS account its namespace belongs to, the claim gets what the SES console's "Create SMTP
credentials" makes:

- an IAM user, `ses-smtp-user-<id>`, whose only permission is an inline policy, `AmazonSesSendingAccess`,
  allowing `ses:SendRawEmail` on the From address's identity
  (`arn:aws:ses:*:*:identity/noreply@shop.example.com`);
- an access key for that user, and the SES SMTP password derived from its secret;
- a connection secret, `notify-smtp`, in the claim's namespace.

The secret holds:

| Key | Value |
|---|---|
| `SMTP_HOST` | `aws-shim.open-infra-aws-shim.svc.cluster.local` (the SES SMTP interface) |
| `SMTP_PORT` | `587` (STARTTLS) |
| `SMTP_USERNAME` | the access key id |
| `SMTP_PASSWORD` | the SMTP password |
| `SMTP_FROM` | the From address |
| `SMTP_FROM_NAME` | the display name |

Reference it from an app, like a bucket's `<name>-minio` secret:

```yaml
apiVersion: openinfra.dev/v1
kind: Application
metadata: { name: web, namespace: shop }
spec:
  image: ghcr.io/acme/web:1.2.3
  secrets: [notify-smtp]     # SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_FROM_NAME
```

The app sends with any SMTP client: connect to `SMTP_HOST:SMTP_PORT`, issue `STARTTLS`, sign in with
`SMTP_USERNAME` / `SMTP_PASSWORD` (AUTH PLAIN or LOGIN), and send with `SMTP_FROM` as both the envelope sender
(MAIL FROM) and the `From` header. A message sent as any other address is refused.

The claim's status shows the identity and its verification:

```sh
kubectl -n shop get emailsender notify
# NAME     FROM                       VERIFICATION   SECRET
# notify   noreply@shop.example.com   SUCCESS        notify-smtp
```

`status.verificationStatus` is `SUCCESS` when the From address is a verified identity of the claim's account
and `PENDING` until it is ([verified identities](#verified-identities-and-the-sandbox)). While it is
`PENDING`, the credentials sign in but every send is refused (`554 Message rejected: Email address is not
verified`), as on SES. `status.iamUser` / `status.iamUserArn` name the IAM user and `status.smtpUsername`
its access key id. Deleting the claim deletes the user, its access key and the secret.

## The SES SMTP interface

The aws-shim's Service serves SMTP submission the way `email-smtp.<region>.amazonaws.com` does:

| Port | Encryption |
|---|---|
| `587` | STARTTLS (connect in clear, then `STARTTLS` before signing in) |
| `465` | TLS Wrapper (TLS from the first byte) |

The connection must be encrypted before credentials are sent. The certificate is the aws-shim's in-cluster
certificate, issued by the platform root CA for `aws-shim.open-infra-aws-shim.svc` and
`aws-shim.open-infra-aws-shim.svc.cluster.local`. A client that verifies certificates needs the root CA,
which the aws-shim serves at `http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/v1/ca-bundle` (and
which every VM guest already trusts).

Each message is SES `SendRawEmail`, as the signed-in IAM user: MAIL FROM is its `Source`, the RCPT TO
addresses its `Destinations`, and the message is sent as received. It is authorized as `SendRawEmail` is,
on every address it is sent as — MAIL FROM and each address in the `From` header — so the envelope cannot
launder a header identity the user may not use. The replies are SES's:

| Reply | When |
|---|---|
| `220 email-smtp.amazonaws.com ESMTP …` | the greeting |
| `250 Ok <MessageId>` | the relay accepted the message |
| `235 …` | signed in |
| `530 Must issue a STARTTLS command first` | AUTH on a connection that is not encrypted |
| `530 Authentication required` | MAIL before signing in |
| `535 Authentication Credentials Invalid` | a wrong user name or password, an inactive or deleted access key, a password derived for another region |
| `454 Temporary authentication failure` | more than 10 failed sign-ins in 5 minutes from one address, or for one access key |
| `553 <address> Invalid email address` | a MAIL FROM that is not one address |
| `554 Access denied: …` | the user's policy does not allow `ses:SendRawEmail` as an address the message is sent as |
| `554 Message rejected: Email address is not verified. The following identities failed the check in region <REGION>: …` | an identity the account has not verified (and, in the sandbox, a recipient it has not verified) |
| `552 Message is too long.` | a message over 10 MB |
| `451 Temporary service failure` | the relay could not take the message; retry |

A message has at most 50 recipients.

## Getting SMTP credentials

SES SMTP credentials belong to an IAM user. The SMTP user name is the user's **access key id**; the SMTP
password is **derived from the access key's secret** — it is not the secret itself. An `EmailSender` makes
the user, the key and the password for you. To send as an existing IAM user instead:

1. Give the user `ses:SendRawEmail` on the identities it sends as. AWS's `AmazonSesSendingAccess` allows
   every identity:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{ "Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "*" }]
   }
   ```

   To send as one address, or every address of one domain, name its identity:
   `"Resource": "arn:aws:ses:*:*:identity/noreply@example.com"` or `"arn:aws:ses:*:*:identity/example.com"`.

2. Create an access key for the user (IAM `CreateAccessKey`, or the console's Security credentials), and
   derive the SMTP password from its secret with AWS's algorithm, in the install's region (`AWS_REGION` of
   the `openinfra-aws-identity` ConfigMap, `us-east-1` by default):

   ```python
   import base64, hashlib, hmac

   def smtp_password(secret_access_key, region):
       def sign(key, msg):
           return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
       sig = sign(("AWS4" + secret_access_key).encode("utf-8"), "11111111")
       for part in (region, "ses", "aws4_request", "SendRawEmail"):
           sig = sign(sig, part)
       return base64.b64encode(bytes([0x04]) + sig).decode("utf-8")
   ```

   This is AWS's published conversion ("Obtaining Amazon SES SMTP credentials"), so the password is the one
   AWS's own `smtp_credentials_generate.py` prints for the same secret and region.

Temporary credentials (an assumed role's session) cannot be converted, as on AWS.

The `ses:FromAddress` condition key is not supported: an `Allow` conditioned on it grants nothing, and a
`Deny` conditioned on it applies unconditionally. Scope a user to its addresses with the identity ARN in
`Resource`, as above.

## Verified identities and the sandbox

SES sends only as identities the account has verified. Identities are an account's own:

- **The management account** (the install's own) sends as every identity the relay is configured for: the
  sending domains you back with DNS and the relay's smarthost.
- **A member account** sends only as the identities its `kind: Account` lists — domains (every address at
  the domain; a subdomain is an identity of its own) and email addresses. SES verifies an identity by proving
  its owner controls it (a DNS record, a confirmation link); you hold the DNS and the relay, so you verify
  identities for an account by recording them on it:

  ```yaml
  apiVersion: organizations.openinfra.dev/v1
  kind: Account
  metadata: { name: "912345678901" }
  spec:
    accountId: "912345678901"
    namespaces: [team-a]
    ses:
      verifiedIdentities: [shop.example.com, alerts@example.org]
      productionAccessEnabled: true
  ```

  A member account is in the **SES sandbox** until `productionAccessEnabled` is set: in the sandbox it also
  sends only **to** its verified identities, as AWS's sandbox allows. Changes take effect within a minute.

`VerifyEmailIdentity`, `VerifyDomainIdentity` and `CreateEmailIdentity` are refused: the platform will not
report an identity verified that no DNS backs. A member account's `ListIdentities`,
`GetIdentityVerificationAttributes`, `ListEmailIdentities` and `GetEmailIdentity` answer its verified
identities, and `GetAccount` its sandbox status. The SES sending quotas (`GetSendQuota`) are reported as
unbounded and are not enforced; the limit is the relay's smarthost.

## Deliverability

Getting mail *accepted* by the internet is not automatic:

- **Direct delivery from a cluster IP usually fails** — outbound port 25 is commonly blocked, and mail
  without correct reverse DNS / SPF / DKIM / DMARC is dropped or spam-filed.
- **The realistic path is a smarthost.** Set `RELAYHOST` (and `RELAYHOST_USERNAME` /
  `RELAYHOST_PASSWORD`) in the `smtp-relay-config` Secret (namespace `mail`) to forward through a
  reputable provider (Amazon SES, SendGrid, Mailgun, or your own MTA). Empty by default (best-effort
  direct delivery).
- **SPF / DKIM / DMARC** on the sending domain are DNS records you own, outside the cluster.

The relay image is pinned but should be confirmed against its releases before you rely on it.

## A test cluster: capture instead of deliver

With `mail.capture: true` (alongside `components.mail: true`), the relay is a capturing sink
(`platform/mail/relay-capture.yaml`, Mailpit) in place of the delivering postfix relay. It is the same
`smtp-relay` Service, taking mail from the aws-shim alone, so the SES API and the SMTP interface send to it
unchanged — but it keeps every message and delivers none: it relays nowhere, and its pod may open no
connection at all. Read what was sent through its API, which listens on the pod's loopback only:

```sh
kubectl -n mail exec deploy/smtp-relay -- wget -qO- http://127.0.0.1:8025/api/v1/messages
```

Messages are kept in memory (the newest 1,000) and go with the pod. Use it to test a template that sends
email, and its UserData, without mailing anyone.

## AWS SDK code (the SES API)

Unmodified SDK code, and an EC2 instance role from a CloudFormation template, can send through the SES API —
v1 `SendEmail` and `SendRawEmail`, and v2 `SendEmail` — as an address identity or any address of a domain
identity its policy names ([aws-shim.md](aws-shim.md#ses-v1-sendemail--sendrawemail-and-v2-sendemail-over-the-platform-smtp-relay-probe-proven)).
SES is served only while the `mail` component is on.

## Status and scope

The SES API is probe-proven (`probe/aws-shim-ses.sh`), in capture mode. The SMTP interface has its probe,
`probe/aws-shim-ses-smtp.sh` (derived credentials, the `530` / `535` / `554` refusals, a member account's
verified identities), which has not yet run against a live cluster. Internet deliverability through a
smarthost is environment-dependent and yours to verify.
