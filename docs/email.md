# Transactional email (`kind: EmailSender`)

`kind: EmailSender` provisions a sending identity for transactional email — the AWS SES-shaped
primitive. Each claim emits a `<name>-smtp` connection secret that apps consume via the existing
`spec.secrets` → `envFrom`, exactly like the `<name>-minio` bucket-credential convention.

It rides the opt-in **`mail`** component (which also deploys the shared SMTP relay). Enable it with
`components.mail: true`.

```yaml
apiVersion: openinfra.dev/v1
kind: EmailSender
metadata: { name: notify, namespace: shop }
spec:
  fromAddress: noreply@shop.example.com
  fromName: "Shop Notifications"
```

The `notify-smtp` secret holds `SMTP_HOST` (the in-cluster relay), `SMTP_PORT` (587), `SMTP_FROM`,
and `SMTP_FROM_NAME`. Reference it from an app:

```yaml
apiVersion: openinfra.dev/v1
kind: Application
metadata: { name: web, namespace: shop }
spec:
  image: ghcr.io/acme/web:1.2.3
  secrets: [notify-smtp]     # SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_FROM_NAME as env vars
```

Send with any SMTP client pointed at `SMTP_HOST:SMTP_PORT`. The relay is ClusterIP-only and relays
for in-cluster senders, so no per-sender credential is minted in this slice.

## The honest part: deliverability

Getting mail *accepted* by the internet is the hard, non-automatic part, and open-infra does not
pretend otherwise:

- **Direct delivery from a cluster IP usually fails** — outbound port 25 is commonly blocked, and
  mail without correct reverse DNS / SPF / DKIM / DMARC is dropped or spam-filed.
- **The realistic path is a smarthost.** Set `RELAYHOST` (and `RELAYHOST_USERNAME` /
  `RELAYHOST_PASSWORD`) in the `smtp-relay-config` Secret (namespace `mail`) to forward through a
  reputable provider (Amazon SES, SendGrid, Mailgun, or your own MTA). Empty by default
  (best-effort direct delivery).
- **SPF / DKIM / DMARC** on the sending domain are DNS records you own — an operator responsibility,
  outside the cluster.

The relay image is pinned but should be confirmed against its releases before you rely on it.

## Status and scope

Built; not yet live-verified end-to-end (deliverability is environment-dependent). A per-identity
SMTP AUTH credential, and an optional AWS-SDK **SES** shim verb (`SendEmail` / `SendRawEmail`
relaying to this service, so unmodified AWS SDK code works) are documented follow-ons, not in this
first slice.
