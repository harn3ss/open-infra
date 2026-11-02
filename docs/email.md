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

## A test cluster: capture instead of deliver

With `mail.capture: true` (alongside `components.mail: true`), the relay is a capturing sink
(`platform/mail/relay-capture.yaml`, Mailpit) in place of the delivering postfix relay. It is the same
`smtp-relay` Service on the same ports, so apps and the aws-shim's SES front door send to it unchanged —
but it keeps every message and delivers none: it relays nowhere, and its pod may open no connection at
all. Read what was sent through its API, which listens on the pod's loopback only:

```sh
kubectl -n mail exec deploy/smtp-relay -- wget -qO- http://127.0.0.1:8025/api/v1/messages
```

Messages are kept in memory (the newest 1,000) and go with the pod. Use it to test a template that sends
email, and its UserData, without mailing anyone.

## AWS SDK code (SES)

The aws-shim fronts SES over this relay — v1 `SendEmail` and `SendRawEmail`, and v2 `SendEmail` — so
unmodified SDK code, and an EC2 instance role from a CloudFormation template, can send, as an address identity
or any address of a domain identity its policy names ([aws-shim.md](aws-shim.md#ses-v1-sendemail--sendrawemail-and-v2-sendemail-over-the-platform-smtp-relay-probe-proven)).
SES is served only while this component is on.

## Status and scope

The SES path is probe-proven (`probe/aws-shim-ses.sh`), in capture mode. Internet deliverability through a
smarthost is environment-dependent and yours to verify. A per-identity SMTP AUTH credential is a
documented follow-on.
