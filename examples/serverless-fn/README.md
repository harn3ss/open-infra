# serverless-fn — scale-to-zero HTTP (open-infra's "Lambda")

A one-file example of `kind: Function`: a container that serves HTTP, autoscaled
by Knative from **0→N→0** based on traffic.

## Deploy

```bash
cd examples/serverless-fn
open-infra deploy          # applies the Function; Knative fans it out
open-infra status          # watch it under "Functions"
```

(or `open-infra init function` in your own repo to scaffold this from scratch.)

## What happens

- Knative creates a Service; with no traffic it **scales to zero** (0 pods, 0 cost).
- The first request **cold-starts** a pod (0→1) and is served once it's ready.
- Under load it scales up to `max`; when idle it scales back to zero.

Verify scale-to-zero from inside the cluster:

```bash
# after ~90s idle, pods drop to 0:
kubectl -n <ns> get pods -l serving.knative.dev/service=serverless-fn
# a request wakes it (0->1):
kubectl run hit --rm -it --image=curlimages/curl --restart=Never -- \
  curl -s http://serverless-fn.<ns>.svc.cluster.local
```

## Notes

- **Functions are stateless** — they connect to resources, they don't own them.
  To use a database/bucket, provision it on an `Application` and reference its
  secret here: `spec.secrets: [api-db-app]`. For event-driven work, set
  `spec.queues: [...]` (injects `NATS_URL` + `OPENINFRA_QUEUES`).
- **Serverless GPU**: set `spec.gpu: 1` for on-demand inference that releases the
  GPU when idle (cold start = pod + model load). See [`docs/serverless.md`](../../docs/serverless.md).
