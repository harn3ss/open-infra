# Model Registry & serving trained models — kind: ModelPackage

`kind: ModelPackage` is open-infra's **model registry** — the SageMaker Model Registry
equivalent. It records a **versioned, approvable** pointer to a trained model artifact
(in the object store) and the container that serves it, closing the loop from training
(`kind: TrainingJob`) to serving (`kind: Model`).

The flow is: **train → register → approve → serve.**

## 1. Register a trained model

After a `kind: TrainingJob` writes an artifact to a bucket, register it:

```yaml
apiVersion: openinfra.dev/v1
kind: ModelPackage
metadata:
  name: fraud-v3
spec:
  modelName: fraud-detector      # the model group; versions share this name
  version: "3"
  artifact:
    bucket: models
    key: fraud/v3/model.pt
  image: my-registry/fraud-serving:1   # a container that loads the artifact + serves HTTP
  port: 8000
  framework: pytorch
  metrics: '{"auc": 0.94}'
  approvalStatus: PendingManualApproval  # the gate (default)
```

A ModelPackage is a **record** — it runs nothing on its own.

**From the console (one click).** On a finished `kind: TrainingJob`'s detail page,
**Register as Model Package** does the above for you: it copies the run's output bucket/key
into a new package, and you supply the serving image (which is *not* the training image) and,
optionally, a version. The package is created `PendingManualApproval`.

This registration is authorized **as you**, not by a background controller: the console
(BFF) runs a `SubjectAccessReview` for your own `create modelpackages` right before it creates
anything, and fails closed. That is deliberate — the identity that may *run* a training job is
not automatically the identity that may *publish a servable model*. Registration never
approves, and promoting to a served `kind: Model` is a second, separately authorized step, so a
user who can train but not serve cannot reach an endpoint through this path.

## 2. Approve it

A package starts `PendingManualApproval`. Only an **Approved** package should be
promoted — the same separation of registry from promotion SageMaker enforces. Approve
from the console (Model Registry → the package → **Approve**) or by editing
`spec.approvalStatus` to `Approved` (or `Rejected`).

## 3. Serve it

Promote an Approved package to a served endpoint — from the console, the package's
**Deploy endpoint** button creates a `kind: Model` for you; or declare it directly with
Model's `serve`:

```yaml
apiVersion: openinfra.dev/v1
kind: Model
metadata:
  name: fraud-endpoint
spec:
  serve:                          # serve a custom artifact instead of a catalog model
    image: my-registry/fraud-serving:1
    port: 8000                    # NOT 8080 (reserved for the key-gate proxy)
    artifact:
      bucket: models
      key: fraud/v3/model.pt
    gpu: 0                        # or 1 + gpuTier for GPU inference
    modelPackage: fraud-v3        # provenance
```

`kind: Model` gains everything the catalog path already has: the **key-gated endpoint**
(a generated API key; unauthenticated calls get 401), a Service, an optional LAN IP
(`expose`) and external Ingress+TLS (`domain`), and a connection secret. The serving
container is handed the artifact location and S3-compatible credentials
(`ARTIFACT_BUCKET` / `ARTIFACT_KEY`, `AWS_ENDPOINT_URL` / `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`) and is expected to download the artifact and serve HTTP on
`serve.port`.

Set **either** `model` (a catalog model on Ollama) **or** `serve` (a custom artifact),
not both.

## The serving container contract

The `serve.image` must:
- read `ARTIFACT_BUCKET` / `ARTIFACT_KEY` and download the artifact (S3 creds injected),
- serve HTTP on `serve.port` (`PORT` is also injected),
- respond to your inference requests (the key-gate proxy forwards authenticated calls).

Use a purpose-built serving image (TorchServe, a FastAPI app, etc.) — the same idea as
a SageMaker inference container. `serve.command`/`serve.args` can override the entrypoint
for a generic base image.

## Notes

- **Approval is a governance gate, not a hard admission control in v1:** the console's
  Deploy action is enabled only for Approved packages, but a Model with `serve` can also
  be created directly (the raw path). Treat ModelPackage + approval as the governed MLOps
  flow on top.
- Registry records are cheap; a served endpoint is a running Model — delete the Model to
  stop serving; the package (and artifact) remain for the next promotion.
