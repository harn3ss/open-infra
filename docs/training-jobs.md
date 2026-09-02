# Model training — kind: TrainingJob

`kind: TrainingJob` runs a **model-training job on a GPU**: your training container
runs to completion on a GPU node, reads a dataset from the object store, and writes
model artifacts back to it. It is the training-loop counterpart to `kind: Model`
(Bedrock-style inference) — open-infra's equivalent of SageMaker Training Jobs.

A TrainingJob is **run-once**: creating one starts a training run; its status is the
underlying batch Job's (the console shows the phase, and `kubectl logs` shows output).

## A first training run

```yaml
apiVersion: openinfra.dev/v1
kind: TrainingJob
metadata:
  name: fraud-model
spec:
  image: pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime
  gpu: 1
  gpuTier: largegpu            # smallgpu (A2000 class) or largegpu (e.g. 3090)
  cpu: "4"
  memory: "8Gi"
  maxRuntimeSeconds: 3600
  env:                         # hyperparameters / config for your script
    - { name: EPOCHS, value: "50" }
    - { name: LR, value: "0.001" }
  dataset:                     # input data (must already exist)
    bucket: training-data
    prefix: fraud/2026-08/
  output:                      # artifacts (bucket created on demand)
    bucket: models
    prefix: fraud/v3/
  command: ["python", "train.py"]
```

## What your container gets

- **GPU:** with `gpu > 0`, the pod is scheduled on a GPU node of the chosen
  `gpuTier` (`runtimeClassName: nvidia`, `nvidia.com/gpu`, and `openinfra.dev/gpu-tier`
  node affinity) — `largegpu` requires a large GPU, `smallgpu` prefers a small one but
  may use a large one. `gpu: 0` runs CPU-only (handy for smoke tests).
- **Hyperparameters/config:** everything in `env` is set on the container. Put your
  hyperparameters here and read them with `os.environ`.
- **Object-store access (when `dataset` or `output` is set):** the bucket(s) are
  ensured to exist and S3-compatible credentials are injected, so `boto3` / `aws-cli`
  work with no extra config:
  - `AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
  - `DATASET_BUCKET` / `DATASET_PREFIX`, `OUTPUT_BUCKET` / `OUTPUT_PREFIX`

  A minimal artifact write:

  ```python
  import os, boto3
  s3 = boto3.client("s3", endpoint_url=os.environ["AWS_ENDPOINT_URL"])
  s3.upload_file("model.pt", os.environ["OUTPUT_BUCKET"],
                 os.environ.get("OUTPUT_PREFIX", "") + "model.pt")
  ```
- **Extra secrets:** list secret names in `secrets` to inject them (`envFrom`) — e.g. a
  model-registry or Hugging Face token.

## Fields

| Field | Purpose |
|-------|---------|
| `image` (required) | Training container image. |
| `command` / `args` | Optional entrypoint / args override. |
| `env` | Environment variables — the place for hyperparameters. |
| `gpu` | GPUs to request (default 1; `0` = CPU-only). |
| `gpuTier` | `smallgpu` (A2000 class) or `largegpu` (e.g. 3090). |
| `cpu` / `memory` | Resource requests/limits. |
| `dataset` `{bucket, prefix}` | Input data in the object store. |
| `output` `{bucket, prefix}` | Artifact destination (bucket auto-created). |
| `secrets` | Extra secrets to inject with `envFrom`. |
| `backoffLimit` | Pod retries before the job fails (default 0). |
| `maxRuntimeSeconds` | Hard wall-clock cap (`activeDeadlineSeconds`). |

## Notes

- A TrainingJob is **run-once and immutable** — to run again (or with changed
  settings), delete it and create a new one, or use a new name.
- It runs **your** container; there is no first-party training image. open-infra
  provides the GPU placement, the object-store wiring, and the lifecycle.
- Training vs serving: train with `kind: TrainingJob`, write the artifact to a bucket,
  then **Register as Model Package** from the finished job's console page (or write the
  `kind: ModelPackage` by hand) → approve → serve as a `kind: Model`. See
  [Model Registry](model-registry.md). Registration is authorized as *you* (a
  `SubjectAccessReview` for `create modelpackages`), not by an ambient controller: running a
  training job does not by itself grant the right to publish a servable model.
