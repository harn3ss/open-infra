# Offline batch inference — kind: BatchTransform

`kind: BatchTransform` scores a whole dataset **offline**, without standing up a live
endpoint — open-infra's SageMaker Batch Transform. It's a run-once job: load a model,
read every input record, write predictions to the object store, then exit. Use it for
nightly scoring, backfills, and evaluation; use `kind: Model` (`serve`) when you need a
live endpoint instead.

## A first batch transform

```yaml
apiVersion: openinfra.dev/v1
kind: BatchTransform
metadata:
  name: nightly-scores
spec:
  image: my-registry/scorer:1        # loads the model + scores records
  artifact:                          # the model to score with (optional if baked in)
    bucket: models
    key: fraud/v3/model.pt
  input:                             # records to score
    bucket: datasets
    prefix: fraud/2026-08-31/
  output:                            # where predictions are written (bucket auto-created)
    bucket: predictions
    prefix: fraud/2026-08-31/
  gpu: 0                             # or 1 + gpuTier for GPU inference
```

## What your container gets

The inference container runs to completion with these injected (the buckets are ensured
to exist and S3-compatible credentials are provided, so `boto3`/`aws-cli` work):

- `INPUT_BUCKET` / `INPUT_PREFIX` — the records to score.
- `OUTPUT_BUCKET` / `OUTPUT_PREFIX` — where to write predictions.
- `ARTIFACT_BUCKET` / `ARTIFACT_KEY` — the model artifact (when `artifact` is set).
- `AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`.

The container is responsible for reading the inputs, scoring them, and writing the
outputs — the same freedom (and contract) as `kind: TrainingJob`.

## Fields

| Field | Purpose |
|-------|---------|
| `image` (required) | Inference container. |
| `command` / `args` | Optional entrypoint / args override. |
| `artifact` `{bucket, key}` | Model artifact to load (optional). |
| `input` `{bucket, prefix}` (required) | Records to score. |
| `output` `{bucket, prefix}` (required) | Prediction destination. |
| `gpu` / `gpuTier` | GPUs (default 0 = CPU) and class (`smallgpu`/`largegpu`). |
| `cpu` / `memory` | Resource requests/limits. |
| `env` / `secrets` | Config and injected secrets. |
| `backoffLimit` / `maxRuntimeSeconds` | Retries and a hard runtime cap. |

## Notes

- Run-once and immutable — to re-run (or with changes), delete and recreate, or use a
  new name. Status is the underlying batch Job's (`kubectl logs -n <ns> job/<name>-transform`).
- It runs **your** container; there's no first-party inference image. open-infra provides
  the GPU placement, the object-store wiring, and the lifecycle.
- Batch vs live: `kind: BatchTransform` scores a dataset once; `kind: Model` `serve`
  stands up a persistent, key-gated endpoint. Both can score the same artifact (register
  it once in the [Model Registry](model-registry.md)).
