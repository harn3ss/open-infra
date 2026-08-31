# Data processing — kind: ProcessingJob

`kind: ProcessingJob` runs a container over data — open-infra's SageMaker Processing.
It's a run-once job with **any number of named inputs and outputs** in the object store,
for preprocessing, feature engineering, dataset validation, or model evaluation. It's the
general form of `kind: BatchTransform` (which is single-model inference).

## A first processing job

```yaml
apiVersion: openinfra.dev/v1
kind: ProcessingJob
metadata:
  name: featurize
spec:
  image: my-registry/featurizer:1
  inputs:
    - { name: raw,   bucket: datasets, prefix: raw/2026-08-31/ }
    - { name: config, bucket: configs, prefix: featurize/ }
  outputs:
    - { name: features, bucket: features, prefix: 2026-08-31/ }
  gpu: 0                     # or 1 + gpuTier for GPU processing
```

## What your container gets

Each channel is injected as environment variables (the buckets are ensured to exist and
S3-compatible credentials are provided, so `boto3`/`aws-cli` work):

- per input `<name>`: `INPUT_<NAME>_BUCKET`, `INPUT_<NAME>_PREFIX` (NAME upper-cased),
- per output `<name>`: `OUTPUT_<NAME>_BUCKET`, `OUTPUT_<NAME>_PREFIX`,
- `INPUTS` and `OUTPUTS` — comma-separated channel names,
- `AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`.

So the example above sets `INPUT_RAW_BUCKET`, `INPUT_CONFIG_BUCKET`,
`OUTPUT_FEATURES_BUCKET`, `INPUTS=raw,config`, `OUTPUTS=features`, and the container reads
its inputs and writes its outputs.

## Fields

| Field | Purpose |
|-------|---------|
| `image` (required) | Processing container. |
| `command` / `args` | Optional entrypoint / args override. |
| `inputs` | Named input channels `{name, bucket, prefix}`. |
| `outputs` | Named output channels `{name, bucket, prefix}` (buckets created on demand). |
| `gpu` / `gpuTier` | GPUs (default 0 = CPU) and class (`smallgpu`/`largegpu`). |
| `cpu` / `memory` | Resource requests/limits. |
| `env` / `secrets` | Config and injected secrets. |
| `backoffLimit` / `maxRuntimeSeconds` | Retries and a hard runtime cap. |

## Processing vs the other ML jobs

open-infra mirrors the SageMaker jobs family, each a run-once container with object-store
wiring but a different purpose:

- **[Training](training-jobs.md)** (`kind: TrainingJob`) — produce a model artifact.
- **Processing** (`kind: ProcessingJob`) — arbitrary data in → data out (this doc).
- **[Batch Transform](batch-transform.md)** (`kind: BatchTransform`) — score a dataset with a model.
- **[Tuning](tuning-jobs.md)** (`kind: TuningJob`) — sweep training over hyperparameters.

## Notes

- Run-once and immutable — to re-run (or with changes), delete and recreate, or use a new
  name. Status is the underlying batch Job's (`kubectl logs -n <ns> job/<name>-proc`).
- It runs **your** container; there's no first-party processing image.
