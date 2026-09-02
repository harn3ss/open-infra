# MNIST — the ML pipeline end to end

A small, **known-answer** walkthrough of the whole training-to-serving loop:

**train → register → approve → serve.**

It trains the canonical PyTorch MNIST CNN with a fixed seed (so the result is repeatable),
registers the artifact in the Model Registry, and serves it behind a key-gated endpoint. It
exercises `kind: TrainingJob`, `kind: ModelPackage`, and `kind: Model` together.

## Layout

| Path | What it is |
|---|---|
| `train/` | Training image — seeded CNN, uploads `model.pt` to the output bucket. |
| `serve/` | Serving image — FastAPI app that loads the artifact and serves `/predict`. |
| `manifests/` | The three resources: `trainingjob.yaml`, `modelpackage.yaml`, `model.yaml`. |

The two images share one network definition (`Net`). It is duplicated in `train/train.py`
and `serve/app.py` on purpose (a self-contained example); they must stay identical, since the
serving side loads the training side's `state_dict`.

## Build the images

```sh
docker build -t ghcr.io/harn3ss/open-infra-mnist-train:1 train/
docker build -t ghcr.io/harn3ss/open-infra-mnist-serve:1 serve/
docker push ghcr.io/harn3ss/open-infra-mnist-train:1
docker push ghcr.io/harn3ss/open-infra-mnist-serve:1
```

## Run it

```sh
kubectl create namespace ml-demo
kubectl apply -f manifests/trainingjob.yaml      # 1. train (on the 3090: gpuTier largegpu)
```

Watch the run to completion and read its accuracy:

```sh
kubectl logs -n ml-demo job/mnist-train -f | grep test_accuracy
# ... epoch 5 test_accuracy 0.99xx
# FINAL test_accuracy 0.99xx
```

**Expected known answer:** test accuracy settles in **~98.5–99.4%** by 5 epochs. A run that
lands well outside that band means something changed (seed, data, image) — that is the point
of a known-answer test. For reference, this recipe on an RTX 3090 lands **99.0%** at training
and **98.8%** when queried through the *served* endpoint (1000-sample) — the served number
reproducing the trained one within noise is the check that matters: it proves the artifact
round-trips through serving unchanged.

Then register, approve, and serve:

```sh
kubectl apply -f manifests/modelpackage.yaml     # 2. register (PendingManualApproval)
# 2b. approve — console: Model Registry → mnist-v1 → Approve
#     or:  kubectl patch modelpackage mnist-v1 -n ml-demo --type merge \
#            -p '{"spec":{"approvalStatus":"Approved"}}'
kubectl apply -f manifests/model.yaml            # 3. serve (once Approved)
```

Or do the whole middle from the console: on the finished **Training Job** page, click
**Register as Model Package** (supply the serving image); then **Approve** the package and
**Deploy endpoint**. Each of those is authorized as *you* — see below.

## Call the served endpoint

The Model exposes a key-gated HTTP endpoint (unauthenticated calls get 401). Read the key from
its connection secret and POST 784 grayscale pixels (a flattened 28×28 image, values in `[0,1]`):

The Model writes a connection secret `mnist-serve-model` with `ENDPOINT` and `API_KEY`
(the same shape apps consume for any served model):

```sh
KEY=$(kubectl get secret -n ml-demo mnist-serve-model -o jsonpath='{.data.API_KEY}' | base64 -d)
EP=$(kubectl get secret -n ml-demo mnist-serve-model -o jsonpath='{.data.ENDPOINT}' | base64 -d)
curl -sS -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  --data '{"pixels": [/* 784 floats */]}' \
  "$EP/predict"
# {"digit": 7, "probs": [...]}
```

(See [../../docs/model-registry.md](../../docs/model-registry.md) for the endpoint, key, and
`expose`/`domain` options.)

## Why registration is a deliberate, authorized step

Turning a finished training run into a servable model is an **authorization** decision, not just
plumbing: the identity that may *run* a training job is not automatically the identity that may
*publish a servable model*. So registration is done **as you**, never by a background controller
with ambient authority — the console runs a `SubjectAccessReview` for your own
`create modelpackages` right and fails closed. The package is created `PendingManualApproval`;
promoting it to a served `kind: Model` is a second, separately authorized step. A user who can
train but not serve therefore cannot reach an endpoint through this path.

## Notes

- **Pins.** The training image is `pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime` (bundles
  torchvision); serving uses the CPU torch wheel (`torch==2.4.1`) since inference is tiny.
  Confirm the base-image tag for your registry/arch before a run.
- **GPU vs CPU.** `trainingjob.yaml` requests `gpuTier: largegpu` (the 3090). Set `gpu: 0` to
  train on CPU (slower, same known answer). The serving pod is CPU-only.
- **Determinism.** Fixed `SEED` + deterministic cuDNN + `num_workers=0` keep the accuracy
  repeatable. Small run-to-run drift within the band is normal across hardware.
