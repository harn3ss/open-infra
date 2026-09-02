#!/usr/bin/env python3
"""MNIST serving container for a kind: Model (spec.serve).

The Model composition injects ARTIFACT_BUCKET/ARTIFACT_KEY plus S3-compatible MinIO
credentials and PORT. This app downloads the trained weights, rebuilds the network, and
serves HTTP inference. The key-gated endpoint proxy in front forwards authenticated calls.

`Net` MUST match ../train/train.py exactly — the state_dict is shared.
"""
import io
import os

import boto3
import torch
import torch.nn as nn
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class Net(nn.Module):
    """Canonical PyTorch MNIST CNN. Keep in lockstep with train/train.py."""

    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.dropout1 = nn.Dropout(0.25)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = F.relu(self.conv2(x))
        x = F.max_pool2d(x, 2)
        x = self.dropout1(x)
        x = torch.flatten(x, 1)
        x = F.relu(self.fc1(x))
        x = self.dropout2(x)
        return self.fc2(x)


MEAN, STD = 0.1307, 0.3081  # must match training normalization


def load_model() -> Net:
    bucket = os.environ["ARTIFACT_BUCKET"]
    key = os.environ.get("ARTIFACT_KEY", "").strip("/") or "model.pt"
    if not key.endswith(".pt"):  # a prefix was given, not the object itself
        key = f"{key}/model.pt"
    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )
    obj = s3.get_object(Bucket=bucket, Key=key)
    state = torch.load(io.BytesIO(obj["Body"].read()), map_location="cpu")
    m = Net()
    m.load_state_dict(state)
    m.eval()
    print(f"loaded model from s3://{bucket}/{key}", flush=True)
    return m


app = FastAPI(title="mnist-serving")
_model: Net | None = None


class Pixels(BaseModel):
    # 784 grayscale values in [0,1], row-major (a flattened 28x28 image).
    pixels: list[float]


@app.on_event("startup")
def _startup():
    global _model
    _model = load_model()


@app.get("/healthz")
def healthz():
    return {"ok": _model is not None}


@app.post("/predict")
def predict(req: Pixels):
    if _model is None:
        raise HTTPException(503, "model not loaded")
    if len(req.pixels) != 784:
        raise HTTPException(400, f"expected 784 pixels, got {len(req.pixels)}")
    x = torch.tensor(req.pixels, dtype=torch.float32).view(1, 1, 28, 28)
    x = (x - MEAN) / STD
    with torch.no_grad():
        logits = _model(x)
        probs = F.softmax(logits, dim=1)[0]
    return {"digit": int(probs.argmax().item()), "probs": [round(p, 4) for p in probs.tolist()]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
