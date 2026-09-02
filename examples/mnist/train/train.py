#!/usr/bin/env python3
"""Seeded MNIST training run — a known-answer test for the open-infra ML pipeline.

It runs inside a kind: TrainingJob, which injects OUTPUT_BUCKET/OUTPUT_PREFIX and
S3-compatible MinIO credentials. The network is the canonical PyTorch MNIST CNN; with a
fixed seed and deterministic cuDNN it lands test accuracy in a tight, repeatable band
(~98.5–99.4% by 5 epochs), so a run that comes back outside that band is a real signal,
not noise. The trained weights are uploaded to OUTPUT_BUCKET/OUTPUT_PREFIX/model.pt for a
ModelPackage → Model to serve.

The serving container (../serve/app.py) MUST define an identical `Net` — the state_dict is
shared between them.
"""
import io
import json
import os

import boto3
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

SEED = int(os.environ.get("SEED", "42"))
EPOCHS = int(os.environ.get("EPOCHS", "5"))
BATCH = int(os.environ.get("BATCH_SIZE", "64"))


class Net(nn.Module):
    """Canonical PyTorch MNIST CNN. Keep in lockstep with serve/app.py."""

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


def main():
    # Determinism: the whole point of a known-answer run.
    torch.manual_seed(SEED)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device={device} seed={SEED} epochs={EPOCHS} batch={BATCH}", flush=True)

    tfm = transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), (0.3081,))])
    data_root = os.environ.get("DATA_ROOT", "/data")
    train_ds = datasets.MNIST(data_root, train=True, download=True, transform=tfm)
    test_ds = datasets.MNIST(data_root, train=False, download=True, transform=tfm)
    # num_workers=0 + a fixed generator keeps shuffling reproducible.
    g = torch.Generator().manual_seed(SEED)
    train_dl = DataLoader(train_ds, batch_size=BATCH, shuffle=True, num_workers=0, generator=g)
    test_dl = DataLoader(test_ds, batch_size=1000, shuffle=False, num_workers=0)

    model = Net().to(device)
    opt = torch.optim.Adadelta(model.parameters(), lr=1.0)
    sched = torch.optim.lr_scheduler.StepLR(opt, step_size=1, gamma=0.7)

    for epoch in range(1, EPOCHS + 1):
        model.train()
        for i, (x, y) in enumerate(train_dl):
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            loss = F.cross_entropy(model(x), y)
            loss.backward()
            opt.step()
            if i % 200 == 0:
                print(f"epoch {epoch} step {i} loss {loss.item():.4f}", flush=True)
        sched.step()

        # test accuracy after each epoch
        model.eval()
        correct = 0
        with torch.no_grad():
            for x, y in test_dl:
                x, y = x.to(device), y.to(device)
                correct += (model(x).argmax(1) == y).sum().item()
        acc = correct / len(test_ds)
        print(f"epoch {epoch} test_accuracy {acc:.4f}", flush=True)

    accuracy = acc
    print(f"FINAL test_accuracy {accuracy:.4f}", flush=True)

    # Serialize weights to an in-memory buffer and upload to the artifact bucket.
    buf = io.BytesIO()
    torch.save(model.state_dict(), buf)
    buf.seek(0)

    bucket = os.environ["OUTPUT_BUCKET"]
    prefix = os.environ.get("OUTPUT_PREFIX", "").strip("/")
    key = f"{prefix}/model.pt" if prefix else "model.pt"
    metrics_key = f"{prefix}/metrics.json" if prefix else "metrics.json"

    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    s3.put_object(
        Bucket=bucket,
        Key=metrics_key,
        Body=json.dumps({"accuracy": round(accuracy, 4), "epochs": EPOCHS, "seed": SEED}).encode(),
        ContentType="application/json",
    )
    print(f"uploaded s3://{bucket}/{key} (accuracy={accuracy:.4f})", flush=True)


if __name__ == "__main__":
    main()
