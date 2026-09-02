# MNIST serving image for a kind: Model (spec.serve).
#
# Inference is tiny, so this is a CPU-only image (the CPU torch wheel, not the multi-GB CUDA
# runtime) — a served Model doesn't request a GPU unless serve.gpuTier is set. It loads the
# artifact from ARTIFACT_BUCKET/ARTIFACT_KEY at startup and serves HTTP on PORT (default 8000;
# never 8080 — that's the endpoint proxy).
FROM python:3.11-slim

RUN pip install --no-cache-dir \
      torch==2.4.1 --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir \
      fastapi==0.115.2 uvicorn==0.32.0 boto3==1.35.36 pydantic==2.9.2

WORKDIR /app
COPY app.py .

# serve.port is injected as PORT; default 8000 here matches the manifests.
ENV PORT=8000
ENTRYPOINT ["python", "app.py"]
