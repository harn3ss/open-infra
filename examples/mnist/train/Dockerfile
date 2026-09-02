# MNIST training image for a kind: TrainingJob (known-answer run).
#
# The PyTorch runtime image already bundles torch + torchvision; we only add boto3 for the
# MinIO upload. It is a CUDA image so the run uses the 3090 when scheduled on a GPU node
# (gpuTier: largegpu); on a CPU node torch falls back automatically (just slower).
#
# NOTE: confirm this exact tag exists for your registry/arch before a run — PyTorch tags move.
FROM pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime

RUN pip install --no-cache-dir boto3==1.35.36

WORKDIR /app
COPY train.py .

# TrainingJob runs the container to completion; env (OUTPUT_BUCKET, AWS_*, SEED, EPOCHS) is injected.
ENTRYPOINT ["python", "train.py"]
