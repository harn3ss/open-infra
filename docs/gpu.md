# GPU & Managed Inference ("Bedrock")

open-infra schedules GPU workloads and offers a Bedrock-like managed-inference
service: declare `kind: Model` and get a GPU-backed, OpenAI-compatible endpoint
gated by an API key — the same intent→infrastructure flow as `kind: Application`.

## 1. GPU host prerequisites (per GPU node)

GPUs are exposed to Kubernetes by the in-cluster **NVIDIA device plugin**
(`platform/gpu/`, GitOps-managed). It depends on two **host-level** prerequisites
that are intentionally NOT in the repo — they touch the host OS, not the cluster:

1. **NVIDIA driver** — install the proprietary driver; verify with `nvidia-smi`.

2. **nvidia-container-toolkit** — lets containerd give containers GPU access:

   ```bash
   # Ubuntu/Debian
   curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
     | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
   curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
     | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
     | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
   sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
   ```

3. **Restart k3s so it detects the NVIDIA runtime.** k3s auto-discovers
   `nvidia-container-runtime` and adds an `nvidia` containerd runtime:

   ```bash
   sudo systemctl restart k3s          # control-plane node
   sudo systemctl restart k3s-agent    # worker node
   # verify it was wired in:
   grep -i nvidia /var/lib/rancher/k3s/agent/etc/containerd/config.toml
   ```

4. **Label the node** so the GPU components target it:

   ```bash
   kubectl label node <node> openinfra.dev/gpu=true
   kubectl label node <node> openinfra.dev/gpu-model=RTX-3090-24GB   # optional; shown in the console
   ```

Confirm GPUs are now advertised to the scheduler:

```bash
kubectl get nodes -o custom-columns=NODE:.metadata.name,GPU:.status.capacity.'nvidia\.com/gpu'
```

## 2. What the platform installs (GitOps, `platform/gpu/`)

- **`nvidia-runtimeclass.yaml`** — RuntimeClass `nvidia` → the containerd runtime.
- **`nvidia-device-plugin.yaml`** — advertises `nvidia.com/gpu` on labeled nodes.
- **`dcgm-exporter.yaml`** — per-GPU metrics (util / VRAM / temp / power) → Prometheus.
- **`gpu-dashboard.yaml`** — the **"open-infra / GPU Overview"** Grafana dashboard.

The console **Nodes** panel shows each node's GPU count + model; the Grafana **GPU
Overview** dashboard shows live utilization, VRAM, temperature, and power per GPU.

## 3. Run a GPU workload directly

Any pod can request a GPU with the `nvidia` runtime class and a resource limit:

```yaml
spec:
  runtimeClassName: nvidia
  nodeSelector: { openinfra.dev/gpu: "true" }
  containers:
    - name: cuda
      image: nvidia/cuda:12.4.1-base-ubuntu22.04
      command: ["nvidia-smi"]
      resources:
        limits: { nvidia.com/gpu: 1 }
```

## 4. Managed inference — `kind: Model` (the "Bedrock")

Declare a model; get a served, key-gated, OpenAI-compatible endpoint:

```yaml
apiVersion: openinfra.dev/v1
kind: Model
metadata:
  name: chat
spec:
  model: llama3.1:8b      # any Ollama model tag
  gpu: 1                  # GPUs to allocate (default 1)
  # domain: chat.example  # optional: expose externally (Ingress + TLS)
  # storageSize: 20Gi     # PVC for cached weights (default 20Gi)
```

The `model` Crossplane Composition compiles this into:

- an **Ollama** Deployment on a GPU node (pulls + caches the model on a PVC),
- an **nginx auth sidecar** enforcing `Authorization: Bearer <key>`,
- a **Service** (the endpoint), plus optional **Ingress** + TLS,
- a connection **Secret `<name>-model`** with `OPENAI_BASE_URL`, `OPENAI_API_KEY`,
  and `MODEL` — the same pattern the database uses.

### Consume it from an app

Reference the secret from your `Application` (it's OpenAI-compatible):

```yaml
spec:
  secrets: [chat-model]   # injects OPENAI_BASE_URL / OPENAI_API_KEY / MODEL as env
```

```bash
curl $OPENAI_BASE_URL/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Hello!"}]}'
```

Access is gated by the API key (network-reachable, key-authenticated — like
Bedrock), so one Model can be shared across namespaces.

## Notes & sizing

- The model is pulled once and cached on the PVC; the first start is slower.
- Pick a model that fits the GPU's VRAM (e.g. `llama3.1:8b` ≈ 5–6 GB quantized;
  a 24 GB card comfortably runs 8–14B models).
- A rolling update can't share a single GPU / RWO PVC, so the Deployment uses the
  `Recreate` strategy (brief downtime when the spec changes).
