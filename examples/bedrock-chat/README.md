# bedrock-chat — managed GPU inference (open-infra's "Bedrock")

A one-file example of `kind: Model`: declare a model, get a GPU-backed,
OpenAI-compatible endpoint gated by an API key.

## Deploy

```bash
cd examples/bedrock-chat
open-infra deploy          # applies the Model; Crossplane fans it out
open-infra status          # watch it under "Models"
```

(or `open-infra init model` in your own repo to scaffold this from scratch.)

This provisions, on a GPU node:

- an **Ollama** server (pulls + caches `llama3.1:8b` on a PVC),
- an **nginx auth sidecar** enforcing the API key,
- a **Service** (+ optional Ingress/TLS if you set `spec.domain`),
- a connection **Secret `bedrock-chat-model`** with `OPENAI_BASE_URL`,
  `OPENAI_API_KEY`, and `MODEL`.

## Consume it

From another app, reference the secret in your `Application`:

```yaml
spec:
  secrets: [bedrock-chat-model]   # -> OPENAI_BASE_URL / OPENAI_API_KEY / MODEL env
```

Then call it (OpenAI-compatible):

```bash
curl $OPENAI_BASE_URL/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Hello!"}]}'
```

Requests without the key get `401`. The endpoint is cluster-reachable, so one
Model can serve many apps across namespaces. See [`docs/gpu.md`](../../docs/gpu.md).
