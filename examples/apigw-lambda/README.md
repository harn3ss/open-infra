# API Gateway (HTTP API v2) → Lambda

The canonical serverless example for open-infra: an **API Gateway HTTP API** fronting a **Lambda**
(`kind: Function`), through the [AWS-SDK shim](../../docs/aws-shim.md). It is the REST/HTTP complement to
AppSync and completes the AWS serverless triad (API Gateway → Lambda → DynamoDB).

[`app.py`](app.py) is a minimal handler written against the **exact API Gateway v2 proxy contract** AWS
documents: it receives the proxy *event* as its request body and returns a structured proxy *response* —
`{statusCode, headers, body, isBase64Encoded}` — which the gateway turns back into a real HTTP response. A
handler proven here runs on AWS unchanged.

## Build and deploy the function

Build this handler and push it to a registry your cluster can pull, then reference it from a `kind: Function`:

```sh
docker build -t <your-registry>/apigw-echo:latest examples/apigw-lambda/
docker push <your-registry>/apigw-echo:latest
```

```yaml
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: apigw-echo }
spec:
  image: <your-registry>/apigw-echo:latest
  port: 8080
  expose: false
```

> Knative resolves an image tag to a digest before deploying, so the image must be pullable by the cluster
> (public, or covered by your node/registry credentials). For a private image, reference it by digest
> (`…@sha256:…`) so Knative skips tag resolution and the node's containerd credentials do the pull.

## Wire the API (AWS CLI, against the shim)

```sh
export AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566

API=$(aws apigatewayv2 create-api --name demo --protocol-type HTTP --query ApiId --output text)
INT=$(aws apigatewayv2 create-integration --api-id "$API" \
  --integration-type AWS_PROXY \
  --integration-uri arn:aws:lambda:us-east-1:open-infra:function:apigw-echo \
  --payload-format-version 2.0 --query IntegrationId --output text)
aws apigatewayv2 create-route  --api-id "$API" --route-key 'POST /items/{id}' --target "integrations/$INT"
aws apigatewayv2 create-stage  --api-id "$API" --stage-name '$default' --auto-deploy
```

## Call it (a real HTTP client — no SigV4 on the data plane)

The invoke URL is returned as the API's `apiEndpoint`. In-cluster it is
`http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/_apigw/<api-id>/<path>` (the shim's stable,
routable form of AWS's per-API `execute-api` hostname — see the [shim docs](../../docs/aws-shim.md)).

```sh
curl -X POST -H 'content-type: application/json' -d '{"hello":"world"}' \
  "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/_apigw/$API/items/123"
# → 201, body: {"received": { ...the v2 proxy event the Lambda saw... }}
```

## Notes

- **Payload format** 2.0 is the default; set `--payload-format-version 1.0` on the integration for the v1
  event shape.
- A **JWT authorizer** (`aws apigatewayv2 create-authorizer --authorizer-type JWT …`) can gate a route; it
  validates the caller's bearer token against the configured OIDC issuer + audience. That is the
  *application's* auth for its *end users*, separate from the platform IAM that authorized creating the API.
- **CORS** is configured on the API (`--cors-configuration`); the gateway answers preflight `OPTIONS`.
- Supported: `AWS_PROXY` integrations to a Lambda, JWT authorizers, CORS, HTTP API (v2). REST API (v1),
  non-Lambda integrations, and REQUEST/Lambda authorizers are refused (not silently accepted).
