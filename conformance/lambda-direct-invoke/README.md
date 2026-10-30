# Conformance: Lambda direct-invoke through open-appsync

Proves, end to end against a **real `kind: Function`**, that the Lambda runtime's direct-invoke path
makes a handler's return value reach an open-appsync resolver as `$ctx.result` — the AWS behaviour,
where AppSync calls Lambda `Invoke` directly and the whole return becomes the result.

The fixture handler returns the shape that the old **API-Gateway proxy** mapping silently broke:

```js
return { statusCode: 200, message: "ok", data: { id, name } };   // NO `body`
```

Under proxy mapping the function emitted an empty `body`, so the resolver saw `$ctx.result = null` and
the field resolved to `null`. With direct-invoke the resolver gets the **whole object**, so its response
template can return `$ctx.result.data` and the GraphQL caller gets the data.

This is a **platform-owned** fixture (synthetic handler + schema, no customer code), per the ownership
boundary: it proves the platform behaves like AWS using its own fixtures.

## Run it

```sh
kubectl apply -f conformance/lambda-direct-invoke/fixture.yaml
kubectl wait --for=condition=Ready function.openinfra.dev/fixture-direct-invoke-fn -n default --timeout=180s

# query the engine (the GraphQL endpoint is /graphql; the probe field is public — no auth)
kubectl port-forward svc/open-appsync-fixture-direct-invoke -n default 18080:80 &
curl -s -H 'Content-Type: application/json' \
  -d '{"query":"{ probe(id:\"e2e-1\"){ id name } }"}' http://127.0.0.1:18080/graphql
```

Expected — the function's `.data`, not `null`:

```json
{"data":{"probe":{"id":"e2e-1","name":"open-infra"}}}
```

A `null` `probe` means the return did not survive the invoke (the proxy-mapping regression).

## Teardown

```sh
kubectl delete -f conformance/lambda-direct-invoke/fixture.yaml
```

## What direct-invoke is

A caller sets `X-Openinfra-Invoke: direct`; the runtime then returns the handler's **raw** return value
as the payload (a `{statusCode,...}` shape is data, never an HTTP mapping), signals a **thrown** error
via `X-Amz-Function-Error` (HTTP stays 200), and passes the event verbatim. The API-Gateway proxy
mapping is unchanged and applies only when the header is absent. The direct callers are the AWS-SDK
shim's `Invoke`, open-appsync, and the Step Functions engine.
