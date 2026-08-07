# Introspection gate #2 — real GraphQL tooling consumes our introspection result

This is the **operability golden** for open-appsync introspection. Introspection is standard GraphQL
(no AWS dialect), so there's no AWS byte-string to diff against — the proof that matters is that a real
tool builds a usable schema from our output.

- `consume.mjs` — feeds an introspection result to **graphql-js `buildClientSchema`** (the exact call
  graphql-codegen / Apollo make) + **`printSchema`**, then runs **graphql-codegen** to generate
  TypeScript types. Asserts the wrappers, enums, defaults, custom scalars, and roots all survive.
  Exits non-zero on any miss.
- `introspection.json` — the introspection result, emitted by the Go probe
  (`TestIntrospection_CanonicalQueryShape`). Gitignored; regenerated on each run.

## Run it

```sh
npm install          # one-time: graphql + @graphql-codegen (gitignored node_modules)
cd ../.. && go test ./probe/ -run TestIntrospection -v
```

The Go test `TestIntrospection_RealToolConsumes` shells out to `node consume.mjs`. It **skips** (never
silently passes) when Node or `node_modules/` is absent — the graduation evidence is that test
*passing*, not skipping. You can also run the consumer directly: `npm run consume`.
