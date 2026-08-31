# Feature store — kind: FeatureGroup

`kind: FeatureGroup` is an **online feature store** — open-infra's SageMaker Feature
Store. It gives real-time inference a low-latency place to read the latest features for a
record: a model endpoint looks up a customer's/entity's features by id in milliseconds
instead of recomputing them.

Each FeatureGroup provisions a small **Valkey** (the online key/value store) and an **API
service** in front of it, exposing two operations.

## A first feature group

```yaml
apiVersion: openinfra.dev/v1
kind: FeatureGroup
metadata:
  name: customer-features
spec:
  recordIdentifier: customer_id     # the primary key
  eventTime: ts                     # latest write wins
  features:                         # advisory schema
    - { name: customer_id, type: string }
    - { name: total_spend, type: fractional }
    - { name: orders,      type: integral }
  ttlSeconds: 86400                 # optional: expire a record 24h after its last write
```

## PutRecord / GetRecord

The service is reachable in-cluster at `http://<name>.<namespace>.svc.cluster.local:8080`
(also in `status.endpoint`). Call it from a Function, a Model serving container, or any
in-cluster workload:

```bash
# PutRecord — upsert the latest features for a record (must include the record identifier)
curl -X POST http://customer-features.default.svc.cluster.local:8080/records \
  -d '{"customer_id": "c-123", "total_spend": 942.5, "orders": 12}'

# GetRecord — read the latest features by id
curl http://customer-features.default.svc.cluster.local:8080/records/c-123
# → {"customer_id":"c-123","total_spend":942.5,"orders":12}
```

Values keep their JSON types across the round-trip (a number comes back a number). With
`ttlSeconds`, a record expires that long after its last write.

## Fields

| Field | Purpose |
|-------|---------|
| `recordIdentifier` (required) | The feature that uniquely identifies a record (the key). |
| `eventTime` | The event-time feature; the latest write wins. |
| `features` | Advisory schema (`{name, type}`); the store itself is schemaless key/value. |
| `ttlSeconds` | Optional per-record TTL in the online store. |

## Notes

- **v1 is the online store only** — low-latency serving. An **offline store** (the full
  feature history in the object store, for training and batch) is a planned follow-up.
- The online store is **in-memory (Valkey) and ephemeral** in v1: if the Valkey pod
  restarts, records are lost until re-ingested. Re-ingest from your source of truth.
- Wire it up by writing features from your pipeline (batch or streaming) via PutRecord,
  and reading them at inference time via GetRecord.
