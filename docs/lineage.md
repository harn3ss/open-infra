# Data lineage — where data comes from and where it goes

Handling regulated data means being able to answer, on demand, *where did this come from and where
does it flow?* open-infra already describes data movement declaratively, so lineage is a **derivation**
over what's already there — not a separate thing to keep in sync:

- **`kind: DataFlow`** — a node+edge topology: datastores wired by migration / replication / stream /
  function edges.
- **`kind: Migration`** — a one-way source→target load/CDC.
- **`kind: Replication`** — two sites kept in sync both ways.
- **`kind: Stream`** — a source database's changes published to an event bus subject.

The console **Data → Lineage** page (and `/api/lineage`) reads all of these and shows every data
movement — source → sink, with its type — so an auditor can trace provenance end to end. It is a
**cluster-wide** view (all namespaces), so it is gated on a **cluster-scoped** SubjectAccessReview to
list DataFlows — i.e. it is for operators/auditors who can already see the whole topology, not a
per-namespace view.

```
postgres db-a/orders  ──migration──▶  sqlserver db-b/orders
siteA (postgres)      ──replication (bidirectional)──▶  siteB (sqlserver)
mysql shop/customers  ──stream──▶  jetstream:customer-events
```

It is read-only and derived from live resources, so it can never drift from what is actually
configured. Because it is assembled server-side, the same lineage is what the
[signed compliance attestation](compliance-attestation.md) can vouch for.

## Scope & honesty

- Lineage reflects **declared** movements (the DataFlow/Migration/Replication/Stream resources). Data
  moved by an application outside these kinds is not captured — model it as one of these kinds to have
  it appear.
- Endpoints are labelled by `engine host/database` as declared; it does not probe the databases.
- The authenticated success path is observable end-to-end with [`probe/lineage.sh`](../probe/lineage.sh):
  it logs in, creates a throwaway `kind: Stream`, and asserts it appears as a lineage flow through
  `/api/lineage` (the SI-12 observation), then deletes it. Needs the root break-glass password.

## Control mapping

- **SI-12** Information Management & Retention — knowing the flow is a prerequisite to governing it.
- **AU / CM** — provenance of data movement for audit and configuration review.
- Supports **CUI**/regulated-data handling: trace where classified data (see
  [`data-classification.md`](data-classification.md)) flows.
