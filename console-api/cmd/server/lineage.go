package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"time"

	"k8s.io/client-go/kubernetes"
)

// The Data Lineage view — provenance of data movement across the platform (source → stream → sink).
//
// open-infra already models data movement declaratively: kind: DataFlow is a node+edge topology of
// datastores wired by migration/replication/stream/function edges, and the standalone kind:
// Migration / Replication / Stream each describe one movement. This endpoint reads them all and
// assembles the lineage — every place data flows from and to — so an auditor can answer "where does
// this data come from, and where does it go?" (provenance for CUI handling; supports SI-12 / AU / CM
// data-management review). It is derived from existing resources, not a separate source of truth.
//
// Gated on the SAR to list DataFlows: whoever can see the data topology can see its lineage. Reads
// use the console ServiceAccount (which can list these kinds); the SAR enforces the caller's right.
//
// The per-kind parsing lives in the small pure functions below (dataFlowFlow/migrationFlow/…) so it is
// unit-testable off a raw CR payload — the handler itself only does I/O (list + auth). The alternative
// (testing through the handler) can't reach the parsing: crList needs a real REST client, and a fake
// clientset yields zero items. This split is what lets the siteA/siteB shape be pinned by a test.

type lineageNode struct {
	Name   string `json:"name"`
	Role   string `json:"role,omitempty"`   // database | topic | function | bucket (DataFlow nodes)
	Engine string `json:"engine,omitempty"` // postgres | mysql | …
}

type lineageEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // migration | replication | stream | <DataFlow edge type>
}

type lineageFlow struct {
	Origin    string        `json:"origin"` // e.g. "DataFlow ns/name" — the resource this lineage came from
	Kind      string        `json:"kind"`   // DataFlow | Migration | Replication | Stream
	Namespace string        `json:"namespace"`
	Name      string        `json:"name"`
	Nodes     []lineageNode `json:"nodes,omitempty"`
	Edges     []lineageEdge `json:"edges"`
}

// crList fetches a cluster-wide list of an openinfra.dev kind as raw JSON items. Best-effort: a kind
// whose CRD is absent (feature disabled) simply yields nothing.
func crList(ctx context.Context, cs kubernetes.Interface, plural string) []json.RawMessage {
	rc := cs.CoreV1().RESTClient()
	// A fake clientset hands back a TYPED nil *rest.RESTClient (non-nil interface, panics on use).
	if rc == nil {
		return nil
	}
	if v := reflect.ValueOf(rc); v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	raw, err := rc.Get().AbsPath("/apis/openinfra.dev/v1/" + plural).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var out struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out.Items
}

type crMeta struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
}

// dbEndpoint is a database reference as it appears in Migration/Replication/Stream specs. The fields
// are matched case-insensitively by encoding/json, so lower-case JSON keys (engine/host/database) bind.
type dbEndpoint struct {
	Engine, Host, Database string
}

// endpointLabel renders a database endpoint as "engine host/db" for display, tolerating missing bits.
func endpointLabel(engine, host, database string) string {
	label := host
	if database != "" {
		label += "/" + database
	}
	if engine != "" {
		if label != "" {
			return engine + " " + label
		}
		return engine
	}
	if label == "" {
		return "(unknown)"
	}
	return label
}

// dataFlowFlow parses a DataFlow item — the richest source: it already carries nodes[] + edges[].
func dataFlowFlow(item json.RawMessage) (lineageFlow, bool) {
	var df struct {
		crMeta
		Spec struct {
			Nodes []struct {
				Name   string `json:"name"`
				Role   string `json:"role"`
				Engine string `json:"engine"`
			} `json:"nodes"`
			Edges []struct {
				From string `json:"from"`
				To   string `json:"to"`
				Type string `json:"type"`
			} `json:"edges"`
		} `json:"spec"`
	}
	if json.Unmarshal(item, &df) != nil {
		return lineageFlow{}, false
	}
	f := lineageFlow{
		Origin: "DataFlow " + df.Metadata.Namespace + "/" + df.Metadata.Name,
		Kind:   "DataFlow", Namespace: df.Metadata.Namespace, Name: df.Metadata.Name,
	}
	for _, n := range df.Spec.Nodes {
		f.Nodes = append(f.Nodes, lineageNode{Name: n.Name, Role: n.Role, Engine: n.Engine})
	}
	for _, e := range df.Spec.Edges {
		t := e.Type
		if t == "" {
			t = "edge"
		}
		f.Edges = append(f.Edges, lineageEdge{From: e.From, To: e.To, Type: t})
	}
	return f, true
}

// migrationFlow parses a Migration item — one directed edge, source DB → target DB.
func migrationFlow(item json.RawMessage) (lineageFlow, bool) {
	var m struct {
		crMeta
		Spec struct {
			Source dbEndpoint `json:"source"`
			Target dbEndpoint `json:"target"`
		} `json:"spec"`
	}
	if json.Unmarshal(item, &m) != nil {
		return lineageFlow{}, false
	}
	return lineageFlow{
		Origin: "Migration " + m.Metadata.Namespace + "/" + m.Metadata.Name,
		Kind:   "Migration", Namespace: m.Metadata.Namespace, Name: m.Metadata.Name,
		Edges: []lineageEdge{{
			From: endpointLabel(m.Spec.Source.Engine, m.Spec.Source.Host, m.Spec.Source.Database),
			To:   endpointLabel(m.Spec.Target.Engine, m.Spec.Target.Host, m.Spec.Target.Database),
			Type: "migration",
		}},
	}, true
}

// replicationFlow parses a Replication item — two sites kept in sync both ways.
//
// The spec fields are siteA / siteB (NOT a sites[] array). Reading the wrong shape here once silently
// dropped every replication edge from the lineage; the test for this function pins siteA/siteB so that
// regression cannot come back.
func replicationFlow(item json.RawMessage) (lineageFlow, bool) {
	var rp struct {
		crMeta
		Spec struct {
			SiteA dbEndpoint `json:"siteA"`
			SiteB dbEndpoint `json:"siteB"`
		} `json:"spec"`
	}
	if json.Unmarshal(item, &rp) != nil {
		return lineageFlow{}, false
	}
	return lineageFlow{
		Origin: "Replication " + rp.Metadata.Namespace + "/" + rp.Metadata.Name,
		Kind:   "Replication", Namespace: rp.Metadata.Namespace, Name: rp.Metadata.Name,
		Edges: []lineageEdge{{
			From: endpointLabel(rp.Spec.SiteA.Engine, rp.Spec.SiteA.Host, rp.Spec.SiteA.Database),
			To:   endpointLabel(rp.Spec.SiteB.Engine, rp.Spec.SiteB.Host, rp.Spec.SiteB.Database),
			Type: "replication (bidirectional)",
		}},
	}, true
}

// streamFlow parses a Stream item — source DB CDC → an event-bus subject named after the Stream.
func streamFlow(item json.RawMessage) (lineageFlow, bool) {
	var st struct {
		crMeta
		Spec struct {
			Source dbEndpoint `json:"source"`
		} `json:"spec"`
	}
	if json.Unmarshal(item, &st) != nil {
		return lineageFlow{}, false
	}
	return lineageFlow{
		Origin: "Stream " + st.Metadata.Namespace + "/" + st.Metadata.Name,
		Kind:   "Stream", Namespace: st.Metadata.Namespace, Name: st.Metadata.Name,
		Edges: []lineageEdge{{
			From: endpointLabel(st.Spec.Source.Engine, st.Spec.Source.Host, st.Spec.Source.Database),
			To:   fmt.Sprintf("jetstream:%s", st.Metadata.Name),
			Type: "stream",
		}},
	}, true
}

func handleLineage(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This is a CLUSTER-WIDE view (it lists dataflows/migrations/replications/streams across all
		// namespaces), so gate it on a CLUSTER-SCOPED SAR (namespace ""), not a single-namespace one —
		// otherwise a user with dataflows-list in one namespace could see every namespace's topology.
		if !authorize(w, r, cs, auth, logger, "list", "openinfra.dev", "dataflows", "", "") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		var flows []lineageFlow
		for _, item := range crList(ctx, cs, "dataflows") {
			if f, ok := dataFlowFlow(item); ok {
				flows = append(flows, f)
			}
		}
		for _, item := range crList(ctx, cs, "migrations") {
			if f, ok := migrationFlow(item); ok {
				flows = append(flows, f)
			}
		}
		for _, item := range crList(ctx, cs, "replications") {
			if f, ok := replicationFlow(item); ok {
				flows = append(flows, f)
			}
		}
		for _, item := range crList(ctx, cs, "streams") {
			if f, ok := streamFlow(item); ok {
				flows = append(flows, f)
			}
		}

		sort.Slice(flows, func(i, j int) bool { return flows[i].Origin < flows[j].Origin })
		writeJSON(w, http.StatusOK, flows)
	}
}
