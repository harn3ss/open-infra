package render

import (
	"os"
	"strings"
	"testing"
)

// kind: Queue's connection Secret is credential-less (NATS is no-auth in-cluster), so it is rendered
// directly by the provider as a composed resource — the stream-init Job writes no Secret and needs no
// secret RBAC. Readiness keys off the Job's own success, not a Secret-as-marker.
func TestQueue_ConnSecretIsComposedNoJobWrite(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/queue-composition.yaml")
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec":     map[string]any{"queueName": "orders"},
		"metadata": map[string]any{"labels": map[string]any{"crossplane.io/claim-name": "orders", "crossplane.io/claim-namespace": "shop"}},
	}}}}
	out := render(t, tmpl, ctx)

	// The connection Secret is a composed Object with the NATS fields.
	for _, want := range []string{
		"composition-resource-name: queue-conn",
		"name: orders-queue, namespace: shop",
		"NATS_URL: nats://nats.nats.svc.cluster.local:4222",
		"QUEUE_STREAM: orders",
		`object.status.succeeded > 0`, // the Job's own success gates readiness
	} {
		if !strings.Contains(out, want) {
			t.Errorf("queue render missing %q:\n%s", want, grepCtx(out, "queue-conn"))
		}
	}
	// The stream-init Job must NOT write a Secret (no kubectl, no secret container) — that was the only
	// reason it held secret RBAC.
	for _, forbidden := range []string{"kubectl create secret", "name: secret", "queue-ready-gate"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("queue setup Job still does %q — it should write no Secret:\n%s", forbidden, grepCtx(out, forbidden))
		}
	}

	// The queue setup SA must carry no secret RBAC any more.
	setup, err := os.ReadFile("../../platform/abstraction/queue-setup.yaml")
	if err != nil {
		t.Fatalf("read queue-setup.yaml: %v", err)
	}
	if strings.Contains(string(setup), "kind: ClusterRole") || strings.Contains(string(setup), "kind: Role") {
		t.Errorf("queue-setup.yaml still defines an RBAC role for the setup SA; it should have none:\n%s", setup)
	}
}
