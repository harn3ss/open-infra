package render

import (
	"fmt"
	"testing"
)

const mailRelayPath = "../../platform/mail/relay.yaml"

// relayIngressPeers returns the relay's ingress-isolating NetworkPolicy (the one selecting podLabel) and,
// for its single ingress rule, its peers and ports.
func relayIngress(t *testing.T, path, podLabel, podValue string) (map[string]any, []any, []any) {
	t.Helper()
	docs, err := parseYAMLDocs(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		if d["kind"] != "NetworkPolicy" {
			continue
		}
		if mstr(d, "spec", "podSelector", "matchLabels", podLabel) != podValue {
			continue
		}
		in, _ := mget(d, "spec", "ingress").([]any)
		if len(in) != 1 {
			t.Fatalf("%s: the relay's policy must have exactly one ingress rule, got %v", path, mget(d, "spec", "ingress"))
		}
		from, _ := mget(in[0], "from").([]any)
		ports, _ := mget(in[0], "ports").([]any)
		return d, from, ports
	}
	t.Fatalf("%s: no NetworkPolicy selects the relay pods (%s=%s)", path, podLabel, podValue)
	return nil, nil, nil
}

// onlyTheShim fails unless from is exactly one peer: the aws-shim's pods, by namespace and pod label (no
// ipBlock, which this cluster's network does not enforce reliably for in-cluster sources, and no open rule).
func onlyTheShim(t *testing.T, path string, from []any) {
	t.Helper()
	if len(from) != 1 {
		t.Fatalf("%s: the relay must admit exactly one peer (the aws-shim), got %v", path, from)
	}
	p := from[0]
	if mget(p, "ipBlock") != nil {
		t.Fatalf("%s: the relay's peer must be a pod selector, not an ipBlock: %v", path, p)
	}
	if mstr(p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "open-infra-aws-shim" ||
		mstr(p, "podSelector", "matchLabels", "app") != "aws-shim" {
		t.Fatalf("%s: the relay's only peer must be the aws-shim's pods in open-infra-aws-shim, got %v", path, p)
	}
}

// The delivering relay accepts mail from the aws-shim alone, on its submission port only: no other pod
// can submit to it (it would send as any identity, unauthenticated), and port 25 admits nothing.
func TestMailRelay_AcceptsOnlyTheShim(t *testing.T) {
	np, from, ports := relayIngress(t, mailRelayPath, "app", "smtp-relay")
	if types := fmt.Sprint(mget(np, "spec", "policyTypes")); types != "[Ingress]" {
		t.Fatalf("the relay's policy governs ingress only (it must deliver outbound): %s", types)
	}
	onlyTheShim(t, mailRelayPath, from)
	if len(ports) != 1 || mstr(ports[0], "port") != "587" || mstr(ports[0], "protocol") != "TCP" {
		t.Fatalf("the relay must admit the shim on its submission port 587 only, got %v", ports)
	}
	if mstr(np, "metadata", "namespace") != "mail" {
		t.Fatalf("the relay's policy must live in the mail namespace, got %q", mstr(np, "metadata", "namespace"))
	}
}

// The capturing relay keeps its no-egress guarantee and, like the delivering one, accepts mail from the
// aws-shim alone.
func TestMailCapture_AcceptsOnlyTheShim(t *testing.T) {
	np, from, ports := relayIngress(t, mailCapturePath, "openinfra.dev/mail-capture", "true")
	if eg, ok := mget(np, "spec", "egress").([]any); !ok || len(eg) != 0 {
		t.Fatalf("the sink must still have no egress, got %v", mget(np, "spec", "egress"))
	}
	onlyTheShim(t, mailCapturePath, from)
	if len(ports) != 1 || mstr(ports[0], "port") != "1025" {
		t.Fatalf("the sink must admit the shim on its SMTP port 1025 only, got %v", ports)
	}
}
