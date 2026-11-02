package render

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

const mailCapturePath = "../../platform/mail/relay-capture.yaml"

// The capturing relay (mail.capture) is a drop-in smtp-relay Service that can never deliver: a
// digest-pinned sink, no egress at all, and its API (every captured message) on the pod's loopback only.
func TestMailCapture_NeverDelivers(t *testing.T) {
	raw := mustRead(t, mailCapturePath)
	docs, err := parseYAMLDocs(raw)
	if err != nil {
		t.Fatal(err)
	}
	var svc, np, dep map[string]any
	for _, d := range docs {
		switch d["kind"] {
		case "Service":
			svc = d
		case "NetworkPolicy":
			np = d
		case "Deployment":
			dep = d
		}
	}
	if svc == nil || np == nil || dep == nil {
		t.Fatalf("relay-capture.yaml must carry the Deployment, the Service and the egress policy")
	}
	if name, _ := svc["metadata"].(map[string]any)["name"].(string); name != "smtp-relay" {
		t.Fatalf("the sink must be the smtp-relay Service (got %q), so submitters need no change", name)
	}
	for _, port := range []string{"port: 587, targetPort: 1025", "port: 25, targetPort: 1025"} {
		if !strings.Contains(raw, port) {
			t.Errorf("the Service must serve the relay's ports onto the sink (%s)", port)
		}
	}
	spec := np["spec"].(map[string]any)
	types, _ := spec["policyTypes"].([]any)
	if len(types) != 2 || types[0] != "Ingress" || types[1] != "Egress" {
		t.Fatalf("the sink's NetworkPolicy must govern ingress (SMTP only) and egress (none): %v", types)
	}
	// SMTP alone is admitted: on kube-ovn an Egress-only deny also drops the replies to an inbound
	// connection that no Ingress rule admitted, so the sink would accept nothing.
	if in, ok := spec["ingress"].([]any); !ok || len(in) != 1 || !strings.Contains(fmt.Sprint(in), "port:1025") {
		t.Fatalf("the sink must admit exactly its SMTP port (1025), got %v", spec["ingress"])
	}
	if eg, ok := spec["egress"].([]any); !ok || len(eg) != 0 {
		t.Fatalf("the sink must have NO egress allowed (egress: []), got %v", spec["egress"])
	}
	if !regexp.MustCompile(`image: \S+@sha256:[0-9a-f]{64}`).MatchString(raw) {
		t.Error("the sink's image must be pinned by digest")
	}
	if !strings.Contains(raw, `MP_UI_BIND_ADDR, value: "127.0.0.1:8025"`) {
		t.Error("the sink's API (every captured message) must listen on loopback only")
	}
	if strings.Contains(raw, "MP_SMTP_RELAY") {
		t.Error("the sink must not be configured to relay anything onward")
	}
}

// install.sh includes exactly one relay: the capturing one only under mail.capture, the delivering one
// otherwise.
func TestMailCapture_ExactlyOneRelay(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`incl mail "abstraction/emailsender-xrd.yaml,abstraction/emailsender-composition.yaml,mail/relay.yaml,mail/relay-capture.yaml"`,
		`if [ "$(yget components.mail)" = "true" ] && [ "$(yget mail.capture)" = "true" ]; then`,
		`EXCLUDES="${EXCLUDES},mail/relay.yaml"`,
		`EXCLUDES="${EXCLUDES},mail/relay-capture.yaml"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh is missing %q", want)
		}
	}
}
