// Package attest assembles a compliance attestation from the LIVE cluster: not a static claim, but a
// snapshot of the government-control machinery actually present and its evidence — how many temporal
// grants, data classifications, customer keys, destruction certificates, and data flows exist, and
// whether the off-site audit chain last verified intact. Both the console's read-only view
// (cmd/server) and the signing tool (cmd/attest) call Assemble, so the signed artifact and the
// on-screen report are the same evidence.
//
// It reads only Kubernetes (custom resources + ConfigMaps) — no object-store or Vault access — so it
// needs no secrets. The audit-chain evidence comes from the ConfigMap anchor the audit off-siter
// writes (a different trust domain than the bucket), which already carries the verified head.
package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// usableREST returns the REST client, or nil if it is a TYPED nil (the fake clientset always hands
// back a typed-nil *rest.RESTClient, which is non-nil as an interface and panics on first use).
func usableREST(cs kubernetes.Interface) rest.Interface {
	rc := cs.CoreV1().RESTClient()
	if rc == nil {
		return nil
	}
	if v := reflect.ValueOf(rc); v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	return rc
}

// ControlCoverage is one NIST control family and the live evidence for it.
type ControlCoverage struct {
	Control  string `json:"control"`  // e.g. "AC-2(2) / AC-6"
	Feature  string `json:"feature"`  // the open-infra mechanism
	Present  bool   `json:"present"`  // is the mechanism deployed / are there resources?
	Evidence string `json:"evidence"` // the live counts / status
}

// Attestation is the whole signed document.
type Attestation struct {
	GeneratedAt string            `json:"generatedAt"` // RFC3339, stamped by the caller (Assemble leaves it empty)
	ConsoleNS   string            `json:"consoleNamespace"`
	Controls    []ControlCoverage `json:"controls"`
	Evidence    map[string]int    `json:"evidence"` // raw counts, for machine checks
	AuditHead   string            `json:"auditHead,omitempty"`
	Note        string            `json:"note"`
}

// countCR lists a cluster-wide custom resource and returns how many exist. Best-effort: a missing CRD
// (feature disabled) counts as 0.
func countCR(ctx context.Context, cs kubernetes.Interface, group, plural string) int {
	rc := usableREST(cs)
	if rc == nil {
		return 0
	}
	raw, err := rc.Get().AbsPath("/apis/" + group + "/v1/" + plural).DoRaw(ctx)
	if err != nil {
		return 0
	}
	var out struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return 0
	}
	return len(out.Items)
}

// countCMs returns how many ConfigMaps in ns carry the given label selector, and — of those — how
// many have data[key] == want (e.g. exists=true, phase=Destroyed).
func countCMs(ctx context.Context, cs kubernetes.Interface, ns, selector, key, want string) (total, matching int) {
	cms, err := cs.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return 0, 0
	}
	for i := range cms.Items {
		total++
		if key != "" && cms.Items[i].Data[key] == want {
			matching++
		}
	}
	return total, matching
}

// countClassifiedWorkloads counts Deployments + StatefulSets carrying the classification label.
func countClassifiedWorkloads(ctx context.Context, cs kubernetes.Interface) int {
	n := 0
	if dl, err := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/classification"}); err == nil {
		n += len(dl.Items)
	}
	if sl, err := cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/classification"}); err == nil {
		n += len(sl.Items)
	}
	return n
}

// Assemble gathers the live evidence and maps it to controls. The caller stamps GeneratedAt (Assemble
// takes no clock, so it stays deterministic/testable). anchorNS is where the audit off-siter writes
// its head anchor (empty → "monitoring").
func Assemble(ctx context.Context, cs kubernetes.Interface, consoleNS, anchorNS string) Attestation {
	if anchorNS == "" {
		anchorNS = "monitoring"
	}
	grants := countCR(ctx, cs, "iam.openinfra.dev", "grants")
	classes, _ := countCMs(ctx, cs, consoleNS, "openinfra.dev/dataclass", "", "")
	classified := countClassifiedWorkloads(ctx, cs)
	encKeys := countCR(ctx, cs, "openinfra.dev", "encryptionkeys")
	_, provisioned := countCMs(ctx, cs, consoleNS, "openinfra.dev/enckey", "exists", "true")
	// Count Destructions by the CR (one each), not the label — which is on BOTH the spec-mirror and
	// the state ConfigMap, so a label count would ~double it. `destroyed` is the state CMs at
	// phase=Destroyed (the state CM alone carries phase).
	destructions := countCR(ctx, cs, "openinfra.dev", "destructions")
	_, destroyed := countCMs(ctx, cs, consoleNS, "openinfra.dev/destruction", "phase", "Destroyed")
	dataflows := countCR(ctx, cs, "openinfra.dev", "dataflows")
	migrations := countCR(ctx, cs, "openinfra.dev", "migrations")
	replications := countCR(ctx, cs, "openinfra.dev", "replications")
	streams := countCR(ctx, cs, "openinfra.dev", "streams")
	lineageFlows := dataflows + migrations + replications + streams

	// Audit-chain evidence from the off-siter's ConfigMap anchor (k8s, no bucket access needed). The
	// anchor records the head the off-siter last VERIFIED, and — crucially — it is NOT advanced when
	// the off-siter detects tampering (it holds the last good head so the alarm persists). So the
	// anchor's mere presence does NOT prove current integrity: report the recorded head + WHEN it was
	// last verified, and defer the live verdict to the console's integrity check. Never say "verified".
	auditHead := ""
	auditVerifiedAt := ""
	auditPresent := false
	if cm, err := cs.CoreV1().ConfigMaps(anchorNS).Get(ctx, "audit-offsite-anchor", metav1.GetOptions{}); err == nil {
		var a struct {
			HeadSeq    int    `json:"headSeq"`
			HeadHash   string `json:"headHash"`
			VerifiedAt string `json:"verifiedAt"`
		}
		if json.Unmarshal([]byte(cm.Data["anchor.json"]), &a) == nil && a.HeadHash != "" {
			auditPresent = true
			auditHead = fmt.Sprintf("#%d %.12s", a.HeadSeq, a.HeadHash)
			auditVerifiedAt = a.VerifiedAt
		}
	}
	auditEvidence := "audit off-siting not enabled / no anchor recorded yet"
	if auditPresent {
		auditEvidence = fmt.Sprintf("off-site anchor at head %s, last verified %s — see console Audit → Integrity for live status",
			auditHead, orNever(auditVerifiedAt))
	}

	// `Present` means "there is live evidence of this control in use" (a resource/instance exists),
	// consistently across families — never a tautology. Zero evidence → not present, with the count
	// shown so the reader sees exactly what backs the claim. Absence of instances is not a claim that
	// the mechanism is uninstalled; it is the honest statement that nothing yet exercises it.
	controls := []ControlCoverage{
		{"AC-2(2) / AC-6(2)/(5)", "kind: Grant (temporal access)", grants > 0,
			fmt.Sprintf("%d active grant(s); expiry reconciler + alert", grants)},
		{"AU-9 / AU-9(2)/(3) / AU-11", "audit off-siting (WORM hash chain)", auditPresent, auditEvidence},
		{"RA-2 / MP-3 / AC-4", "kind: DataClassification", classes > 0,
			fmt.Sprintf("%d classification(s); %d classified workload(s) — compliance on the Data Classification page", classes, classified)},
		{"SC-12 / SC-13 / SC-28 / SC-28(1)", "customer-owned keys (Vault Transit)", encKeys > 0,
			fmt.Sprintf("%d encryption key(s), %d provisioned", encKeys, provisioned)},
		{"MP-6 / SP 800-88", "crypto-erase (kind: Destruction)", destructions > 0,
			fmt.Sprintf("%d destruction(s), %d completed with certificate", destructions, destroyed)},
		{"SI-12 / AU", "data lineage", lineageFlows > 0,
			fmt.Sprintf("%d data movement(s) tracked (dataflow/migration/replication/stream)", lineageFlows)},
	}

	return Attestation{
		ConsoleNS: consoleNS,
		Controls:  controls,
		AuditHead: auditHead,
		Evidence: map[string]int{
			"grants": grants, "dataClassifications": classes, "classifiedWorkloads": classified,
			"encryptionKeys": encKeys, "encryptionKeysProvisioned": provisioned,
			"destructions": destructions, "destructionsCompleted": destroyed,
			"lineageFlows": lineageFlows,
		},
		Note: "Live evidence of the government-control machinery present in this cluster, mapped to NIST 800-53. " +
			"Presence of a mechanism is not a certification; see docs/security-and-compliance.md for the full control mapping and honesty notes.",
	}
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

// Markdown renders a human-readable attestation (what a signer signs alongside the JSON).
func Markdown(a Attestation) string {
	s := "# open-infra compliance attestation\n\n"
	s += "Generated: " + a.GeneratedAt + "\n\n"
	s += "| Control | Mechanism | Present | Evidence |\n|---|---|---|---|\n"
	for _, c := range a.Controls {
		present := "no"
		if c.Present {
			present = "yes"
		}
		s += fmt.Sprintf("| %s | %s | %s | %s |\n", c.Control, c.Feature, present, c.Evidence)
	}
	s += "\n" + a.Note + "\n"
	return s
}
