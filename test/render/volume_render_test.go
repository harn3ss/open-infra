package render

import (
	"regexp"
	"strings"
	"testing"
)

const volumeCompositionPath = "../../platform/abstraction/volume-composition.yaml"

// pvcReadiness is the readiness the Volume's PVC Object must carry: Ready only once Bound.
const pvcReadiness = "celQuery: has(object.status) && has(object.status.phase) && object.status.phase == 'Bound'"

// kind: Volume reports Ready only once its PVC is Bound — never merely because the PVC object
// exists. An encrypted volume's PVC stays Pending until its LUKS passphrase Secret is materialized,
// and the provider default (Ready on create) let a CloudFormation stack complete over an unusable
// disk. Every variant (plain, migratable, encrypted, restored) carries the same readiness.
func TestVolume_ReadyOnlyWhenBound(t *testing.T) {
	tmpl := extractInlineTemplate(t, volumeCompositionPath)
	for _, tc := range []struct {
		name  string
		spec  map[string]any
		class string
	}{
		{"plain", map[string]any{"size": "10Gi"}, "longhorn"},
		{"migratable", map[string]any{"size": "10Gi", "migratable": true}, "longhorn-migratable"},
		{"encrypted", map[string]any{"size": "10Gi", "encrypted": true, "encryptionKey": "k1"}, "longhorn-encrypted"},
		{"restored", map[string]any{"size": "10Gi", "source": map[string]any{"snapshot": "snap-1"}}, "longhorn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tmpl, compositeCtx(tc.spec))
			if !strings.Contains(out, "policy: DeriveFromCelQuery") || !strings.Contains(out, pvcReadiness) {
				t.Errorf("the Volume PVC must be Ready only once Bound; got:\n%s", grepCtx(out, "readiness"))
			}
			if !strings.Contains(out, "storageClassName: "+tc.class+"\n") {
				t.Errorf("want storageClassName %s; got:\n%s", tc.class, grepCtx(out, "storageClassName"))
			}
			if strings.Count(out, "readiness:") != 1 {
				t.Errorf("exactly one composed resource (the PVC) carries readiness; got %d", strings.Count(out, "readiness:"))
			}
		})
	}
	// The encrypted variant still names its EncryptionKey (what the volume-crypto reconciler keys on).
	out := render(t, tmpl, compositeCtx(map[string]any{"size": "10Gi", "encrypted": true, "encryptionKey": "k1"}))
	if !strings.Contains(out, `openinfra.dev/encryption-key: "k1"`) {
		t.Errorf("an encrypted Volume must annotate its PVC with its EncryptionKey; got:\n%s", grepCtx(out, "encryption-key"))
	}
}

// Ready-on-Bound is only sound for Immediate-binding classes: a WaitForFirstConsumer PVC never
// binds until a pod mounts it, so the Volume would never go Ready. Pin every class the composition
// can select to Immediate.
func TestVolume_StorageClassesBindImmediately(t *testing.T) {
	comp := mustRead(t, volumeCompositionPath)
	line := regexp.MustCompile(`storageClassName: (\{\{.*\}\})`).FindStringSubmatch(comp)
	if line == nil {
		t.Fatal("no storageClassName template line in the Volume composition")
	}
	classes := map[string]bool{}
	for _, c := range regexp.MustCompile(`\}\}(longhorn[a-z-]*)\{\{`).FindAllStringSubmatch(line[1], -1) {
		classes[c[1]] = true
	}
	for _, want := range []string{"longhorn", "longhorn-migratable", "longhorn-encrypted"} {
		if !classes[want] {
			t.Fatalf("expected the composition to select %s; parsed classes %v from %q — update this test with the new class set", want, classes, line[1])
		}
	}
	if len(classes) != 3 {
		t.Fatalf("the Volume composition selects a class this test does not pin (%v): add its binding-mode check", classes)
	}
	for class, file := range map[string]string{
		"longhorn-migratable": "../../platform/storage/longhorn-migratable.yaml",
		"longhorn-encrypted":  "../../platform/storage/longhorn-encrypted.yaml",
	} {
		sc := mustRead(t, file)
		if !strings.Contains(sc, "name: "+class+"\n") || !strings.Contains(sc, "volumeBindingMode: Immediate\n") {
			t.Errorf("%s (%s) must declare volumeBindingMode: Immediate — the Volume's Ready-on-Bound depends on it", class, file)
		}
	}
	// `longhorn` is the Longhorn chart's own class; the chart default binding mode is Immediate, so
	// the values must not override it.
	if strings.Contains(mustRead(t, "../../platform/storage/longhorn.yaml"), "WaitForFirstConsumer") {
		t.Errorf("the longhorn class must stay Immediate-binding — the Volume's Ready-on-Bound depends on it")
	}
}
