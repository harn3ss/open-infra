package iamcompile

import (
	"context"
	"encoding/base64"
	"reflect"
	"sort"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/yaml"
)

// statementsOf is every statement the corpus applies to a principal, in a comparable form.
func statementsOf(t *testing.T, grants []Grant, principal string) []string {
	t.Helper()
	var out []string
	for _, g := range grants {
		for _, a := range g.AppliesTo {
			if a != principal {
				continue
			}
			for _, s := range g.Statements {
				b, err := yaml.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, string(b))
			}
		}
	}
	sort.Strings(out)
	return out
}

// Principals that hold the same policies compile to the same statements — thousands of resources each for
// a managed policy like PowerUserAccess — and the corpus carries them once, for all of them. Each
// principal's statements are exactly what they were: merging never widens or narrows anyone.
func TestMergeGrants_OnceForEveryPrincipalThatHoldsThem(t *testing.T) {
	out := Compile(Input{World: world(
		[]iamauthz.Policy{doc(t, "PowerUserAccess", powerUserDoc), doc(t, "AdministratorAccess", adminDoc)},
		map[string][]string{"User::alice": {"PowerUserAccess"}, "User::bob": {"PowerUserAccess"}, "User::carol": {"AdministratorAccess"}}),
		Principals: []Principal{
			{Kind: "User", Namespace: "open-infra-console", Name: "alice"},
			{Kind: "User", Namespace: "open-infra-console", Name: "bob"},
			{Kind: "User", Namespace: "open-infra-console", Name: "carol"},
		}})
	merged := MergeGrants(out.Corpus)
	if len(merged) >= len(out.Corpus) {
		t.Fatalf("%d grants merged into %d: alice's and bob's identical grants were not folded", len(out.Corpus), len(merged))
	}
	var principals []string
	for _, g := range out.Corpus {
		principals = append(principals, g.AppliesTo...)
	}
	if len(principals) == 0 {
		t.Fatal("the compile produced no grants")
	}
	for _, p := range principals {
		if before, after := statementsOf(t, out.Corpus, p), statementsOf(t, merged, p); !reflect.DeepEqual(before, after) {
			t.Errorf("%s: %d statements before merging, %d after", p, len(before), len(after))
		}
	}
	// What the webhook loads from the merged, compressed corpus is the same per principal.
	raw, err := MarshalCorpus(merged)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := GzipCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata":   map[string]any{"name": CorpusName, "namespace": CorpusNamespace},
		"binaryData": map[string]any{CorpusGzipKey: base64.StdEncoding.EncodeToString(gz)},
	}}
	dc := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{configMapGVR: "ConfigMapList"}, cm)
	docs, err := CorpusLoader(dc)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(docs, direct) || len(docs) == 0 {
		t.Fatalf("the loader read %d docs from the compressed corpus, want the %d the plain one parses to", len(docs), len(direct))
	}
}

// A corpus written before compression (plain YAML in data) is still read.
func TestCorpusLoader_ReadsAPlainCorpus(t *testing.T) {
	raw, err := MarshalCorpus([]Grant{{AppliesTo: []string{"User::alice"}, Statements: []Statement{{Effect: "Allow", Actions: []string{"get"}, Resources: []string{"*"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	cm := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": CorpusName, "namespace": CorpusNamespace},
		"data":     map[string]any{CorpusKey: string(raw)},
	}}
	dc := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{configMapGVR: "ConfigMapList"}, cm)
	docs, err := CorpusLoader(dc)(context.Background())
	if err != nil || len(docs) != 1 || docs[0].AppliesTo[0] != "User::alice" {
		t.Fatalf("plain corpus: %v %+v", err, docs)
	}
}
