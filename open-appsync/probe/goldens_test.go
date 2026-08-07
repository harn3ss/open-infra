package probe

import (
	"embed"
	"encoding/json"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// The runtime goldens harness (handoff §1): render each corpus template and diff it against a checked-
// in golden request object. Today the goldens are `source: documented` (authored from AWS's published
// semantics), so this is green and proves the harness + CI wiring work NOW. When the maintainer
// captures real AppSync output (once, their account) the goldens flip to `source: aws-capture` and this
// same diff becomes the behavior-faithful gate — see goldens/README.md. Non-determinism is pinned via
// the engine's injectable AutoID/Now providers so both sides of the diff are deterministic.

//go:embed goldens/*.json
var goldenFS embed.FS

type golden struct {
	Source      string         `json:"source"`
	Description string         `json:"description"`
	Template    string         `json:"template"`
	AutoID      string         `json:"autoId"`
	Now         string         `json:"now"`
	Context     map[string]any `json:"context"`
	Expected    any            `json:"expected"`
}

func loadGoldens(t *testing.T) map[string]golden {
	t.Helper()
	entries, err := goldenFS.ReadDir("goldens")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]golden{}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := goldenFS.ReadFile("goldens/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		var g golden
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatalf("golden %s: %v", e.Name(), err)
		}
		out[e.Name()] = g
	}
	if len(out) == 0 {
		t.Fatal("no goldens found — the harness must have at least one case")
	}
	return out
}

// engineFor builds a VTL engine with this golden's pinned autoId/now, so the render is deterministic
// and (once captured) byte-comparable to the values AWS produced.
func engineFor(t *testing.T, g golden) *vtl.Engine {
	t.Helper()
	e := vtl.New()
	e.Util().AutoID = func() string { return g.AutoID }
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	if g.Now != "" {
		parsed, err := time.Parse(time.RFC3339, g.Now)
		if err != nil {
			t.Fatalf("golden %s: bad now %q: %v", g.Description, g.Now, err)
		}
		now = parsed
	}
	e.Util().Now = func() time.Time { return now }
	return e
}

func TestGoldens_MatchCorpusRenders(t *testing.T) {
	for name, g := range loadGoldens(t) {
		name, g := name, g
		t.Run(name, func(t *testing.T) {
			tmpl, err := corpus.ReadFile("corpus/" + g.Template)
			if err != nil {
				t.Fatalf("golden references missing corpus template %q: %v", g.Template, err)
			}
			out, err := engineFor(t, g).Render(string(tmpl), g.Context)
			if err != nil {
				t.Fatalf("render %s: %v", g.Template, err)
			}
			var got any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("%s: render is not valid JSON: %v\n---\n%s", g.Template, err, out)
			}
			// Round-trip `expected` through JSON too so numeric types match (float64 both sides).
			var want any
			eb, _ := json.Marshal(g.Expected)
			_ = json.Unmarshal(eb, &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s diverges from golden %q [%s]:\n got %v\nwant %v", g.Template, name, g.Source, got, want)
			}
		})
	}
}

// TestGoldens_GraduationStatus reports the Clock-A gate: how many goldens are still authored from docs
// vs captured from real AWS. It never fails (so CI is green while the capture is pending) — it makes
// the gate visible. The runtime stays labeled experimental until this reports all captured.
func TestGoldens_GraduationStatus(t *testing.T) {
	goldens := loadGoldens(t)
	captured := 0
	for _, g := range goldens {
		if g.Source == "aws-capture" {
			captured++
		}
	}
	total := len(goldens)
	t.Logf("runtime goldens: %d/%d captured from real AWS (%d still documented)", captured, total, total-captured)
	if captured < total {
		t.Skipf("Clock A gate not cleared: %d/%d goldens still documented — runtime stays EXPERIMENTAL until captured from real AppSync (see goldens/README.md)", total-captured, total)
	}
}
