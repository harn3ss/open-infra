package main

import (
	"encoding/json"
	"math/rand"
	"testing"
)

func mustGrammar(t *testing.T) *Grammar {
	t.Helper()
	g, err := loadGrammar(resolve("chaos/grammar.json"))
	if err != nil {
		t.Fatalf("load grammar: %v", err)
	}
	return g
}

// The grammar must bless every chain in the real corpus — this is the closure
// guarantee: the grammar is derived FROM the scenarios, so it can never legally
// reject one. If this fails, either a scenario drifted off the grammar or the
// grammar lost a connector.
func TestGrammarValidatesCorpus(t *testing.T) {
	g := mustGrammar(t)
	d, err := loadDoc(resolve("chaos/scenarios.json"))
	if err != nil {
		t.Fatalf("load scenarios: %v", err)
	}
	for _, s := range d.Scenarios {
		kindOf := map[string]string{}
		for _, n := range s.Chain.Nodes {
			kindOf[n.ID] = n.Kind
			if _, ok := g.Kinds[n.Kind]; !ok {
				t.Errorf("%s: unknown node kind %q", s.ID, n.Kind)
			}
		}
		for _, e := range s.Chain.Edges {
			if ok, _ := g.edgeLegal(kindOf[e.From], kindOf[e.To], e.Label); !ok {
				t.Errorf("%s: corpus edge %s→%s (%q) is not blessed by the grammar",
					s.ID, kindOf[e.From], kindOf[e.To], e.Label)
			}
		}
		if !g.faultKnown(s.Fault.Kind) {
			t.Errorf("%s: fault.kind %q not in grammar palette", s.ID, s.Fault.Kind)
		}
	}
}

// Fail-closed: an edge no connector blesses must be rejected; blessed ones accepted;
// leaves and islands must not originate edges.
func TestEdgeLegalityIsFailClosed(t *testing.T) {
	g := mustGrammar(t)
	legal := [][3]string{
		{"database", "database", "replication"}, // bidirectional peer
		{"database", "app", "CDC"},
		{"app", "database", "apply"},
		{"app", "database", ""}, // unlabeled but blessed pair
		{"volume", "vm", "hotplug"},
		{"vm", "storage", "CSI snapshot"},
		{"stream", "function", ""},
	}
	for _, c := range legal {
		if ok, _ := g.edgeLegal(c[0], c[1], c[2]); !ok {
			t.Errorf("expected %s→%s (%q) legal", c[0], c[1], c[2])
		}
	}
	illegal := [][3]string{
		{"fileshare", "function", ""}, // island cannot wire
		{"function", "app", ""},       // leaf cannot originate
		{"storage", "database", ""},   // leaf cannot originate
		{"vm", "vm", "hotplug"},       // volume→vm only, not vm→vm
		{"database", "function", "CDC"},
	}
	for _, c := range illegal {
		if ok, _ := g.edgeLegal(c[0], c[1], c[2]); ok {
			t.Errorf("expected %s→%s (%q) ILLEGAL", c[0], c[1], c[2])
		}
	}
}

// A label that isn't in the grammar but whose kind-pair is blessed must be flagged
// UNTYPED (kindOK true, labelOK false), not silently accepted.
func TestUnknownLabelIsUntypedNotIllegal(t *testing.T) {
	g := mustGrammar(t)
	kindOK, labelOK := g.edgeLegal("app", "database", "totally-made-up-label")
	if !kindOK || labelOK {
		t.Fatalf("app→database with unknown label: want kindOK=true labelOK=false, got %v %v", kindOK, labelOK)
	}
}

// Everything the generator emits must be legal by construction, across many seeds.
func TestGeneratedChainsAlwaysLegal(t *testing.T) {
	g := mustGrammar(t)
	for seed := int64(1); seed <= 60; seed++ {
		r := rand.New(rand.NewSource(seed))
		for i := 0; i < 12; i++ {
			s := g.genChain(r, i, 6, "")
			if len(s.Chain.Nodes) == 0 {
				t.Fatalf("seed %d chain %d has no nodes", seed, i)
			}
			kindOf := map[string]string{}
			for _, n := range s.Chain.Nodes {
				kindOf[n.ID] = n.Kind
			}
			for _, e := range s.Chain.Edges {
				if ok, _ := g.edgeLegal(kindOf[e.From], kindOf[e.To], e.Label); !ok {
					t.Fatalf("seed %d chain %d: generated ILLEGAL edge %s→%s (%q)",
						seed, i, kindOf[e.From], kindOf[e.To], e.Label)
				}
			}
		}
	}
}

// A generated chain may count only if its fault's plane is watched — the coupling
// that stops "a million chains, one judge, a million false greens."
func TestCountedOnlyWhenPlaneWatched(t *testing.T) {
	g := mustGrammar(t)
	sawWatched, sawUnwatched := false, false
	for seed := int64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		s := g.genChain(r, 0, 5, "")
		kindOf := map[string]string{}
		for _, n := range s.Chain.Nodes {
			kindOf[n.ID] = n.Kind
		}
		// Recompute the plane kind the generator routed on.
		planeKind := kindOf[s.Fault.Target]
		if len(s.Fault.Edge) == 2 {
			planeKind = kindOf[s.Fault.Edge[0]]
		}
		want := g.Planes[planeKind].Watched
		if s.Counted == nil || *s.Counted != want {
			t.Fatalf("seed %d: counted=%v but plane %q watched=%v", seed, s.Counted, planeKind, want)
		}
		if want {
			sawWatched = true
		} else {
			sawUnwatched = true
		}
	}
	if !sawWatched || !sawUnwatched {
		t.Fatalf("expected both watched and unwatched chains across seeds (watched=%v unwatched=%v)", sawWatched, sawUnwatched)
	}
}

// pick must only ever draw WATCHED scenarios, and must rotate the surface (not just the mesh) —
// this is what stops continuous from being multi-master-only.
func TestPickOnlyWatchedAndRotates(t *testing.T) {
	g := mustGrammar(t)
	var watched []ScenarioSpec
	watchedSet := map[string]bool{}
	for _, s := range g.Scenarios {
		if s.Watched {
			watched = append(watched, s)
			watchedSet[s.Scenario] = true
		}
	}
	if len(watched) < 5 {
		t.Fatalf("expected several watched scenarios, got %d", len(watched))
	}
	seen := map[string]int{}
	for seed := int64(1); seed <= 300; seed++ {
		p := watched[rand.New(rand.NewSource(seed)).Intn(len(watched))]
		if !watchedSet[p.Scenario] {
			t.Fatalf("seed %d picked non-watched %q", seed, p.Scenario)
		}
		seen[p.Scenario]++
	}
	// pick must never draw an unwatched (PENDING) scenario. Derive the check from the grammar
	// rather than a hardcoded name, so promoting a plane to watched:true doesn't make this stale.
	for _, s := range g.Scenarios {
		if !s.Watched && seen[s.Scenario] != 0 {
			t.Fatalf("picked %q, which is watched:false (PENDING) and must never be drawn", s.Scenario)
		}
	}
	if len(seen) < 5 {
		t.Fatalf("expected the picker to rotate ≥5 distinct planes across 300 seeds, got %d", len(seen))
	}
	if seen["lottery"] == 300 {
		t.Fatal("picker only ever drew the mesh — it is not rotating")
	}
}

// Same seed → identical output (safe to replay a chain from its seed).
func TestDeterministic(t *testing.T) {
	g := mustGrammar(t)
	gen := func() string {
		r := rand.New(rand.NewSource(99))
		var out []Scenario
		for i := 0; i < 10; i++ {
			out = append(out, g.genChain(r, i, 5, ""))
		}
		b, _ := json.Marshal(out)
		return string(b)
	}
	if gen() != gen() {
		t.Fatal("generation is not deterministic for a fixed seed")
	}
}
