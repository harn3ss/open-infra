// Command chainforge turns the chaos chain topology from hand-authored into generated.
//
// It reads the fail-closed grammar (chaos/grammar.json) and:
//   - validate: proves every chain in chaos/scenarios.json is type-legal (a CI drift gate
//     and a closure check on the grammar itself).
//   - generate: emits new, seed-reproducible, type-legal chains (the fuzzer's front half).
//   - matrix:   renders the full kind×kind compatibility matrix as an audit lens.
//
// Stdlib only. Run from the repo root.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// resolve makes a repo-root-relative path work whether the tool is run from the
// repo root or from within tools/chainforge (each tool is its own module, so it is
// invoked as `cd tools/chainforge && go run .`). It walks up from the CWD until the
// file exists.
func resolve(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	dir, err := os.Getwd()
	if err != nil {
		return rel
	}
	for {
		p := filepath.Join(dir, rel)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return rel
		}
		dir = parent
	}
}

// ---- grammar ----

type Grammar struct {
	PortTypes  map[string]string   `json:"portTypes"`
	Kinds      map[string]KindSpec `json:"kinds"`
	Connectors []Connector         `json:"connectors"`
	Faults     FaultPalette        `json:"faults"`
	Planes     map[string]Plane    `json:"planes"`
}

type KindSpec struct {
	Role    string   `json:"role"`
	Offers  []string `json:"offers"`
	Accepts []string `json:"accepts"`
}

type Connector struct {
	Port   string   `json:"port"`
	From   string   `json:"from"`
	To     []string `json:"to"`
	Dir    string   `json:"dir"`
	Labels []string `json:"labels"`
}

type FaultPalette struct {
	Node   []string `json:"node"`
	Edge   []string `json:"edge"`
	Either []string `json:"either"`
}

type Plane struct {
	Oracle  string `json:"oracle"`
	Mode    string `json:"mode"`
	Watched bool   `json:"watched"`
	Note    string `json:"note"`
}

// ---- scenarios.json (subset, matching tools/chaosdoc) ----

type Doc struct {
	Scenarios []Scenario `json:"scenarios"`
}
type Node struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}
type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
	Dir   string `json:"dir,omitempty"`
}
type Fault struct {
	Target string   `json:"target,omitempty"`
	Edge   []string `json:"edge,omitempty"`
	Node   string   `json:"node,omitempty"`
	Kind   string   `json:"kind"`
	Label  string   `json:"label"`
}
type Oracle struct {
	Mode      string `json:"mode"`
	Invariant string `json:"invariant"`
}
type Chain struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
type Scenario struct {
	ID       string `json:"id"`
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"`
	Chain    Chain  `json:"chain"`
	Fault    Fault  `json:"fault"`
	Oracle   Oracle `json:"oracle"`
	Counted  *bool  `json:"counted,omitempty"` // generated chains: may this chain bank a green?
}

// ---- helpers ----

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func (g *Grammar) faultKnown(kind string) bool {
	if kind == "" {
		return true
	}
	return contains(g.Faults.Node, kind) || contains(g.Faults.Edge, kind) || contains(g.Faults.Either, kind)
}

// edgeLegal reports whether some connector blesses the (fromKind→toKind) pair, and
// whether the specific label is also typed by that connector. An empty label is
// treated as typed (the corpus uses "" for genuinely unlabeled but blessed links).
func (g *Grammar) edgeLegal(fromKind, toKind, label string) (kindOK, labelOK bool) {
	label = strings.TrimSpace(label)
	for _, c := range g.Connectors {
		fwd := c.From == fromKind && contains(c.To, toKind)
		rev := c.Dir == "both" && c.From == toKind && contains(c.To, fromKind)
		if !fwd && !rev {
			continue
		}
		kindOK = true
		if label == "" || contains(c.Labels, label) {
			labelOK = true
		}
	}
	return
}

func loadGrammar(path string) (*Grammar, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g Grammar
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &g, nil
}

func loadDoc(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &d, nil
}

// ---- validate ----

func cmdValidate(g *Grammar, d *Doc) int {
	var illegal, untyped, structural int
	for _, s := range d.Scenarios {
		kindOf := map[string]string{}
		for _, n := range s.Chain.Nodes {
			kindOf[n.ID] = n.Kind
			if _, ok := g.Kinds[n.Kind]; !ok {
				fmt.Printf("STRUCT  %s: node %q has unknown kind %q\n", s.ID, n.ID, n.Kind)
				structural++
			}
		}
		for _, e := range s.Chain.Edges {
			fk, fok := kindOf[e.From]
			tk, tok := kindOf[e.To]
			if !fok || !tok {
				fmt.Printf("STRUCT  %s: edge %s→%s references an undefined node id\n", s.ID, e.From, e.To)
				structural++
				continue
			}
			kindOK, labelOK := g.edgeLegal(fk, tk, e.Label)
			if !kindOK {
				fmt.Printf("ILLEGAL %s: %s(%s) --%q--> %s(%s) — no connector blesses this kind pair\n",
					s.ID, e.From, fk, e.Label, e.To, tk)
				illegal++
			} else if !labelOK {
				fmt.Printf("UNTYPED %s: %s(%s) --%q--> %s(%s) — kind pair OK, label not in grammar (fold it into a connector)\n",
					s.ID, e.From, fk, e.Label, e.To, tk)
				untyped++
			}
		}
		// fault structural sanity
		if !g.faultKnown(s.Fault.Kind) {
			fmt.Printf("STRUCT  %s: fault.kind %q not in grammar palette\n", s.ID, s.Fault.Kind)
			structural++
		}
		if s.Fault.Target != "" {
			if _, ok := kindOf[s.Fault.Target]; !ok {
				fmt.Printf("STRUCT  %s: fault.target %q is not a node id\n", s.ID, s.Fault.Target)
				structural++
			}
		}
		for _, id := range s.Fault.Edge {
			if _, ok := kindOf[id]; !ok {
				fmt.Printf("STRUCT  %s: fault.edge references non-node id %q\n", s.ID, id)
				structural++
			}
		}
	}
	fmt.Printf("\nchainforge validate: %d scenarios — %d illegal, %d untyped-label, %d structural\n",
		len(d.Scenarios), illegal, untyped, structural)
	if illegal > 0 || structural > 0 {
		fmt.Println("FAIL: the grammar is fail-closed — an illegal or malformed chain must be fixed (in the scenario or the grammar).")
		return 1
	}
	fmt.Println("OK: every chain is type-legal against chaos/grammar.json.")
	return 0
}

// ---- generate ----

// fromKinds are the kinds that can originate an edge (appear as a connector source).
func (g *Grammar) fromKinds() []string {
	set := map[string]bool{}
	for _, c := range g.Connectors {
		set[c.From] = true
	}
	out := keys(set)
	return out
}

// connectorsFrom returns connectors whose source is kind k.
func (g *Grammar) connectorsFrom(k string) []Connector {
	var out []Connector
	for _, c := range g.Connectors {
		if c.From == k {
			out = append(out, c)
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

// islandKinds are stand-alone fault targets with no edges.
func (g *Grammar) islandKinds() []string {
	var out []string
	for k, spec := range g.Kinds {
		if spec.Role == "island" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (g *Grammar) genChain(r *rand.Rand, idx, maxNodes int) Scenario {
	var nodes []Node
	var edges []Edge
	addNode := func(kind string) string {
		id := fmt.Sprintf("n%d", len(nodes)+1) // globally unique within the chain
		nodes = append(nodes, Node{ID: id, Label: kind, Kind: kind})
		return id
	}

	// ~20% of the time, an island single-node chain (fileshare/directory hit directly).
	islands := g.islandKinds()
	if len(islands) > 0 && r.Intn(5) == 0 {
		k := pick(r, islands)
		addNode(k)
	} else {
		start := pick(r, g.fromKinds())
		curID := addNode(start)
		curKind := start
		steps := 1
		if maxNodes > 2 {
			steps = 1 + r.Intn(maxNodes-1) // at least one edge
		}
		for i := 0; i < steps; i++ {
			cs := g.connectorsFrom(curKind)
			if len(cs) == 0 {
				break // reached a leaf
			}
			c := pick(r, cs)
			toKind := pick(r, c.To)
			toID := addNode(toKind)
			label := ""
			if len(c.Labels) > 0 {
				label = pick(r, c.Labels)
			}
			e := Edge{From: curID, To: toID, Label: label}
			if c.Dir == "both" {
				e.Dir = "both"
			}
			edges = append(edges, e)
			curID, curKind = toID, toKind
		}
	}

	// Attach one fault to a legal site.
	var f Fault
	var planeKind string
	if len(edges) > 0 && r.Intn(2) == 0 {
		e := edges[r.Intn(len(edges))]
		kinds := append(append([]string{}, g.Faults.Edge...), g.Faults.Either...)
		f = Fault{Edge: []string{e.From, e.To}, Kind: pick(r, kinds)}
		for _, n := range nodes {
			if n.ID == e.From {
				planeKind = n.Kind
			}
		}
		f.Label = fmt.Sprintf("%s on edge %s→%s", f.Kind, e.From, e.To)
	} else {
		n := nodes[r.Intn(len(nodes))]
		kinds := append(append([]string{}, g.Faults.Node...), g.Faults.Either...)
		f = Fault{Target: n.ID, Kind: pick(r, kinds)}
		planeKind = n.Kind
		f.Label = fmt.Sprintf("%s on %s", f.Kind, n.Label)
	}

	// Route to the plane's oracle; a chain touching an unwatched plane may NOT count.
	pl := g.Planes[planeKind]
	counted := pl.Watched
	return Scenario{
		ID:       fmt.Sprintf("gen-%d", idx),
		Category: "generated",
		Chain:    Chain{Nodes: nodes, Edges: edges},
		Fault:    f,
		Oracle:   Oracle{Mode: pl.Mode, Invariant: fmt.Sprintf("%s (%s plane)", pl.Oracle, planeKind)},
		Counted:  &counted,
	}
}

func cmdGenerate(g *Grammar, seed int64, count, maxNodes int) int {
	r := rand.New(rand.NewSource(seed))
	out := make([]Scenario, 0, count)
	countable := 0
	for i := 0; i < count; i++ {
		s := g.genChain(r, i, maxNodes)
		out = append(out, s)
		if s.Counted != nil && *s.Counted {
			countable++
		}
		// human summary → stderr, JSON → stdout
		kinds := make([]string, 0, len(s.Chain.Nodes))
		for _, n := range s.Chain.Nodes {
			kinds = append(kinds, n.Kind)
		}
		tag := "COUNTED"
		if s.Counted == nil || !*s.Counted {
			tag = "exploratory (unwatched plane)"
		}
		fmt.Fprintf(os.Stderr, "%-8s [%s]  fault=%s  oracle=%s/%s  %s\n",
			s.ID, strings.Join(kinds, "→"), s.Fault.Kind, s.Oracle.Mode,
			strings.SplitN(s.Oracle.Invariant, " ", 2)[0], tag)
	}
	// Verify what we generated is legal by construction.
	bad := 0
	for _, s := range out {
		kindOf := map[string]string{}
		for _, n := range s.Chain.Nodes {
			kindOf[n.ID] = n.Kind
		}
		for _, e := range s.Chain.Edges {
			if ok, _ := g.edgeLegal(kindOf[e.From], kindOf[e.To], e.Label); !ok {
				bad++
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\nchainforge generate: %d chains (%d countable, %d exploratory), %d illegal edges (must be 0)\n",
		count, countable, count-countable, bad)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if bad > 0 {
		return 1
	}
	return 0
}

// ---- matrix ----

func cmdMatrix(g *Grammar) int {
	kinds := make([]string, 0, len(g.Kinds))
	for k := range g.Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	// blessed[from][to] = true
	blessed := map[string]map[string]bool{}
	for _, f := range kinds {
		blessed[f] = map[string]bool{}
	}
	for _, c := range g.Connectors {
		for _, t := range c.To {
			blessed[c.From][t] = true
			if c.Dir == "both" {
				blessed[t][c.From] = true
			}
		}
	}
	fmt.Println("Compatibility matrix (row FROM → col TO), Y = blessed connector, . = illegal:")
	fmt.Printf("%-10s", "")
	for _, t := range kinds {
		fmt.Printf(" %-3s", abbr(t))
	}
	fmt.Println()
	alive := 0
	for _, f := range kinds {
		fmt.Printf("%-10s", f)
		for _, t := range kinds {
			if blessed[f][t] {
				fmt.Printf(" %-3s", "Y")
				alive++
			} else {
				fmt.Printf(" %-3s", ".")
			}
		}
		fmt.Println()
	}
	total := len(kinds) * len(kinds)
	fmt.Printf("\n%d/%d cells alive (%.0f%%).\n", alive, total, 100*float64(alive)/float64(total))
	fmt.Println("\nPlane coverage (which generated chains may count):")
	pk := make([]string, 0, len(g.Planes))
	for k := range g.Planes {
		pk = append(pk, k)
	}
	sort.Strings(pk)
	for _, k := range pk {
		p := g.Planes[k]
		mark := "WATCHED  "
		if !p.Watched {
			mark = "unwatched"
		}
		fmt.Printf("  %-10s %s  %-20s %s\n", k, mark, p.Oracle+"/"+p.Mode, p.Note)
	}
	return 0
}

func abbr(s string) string {
	if len(s) <= 3 {
		return s
	}
	return s[:3]
}

// ---- main ----

func main() {
	grammarPath := flag.String("grammar", "chaos/grammar.json", "grammar file (repo-root-relative)")
	inPath := flag.String("in", "chaos/scenarios.json", "scenarios file (repo-root-relative)")
	seed := flag.Int64("seed", 1, "generate: RNG seed (reproducible)")
	count := flag.Int("count", 5, "generate: number of chains")
	maxNodes := flag.Int("maxnodes", 5, "generate: max nodes per chain")
	// Parse flags on either side of the subcommand: `generate -seed 7` and
	// `-seed 7 generate` both work. flag.Parse() stops at the first non-flag arg
	// (the subcommand); re-parse the remainder to pick up trailing flags.
	flag.Parse()
	cmd := flag.Arg(0)
	if rest := flag.Args(); len(rest) > 1 {
		_ = flag.CommandLine.Parse(rest[1:])
	}

	g, err := loadGrammar(resolve(*grammarPath))
	if err != nil {
		fmt.Fprintln(os.Stderr, "load grammar:", err)
		os.Exit(2)
	}

	switch cmd {
	case "", "validate":
		d, err := loadDoc(resolve(*inPath))
		if err != nil {
			fmt.Fprintln(os.Stderr, "load scenarios:", err)
			os.Exit(2)
		}
		os.Exit(cmdValidate(g, d))
	case "generate":
		os.Exit(cmdGenerate(g, *seed, *count, *maxNodes))
	case "matrix":
		os.Exit(cmdMatrix(g))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (want: validate | generate | matrix)\n", cmd)
		os.Exit(2)
	}
}
