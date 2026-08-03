// Command chaosdoc generates docs/chaos-scenarios.md from chaos/scenarios.json.
//
// It is the single source-of-truth renderer for the public chaos-scenario gallery: each
// scenario becomes a Mermaid flowchart showing the resource CHAIN, a red ⚡ FAULT marker at
// the exact injection point, and a green/amber/blue ORACLE badge stating the invariant + mode.
// Grouped by batch. Deterministic output so a CI drift-guard can assert it stays in sync.
//
// Usage (from repo root):  go run ./tools/chaosdoc   [-check]
//
//	-check : regenerate in memory and fail if docs/chaos-scenarios.md is stale (for CI).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Doc struct {
	Batches   []Batch    `json:"batches"`
	Scenarios []Scenario `json:"scenarios"`
}
type Batch struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}
type Node struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Kind  string  `json:"kind"` // database|stream|function|vm|storage|directory|app|node|external
	On    []Place `json:"on"`   // sandbox node(s) this resource occupied (>1 = spread across nodes)
}
type Place struct {
	Node string `json:"node"` // sandbox-node-01 | sandbox-node-02 | sandbox-node-03
	Role string `json:"role"` // optional: primary|replica|member|from|to|...
}
type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"`
	Dir   string `json:"dir"` // "" (one-way) | "both"
}
type Fault struct {
	Target string   `json:"target"` // node id the fault hits (omit if Edge set)
	Edge   []string `json:"edge"`   // [from,to] if the fault is injected on an edge
	Node   string   `json:"node"`   // optional: sandbox node whose instance of Target is hit (e.g. lose a replica)
	Kind   string   `json:"kind"`   // PodChaos|NetworkChaos|StressChaos|kill|config|quota|...
	Label  string   `json:"label"`
}
type Oracle struct {
	Mode      string `json:"mode"` // recover|tolerate|deny
	Invariant string `json:"invariant"`
}
type Scenario struct {
	ID           string `json:"id"`
	Batch        string `json:"batch"`
	Title        string `json:"title"`
	Category     string `json:"category"`
	Status       string `json:"status"`       // PASS|FINDING|INCONCLUSIVE|PENDING|PARKED
	Key          string `json:"key"`          // workflow scenario name, to join nightly run status
	LastVerified string `json:"lastVerified"` // YYYY-MM-DD the result was last observed (empty = not recorded)
	VerifiedBy   string `json:"verifiedBy"`   // nightly-lottery | hand-driven | on-demand
	Note         string `json:"note"`
	Chain        struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	} `json:"chain"`
	Fault  Fault  `json:"fault"`
	Oracle Oracle `json:"oracle"`
}

// Nightly is an optional sidecar (chaos/nightly-status.json) written by the nightly workflow;
// it overlays each night's live result onto the (otherwise static) scenario catalog.
type Nightly struct {
	Updated string               `json:"updated"`
	Runs    map[string]RunStatus `json:"runs"`
}
type RunStatus struct {
	Conclusion string `json:"conclusion"` // success|failure|inconclusive
	Date       string `json:"date"`
	RunURL     string `json:"runUrl"`
}

func runEmoji(c string) string {
	switch strings.ToLower(c) {
	case "success":
		return "🟢"
	case "failure":
		return "🔴"
	case "inconclusive":
		return "⚪"
	default:
		return "•"
	}
}

func statusBadge(s string) string {
	switch strings.ToUpper(s) {
	case "PASS":
		return "🟢 PASS"
	case "FINDING":
		return "🔴 FINDING"
	case "INCONCLUSIVE":
		return "⚪ INCONCLUSIVE"
	case "PENDING":
		return "⏳ PENDING"
	case "PARKED":
		return "⏸️ PARKED"
	default:
		return s
	}
}

// Mermaid node shape by kind. %s is the (quoted) label.
func shape(kind string) (string, string) {
	switch kind {
	case "database", "storage", "volume", "fileshare":
		return "[(", ")]" // cylinder
	case "stream", "queue", "directory":
		return "[[", "]]" // subroutine
	case "function":
		return "([", "])" // stadium
	case "vm":
		return "[/", "/]" // parallelogram
	case "node":
		return "{{", "}}" // hexagon
	default:
		return "[", "]" // rectangle
	}
}

func q(s string) string { return "\"" + strings.ReplaceAll(s, "\"", "'") + "\"" }

func aliasSafe(s string) string {
	return strings.NewReplacer("-", "_", ".", "_", " ", "_", "/", "_").Replace(s)
}

func filepathIsAbs(p string) bool { return strings.HasPrefix(p, "/") }

// repoRoot walks up from the CWD looking for a .git directory; falls back to ".".
func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if fi, err := os.Stat(dir + "/.git"); err == nil && fi.IsDir() {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == "" || parent == dir {
			return "."
		}
		dir = parent
	}
}

// involvedNodes returns the sorted set of sandbox nodes referenced by a scenario's placements.
func involvedNodes(sc Scenario) []string {
	set := map[string]bool{}
	for _, n := range sc.Chain.Nodes {
		for _, p := range n.On {
			set[p.Node] = true
		}
	}
	var out []string
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func ranOn(sc Scenario) string {
	ns := involvedNodes(sc)
	if len(ns) == 0 {
		return "scheduler-placed within the sandbox-node-01…03 pool"
	}
	return strings.Join(ns, ", ")
}

func mermaid(sc Scenario) string {
	placed := len(involvedNodes(sc)) > 0
	var b strings.Builder
	b.WriteString("```mermaid\nflowchart LR\n")

	// rep maps a resource id -> the mermaid node id used for edges/faults.
	rep := map[string]string{}

	if !placed {
		for _, n := range sc.Chain.Nodes {
			l, r := shape(n.Kind)
			fmt.Fprintf(&b, "  n_%s%s%s%s\n", n.ID, l, q(n.Label), r)
			rep[n.ID] = "n_" + n.ID
		}
	} else {
		// unplaced resources render plainly, above the node subgraphs
		for _, n := range sc.Chain.Nodes {
			if len(n.On) == 0 {
				l, r := shape(n.Kind)
				fmt.Fprintf(&b, "  n_%s%s%s%s\n", n.ID, l, q(n.Label), r)
				rep[n.ID] = "n_" + n.ID
			}
		}
		// one subgraph per sandbox node; a resource on N nodes gets one instance per node
		for _, a := range involvedNodes(sc) {
			fmt.Fprintf(&b, "  subgraph sg_%s[%s]\n", aliasSafe(a), q(a))
			for _, n := range sc.Chain.Nodes {
				for _, p := range n.On {
					if p.Node != a {
						continue
					}
					l, r := shape(n.Kind)
					label := n.Label
					if p.Role != "" {
						label = n.Label + " · " + p.Role
					}
					fmt.Fprintf(&b, "    n_%s__%s%s%s%s\n", n.ID, aliasSafe(a), l, q(label), r)
				}
			}
			b.WriteString("  end\n")
		}
		// representative instance = first placement
		for _, n := range sc.Chain.Nodes {
			if len(n.On) > 0 {
				rep[n.ID] = fmt.Sprintf("n_%s__%s", n.ID, aliasSafe(n.On[0].Node))
			}
		}
		// dotted links tie together the instances of one multi-node resource
		for _, n := range sc.Chain.Nodes {
			for i := 1; i < len(n.On); i++ {
				lbl := "HA"
				if n.On[i].Role != "" {
					lbl = n.On[i].Role
				}
				fmt.Fprintf(&b, "  n_%s__%s -.->|%s| n_%s__%s\n",
					n.ID, aliasSafe(n.On[0].Node), q(lbl), n.ID, aliasSafe(n.On[i].Node))
			}
		}
	}

	// edges (via representative instances)
	for _, e := range sc.Chain.Edges {
		from, to := rep[e.From], rep[e.To]
		if from == "" {
			from = "n_" + e.From
		}
		if to == "" {
			to = "n_" + e.To
		}
		arrow := "-->"
		if e.Dir == "both" {
			arrow = "<-->"
		}
		if e.Label != "" {
			fmt.Fprintf(&b, "  %s %s|%s| %s\n", from, arrow, q(e.Label), to)
		} else {
			fmt.Fprintf(&b, "  %s %s %s\n", from, arrow, to)
		}
	}
	// fault marker
	if sc.Fault.Label != "" {
		fl := q("⚡ " + sc.Fault.Label)
		var tgt string
		switch {
		case len(sc.Fault.Edge) == 2:
			tgt = rep[sc.Fault.Edge[1]]
			if tgt == "" {
				tgt = "n_" + sc.Fault.Edge[1]
			}
		case sc.Fault.Node != "" && sc.Fault.Target != "":
			tgt = fmt.Sprintf("n_%s__%s", sc.Fault.Target, aliasSafe(sc.Fault.Node)) // a specific node's instance
		case sc.Fault.Target != "":
			tgt = rep[sc.Fault.Target]
			if tgt == "" {
				tgt = "n_" + sc.Fault.Target
			}
		}
		if tgt != "" {
			fmt.Fprintf(&b, "  FAULT((%s)):::fault\n", fl)
			fmt.Fprintf(&b, "  FAULT -.-> %s\n", tgt)
		}
	}
	// oracle badge
	if sc.Oracle.Invariant != "" {
		cls := "oracle_recover"
		switch sc.Oracle.Mode {
		case "tolerate":
			cls = "oracle_tolerate"
		case "deny":
			cls = "oracle_deny"
		}
		fmt.Fprintf(&b, "  ORACLE{{%s}}:::%s\n", q(sc.Oracle.Mode+" · "+sc.Oracle.Invariant), cls)
	}
	// styles (repeated per-graph so each renders standalone on GitHub)
	b.WriteString("  classDef fault fill:#ef4444,color:#fff,stroke:#b91c1c;\n")
	b.WriteString("  classDef oracle_recover fill:#dcfce7,stroke:#16a34a,color:#14532d;\n")
	b.WriteString("  classDef oracle_tolerate fill:#fef9c3,stroke:#ca8a04,color:#713f12;\n")
	b.WriteString("  classDef oracle_deny fill:#dbeafe,stroke:#2563eb,color:#1e3a8a;\n")
	b.WriteString("```\n")
	return b.String()
}

func render(d Doc, nl Nightly) string {
	// tally
	counts := map[string]int{}
	for _, s := range d.Scenarios {
		counts[strings.ToUpper(s.Status)]++
	}
	var h strings.Builder
	h.WriteString("<!-- GENERATED by tools/chaosdoc from chaos/scenarios.json — DO NOT EDIT BY HAND. -->\n")
	h.WriteString("<!-- Regenerate:  go run ./tools/chaosdoc   (CI drift-guard: go run ./tools/chaosdoc -check) -->\n\n")
	h.WriteString("# Chaos scenarios — what we break, and what must hold\n\n")
	h.WriteString("open-infra is **continuously tested against failure**. Every scenario below drives a real\n")
	h.WriteString("resource *chain*, injects a real fault at a marked point (⚡), and asserts a business- or\n")
	h.WriteString("systems-level **invariant** — not just \"did it come back up\". This page is generated from\n")
	h.WriteString("[`chaos/scenarios.json`](../chaos/scenarios.json); it can never drift from the source-of-truth.\n\n")
	fmt.Fprintf(&h, "**Tally:** %d scenarios — 🟢 %d pass · 🔴 %d finding · ⚪ %d inconclusive · ⏳ %d pending · ⏸️ %d parked.\n\n",
		len(d.Scenarios), counts["PASS"], counts["FINDING"], counts["INCONCLUSIVE"], counts["PENDING"], counts["PARKED"])

	// Live nightly overlay (written by the nightly workflow; this page regenerates each night).
	if len(nl.Runs) > 0 {
		var keys []string
		for k := range nl.Runs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			r := nl.Runs[k]
			link := r.Date
			if r.RunURL != "" {
				link = fmt.Sprintf("[%s](%s)", r.Date, r.RunURL)
			}
			parts = append(parts, fmt.Sprintf("`%s` %s %s (%s)", k, runEmoji(r.Conclusion), r.Conclusion, link))
		}
		fmt.Fprintf(&h, "**Last nightly:** %s\n\n", strings.Join(parts, " · "))
	}

	h.WriteString("> **Freshness — read this before the green.** Only **nightly-lottery** scenarios are ")
	h.WriteString("re-verified every night; **hand-driven** and **on-demand** results are point-in-time ")
	h.WriteString("(see each scenario's *Verified* date + method). The nightly banner above reflects the ")
	h.WriteString("**lottery only** — a PASS elsewhere means \"passed when last run\", not \"passed last night\".\n\n")

	h.WriteString("### Legend\n\n")
	h.WriteString("| Symbol | Meaning |\n|---|---|\n")
	h.WriteString("| ⚡ (red) | fault-injection point — where the break is applied |\n")
	h.WriteString("| green badge | **recover** — after the fault heals, no acknowledged work was lost |\n")
	h.WriteString("| amber badge | **tolerate** — a continuous SLO held *while* the fault was live |\n")
	h.WriteString("| blue badge | **deny** — a negative invariant that must NEVER happen (zero tolerance) |\n")
	h.WriteString("| 🟢🔴⚪⏳⏸️ | pass · finding · inconclusive · pending · parked |\n\n")
	h.WriteString("Shapes: `[(cylinder)]` = database/storage · `[[subroutine]]` = stream/directory · ")
	h.WriteString("`([stadium])` = function · `[/parallelogram/]` = VM · `[rectangle]` = app/service. ")
	h.WriteString("Where a resource spanned multiple sandbox nodes (HA / replicas / live-migration), each ")
	h.WriteString("node is drawn as its own **subgraph** and the instances are tied together.\n\n")

	// Scannable index — keeps the page navigable as scenarios accumulate. (The gallery grows with
	// distinct SCENARIOS, not with runs: the nightly suite re-runs the same set and updates status.)
	h.WriteString("### Scenario index\n\n")
	h.WriteString("| ID | Scenario | Category | Sandbox nodes | Status | Verified |\n|---|---|---|---|---|---|\n")
	for _, bt := range d.Batches {
		var scs []Scenario
		for _, s := range d.Scenarios {
			if s.Batch == bt.ID {
				scs = append(scs, s)
			}
		}
		sort.SliceStable(scs, func(i, j int) bool { return scs[i].ID < scs[j].ID })
		for _, s := range scs {
			nodes := "pool"
			if inv := involvedNodes(s); len(inv) > 0 {
				var short []string
				for _, a := range inv {
					short = append(short, strings.TrimPrefix(a, "sandbox-node-"))
				}
				nodes = strings.Join(short, ",")
			}
			ver := s.LastVerified
			if ver == "" {
				ver = "not recorded"
			}
			if s.VerifiedBy != "" {
				ver = ver + " · " + s.VerifiedBy
			}
			fmt.Fprintf(&h, "| [%s](#s-%s) | %s | %s | %s | %s | %s |\n", s.ID, s.ID, s.Title, s.Category, nodes, statusBadge(s.Status), ver)
		}
	}
	h.WriteString("\n> **Sandbox nodes** column: which of `sandbox-node-01/02/03` a scenario used. ")
	h.WriteString("`pool` = a single pod scheduler-placed within the 3-node sandbox; numbers = a resource ")
	h.WriteString("spread across those specific nodes (see the per-scenario subgraphs).\n\n")
	h.WriteString("---\n\n")

	for _, bt := range d.Batches {
		var scs []Scenario
		for _, s := range d.Scenarios {
			if s.Batch == bt.ID {
				scs = append(scs, s)
			}
		}
		if len(scs) == 0 {
			continue
		}
		sort.SliceStable(scs, func(i, j int) bool { return scs[i].ID < scs[j].ID })
		fmt.Fprintf(&h, "## %s\n\n", bt.Title)
		if bt.Desc != "" {
			fmt.Fprintf(&h, "%s\n\n", bt.Desc)
		}
		for _, s := range scs {
			fmt.Fprintf(&h, "<a id=\"s-%s\"></a>\n", s.ID)
			fmt.Fprintf(&h, "### %s · %s &nbsp; %s\n\n", s.ID, s.Title, statusBadge(s.Status))
			fmt.Fprintf(&h, "**Category:** %s &nbsp;•&nbsp; **Oracle:** %s — %s\n\n", s.Category, s.Oracle.Mode, s.Oracle.Invariant)
			fmt.Fprintf(&h, "**Ran on:** %s\n\n", ranOn(s))
			lv := s.LastVerified
			if lv == "" {
				lv = "not recorded"
			}
			vb := s.VerifiedBy
			if vb == "" {
				vb = "—"
			}
			fmt.Fprintf(&h, "**Verified:** %s · %s\n\n", lv, vb)
			if s.Key != "" {
				if r, ok := nl.Runs[s.Key]; ok {
					link := r.Date
					if r.RunURL != "" {
						link = fmt.Sprintf("[%s](%s)", r.Date, r.RunURL)
					}
					fmt.Fprintf(&h, "**Last nightly:** %s %s · %s\n\n", runEmoji(r.Conclusion), r.Conclusion, link)
				}
			}
			if s.Note != "" {
				fmt.Fprintf(&h, "> %s\n\n", s.Note)
			}
			// Diagram collapses by default so the page stays navigable as scenarios accumulate;
			// findings / inconclusive stay open so problems are visible at a glance.
			openAttr := ""
			if st := strings.ToUpper(s.Status); st != "PASS" && st != "PARKED" {
				openAttr = " open"
			}
			fmt.Fprintf(&h, "<details%s><summary>diagram — chain, ⚡ fault, oracle</summary>\n\n", openAttr)
			h.WriteString(mermaid(s))
			h.WriteString("\n</details>\n\n")
		}
		h.WriteString("---\n\n")
	}
	h.WriteString("_Generated by [`tools/chaosdoc`](../tools/chaosdoc). Add or update a scenario in ")
	h.WriteString("[`chaos/scenarios.json`](../chaos/scenarios.json) and run `go run ./tools/chaosdoc`._\n")
	return h.String()
}

func main() {
	check := flag.Bool("check", false, "fail if docs/chaos-scenarios.md is stale (CI drift-guard)")
	in := flag.String("in", "chaos/scenarios.json", "source-of-truth JSON (repo-root-relative)")
	out := flag.String("out", "docs/chaos-scenarios.md", "output markdown (repo-root-relative)")
	flag.Parse()

	// Resolve repo-relative paths from the repo root (walk up for .git), so this runs the
	// same from the repo root or from tools/chaosdoc.
	root := repoRoot()
	inPath, outPath := *in, *out
	if !filepathIsAbs(inPath) {
		inPath = root + "/" + inPath
	}
	if !filepathIsAbs(outPath) {
		outPath = root + "/" + outPath
	}
	in, out = &inPath, &outPath

	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		fmt.Fprintln(os.Stderr, "parse scenarios.json:", err)
		os.Exit(1)
	}
	// Optional nightly-status sidecar (written by the nightly workflow).
	var nl Nightly
	if b, err := os.ReadFile(root + "/chaos/nightly-status.json"); err == nil {
		_ = json.Unmarshal(b, &nl)
	}
	got := render(d, nl)

	if *check {
		cur, _ := os.ReadFile(*out)
		if string(cur) != got {
			fmt.Fprintf(os.Stderr, "%s is STALE — run `go run ./tools/chaosdoc` and commit.\n", *out)
			os.Exit(1)
		}
		fmt.Println("chaosdoc: up to date")
		return
	}
	if err := os.WriteFile(*out, []byte(got), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("chaosdoc: wrote %s (%d scenarios)\n", *out, len(d.Scenarios))
}
