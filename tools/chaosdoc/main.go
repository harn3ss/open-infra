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
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // database|stream|function|vm|storage|directory|app|node|external
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
	Kind   string   `json:"kind"`   // PodChaos|NetworkChaos|StressChaos|kill|config|quota|...
	Label  string   `json:"label"`
}
type Oracle struct {
	Mode      string `json:"mode"` // recover|tolerate|deny
	Invariant string `json:"invariant"`
}
type Scenario struct {
	ID       string `json:"id"`
	Batch    string `json:"batch"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Status   string `json:"status"` // PASS|FINDING|INCONCLUSIVE|PENDING|PARKED
	Note     string `json:"note"`
	Chain    struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	} `json:"chain"`
	Fault  Fault  `json:"fault"`
	Oracle Oracle `json:"oracle"`
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

func mermaid(sc Scenario) string {
	var b strings.Builder
	b.WriteString("```mermaid\nflowchart LR\n")
	// nodes
	for _, n := range sc.Chain.Nodes {
		l, r := shape(n.Kind)
		fmt.Fprintf(&b, "  n_%s%s%s%s\n", n.ID, l, q(n.Label), r)
	}
	// edges
	for _, e := range sc.Chain.Edges {
		arrow := "-->"
		if e.Dir == "both" {
			arrow = "<-->"
		}
		if e.Label != "" {
			fmt.Fprintf(&b, "  n_%s %s|%s| n_%s\n", e.From, arrow, q(e.Label), e.To)
		} else {
			fmt.Fprintf(&b, "  n_%s %s n_%s\n", e.From, arrow, e.To)
		}
	}
	// fault marker
	if sc.Fault.Label != "" {
		fl := q("⚡ " + sc.Fault.Label)
		if len(sc.Fault.Edge) == 2 {
			// fault on an edge: draw the fault node between the two endpoints
			fmt.Fprintf(&b, "  FAULT((%s)):::fault\n", fl)
			fmt.Fprintf(&b, "  FAULT -.-> n_%s\n", sc.Fault.Edge[1])
		} else if sc.Fault.Target != "" {
			fmt.Fprintf(&b, "  FAULT((%s)):::fault\n", fl)
			fmt.Fprintf(&b, "  FAULT -.-> n_%s\n", sc.Fault.Target)
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

func render(d Doc) string {
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

	h.WriteString("### Legend\n\n")
	h.WriteString("| Symbol | Meaning |\n|---|---|\n")
	h.WriteString("| ⚡ (red) | fault-injection point — where the break is applied |\n")
	h.WriteString("| green badge | **recover** — after the fault heals, no acknowledged work was lost |\n")
	h.WriteString("| amber badge | **tolerate** — a continuous SLO held *while* the fault was live |\n")
	h.WriteString("| blue badge | **deny** — a negative invariant that must NEVER happen (zero tolerance) |\n")
	h.WriteString("| 🟢🔴⚪⏳⏸️ | pass · finding · inconclusive · pending · parked |\n\n")
	h.WriteString("Shapes: `[(cylinder)]` = database/storage · `[[subroutine]]` = stream/directory · ")
	h.WriteString("`([stadium])` = function · `[/parallelogram/]` = VM · `[rectangle]` = app/service.\n\n")
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
			fmt.Fprintf(&h, "### %s · %s &nbsp; %s\n\n", s.ID, s.Title, statusBadge(s.Status))
			fmt.Fprintf(&h, "**Category:** %s &nbsp;•&nbsp; **Oracle:** %s — %s\n\n", s.Category, s.Oracle.Mode, s.Oracle.Invariant)
			if s.Note != "" {
				fmt.Fprintf(&h, "> %s\n\n", s.Note)
			}
			h.WriteString(mermaid(s))
			h.WriteString("\n")
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
	got := render(d)

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
