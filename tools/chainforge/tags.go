package main

// Read the chaos topology tags OFF the resources (the XRDs' openinfra.dev/chaos-* annotations) and
// verify the central grammar is grounded on them. This makes the resources the source of truth: a
// kind's ports live on its XRD, discoverable with `kubectl get xrd -o yaml`, and grammar.json is
// checked against them (a drift gate), rather than hand-maintained in isolation.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	reRole  = regexp.MustCompile(`openinfra\.dev/chaos-role:\s*"([^"]*)"`)
	reOff   = regexp.MustCompile(`openinfra\.dev/chaos-offers:\s*"([^"]*)"`)
	reAcc   = regexp.MustCompile(`openinfra\.dev/chaos-accepts:\s*"([^"]*)"`)
	reHosts = regexp.MustCompile(`openinfra\.dev/chaos-hosts:\s*"([^"]*)"`)
)

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		seen[x] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// loadTags aggregates the chaos-role/offers/accepts annotations across the XRDs into a kinds map
// (role -> ports), plus the set of "hosted" node-kinds declared via chaos-hosts (a resource's
// sub-features, e.g. Application hosts database + storage). role "none" is recorded (tagged) but
// contributes no kind.
func loadTags(dir string) (kinds map[string]KindSpec, hosted map[string]bool, tagged int) {
	kinds = map[string]KindSpec{}
	hosted = map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(dir, "*xrd*.yaml"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := string(b)
		role := firstGroup(reRole, s)
		if role == "" {
			continue // not a chaos-tagged resource
		}
		tagged++
		for _, k := range splitCSV(firstGroup(reHosts, s)) {
			hosted[k] = true
		}
		if role == "none" {
			continue
		}
		ks := kinds[role]
		ks.Offers = unionSorted(ks.Offers, splitCSV(firstGroup(reOff, s)))
		ks.Accepts = unionSorted(ks.Accepts, splitCSV(firstGroup(reAcc, s)))
		kinds[role] = ks
	}
	return kinds, hosted, tagged
}

// verifyTags is the drift gate: every grammar kind must be grounded on the resources — either tagged
// on an XRD (with ports that match) or declared as a hosted capability — and every tagged role must
// be a known grammar kind.
func verifyTags(g *Grammar, xrdDir string) (problems int) {
	kinds, hosted, _ := loadTags(xrdDir)
	for k, spec := range g.Kinds {
		if tk, ok := kinds[k]; ok {
			if !sameSet(tk.Offers, spec.Offers) || !sameSet(tk.Accepts, spec.Accepts) {
				fmt.Printf("DRIFT      %s: XRD tags offer/accept %v / %v; grammar says %v / %v\n",
					k, tk.Offers, tk.Accepts, spec.Offers, spec.Accepts)
				problems++
			}
		} else if !hosted[k] {
			fmt.Printf("UNGROUNDED %s: no XRD tagged chaos-role=%q, and not chaos-hosted by any resource\n", k, k)
			problems++
		}
	}
	for k := range kinds {
		if _, ok := g.Kinds[k]; !ok {
			fmt.Printf("UNKNOWN    %s: an XRD tags chaos-role=%q but the grammar has no such kind\n", k, k)
			problems++
		}
	}
	return problems
}

// cmdTags prints the ports read off the resources (and runs the drift check).
func cmdTags(g *Grammar, xrdDir string) int {
	kinds, hosted, tagged := loadTags(xrdDir)
	fmt.Printf("Chaos port tags read from %d tagged XRDs in %s:\n\n", tagged, xrdDir)
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Printf("  %-10s offers=%-45v accepts=%v\n", k,
			fmt.Sprintf("%v", kinds[k].Offers), kinds[k].Accepts)
	}
	hn := make([]string, 0, len(hosted))
	for k := range hosted {
		hn = append(hn, k)
	}
	sort.Strings(hn)
	fmt.Printf("\n  hosted capabilities (no standalone XRD): %v\n", hn)
	if verifyTags(g, xrdDir) == 0 {
		fmt.Println("\nOK: grammar.json is fully grounded on the resource tags (no drift).")
		return 0
	}
	return 1
}
