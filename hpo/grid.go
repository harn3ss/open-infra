// Grid search over a hyperparameter space, and objective-value comparison.
package main

import (
	"regexp"
	"strconv"
)

// Param is one hyperparameter and the discrete values to try.
type Param struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// gridTrials returns the cartesian product of the parameters as ordered
// name->value maps. If max > 0 the grid is truncated to that many trials. A
// parameter with no values contributes nothing (its trials are skipped).
func gridTrials(params []Param, max int) []map[string]string {
	combos := []map[string]string{{}}
	for _, p := range params {
		if len(p.Values) == 0 {
			continue
		}
		var next []map[string]string
		for _, base := range combos {
			for _, v := range p.Values {
				m := make(map[string]string, len(base)+1)
				for k, bv := range base {
					m[k] = bv
				}
				m[p.Name] = v
				next = append(next, m)
			}
		}
		combos = next
	}
	if max > 0 && len(combos) > max {
		combos = combos[:max]
	}
	return combos
}

var defaultMetricRe = regexp.MustCompile(`OPENINFRA_METRIC=([-0-9.eE+]+)`)

// extractMetric pulls the LAST objective value from a trial's logs. An empty
// pattern (or one that fails to compile) uses the default OPENINFRA_METRIC=... form.
func extractMetric(logs, pattern string) (string, bool) {
	re := defaultMetricRe
	if pattern != "" {
		if r, err := regexp.Compile(pattern); err == nil {
			re = r
		}
	}
	ms := re.FindAllStringSubmatch(logs, -1)
	if len(ms) == 0 {
		return "", false
	}
	last := ms[len(ms)-1]
	if len(last) < 2 {
		return "", false
	}
	return last[1], true
}

// better reports whether metric value a is strictly better than b for the goal.
// Non-numeric values are never better.
func better(a, b string, goal string) bool {
	af, aerr := strconv.ParseFloat(a, 64)
	bf, berr := strconv.ParseFloat(b, 64)
	if aerr != nil {
		return false
	}
	if berr != nil {
		return true // any number beats a non-number
	}
	if goal == "Maximize" {
		return af > bf
	}
	return af < bf // Minimize (default)
}
