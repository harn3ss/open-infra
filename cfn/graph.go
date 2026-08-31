// Dependency ordering for the CFN engine (Phase 1).
//
// Resources are provisioned in dependency order: a resource that Refs / GetAtts / Subs
// another, or names it in DependsOn, comes after it. We build the edge set, then Kahn's
// algorithm gives a stable topological order (ties broken by template order, so the plan is
// deterministic). A cycle is a hard error — CloudFormation refuses circular dependencies and
// so do we.
package main

import (
	"fmt"
	"sort"
)

// order returns the resource logical ids in dependency order. deps maps a resource to the
// resources it depends on (from resolveResource + DependsOn). A cycle returns an error naming
// the resources still tangled.
func order(rawOrder []string, deps map[string][]string) ([]string, error) {
	// position in template order, for deterministic tie-breaking.
	pos := make(map[string]int, len(rawOrder))
	for i, id := range rawOrder {
		pos[id] = i
	}

	indeg := make(map[string]int, len(rawOrder))
	dependents := make(map[string][]string, len(rawOrder))
	for _, id := range rawOrder {
		indeg[id] = 0
	}
	// unique edges dep -> id (id depends on dep).
	for _, id := range rawOrder {
		seen := map[string]bool{}
		for _, dep := range deps[id] {
			if dep == id || seen[dep] {
				continue
			}
			if _, ok := indeg[dep]; !ok {
				continue // dep is not a resource (a param/pseudo already resolved)
			}
			seen[dep] = true
			dependents[dep] = append(dependents[dep], id)
			indeg[id]++
		}
	}

	// ready = indegree-0, kept sorted by template position for stable output.
	var ready []string
	for _, id := range rawOrder {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	sortByPos(ready, pos)

	var out []string
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		next := dependents[id]
		sort.Slice(next, func(i, j int) bool { return pos[next[i]] < pos[next[j]] })
		for _, d := range next {
			indeg[d]--
			if indeg[d] == 0 {
				ready = insertByPos(ready, d, pos)
			}
		}
	}

	if len(out) != len(rawOrder) {
		var stuck []string
		for _, id := range rawOrder {
			if indeg[id] > 0 {
				stuck = append(stuck, id)
			}
		}
		sortByPos(stuck, pos)
		return nil, fmt.Errorf("circular dependency among resources: %v", stuck)
	}
	return out, nil
}

func sortByPos(ids []string, pos map[string]int) {
	sort.Slice(ids, func(i, j int) bool { return pos[ids[i]] < pos[ids[j]] })
}

// insertByPos keeps ready sorted by template position as new nodes become ready.
func insertByPos(ready []string, id string, pos map[string]int) []string {
	i := sort.Search(len(ready), func(i int) bool { return pos[ready[i]] > pos[id] })
	ready = append(ready, "")
	copy(ready[i+1:], ready[i:])
	ready[i] = id
	return ready
}
