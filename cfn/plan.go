// Plan construction for the CFN engine (Phase 1) — the read-only dry-run.
//
// BuildPlan turns a template into a verdict WITHOUT provisioning anything. The verdict is the
// honesty rail:
//
//	PROVISIONABLE                — every included resource maps to a faithful kind, every
//	                               intrinsic resolved, dependencies order cleanly.
//	PROVISIONABLE_WITH_CAVEATS   — same, but at least one resource maps only `partial`
//	                               (lossy); the caveats are listed loudly.
//	REJECTED                     — at least one blocker: an unsupported/gated resource type,
//	                               an unsupported intrinsic, a macro Transform, a missing
//	                               required parameter, a broken reference, or a dependency
//	                               cycle. The exact blockers are listed; nothing is provisioned.
//
// The cardinal rule: never silently drop or approximate something we cannot model. If
// in doubt, REJECT and say exactly why.
package main

import (
	"fmt"
	"sort"
)

type Verdict string

const (
	Provisionable            Verdict = "PROVISIONABLE"
	ProvisionableWithCaveats Verdict = "PROVISIONABLE_WITH_CAVEATS"
	Rejected                 Verdict = "REJECTED"
)

type PlannedResource struct {
	LogicalID string
	CFNType   string
	Kind      string
	Status    Status
	Note      string
	Included  bool     // false when a Condition excluded it
	Condition string   // the gating condition, if any
	DependsOn []string // resolved dependency ids (included resources only)
}

type Plan struct {
	Verdict   Verdict
	Order     []string          // included resources in provisioning order
	Resources []PlannedResource // all resources, in template order
	Findings  []Finding         // intrinsic/reference problems
	Blockers  []string          // human-readable REJECTED reasons
}

// BuildPlan parses a template and produces a dry-run plan. params supplies parameter values
// (overriding defaults); stackName seeds AWS::StackName. It never contacts the cluster.
func BuildPlan(data []byte, params map[string]string, stackName string) (*Plan, error) {
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Verdict: Provisionable}

	// A macro/SAM Transform means the template is expanded server-side before deploy — we
	// cannot honor it, so it is a hard blocker rather than a silent drop.
	if t.Transform != nil {
		plan.Blockers = append(plan.Blockers, "template uses Transform (macro/SAM) — not supported; the expanded form is not what open-infra provisions")
	}

	// Resolve parameters: supplied value > default. A required parameter with neither is a
	// blocker — we will not plan against an unknown value.
	pvals := map[string]any{}
	var missing []string
	for name, p := range t.Parameters {
		if v, ok := params[name]; ok {
			pvals[name] = v
		} else if p.hasDef {
			pvals[name] = p.Default
		} else {
			// Seed a placeholder so Refs to it resolve cleanly — the missing-value
			// blocker below is the single, precise reason; no redundant "undefined Ref".
			pvals[name] = "<param:" + name + ">"
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		plan.Blockers = append(plan.Blockers, "parameter "+name+" has no default and no value supplied (pass -param "+name+"=…)")
	}

	r := newResolver(t, pvals, pseudoParams(stackName))
	r.evalConditions()

	// Decide inclusion + mapping for every resource, walking properties only for included ones.
	deps := map[string][]string{}
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		included := true
		if res.Condition != "" {
			included = r.conds[res.Condition]
		}
		entry := Lookup(res.Type)
		pr := PlannedResource{
			LogicalID: id,
			CFNType:   res.Type,
			Kind:      entry.Kind,
			Status:    entry.Status,
			Note:      entry.Note,
			Included:  included,
			Condition: res.Condition,
		}
		if included {
			d := r.resolveResource(id, res)
			d = append(d, res.DependsOn...)
			deps[id] = d
			pr.DependsOn = dedupSorted(d)
			if !entry.mappable() {
				plan.Blockers = append(plan.Blockers,
					fmt.Sprintf("%s (%s): %s — %s", id, res.Type, entry.Status, noteOr(entry.Note, "no backing kind")))
			}
		}
		plan.Resources = append(plan.Resources, pr)
	}
	plan.Findings = r.findings
	for _, f := range r.findings {
		plan.Blockers = append(plan.Blockers, f.Where+": "+f.Reason)
	}

	// Dependency ordering over included resources only.
	var included []string
	incDeps := map[string][]string{}
	for _, pr := range plan.Resources {
		if pr.Included {
			included = append(included, pr.LogicalID)
			incDeps[pr.LogicalID] = deps[pr.LogicalID]
		}
	}
	if ord, err := order(included, incDeps); err != nil {
		plan.Blockers = append(plan.Blockers, err.Error())
	} else {
		plan.Order = ord
	}

	// Final verdict.
	switch {
	case len(plan.Blockers) > 0:
		plan.Verdict = Rejected
	case plan.hasPartial():
		plan.Verdict = ProvisionableWithCaveats
	default:
		plan.Verdict = Provisionable
	}
	return plan, nil
}

func (p *Plan) hasPartial() bool {
	for _, r := range p.Resources {
		if r.Included && r.Status == Partial {
			return true
		}
	}
	return false
}

// pseudoParams returns the AWS pseudo-parameter values used for resolution. They are
// placeholders — Phase 1 does not provision, so exact values do not matter, only that the
// references resolve rather than becoming findings.
func pseudoParams(stackName string) map[string]any {
	if stackName == "" {
		stackName = "openinfra-stack"
	}
	return map[string]any{
		"AWS::Region":           "openinfra",
		"AWS::AccountId":        "000000000000",
		"AWS::Partition":        "aws",
		"AWS::URLSuffix":        "amazonaws.com",
		"AWS::StackName":        stackName,
		"AWS::StackId":          "openinfra/" + stackName,
		"AWS::NoValue":          nil,
		"AWS::NotificationARNs": []any{},
	}
}

func dedupSorted(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func noteOr(note, fallback string) string {
	if note == "" {
		return fallback
	}
	return note
}
