package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/client-go/kubernetes"
)

// The AWS-policy import preview — the "Actions ▾ → Import policy" surface in the policy editor. It takes
// a pasted AWS IAM policy JSON and DRY-RUNS policyengine.ImportAWS, returning a three-column report:
// what translates faithfully, what is REFUSED (with the reason — never silently dropped), and what
// translated but needs a human's eye (wildcard/broad grants). It writes NOTHING — it creates no Policy;
// it only tells the operator what an import would and would not honor.
//
// Refuse-not-degrade carries into this surface by construction: the engine refuses a whole statement
// rather than emit it with a condition or action dropped (dropping an Allow's condition would WIDEN the
// grant), and this endpoint surfaces every refusal instead of hiding it. A dialog that silently drops a
// Deny or a condition is worse than one that refuses — so the refused column is first-class, and the
// operator authors those parts natively on kind: Policy spec.dataPlane.
//
// Gated by the same admin SAR as the other IAM endpoints (list policies), fail closed.

type importReq struct {
	// PolicyDocument is the AWS IAM policy JSON to import (the document itself, not a wrapper).
	PolicyDocument string `json:"policyDocument"`
}

// importedIPCondition mirrors policyengine.IPCondition but with the LOWERCASE json tags the
// kind: Policy XRD requires (key/cidr/negate) — the engine type carries no tags, so it would otherwise
// marshal as Key/CIDR/Negate and a copied/merged statement would fail XRD validation.
type importedIPCondition struct {
	Key    string `json:"key"`
	CIDR   string `json:"cidr"`
	Negate bool   `json:"negate,omitempty"`
}

// importedStatement is one translated statement in the kind: Policy spec.dataPlane shape (so it can be
// authored as-is), plus a `broad` flag when it carries a wildcard the operator should confirm.
type importedStatement struct {
	Effect       string                `json:"effect"`
	Actions      []string              `json:"actions"`
	Resources    []string              `json:"resources,omitempty"`
	Condition    map[string]string     `json:"condition,omitempty"`
	IPConditions []importedIPCondition `json:"ipConditions,omitempty"`
	Broad        bool                  `json:"broad"`
}

type importSummary struct {
	Translated  int `json:"translated"`
	Refused     int `json:"refused"`
	NeedsReview int `json:"needsReview"`
}

type importResp struct {
	// Translated are the statements ImportAWS honored faithfully, ready to author on spec.dataPlane.
	Translated []importedStatement `json:"translated"`
	// Refused lists the parts that could NOT be honored, each with its reason. Shown, never dropped.
	Refused []string `json:"refused"`
	// NeedsReview flags translated-but-broad statements (a "*" action or resource) — honored exactly as
	// written, but worth a conscious confirmation of the breadth.
	NeedsReview []string `json:"needsReview"`
	// Faithful is true iff nothing was refused — the whole document maps onto the data plane.
	Faithful bool          `json:"faithful"`
	Summary  importSummary `json:"summary"`
}

func handleIAMImport(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A dry-run import preview is an admin IAM tool; gate it exactly like listing policies.
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "policies", auth.ns, "") {
			return
		}
		var in importReq
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		doc := strings.TrimSpace(in.PolicyDocument)
		if doc == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policyDocument is required (paste an AWS IAM policy JSON)"})
			return
		}
		stmts, refused, err := policyengine.ImportAWS(doc)
		if err != nil {
			// A document-level parse failure (not JSON, missing/invalid Effect, malformed Statement) — a
			// malformed input, distinct from a refusal. Report it as a 400 with the engine's reason.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, buildImportResp(stmts, refused))
	}
}

// buildImportResp turns the engine's (statements, refusals) into the three-column report. Kept as a pure
// function so the report logic is unit-tested without the HTTP/auth wrapper.
func buildImportResp(stmts []policyengine.Statement, refused []string) importResp {
	translated := make([]importedStatement, 0, len(stmts))
	needsReview := []string{}
	for i, s := range stmts {
		broad := hasWildcard(s.Actions) || hasWildcard(s.Resources)
		var ipc []importedIPCondition
		for _, c := range s.IPConditions {
			ipc = append(ipc, importedIPCondition{Key: c.Key, CIDR: c.CIDR, Negate: c.Negate})
		}
		translated = append(translated, importedStatement{
			Effect:       string(s.Effect),
			Actions:      s.Actions,
			Resources:    s.Resources,
			Condition:    s.Condition,
			IPConditions: ipc,
			Broad:        broad,
		})
		if broad {
			needsReview = append(needsReview, fmt.Sprintf(
				"statement %d (%s %v on %v) is a wildcard grant — confirm the breadth is intended",
				i+1, s.Effect, s.Actions, s.Resources))
		}
	}
	if refused == nil {
		refused = []string{}
	}
	return importResp{
		Translated:  translated,
		Refused:     refused,
		NeedsReview: needsReview,
		Faithful:    len(refused) == 0,
		Summary: importSummary{
			Translated:  len(translated),
			Refused:     len(refused),
			NeedsReview: len(needsReview),
		},
	}
}

// hasWildcard reports whether any entry is "*" or contains a "*" (e.g. "s3:*", "Bucket::log-*").
func hasWildcard(xs []string) bool {
	for _, x := range xs {
		if strings.Contains(x, "*") {
			return true
		}
	}
	return false
}
