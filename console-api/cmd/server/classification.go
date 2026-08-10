package main

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// The DataClassification compliance auditor — the "enforce handling by classification" half.
//
// kind: DataClassification defines a taxonomy (level + handling requirements) mirrored to labelled
// ConfigMaps in the console namespace. Workloads are tagged with `openinfra.dev/classification:
// <name>`. This endpoint evaluates each tagged workload against its class's mechanically-checkable
// requirements and reports per-rule pass / fail / unknown — a detect-and-report control, like AWS
// Config rules, mapped to NIST RA-2 (categorization) plus the handling controls (AC-4, SC-28, ...).
//
// Honesty about scope: it checks what is checkable NOW from the typed API — public exposure
// (LoadBalancer Services targeting the workload), network restriction (a NetworkPolicy selecting its
// pods), and residency (nodeSelector pinning). encryptionAtRest and backup are reported as UNKNOWN
// until the encryption/backup features can be interrogated, rather than pretending to verify them.
//
// Admin-gated with the same SubjectAccessReview as the rest of Security & Identity.

const classificationLabel = "openinfra.dev/classification"

type ruleCheck struct {
	Rule   string `json:"rule"`
	Status string `json:"status"` // pass | fail | unknown | n/a
	Detail string `json:"detail"`
}

type classifiedResource struct {
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Kind      string      `json:"kind"`
	Class     string      `json:"class"`
	Level     string      `json:"level"`
	Compliant bool        `json:"compliant"` // no failing checks (unknowns do not fail)
	Checks    []ruleCheck `json:"checks"`
}

type classComplianceResp struct {
	Classes   []classSummary       `json:"classes"`
	Resources []classifiedResource `json:"resources"`
}

type classSummary struct {
	Name  string `json:"name"`
	Level string `json:"level"`
}

// classPolicy is the parsed taxonomy from a ConfigMap mirror.
type classPolicy struct {
	level              string
	encryptionAtRest   bool
	networkRestricted  bool
	noPublicExposure   bool
	backup             bool
	residencyNodeLabel string
}

// workload is the common shape we evaluate, drawn from Deployments and StatefulSets.
type workload struct {
	namespace    string
	name         string
	kind         string
	class        string
	podLabels    map[string]string
	nodeSelector map[string]string
}

func handleClassificationCompliance(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		// 1. Load the taxonomy from the ConfigMap mirrors.
		classes := map[string]classPolicy{}
		var summaries []classSummary
		cms, err := cs.CoreV1().ConfigMaps(auth.ns).List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/dataclass"})
		if err != nil {
			logger.Warn("classification: list mirrors", slog.String("error", err.Error()))
		} else {
			for _, cm := range cms.Items {
				name := cm.Labels["openinfra.dev/dataclass"]
				if name == "" {
					continue
				}
				p := classPolicy{
					level:              cm.Data["level"],
					encryptionAtRest:   cm.Data["encryptionAtRest"] == "true",
					networkRestricted:  cm.Data["networkRestricted"] == "true",
					noPublicExposure:   cm.Data["noPublicExposure"] == "true",
					backup:             cm.Data["backup"] == "true",
					residencyNodeLabel: cm.Data["residencyNodeLabel"],
				}
				classes[name] = p
				summaries = append(summaries, classSummary{Name: name, Level: p.level})
			}
		}
		sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })

		// 2. Collect tagged workloads (Deployments + StatefulSets, all namespaces).
		var workloads []workload
		if dl, e := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{LabelSelector: classificationLabel}); e == nil {
			for i := range dl.Items {
				d := &dl.Items[i]
				workloads = append(workloads, workload{
					namespace: d.Namespace, name: d.Name, kind: "Deployment",
					class:        d.Labels[classificationLabel],
					podLabels:    d.Spec.Template.Labels,
					nodeSelector: d.Spec.Template.Spec.NodeSelector,
				})
			}
		}
		if sl, e := cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{LabelSelector: classificationLabel}); e == nil {
			for i := range sl.Items {
				s := &sl.Items[i]
				workloads = append(workloads, workload{
					namespace: s.Namespace, name: s.Name, kind: "StatefulSet",
					class:        s.Labels[classificationLabel],
					podLabels:    s.Spec.Template.Labels,
					nodeSelector: s.Spec.Template.Spec.NodeSelector,
				})
			}
		}

		// 3. Evaluate each workload against its class.
		resources := make([]classifiedResource, 0, len(workloads))
		for _, wl := range workloads {
			res := classifiedResource{
				Namespace: wl.namespace, Name: wl.name, Kind: wl.kind, Class: wl.class,
			}
			pol, ok := classes[wl.class]
			if !ok {
				res.Checks = []ruleCheck{{Rule: "class", Status: "fail", Detail: "no DataClassification named " + wl.class}}
				res.Compliant = false
				resources = append(resources, res)
				continue
			}
			res.Level = pol.level
			res.Checks = evaluateWorkload(ctx, cs, wl, pol)
			res.Compliant = true
			for _, c := range res.Checks {
				if c.Status == "fail" {
					res.Compliant = false
				}
			}
			resources = append(resources, res)
		}
		sort.Slice(resources, func(i, j int) bool {
			if resources[i].Namespace != resources[j].Namespace {
				return resources[i].Namespace < resources[j].Namespace
			}
			return resources[i].Name < resources[j].Name
		})

		writeJSON(w, http.StatusOK, classComplianceResp{Classes: summaries, Resources: resources})
	}
}

// evaluateWorkload runs the mechanically-checkable requirements. Requirements not requested by the
// class are skipped; requirements we cannot verify yet are reported "unknown", never silently passed.
func evaluateWorkload(ctx context.Context, cs kubernetes.Interface, wl workload, pol classPolicy) []ruleCheck {
	var checks []ruleCheck
	podSet := labels.Set(wl.podLabels)

	if pol.noPublicExposure {
		exposed := ""
		if svcs, err := cs.CoreV1().Services(wl.namespace).List(ctx, metav1.ListOptions{}); err == nil {
			for i := range svcs.Items {
				s := &svcs.Items[i]
				if s.Spec.Type != corev1.ServiceTypeLoadBalancer || len(s.Spec.Selector) == 0 {
					continue
				}
				if labels.SelectorFromSet(s.Spec.Selector).Matches(podSet) {
					exposed = s.Name
					break
				}
			}
		}
		if exposed != "" {
			checks = append(checks, ruleCheck{"noPublicExposure", "fail", "reachable via LoadBalancer Service " + exposed})
		} else {
			checks = append(checks, ruleCheck{"noPublicExposure", "pass", "no LoadBalancer Service targets it"})
		}
	}

	if pol.networkRestricted {
		covered := false
		if nps, err := cs.NetworkingV1().NetworkPolicies(wl.namespace).List(ctx, metav1.ListOptions{}); err == nil {
			for i := range nps.Items {
				sel, e := metav1.LabelSelectorAsSelector(&nps.Items[i].Spec.PodSelector)
				if e == nil && sel.Matches(podSet) {
					covered = true
					break
				}
			}
		}
		if covered {
			checks = append(checks, ruleCheck{"networkRestricted", "pass", "a NetworkPolicy selects its pods"})
		} else {
			checks = append(checks, ruleCheck{"networkRestricted", "fail", "no NetworkPolicy selects its pods"})
		}
	}

	if pol.residencyNodeLabel != "" {
		if _, ok := wl.nodeSelector[pol.residencyNodeLabel]; ok {
			checks = append(checks, ruleCheck{"residency", "pass", "pinned via nodeSelector " + pol.residencyNodeLabel})
		} else {
			checks = append(checks, ruleCheck{"residency", "fail", "not pinned to " + pol.residencyNodeLabel + " nodes"})
		}
	}

	if pol.encryptionAtRest {
		checks = append(checks, ruleCheck{"encryptionAtRest", "unknown", "verifiable once customer-key encryption ships"})
	}
	if pol.backup {
		checks = append(checks, ruleCheck{"backup", "unknown", "backup-policy interrogation not yet wired"})
	}
	return checks
}
