// rbac-to-cedar reads the cluster's Kubernetes RBAC and emits an open-infra control-plane Cedar
// corpus — one kind: Policy (spec.controlPlane) per principal, mirroring what RBAC grants. It is the
// scalable, reproducible way to give the enumerated implicit principals explicit Cedar grants for
// the Phase 2 shadow run (docs/authz-webhook.md). Read-only against the cluster; writes YAML to
// stdout. Faithfulness caveats are emitted as annotations so a reviewer sees where to tighten.
//
//	KUBECONFIG=... go run ./cmd/rbac-to-cedar [-namespace open-infra-authz] > corpus.yaml
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/rbactocedar"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

func main() {
	ns := flag.String("namespace", "open-infra-authz", "namespace for the generated objects")
	asCM := flag.Bool("configmap", false, "emit ONE control-plane-corpus ConfigMap bundle instead of one kind: Policy per principal — a lighter delivery the webhook loader reads (no Crossplane claim per principal). Must land in the open-infra-authz namespace.")
	flag.Parse()

	cs, err := clientset()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kube client:", err)
		os.Exit(1)
	}
	ctx := context.Background()

	in := rbactocedar.Inputs{ClusterRoles: map[string]rbacv1.ClusterRole{}, Roles: map[string]rbacv1.Role{}}
	crs, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	must(err)
	for _, cr := range crs.Items {
		in.ClusterRoles[cr.Name] = cr
	}
	roles, err := cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	must(err)
	for _, r := range roles.Items {
		in.Roles[r.Namespace+"/"+r.Name] = r
	}
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	must(err)
	in.ClusterRoleBindings = crbs.Items
	rbs, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	must(err)
	in.RoleBindings = rbs.Items

	grants := rbactocedar.Generate(in)
	fmt.Fprintf(os.Stderr, "generated %d principal grants from %d ClusterRoles / %d ClusterRoleBindings / %d RoleBindings\n",
		len(grants), len(in.ClusterRoles), len(in.ClusterRoleBindings), len(in.RoleBindings))

	if *asCM {
		out, err := yaml.Marshal(configMapObject(*ns, grants))
		must(err)
		fmt.Print(string(out))
		return
	}
	for _, g := range grants {
		obj := policyObject(*ns, g)
		out, err := yaml.Marshal(obj)
		must(err)
		fmt.Println("---")
		fmt.Print(string(out))
	}
}

// configMapObject renders the whole corpus as ONE control-plane-corpus ConfigMap (data key
// corpus.yaml = a list of grants), the lighter delivery the webhook loader reads. Caveats ride along
// per grant for the reviewer; the loader ignores them.
func configMapObject(ns string, grants []rbactocedar.Grant) map[string]any {
	bundle := make([]any, 0, len(grants))
	for _, g := range grants {
		stmts := make([]any, 0, len(g.Statements))
		for _, s := range g.Statements {
			m := map[string]any{"effect": string(s.Effect), "actions": toAny(s.Actions)}
			if len(s.Resources) > 0 {
				m["resources"] = toAny(s.Resources)
			}
			stmts = append(stmts, m)
		}
		gm := map[string]any{"appliesTo": []any{g.Principal}, "statements": stmts}
		if len(g.Caveats) > 0 {
			gm["caveats"] = toAny(g.Caveats)
		}
		bundle = append(bundle, gm)
	}
	corpus, err := yaml.Marshal(bundle)
	must(err)
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      "control-plane-corpus",
			"namespace": ns,
			"labels":    map[string]any{"openinfra.dev/generated-by": "rbac-to-cedar"},
		},
		"data": map[string]any{"corpus.yaml": string(corpus)},
	}
}

// policyObject renders one grant as a kind: Policy (spec.controlPlane), caveats in an annotation.
func policyObject(ns string, g rbactocedar.Grant) map[string]any {
	stmts := make([]any, 0, len(g.Statements))
	for _, s := range g.Statements {
		m := map[string]any{"effect": string(s.Effect), "actions": toAny(s.Actions)}
		if len(s.Resources) > 0 {
			m["resources"] = toAny(s.Resources)
		}
		stmts = append(stmts, m)
	}
	meta := map[string]any{
		"name":      "cp-" + sanitize(g.Principal),
		"namespace": ns,
		"labels":    map[string]any{"openinfra.dev/generated-by": "rbac-to-cedar"},
	}
	if len(g.Caveats) > 0 {
		meta["annotations"] = map[string]any{"openinfra.dev/faithfulness-caveats": strings.Join(g.Caveats, "; ")}
	}
	return map[string]any{
		"apiVersion": "iam.openinfra.dev/v1",
		"kind":       "Policy",
		"metadata":   meta,
		"spec": map[string]any{
			"controlPlane": map[string]any{
				"appliesTo":  []any{g.Principal},
				"statements": stmts,
			},
		},
	}
}

var nonDNS = regexp.MustCompile(`[^a-z0-9]+`)

// sanitize turns a principal ("ServiceAccount::kube-system/op") into a DNS-safe name fragment.
// The object name is "cp-"+this and must fit in 63 bytes (the applied limit — longer names were
// rejected). When the sanitized form is too long, truncate and append a short deterministic hash of
// the FULL principal, so two principals that share a 51-char prefix still get distinct, stable names
// (a plain truncation collided and dropped principals from the corpus).
func sanitize(p string) string {
	s := strings.ToLower(p)
	s = strings.NewReplacer("serviceaccount::", "sa-", "group::", "group-", "user::", "user-").Replace(s)
	s = nonDNS.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	const max = 60 // 3 ("cp-") + 60 = 63
	if len(s) > max {
		sum := sha256.Sum256([]byte(p))
		s = strings.Trim(s[:max-9], "-") + "-" + hex.EncodeToString(sum[:])[:8] // <=51 + "-" + 8 = <=60
	}
	return s
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func clientset() (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kc)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
