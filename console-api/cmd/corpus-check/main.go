// corpus-check audits the control-plane Cedar corpus derived from the cluster's RBAC and prints an
// assurance report — the machine-checkable evidence (#109 Phase 3 / #110 CM-6) that replaces the CIS
// benchmark's inherited guarantees once Cedar is the authority: cluster-admin sprawl, wildcard
// grants, cluster-wide secrets access, privilege-escalation verbs. Read-only. Exits non-zero on any
// HIGH finding when -strict is set (so it can gate CI).
//
//	KUBECONFIG=... go run ./cmd/corpus-check [-strict]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/harn3ss/open-infra/console-api/internal/corpuscheck"
	"github.com/harn3ss/open-infra/console-api/internal/rbactocedar"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	strict := flag.Bool("strict", false, "exit non-zero if any HIGH finding is present (for CI gating)")
	flag.Parse()

	cs, err := clientset()
	must(err)
	in, err := readRBAC(context.Background(), cs)
	must(err)

	grants := rbactocedar.Generate(in)
	findings := corpuscheck.Check(grants)
	sum := corpuscheck.Summary(findings)

	fmt.Printf("Control-plane corpus audit — %d principals, %d findings (high=%d warn=%d info=%d)\n\n",
		len(grants), len(findings), sum[corpuscheck.High], sum[corpuscheck.Warn], sum[corpuscheck.Info])
	for _, f := range findings {
		fmt.Printf("  [%-4s] %-40s %s\n         %s\n", f.Severity, f.Rule, f.Principal, f.Detail)
	}
	if len(findings) == 0 {
		fmt.Println("  (no findings)")
	}

	if *strict && sum[corpuscheck.High] > 0 {
		fmt.Fprintf(os.Stderr, "\nFAIL (-strict): %d HIGH finding(s)\n", sum[corpuscheck.High])
		os.Exit(1)
	}
}

func readRBAC(ctx context.Context, cs kubernetes.Interface) (rbactocedar.Inputs, error) {
	in := rbactocedar.Inputs{ClusterRoles: map[string]rbacv1.ClusterRole{}, Roles: map[string]rbacv1.Role{}}
	crs, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return in, err
	}
	for _, cr := range crs.Items {
		in.ClusterRoles[cr.Name] = cr
	}
	roles, err := cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return in, err
	}
	for _, r := range roles.Items {
		in.Roles[r.Namespace+"/"+r.Name] = r
	}
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return in, err
	}
	in.ClusterRoleBindings = crbs.Items
	rbs, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return in, err
	}
	in.RoleBindings = rbs.Items
	return in, nil
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
