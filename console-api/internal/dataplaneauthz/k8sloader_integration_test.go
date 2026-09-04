//go:build integration

// Live end-to-end: the real K8sLoader lists kind: Policy from the cluster, the Checker resolves the
// principal's dataPlane statements, and the Cedar engine decides — against a real analyst-scope
// policy. Run with a cluster + the analyst-scope policy in ns pe-test:
//
//	KUBECONFIG=/etc/rancher/k3s/k3s.yaml go test -tags integration -run K8sLoader_Live ./internal/dataplaneauthz/
package dataplaneauthz

import (
	"context"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

func TestK8sLoader_Live(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set KUBECONFIG to run the live loader test")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}

	c := New(K8sLoader(dc), time.Second)
	ctx := context.Background()
	authed := map[string]any{"authenticated": true}
	check := func(name, action, rt, rid string, cxt map[string]any, wantAllow, wantGov bool) {
		a, g, reason := c.Authorize(ctx, "User", "analyst", nil, action, rt, rid, cxt)
		if a != wantAllow || g != wantGov {
			t.Errorf("%s: allowed=%v governed=%v, want %v/%v — %s", name, a, g, wantAllow, wantGov, reason)
		}
	}
	// Governed by the analyst-scope policy (User::analyst): Allow s3:* on reports, Deny s3:DeleteObject,
	// Allow dynamodb:Query/GetItem on metrics when authenticated.
	check("get reports", "s3:GetObject", "Bucket", "reports", authed, true, true)
	check("delete reports (forbid overrides)", "s3:DeleteObject", "Bucket", "reports", authed, false, true)
	check("get a different bucket (not allowed)", "s3:GetObject", "Bucket", "secrets", authed, false, true)
	check("query metrics authenticated", "dynamodb:Query", "Table", "metrics", authed, true, true)
	check("query metrics unauthenticated (condition fails)", "dynamodb:Query", "Table", "metrics", map[string]any{"authenticated": false}, false, true)
	check("query a different table (not allowed)", "dynamodb:Query", "Table", "other", authed, false, true)
	// Lambda: no statement names it → ungoverned → the coarse RBAC decision stands.
	check("invoke a function (ungoverned service)", "lambda:InvokeFunction", "Function", "x", authed, true, false)
}
