package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// An instance role is the VM namespace's kind: Role, else — when that namespace has none of the name — its
// account's IAM home's, where the IAM API makes roles (the role of an instance profile made with
// CreateInstanceProfile), as a function's or an application's role is found. A role the VM's namespace has
// is the one it names: one there that does not trust the instance is never traded for the home's.
func TestVMCreds_InstanceRoleInTheIAMHome(t *testing.T) {
	const vmNS, home = "stacks", "iam-home"
	dyn := fakeDynWith(roleGVR)
	put := func(ns, name string, trust ...any) {
		t.Helper()
		obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "Role",
			"metadata": map[string]any{"name": name, "namespace": ns}, "spec": map[string]any{"trust": trust}}}
		if _, err := dyn.Resource(roleGVR).Namespace(ns).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	put(home, "web-role", "vm")
	put(vmNS, "local", "vm")
	put(home, "local", "vm")
	put(vmNS, "shadowed", "Service::lambda.amazonaws.com")
	put(home, "shadowed", "vm")
	m, err := awssts.NewMinter([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]saIdentity{}
	for _, role := range []string{"web-role", "local", "shadowed", "ghost"} {
		tokens[role+"-token"] = saIdentity{role: role, namespace: vmNS, caller: "system:serviceaccount:" + vmNS + ":vm-" + role, vmName: role}
	}
	h := &vmCredsHandler{resolver: fakeSAResolver{byToken: tokens}, trust: &k8sRoleTrustChecker{dyn: dyn}, minter: m, ttl: time.Hour, rolesHome: home}
	session := func(token string) (awssts.Session, int) {
		t.Helper()
		w := callVMCreds(h, http.MethodGet, token)
		if w.Code != 200 {
			return awssts.Session{}, w.Code
		}
		var c containerCreds
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		sess, ok := m.Verify(c.AccessKeyID, c.Token)
		if !ok {
			t.Fatalf("%s: the minted credential does not verify", token)
		}
		return sess, 200
	}
	if s, code := session("web-role-token"); code != 200 || s.RoleName != "web-role" || s.Namespace != "" {
		t.Errorf("a role in the IAM home: %d %+v (want the home's role, its session in the home)", code, s)
	}
	if s, code := session("local-token"); code != 200 || s.Namespace != vmNS {
		t.Errorf("a role the VM's namespace has: %d %+v (want the namespace's own)", code, s)
	}
	if _, code := session("shadowed-token"); code != http.StatusForbidden {
		t.Errorf("the VM namespace's role does not trust the instance: %d, want 403 (never the home's of the name)", code)
	}
	if _, code := session("ghost-token"); code != http.StatusForbidden {
		t.Errorf("a role nowhere: %d, want 403", code)
	}
	h.rolesHome = ""
	if _, code := session("web-role-token"); code != http.StatusForbidden {
		t.Errorf("with no IAM home, only the VM's namespace: %d, want 403", code)
	}
}
