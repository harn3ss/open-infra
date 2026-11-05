package iamcompile

import (
	"context"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func unstr(gvk schema.GroupVersionKind, ns, name string, spec map[string]any, labels map[string]string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace(ns)
	u.SetName(name)
	u.SetLabels(labels)
	return u
}

func fakeDynamic(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	gvrs := map[schema.GroupVersionResource]string{
		userGVR: "UserList", roleGVR: "RoleList", groupGVR: "GroupList", policyGVR: "PolicyList", crdGVR: "CustomResourceDefinitionList",
	}
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs, objs...)
}

// LoadInput reads the IAM world, every User (with its groups) and Role, and the namespaces' accounts.
func TestLoadInput(t *testing.T) {
	iam := func(k string) schema.GroupVersionKind {
		return schema.GroupVersionKind{Group: "iam.openinfra.dev", Version: "v1", Kind: k}
	}
	dc := fakeDynamic(
		unstr(iam("Policy"), "open-infra-console", "AdministratorAccess", map[string]any{"document": adminDoc}, nil),
		unstr(iam("User"), "open-infra-console", "alice", map[string]any{"groups": []any{"admins"}, "policies": []any{"AdministratorAccess"}}, nil),
		unstr(iam("Role"), "main-dev", "worker", map[string]any{}, nil),
	)
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{AccountIDLabel: "912345678901"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "open-infra-console", Labels: map[string]string{AccountIDLabel: "000000000000"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "bad", Labels: map[string]string{AccountIDLabel: "not-an-id"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}},
	)
	in, err := LoadInput(context.Background(), dc, cs, iamauthz.DefaultHomeNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Principals) != 2 || in.NamespaceAccounts["team-a"] != "912345678901" || len(in.NamespaceAccounts) != 2 {
		t.Fatalf("input = %+v", in)
	}
	out := Compile(in)
	if r := reportFor(out, "alice"); r.Allows == 0 || len(r.Policies) != 1 {
		t.Errorf("alice compiles her attached AdministratorAccess: %+v", r)
	}
}

// Report mode writes the report and nothing that enforces; apply mode writes the corpus and makes the
// generated RBAC exactly the compile's — creating, updating and deleting only objects it generated.
func TestWriter_ReportThenApply(t *testing.T) {
	ctx := context.Background()
	handWritten := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "openinfra-root-break-glass"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "open-infra-console"},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: "openinfra:000000000000:root"}}}
	stale := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "openinfra-iam:000000000000:user:gone",
		Labels: map[string]string{GeneratedByLabel: GeneratedBy}}}
	staleRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "openinfra-iam:000000000000:user:gone", Namespace: "team-a",
		Labels: map[string]string{GeneratedByLabel: GeneratedBy}}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "openinfra-iam:000000000000:user:gone"}}
	cs := fake.NewSimpleClientset(handWritten, stale, staleRB)
	wr := Writer{CS: cs, DC: fakeDynamic()}

	in := Input{World: world([]iamauthz.Policy{doc(t, "PowerUserAccess", powerUserDoc)}, map[string][]string{"User::alice": {"PowerUserAccess"}}),
		Principals: []Principal{{Kind: "User", Namespace: "open-infra-console", Name: "alice"}}}
	out := Compile(in)

	if err := wr.Write(ctx, ModeReport, in, out); err != nil {
		t.Fatal(err)
	}
	rep, err := cs.CoreV1().ConfigMaps(CorpusNamespace).Get(ctx, ReportName, metav1.GetOptions{})
	if err != nil || !strings.Contains(rep.Data["report.yaml"], "alice") {
		t.Fatalf("report: %v %v", err, rep)
	}
	if _, err := cs.CoreV1().ConfigMaps(CorpusNamespace).Get(ctx, CorpusName, metav1.GetOptions{}); err == nil {
		t.Fatal("report mode must not write the corpus")
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, "openinfra-iam:000000000000:user:alice", metav1.GetOptions{}); err == nil {
		t.Fatal("report mode must not write RBAC")
	}

	if err := wr.Write(ctx, ModeApply, in, out); err != nil {
		t.Fatal(err)
	}
	corpus, err := cs.CoreV1().ConfigMaps(CorpusNamespace).Get(ctx, CorpusName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ParseCorpus([]byte(corpus.Data[CorpusKey]))
	if err != nil || len(docs) != 1 || docs[0].AppliesTo[0] != "User::"+alice {
		t.Fatalf("corpus: %v %+v", err, docs)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, "openinfra-iam:000000000000:user:alice", metav1.GetOptions{}); err != nil {
		t.Fatalf("apply must create the generated role: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "openinfra-iam:000000000000:user:alice", metav1.GetOptions{}); err != nil {
		t.Fatalf("apply must bind it: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, stale.Name, metav1.GetOptions{}); err == nil {
		t.Error("a generated role the compile no longer wants is deleted")
	}
	if _, err := cs.RbacV1().RoleBindings("team-a").Get(ctx, staleRB.Name, metav1.GetOptions{}); err == nil {
		t.Error("a generated binding the compile no longer wants is deleted")
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, handWritten.Name, metav1.GetOptions{}); err != nil {
		t.Error("hand-written RBAC (no generated-by label) is never touched")
	}

	// Detaching the policy: the next apply leaves alice with nothing.
	in.World.Attach = nil
	if err := wr.Write(ctx, ModeApply, in, Compile(in)); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, "openinfra-iam:000000000000:user:alice", metav1.GetOptions{}); err == nil {
		t.Error("a principal whose policy is detached loses its generated role")
	}
	corpus, _ = cs.CoreV1().ConfigMaps(CorpusNamespace).Get(ctx, CorpusName, metav1.GetOptions{})
	if docs, _ := ParseCorpus([]byte(corpus.Data[CorpusKey])); len(docs) != 0 {
		t.Errorf("and its corpus grant: %+v", docs)
	}
}
