package main

import (
	"context"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// reviewedToken is what the fake TokenReview reports for one token.
type reviewedToken struct {
	user           string
	podName, podID string
}

// resolverWith builds the real resolver over fake clients: TokenReview answers from tokens, the
// ServiceAccounts and VMIs are seeded objects.
func resolverWith(t *testing.T, tokens map[string]reviewedToken, sas []*corev1.ServiceAccount, vmis ...*unstructured.Unstructured) *k8sSARoleResolver {
	t.Helper()
	objs := make([]runtime.Object, 0, len(sas))
	for _, sa := range sas {
		objs = append(objs, sa)
	}
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		out := tr.DeepCopy()
		if rt, ok := tokens[tr.Spec.Token]; ok {
			out.Status.Authenticated = true
			out.Status.User.Username = rt.user
			out.Status.User.Extra = map[string]authnv1.ExtraValue{}
			if rt.podName != "" {
				out.Status.User.Extra[extraPodName] = authnv1.ExtraValue{rt.podName}
			}
			if rt.podID != "" {
				out.Status.User.Extra[extraPodUID] = authnv1.ExtraValue{rt.podID}
			}
		}
		return true, out, nil
	})
	dobjs := make([]runtime.Object, 0, len(vmis))
	for _, v := range vmis {
		dobjs = append(dobjs, v)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{vmiGVR: "VirtualMachineInstanceList"}, dobjs...)
	return &k8sSARoleResolver{cs: cs, dyn: dyn}
}

func vmSA(ns, name, vm, role string) *corev1.ServiceAccount {
	ann := map[string]string{annInstanceRole: role}
	if vm != "" {
		ann[annVMName] = vm
	}
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: ann}}
}

func vmi(ns, name, saName string, activePodUIDs ...string) *unstructured.Unstructured {
	active := map[string]any{}
	for _, uid := range activePodUIDs {
		active[uid] = "node-a"
	}
	vols := []any{map[string]any{"name": "root", "dataVolume": map[string]any{"name": name + "-root"}}}
	if saName != "" {
		vols = append(vols, map[string]any{"name": "identity", "serviceAccount": map[string]any{"serviceAccountName": saName}})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec":     map[string]any{"volumes": vols},
		"status":   map[string]any{"activePods": active},
	}}
}

// The token must belong to the VM's own launcher pod: another pod running as the same ServiceAccount
// (an Application named vm-<x> in the VM's namespace) gets nothing.
func TestVMCredsResolver_TokenMustBeTheLaunchersOwn(t *testing.T) {
	const sa = "system:serviceaccount:shop:vm-web01"
	tokens := map[string]reviewedToken{
		"launcher":       {user: sa, podName: "virt-launcher-web01-abcde", podID: "uid-launcher"},
		"migration":      {user: sa, podName: "virt-launcher-web01-fghij", podID: "uid-target"},
		"app-pod":        {user: sa, podName: "vm-web01-7d9f-xyz", podID: "uid-app"},
		"unbound":        {user: sa},
		"other-sa":       {user: "system:serviceaccount:shop:vm-db01", podName: "virt-launcher-db01-q", podID: "uid-db"},
		"not-vm-sa":      {user: "system:serviceaccount:shop:plain", podName: "p", podID: "uid-plain"},
		"user-not-an-sa": {user: "openinfra:alice", podName: "p", podID: "uid-launcher"},
	}
	sas := []*corev1.ServiceAccount{
		vmSA("shop", "vm-web01", "web01", "webrole"),
		vmSA("shop", "vm-db01", "db01", "dbrole"),
		vmSA("shop", "plain", "", "webrole"), // annotated by hand, no openinfra.dev/vm
	}
	r := resolverWith(t, tokens, sas,
		vmi("shop", "web01", "vm-web01", "uid-launcher", "uid-target"),
		vmi("shop", "db01", "vm-other", "uid-db"), // the db01 VMI does not mount vm-db01
	)
	for tok, want := range map[string]bool{
		"launcher": true, "migration": true,
		"app-pod": false, "unbound": false, "other-sa": false, "not-vm-sa": false, "user-not-an-sa": false,
		"unknown-token": false,
	} {
		id, ok := r.resolveSARole(context.Background(), tok)
		if ok != want {
			t.Errorf("%s: ok=%v want %v", tok, ok, want)
			continue
		}
		if ok && (id.role != "webrole" || id.namespace != "shop" || id.vmName != "web01") {
			t.Errorf("%s: identity %+v", tok, id)
		}
	}
}

// Without the VMI (stopped VM) or without a dynamic client, nothing resolves.
func TestVMCredsResolver_FailsClosedWithoutTheVMI(t *testing.T) {
	tokens := map[string]reviewedToken{"t": {user: "system:serviceaccount:shop:vm-web01", podName: "p", podID: "u"}}
	sas := []*corev1.ServiceAccount{vmSA("shop", "vm-web01", "web01", "webrole")}
	if _, ok := resolverWith(t, tokens, sas).resolveSARole(context.Background(), "t"); ok {
		t.Fatal("no VMI: must not resolve")
	}
	r := resolverWith(t, tokens, sas, vmi("shop", "web01", "vm-web01", "u"))
	r.dyn = nil
	if _, ok := r.resolveSARole(context.Background(), "t"); ok {
		t.Fatal("no dynamic client: must not resolve")
	}
}
