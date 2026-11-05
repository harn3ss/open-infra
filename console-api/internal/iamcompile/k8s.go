package iamcompile

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// Mode is what a compile run writes.
type Mode string

const (
	// ModeReport computes and writes only the report (and status.compiled where the schema has it).
	ModeReport Mode = "report"
	// ModeApply also writes the iam-corpus and reconciles the generated RBAC.
	ModeApply Mode = "apply"
)

// AccountIDLabel is the namespace label naming the account a namespace belongs to.
const AccountIDLabel = "openinfra.dev/account-id"

// ReportName is the ConfigMap the compiler writes its report to, beside the corpus.
const ReportName = "iam-compiler-report"

var (
	userGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "users"}
	roleGVR   = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}
	groupGVR  = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "groups"}
	policyGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "policies"}
	crdGVR    = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
)

// LoadInput reads one compile's input from the cluster: the IAM world (iamauthz's loader), every User
// (with its groups) and Role, and each namespace's account.
func LoadInput(ctx context.Context, dc dynamic.Interface, cs kubernetes.Interface, home string) (Input, error) {
	w, err := iamauthz.K8sLoaderIn(dc, home)(ctx)
	if err != nil {
		return Input{}, fmt.Errorf("IAM world: %w", err)
	}
	in := Input{World: w, Home: home, NamespaceAccounts: map[string]string{}}
	for _, k := range []struct {
		gvr  schema.GroupVersionResource
		kind string
	}{{userGVR, "User"}, {roleGVR, "Role"}} {
		list, err := dc.Resource(k.gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return Input{}, fmt.Errorf("list %s: %w", k.gvr.Resource, err)
		}
		for _, o := range list.Items {
			p := Principal{Kind: k.kind, Namespace: o.GetNamespace(), Name: o.GetName()}
			if p.Namespace == "" {
				p.Namespace = home
			}
			if k.kind == "User" {
				spec, _ := o.Object["spec"].(map[string]any)
				for _, g := range toSlice(spec["groups"]) {
					if s, ok := g.(string); ok && s != "" {
						p.Groups = append(p.Groups, s)
					}
				}
			}
			in.Principals = append(in.Principals, p)
		}
	}
	nss, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: AccountIDLabel})
	if err != nil {
		return Input{}, fmt.Errorf("list namespaces: %w", err)
	}
	for _, ns := range nss.Items {
		if id := ns.Labels[AccountIDLabel]; validAccountID(id) {
			in.NamespaceAccounts[ns.Name] = id
		}
	}
	if len(in.NamespaceAccounts) == 0 {
		in.NamespaceAccounts = nil
	}
	return in, nil
}

func validAccountID(id string) bool {
	if len(id) != 12 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func toSlice(v any) []any { s, _ := v.([]any); return s }

// Report is the compile report the compiler writes for review.
type Report struct {
	Mode       Mode              `json:"mode"`
	Principals []PrincipalReport `json:"principals"`
	// Policies maps a Policy to what compiling its document could not honour faithfully (iamauthz).
	Policies map[string][]string `json:"policies,omitempty"`
	Counts   map[string]int      `json:"counts"`
}

// BuildReport assembles the report of one compile.
func BuildReport(mode Mode, in Input, out Output) Report {
	r := Report{Mode: mode, Principals: out.Principals, Policies: map[string][]string{}, Counts: map[string]int{
		"principals": len(out.Principals), "grants": len(out.Corpus), "clusterRoles": len(out.ClusterRoles),
		"clusterRoleBindings": len(out.ClusterRoleBindings), "roleBindings": len(out.RoleBindings)}}
	for _, p := range in.World.Docs {
		if len(p.Report) > 0 {
			r.Policies[p.Name] = p.Report
		}
	}
	narrowed := 0
	for _, p := range out.Principals {
		if len(p.Dropped) > 0 {
			narrowed++
		}
	}
	r.Counts["narrowed"] = narrowed
	return r
}

// Writer writes a compile's result to the cluster.
type Writer struct {
	CS kubernetes.Interface
	DC dynamic.Interface
	// Namespace holds the corpus and the report (CorpusNamespace).
	Namespace string
}

// Write writes the report and status.compiled always, and in apply mode the iam-corpus and the
// generated RBAC.
func (wr Writer) Write(ctx context.Context, mode Mode, in Input, out Output) error {
	ns := wr.Namespace
	if ns == "" {
		ns = CorpusNamespace
	}
	rep, err := yaml.Marshal(BuildReport(mode, in, out))
	if err != nil {
		return err
	}
	if err := wr.putConfigMap(ctx, ns, ReportName, "report.yaml", string(rep)); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if err := wr.writeStatus(ctx, in, out); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if mode != ModeApply {
		return nil
	}
	corpus, err := MarshalCorpus(out.Corpus)
	if err != nil {
		return err
	}
	if err := wr.putConfigMap(ctx, ns, CorpusName, CorpusKey, string(corpus)); err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	return wr.reconcileRBAC(ctx, out)
}

func (wr Writer) putConfigMap(ctx context.Context, ns, name, key, value string) error {
	cms := wr.CS.CoreV1().ConfigMaps(ns)
	cur, err := cms.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns,
			Labels: map[string]string{GeneratedByLabel: GeneratedBy}}, Data: map[string]string{key: value}}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cur.Data[key] == value {
		return nil
	}
	cur = cur.DeepCopy()
	if cur.Data == nil {
		cur.Data = map[string]string{}
	}
	cur.Data[key] = value
	_, err = cms.Update(ctx, cur, metav1.UpdateOptions{})
	return err
}

// writeStatus sets status.compiled on each User and Role (its compile result) and Policy (its document's
// compile result) — only for a kind whose schema declares status.compiled, so the API server keeps it.
func (wr Writer) writeStatus(ctx context.Context, in Input, out Output) error {
	if wr.DC == nil {
		return nil
	}
	results := map[schema.GroupVersionResource]map[types.NamespacedName]string{userGVR: {}, roleGVR: {}, policyGVR: {}, groupGVR: {}}
	for _, p := range out.Principals {
		gvr := userGVR
		if p.Kind == "Role" {
			gvr = roleGVR
		}
		results[gvr][types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = p.Status()
	}
	for _, p := range in.World.Docs {
		ns, name := iamauthz.SplitQualified(in.Home, p.Name)
		s := "ok"
		if len(p.Report) > 0 {
			s = fmt.Sprintf("ok, %d statement(s) narrowed (see the iam-compiler report)", len(p.Report))
		}
		results[policyGVR][types.NamespacedName{Namespace: ns, Name: name}] = s
	}
	for _, gvr := range []schema.GroupVersionResource{userGVR, roleGVR, policyGVR} {
		if !wr.statusDeclared(ctx, gvr) {
			continue
		}
		keys := make([]types.NamespacedName, 0, len(results[gvr]))
		for k := range results[gvr] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			patch, _ := json.Marshal(map[string]any{"status": map[string]any{"compiled": results[gvr][k]}})
			_, err := wr.DC.Resource(gvr).Namespace(k.Namespace).Patch(ctx, k.Name, types.MergePatchType, patch, metav1.PatchOptions{}, "status")
			if err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("%s %s: %w", gvr.Resource, k, err)
			}
		}
	}
	return nil
}

// statusDeclared reports whether the kind's CRD declares status.compiled (a field the schema does not
// declare would be pruned, so writing it would only churn).
func (wr Writer) statusDeclared(ctx context.Context, gvr schema.GroupVersionResource) bool {
	crd, err := wr.DC.Resource(crdGVR).Get(ctx, gvr.Resource+"."+gvr.Group, metav1.GetOptions{})
	if err != nil {
		return false
	}
	spec, _ := crd.Object["spec"].(map[string]any)
	for _, v := range toSlice(spec["versions"]) {
		vm, _ := v.(map[string]any)
		if vm["name"] != gvr.Version {
			continue
		}
		sch, _ := vm["schema"].(map[string]any)
		root, _ := sch["openAPIV3Schema"].(map[string]any)
		props, _ := root["properties"].(map[string]any)
		status, _ := props["status"].(map[string]any)
		sprops, _ := status["properties"].(map[string]any)
		_, ok := sprops["compiled"]
		return ok
	}
	return false
}

// reconcileRBAC makes the generated RBAC exactly the compile's: creates and updates what it wants and
// deletes any generated object it no longer wants. It touches only objects carrying the generated-by
// label, so hand-written RBAC (the break-glass binding, platform roles) is never changed.
func (wr Writer) reconcileRBAC(ctx context.Context, out Output) error {
	sel := metav1.ListOptions{LabelSelector: GeneratedByLabel + "=" + GeneratedBy}
	rb := wr.CS.RbacV1()

	// ClusterRoles first, so a binding never names a role that does not exist yet.
	want := map[string]rbacv1.ClusterRole{}
	for _, cr := range out.ClusterRoles {
		want[cr.Name] = cr
	}
	have, err := rb.ClusterRoles().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, cur := range have.Items {
		if w, ok := want[cur.Name]; ok {
			if !reflect.DeepEqual(cur.Rules, w.Rules) || !sameMeta(cur.ObjectMeta, w.ObjectMeta) {
				upd := cur.DeepCopy()
				upd.Rules, upd.Labels, upd.Annotations = w.Rules, w.Labels, w.Annotations
				if _, err := rb.ClusterRoles().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
					return err
				}
			}
			delete(want, cur.Name)
		}
	}
	for _, name := range sortedNames(want) {
		cr := want[name]
		if _, err := rb.ClusterRoles().Create(ctx, &cr, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	wantCRB := map[string]rbacv1.ClusterRoleBinding{}
	for _, b := range out.ClusterRoleBindings {
		wantCRB[b.Name] = b
	}
	haveCRB, err := rb.ClusterRoleBindings().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, cur := range haveCRB.Items {
		w, ok := wantCRB[cur.Name]
		switch {
		case !ok:
			if err := rb.ClusterRoleBindings().Delete(ctx, cur.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		case cur.RoleRef != w.RoleRef:
			// roleRef is immutable: replace the binding.
			if err := rb.ClusterRoleBindings().Delete(ctx, cur.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		case !reflect.DeepEqual(cur.Subjects, w.Subjects) || !sameMeta(cur.ObjectMeta, w.ObjectMeta):
			upd := cur.DeepCopy()
			upd.Subjects, upd.Labels, upd.Annotations = w.Subjects, w.Labels, w.Annotations
			if _, err := rb.ClusterRoleBindings().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
				return err
			}
			delete(wantCRB, cur.Name)
		default:
			delete(wantCRB, cur.Name)
		}
	}
	for _, name := range sortedNamesCRB(wantCRB) {
		b := wantCRB[name]
		if _, err := rb.ClusterRoleBindings().Create(ctx, &b, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	wantRB := map[types.NamespacedName]rbacv1.RoleBinding{}
	for _, b := range out.RoleBindings {
		wantRB[types.NamespacedName{Namespace: b.Namespace, Name: b.Name}] = b
	}
	haveRB, err := rb.RoleBindings("").List(ctx, sel)
	if err != nil {
		return err
	}
	for _, cur := range haveRB.Items {
		k := types.NamespacedName{Namespace: cur.Namespace, Name: cur.Name}
		w, ok := wantRB[k]
		switch {
		case !ok, cur.RoleRef != w.RoleRef:
			if err := rb.RoleBindings(cur.Namespace).Delete(ctx, cur.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		case !reflect.DeepEqual(cur.Subjects, w.Subjects) || !sameMeta(cur.ObjectMeta, w.ObjectMeta):
			upd := cur.DeepCopy()
			upd.Subjects, upd.Labels, upd.Annotations = w.Subjects, w.Labels, w.Annotations
			if _, err := rb.RoleBindings(cur.Namespace).Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
				return err
			}
			delete(wantRB, k)
		default:
			delete(wantRB, k)
		}
	}
	keys := make([]types.NamespacedName, 0, len(wantRB))
	for k := range wantRB {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, k := range keys {
		b := wantRB[k]
		if _, err := rb.RoleBindings(k.Namespace).Create(ctx, &b, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	// Stale roles last, once nothing generated binds them.
	wantNames := map[string]bool{}
	for _, cr := range out.ClusterRoles {
		wantNames[cr.Name] = true
	}
	for _, cur := range have.Items {
		if !wantNames[cur.Name] {
			if err := rb.ClusterRoles().Delete(ctx, cur.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func sameMeta(a, b metav1.ObjectMeta) bool {
	return reflect.DeepEqual(a.Labels, b.Labels) && reflect.DeepEqual(a.Annotations, b.Annotations)
}

func sortedNames(m map[string]rbacv1.ClusterRole) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNamesCRB(m map[string]rbacv1.ClusterRoleBinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
