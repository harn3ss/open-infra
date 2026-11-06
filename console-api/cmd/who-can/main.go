// who-can lists every identity the live API server lets read (or otherwise act on) one object, asking it
// the question itself: a SubjectAccessReview per candidate, so the answer is the whole authorization chain
// a real request meets — the control-plane authorization webhook (its RBAC-derived and IAM corpora, its
// break-glass floor) and then RBAC — not a re-implementation of either. Read-only: it creates
// SubjectAccessReviews and nothing else, and never reads the object.
//
// Candidates: every ServiceAccount in the cluster, every User and Group an RBAC binding names, every
// principal the two corpora name (control-plane-corpus, iam-corpus), and the break-glass group
// system:masters. A Group is asked as a synthetic member with no other group.
//
//	KUBECONFIG=... go run ./cmd/who-can -resource secrets -namespace cert-manager -name openinfra-root-ca-2 [-verbs get,list,watch] [-group ""]
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

type candidate struct {
	kind, name string // ServiceAccount (ns/name) | User | Group
	why        string // where the candidate came from
}

func main() {
	resource := flag.String("resource", "secrets", "resource (plural)")
	group := flag.String("group", "", "API group (\"\" for core)")
	namespace := flag.String("namespace", "", "namespace of the object")
	name := flag.String("name", "", "name of the object")
	verbs := flag.String("verbs", "get,list,watch", "comma-separated verbs to ask")
	flag.Parse()
	if *name == "" {
		fmt.Fprintln(os.Stderr, "-name is required")
		os.Exit(2)
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	must(err)
	cs, err := kubernetes.NewForConfig(cfg)
	must(err)
	ctx := context.Background()

	cands := map[string]candidate{}
	add := func(c candidate) {
		k := c.kind + "/" + c.name
		if _, ok := cands[k]; !ok {
			cands[k] = c
		}
	}
	sas, err := cs.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	must(err)
	for _, sa := range sas.Items {
		add(candidate{"ServiceAccount", sa.Namespace + "/" + sa.Name, "service account"})
	}
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	must(err)
	for _, b := range crbs.Items {
		for _, s := range b.Subjects {
			if s.Kind == "User" || s.Kind == "Group" {
				add(candidate{s.Kind, s.Name, "ClusterRoleBinding " + b.Name})
			}
		}
	}
	rbs, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	must(err)
	for _, b := range rbs.Items {
		for _, s := range b.Subjects {
			if s.Kind == "User" || s.Kind == "Group" {
				add(candidate{s.Kind, s.Name, "RoleBinding " + b.Namespace + "/" + b.Name})
			}
		}
	}
	for _, src := range []struct{ cm, key string }{{"control-plane-corpus", "corpus.yaml"}, {"iam-corpus", "corpus.yaml.gz"}} {
		cm, err := cs.CoreV1().ConfigMaps("open-infra-authz").Get(ctx, src.cm, metav1.GetOptions{})
		if err != nil {
			continue
		}
		raw := []byte(cm.Data[src.key])
		if gz := cm.BinaryData[src.key]; len(gz) > 0 {
			if r, err := gzip.NewReader(bytes.NewReader(gz)); err == nil {
				raw, _ = io.ReadAll(r)
			}
		}
		var grants []struct {
			AppliesTo []string `json:"appliesTo"`
		}
		_ = yaml.Unmarshal(raw, &grants)
		for _, g := range grants {
			for _, a := range g.AppliesTo {
				kind, id, ok := strings.Cut(a, "::")
				if !ok {
					continue
				}
				switch kind {
				case "ServiceAccount", "User", "Group":
					add(candidate{kind, id, src.cm})
				}
			}
		}
	}
	add(candidate{"Group", "system:masters", "break-glass group"})

	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type hit struct {
		c     candidate
		verbs []string
	}
	var mu sync.Mutex
	var hits []hit
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, k := range keys {
		c := cands[k]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var got []string
			for _, v := range strings.Split(*verbs, ",") {
				spec := authzv1.SubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{
					Verb: v, Group: *group, Resource: *resource, Namespace: *namespace, Name: *name}}
				switch c.kind {
				case "ServiceAccount":
					ns, n, _ := strings.Cut(c.name, "/")
					spec.User = "system:serviceaccount:" + ns + ":" + n
					spec.Groups = []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}
				case "User":
					spec.User = c.name
					spec.Groups = []string{"system:authenticated"}
				case "Group":
					spec.User = "who-can:member-of:" + c.name
					spec.Groups = []string{c.name, "system:authenticated"}
				}
				r, err := cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{Spec: spec}, metav1.CreateOptions{})
				if err == nil && r.Status.Allowed {
					got = append(got, v)
				}
			}
			if len(got) > 0 {
				mu.Lock()
				hits = append(hits, hit{c, got})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].c.kind+hits[i].c.name < hits[j].c.kind+hits[j].c.name })
	obj := *resource
	if *group != "" {
		obj += "." + *group
	}
	fmt.Printf("%d of %d candidate identities may %s %s %s/%s:\n", len(hits), len(keys), *verbs, obj, *namespace, *name)
	for _, h := range hits {
		fmt.Printf("  %-14s %-70s %-16s (%s)\n", h.c.kind, h.c.name, strings.Join(h.verbs, ","), h.c.why)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
