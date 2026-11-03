package render

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A pod in a namespace with thousands of Services gets every Service's link variables in its
// environment, and past a few thousand the environment overflows execve: the container dies on start
// with "argument list too long" before the app runs. So every workload a composition puts in a
// claim's namespace (a tenant namespace may hold any number of Services) turns service links off.
// Exempt: workloads in a fixed platform namespace with few Services (the setup Jobs in minio and nats;
// a Job's pod template is immutable, so changing one would only re-create it), and Knative revisions,
// which Knative already runs with service links off.
func TestCompositions_WorkloadsInClaimNamespacesTurnServiceLinksOff(t *testing.T) {
	files, err := filepath.Glob("../../platform/abstraction/*composition*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compositions found: %v", err)
	}
	workload := regexp.MustCompile(`(?m)^\s+kind: (Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)\s*$`)
	nsLine := regexp.MustCompile(`namespace: ([^\s,}]+)`)
	fixed := map[string]bool{"minio": true, "nats": true}
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "template: |") {
			continue
		}
		for _, doc := range strings.Split(extractInlineTemplate(t, f), "\n---") {
			loc := workload.FindStringIndex(doc)
			if loc == nil || !strings.Contains(doc, "containers:") {
				continue
			}
			ns := ""
			if m := nsLine.FindStringSubmatch(doc[loc[1]:]); m != nil {
				ns = m[1]
			}
			if fixed[strings.Trim(ns, `"`)] {
				continue
			}
			checked++
			if !strings.Contains(doc, "enableServiceLinks: false") {
				kind := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(doc[loc[0]:loc[1]]), "kind:"))
				name := ""
				if i := strings.Index(doc, "composition-resource-name: "); i >= 0 {
					name = strings.Fields(doc[i+len("composition-resource-name: "):])[0]
				}
				t.Errorf("%s: the %s %q (namespace %q) leaves service links on", filepath.Base(f), kind, name, ns)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d composed workloads found: the scan no longer sees the compositions", checked)
	}
}
