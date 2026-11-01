package render

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The aws-shim's CloudFront invalidations are Completed once the site has finished a sync that started
// after the invalidation: the site records each successful sync's start time (/status/synced) and serves it
// on its status port 8081, which only the aws-shim may reach and no Ingress routes to.
func TestStaticSite_SyncStatusPort(t *testing.T) {
	tmpl := extractInlineTemplate(t, staticsiteCompositionPath)
	out := render(t, tmpl, staticsiteCtx(map[string]any{"domain": "app.example.com"}))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]any{}
	for _, m := range docs {
		ann, _ := mget(m, "metadata", "annotations").(map[string]any)
		if n, _ := ann["gotemplating.fn.crossplane.io/composition-resource-name"].(string); n != "" {
			byName[n], _ = mget(m, "spec", "forProvider", "manifest").(map[string]any)
		}
	}

	conf := mstr(byName["nginx-config"], "data", "status.conf")
	for _, want := range []string{"listen 8081;", "location = /synced", "alias /status/synced;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx status.conf lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(mstr(byName["nginx-config"], "data", "default.conf"), "8081") {
		t.Error("the public server block must not serve the status port")
	}

	ports, _ := mget(byName["service"], "spec", "ports").([]any)
	var svcStatus bool
	for _, p := range ports {
		if fmt.Sprint(mget(p, "port")) == "8081" {
			svcStatus = true
		}
	}
	if !svcStatus {
		t.Errorf("the site Service must expose the status port 8081: %v", ports)
	}
	for _, rule := range mget(byName["ingress"], "spec", "rules").([]any) {
		for _, p := range mget(rule, "http", "paths").([]any) {
			if n := fmt.Sprint(mget(p, "backend", "service", "port", "number")); n != "80" {
				t.Errorf("the Ingress must route only to port 80, got %v", n)
			}
		}
	}

	// The isolation policy admits the aws-shim on the status port only.
	var shimRule bool
	for _, rule := range mget(byName["isolation-netpol"], "spec", "ingress").([]any) {
		for _, peer := range mget(rule, "from").([]any) {
			if mstr(peer, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "open-infra-aws-shim" {
				continue
			}
			shimRule = true
			if mstr(peer, "podSelector", "matchLabels", "app") != "aws-shim" {
				t.Errorf("the aws-shim peer must select the shim's pods: %v", peer)
			}
			rp, _ := mget(rule, "ports").([]any)
			if len(rp) != 1 || fmt.Sprint(mget(rp[0], "port")) != "8081" {
				t.Errorf("the aws-shim must be admitted on port 8081 only, got %v", rp)
			}
		}
	}
	if !shimRule {
		t.Error("the isolation policy must admit the aws-shim on the status port")
	}

	// The scripts: a successful sync records its START time; a failed one leaves the last record alone.
	initScript, loopScript := "", ""
	tplSpec, _ := mget(byName["server"], "spec", "template", "spec").(map[string]any)
	for _, c := range tplSpec["initContainers"].([]any) {
		if mstr(c, "name") == "sync-init" {
			a, _ := mget(c, "args").([]any)
			initScript, _ = a[0].(string)
		}
	}
	for _, c := range tplSpec["containers"].([]any) {
		if mstr(c, "name") == "sync" {
			a, _ := mget(c, "args").([]any)
			loopScript, _ = a[0].(string)
		}
		if mstr(c, "name") == "nginx" {
			var ro bool
			for _, vm := range mget(c, "volumeMounts").([]any) {
				if mstr(vm, "mountPath") == "/status" && fmt.Sprint(mget(vm, "readOnly")) == "true" {
					ro = true
				}
			}
			if !ro {
				t.Error("nginx must mount /status read-only")
			}
		}
	}
	if initScript == "" || loopScript == "" {
		t.Fatalf("sync-init or sync script not rendered")
	}
	if !strings.HasPrefix(loopScript, "while true; do ") {
		t.Fatalf("the sync loop changed shape: %s", loopScript)
	}
	once := strings.Replace(loopScript, "while true; do ", "for _ in 1; do ", 1) // one pass of the loop

	for _, tc := range []struct {
		name, script string
	}{{"sync-init", initScript}, {"sync loop", once}} {
		for _, ok := range []bool{true, false} {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			status := filepath.Join(dir, "status")
			for _, d := range []string{bin, status, filepath.Join(dir, "web")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			code := "0"
			if !ok {
				code = "1"
			}
			if err := os.WriteFile(filepath.Join(bin, "aws"), []byte("#!/bin/sh\nexit "+code+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if !ok { // a failed sync keeps the previous record
				if err := os.WriteFile(filepath.Join(status, "synced"), []byte("12345\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			s := strings.ReplaceAll(tc.script, "/status/", status+"/")
			s = strings.ReplaceAll(s, " /web ", " "+filepath.Join(dir, "web")+" ")
			before := time.Now().Unix()
			cmd := exec.Command("/bin/sh", "-c", s)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "MINIO_ENDPOINT=http://minio.invalid"}
			if outb, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s (aws ok=%v): %v\n%s", tc.name, ok, err, outb)
			}
			got, err := os.ReadFile(filepath.Join(status, "synced"))
			if err != nil {
				t.Fatalf("%s (aws ok=%v): no /status/synced: %v", tc.name, ok, err)
			}
			v := strings.TrimSpace(string(got))
			if !ok {
				if v != "12345" {
					t.Errorf("%s: a failed sync must leave the last record (got %q)", tc.name, v)
				}
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < before || n > time.Now().Unix() {
				t.Errorf("%s: a successful sync must record its start time, got %q (window %d..now)", tc.name, v, before)
			}
		}
	}
}
