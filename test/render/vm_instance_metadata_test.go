package render

import (
	"encoding/json"
	"strings"
	"testing"
)

// jsonValue is the JSON document a rendered `key: "<JSON-quoted JSON>"` line in doc carries.
func jsonValue(t *testing.T, doc, key string) map[string]any {
	t.Helper()
	for _, ln := range strings.Split(doc, "\n") {
		c := strings.TrimSpace(ln)
		if !strings.HasPrefix(c, key+": ") {
			continue
		}
		var s string
		if err := json.Unmarshal([]byte(strings.TrimPrefix(c, key+": ")), &s); err != nil {
			t.Fatalf("%s is not a JSON-quoted scalar: %v\n%s", key, err, c)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("%s is not JSON: %v\n%s", key, err, s)
		}
		return m
	}
	t.Fatalf("no %s in:\n%s", key, doc)
	return nil
}

// A Windows instance's metadata is served outside the guest, as EC2's is: its pod carries the label the
// instance metadata webhook selects; its metadata Secret carries the agent and its configuration for serving
// from the pod (the pod's files, no network namespace, no guest setup, no Run Command); and its launch
// configuration tells the guest's agent the service is outside (it routes 169.254.169.254 through the gateway).
func TestVM_WindowsInstanceMetadataServedOutsideTheGuest(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, withPlatformCA(vmCtxFW("windows-server-2022", map[string]any{
		"instanceRole": "build-instance", "userData": "<powershell>\nWrite-Output hi\n</powershell>",
		"metadataOptions": map[string]any{"httpTokens": "required", "httpPutResponseHopLimit": 2}})))
	vm := docWith(out, "kind: VirtualMachine\n")
	if !strings.Contains(vm, "openinfra.dev/instance-metadata: pod") {
		t.Errorf("the instance's pod must carry openinfra.dev/instance-metadata=pod:\n%s", grepCtx(vm, "labels"))
	}
	sec := docWith(out, "composition-resource-name: instance-metadata")
	if sec == "" || !strings.Contains(sec, "name: myvm-metadata") || !strings.Contains(sec, "metadata-agent.py: |") {
		t.Fatalf("the instance's metadata Secret:\n%s", sec)
	}
	cfg := jsonValue(t, sec, "metadata-agent.json")
	imds, _ := cfg["imds"].(map[string]any)
	for k, want := range map[string]any{
		"role": "build-instance", "tokenFile": "/etc/openinfra-metadata/token", "userDataFile": "/etc/openinfra-metadata/user-data",
		"caFile": "/etc/openinfra-metadata/platform-root-ca.pem", "commandsUrl": "", "trustPlatformCA": false, "caBundleLink": "",
		"credentialsUrl": "https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567/v1/vm-credentials",
		"identityUrl":    "https://aws-shim.open-infra-aws-shim.svc.cluster.local:4567/v1/vm-identity",
	} {
		if cfg[k] != want {
			t.Errorf("metadata-agent.json %s = %#v, want %#v", k, cfg[k], want)
		}
	}
	if imds["netns"] != "" || imds["address"] != "169.254.169.254" || imds["port"] != float64(80) || imds["enabled"] != true ||
		imds["httpTokens"] != "required" || imds["hopLimit"] != float64(2) {
		t.Errorf("the pod serves 169.254.169.254:80 itself, with the instance's metadata options: %#v", imds)
	}
	if relay, _ := cfg["relay"].(map[string]any); relay["enabled"] != false {
		t.Errorf("no container-credentials relay in the pod: %#v", cfg["relay"])
	}
	if c, _ := cfg["containers"].(map[string]any); len(c["env"].([]any)) != 0 {
		t.Errorf("no guest container setup in the pod: %#v", cfg["containers"])
	}
	launch := jsonValue(t, docWith(out, "composition-resource-name: launch"), "launch-config.json")
	if li, _ := launch["imds"].(map[string]any); li["outside"] != true {
		t.Errorf("the launch agent must be told the metadata service is outside: %#v", launch["imds"])
	}

	// Without a role or user data the files it would read are not named.
	bare := jsonValue(t, docWith(render(t, tmpl, withPlatformCA(vmCtx("windows-server-2022", ""))), "composition-resource-name: instance-metadata"), "metadata-agent.json")
	if bare["userDataFile"] != "" || bare["role"] != "" {
		t.Errorf("an instance with no user data or role: %#v", bare)
	}

	// No metadata service (httpEndpoint disabled), a Linux instance (its agent serves it in its own
	// namespace), and a Windows instance from before the launch agent: none of it.
	for name, ctx := range map[string]map[string]any{
		"metadata disabled": vmCtxFW("windows-server-2022", map[string]any{"metadataOptions": map[string]any{"httpEndpoint": "disabled"}}),
		"linux":             vmCtx("ubuntu-24.04", ""),
		"before the agent":  launchedOn(vmCtx("windows-server-2022", ""), "2026-01-01T00:00:00Z"),
	} {
		o := render(t, tmpl, withPlatformCA(ctx))
		if strings.Contains(o, "openinfra.dev/instance-metadata: pod") || strings.Contains(o, "myvm-metadata") {
			t.Errorf("%s: no metadata service in the pod:\n%s", name, grepCtx(o, "instance-metadata"))
		}
	}
	off := jsonValue(t, docWith(render(t, tmpl, withPlatformCA(vmCtxFW("windows-server-2022",
		map[string]any{"metadataOptions": map[string]any{"httpEndpoint": "disabled"}}))), "composition-resource-name: launch"), "launch-config.json")
	if oi, _ := off["imds"].(map[string]any); oi["outside"] != false || oi["enabled"] != false {
		t.Errorf("metadata disabled: %#v", off["imds"])
	}
}

// The metadata Secret carries the Linux guests' metadata agent exactly (platform/abstraction/files/embed.py
// copies it from its cloud-init entry), so the agent the pod runs is the one the tests under test/vm-creds run.
func TestVM_InstanceMetadata_EmbedsTheLinuxAgent(t *testing.T) {
	comp := mustRead(t, "../../platform/abstraction/vm-composition.yaml")
	const begin, end = "# BEGIN metadata-agent.py\n", "# END metadata-agent.py"
	i, j := strings.Index(comp, begin), strings.Index(comp, end)
	if i < 0 || j < i {
		t.Fatal("the composition has no metadata-agent.py block")
	}
	pad := comp[strings.LastIndex(comp[:i], "\n")+1 : i]
	var embedded strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(comp[i+len(begin):j], pad), "\n") {
		embedded.WriteString(strings.TrimPrefix(line, pad) + "\n")
	}
	// The cloud-init entry's body, dedented as cloud-init writes it.
	lines := strings.Split(comp, "\n")
	var guest strings.Builder
	for k, ln := range lines {
		if strings.TrimSpace(ln) != "- path: /usr/local/lib/openinfra/metadata-agent.py" {
			continue
		}
		for m := k + 1; m < k+4; m++ {
			if strings.TrimSpace(lines[m]) != "content: |" {
				continue
			}
			indent := len(lines[m]) - len(strings.TrimLeft(lines[m], " "))
			for _, b := range lines[m+1:] {
				if strings.TrimSpace(b) == "" {
					guest.WriteString("\n")
					continue
				}
				if len(b)-len(strings.TrimLeft(b, " ")) <= indent {
					break
				}
				guest.WriteString(b[indent+2:] + "\n")
			}
			break
		}
		break
	}
	g, e := strings.TrimRight(guest.String(), "\n"), strings.TrimRight(embedded.String(), "\n")
	if g == "" || g != e {
		t.Fatal("the metadata Secret's agent differs from the Linux guests': run python3 platform/abstraction/files/embed.py")
	}
}

// The webhook selects exactly the pods the composition marks, sends them to the aws-shim's handler over its
// internal TLS port, and holds a marked pod back rather than start an instance without its metadata service.
func TestInstanceMetadataWebhook_SelectsTheMarkedLauncherPods(t *testing.T) {
	w := mustRead(t, "../../platform/aws-shim/instance-metadata-webhook.yaml")
	for _, want := range []string{
		"kind: MutatingWebhookConfiguration", "kubevirt.io: virt-launcher", "openinfra.dev/instance-metadata: pod",
		"failurePolicy: Fail", "sideEffects: None", "operations: [CREATE]", "resources: [pods]",
		"name: aws-shim", "namespace: open-infra-aws-shim", "port: 4567", "path: /v1/admission/instance-metadata",
		"cert-manager.io/inject-ca-from: open-infra-aws-shim/aws-shim-internal-tls",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("the instance metadata webhook lacks %s", want)
		}
	}
	if strings.Contains(w, "namespaceSelector") {
		t.Error("the webhook selects by the pod's labels alone: every account's namespace")
	}
}
