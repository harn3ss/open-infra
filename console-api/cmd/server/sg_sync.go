package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Keep each running VM's launcher-pod SecurityGroup labels in sync with its
// spec.securityGroups — LIVE, without a restart (the EC2 model).
//
// SG membership is enforced by NetworkPolicies that select pods labelled
// openinfra.dev/sg-<name>. Those labels are stamped onto a VM's launcher pod from
// the VMI pod template, but KubeVirt only applies template labels at pod creation.
// So editing a *running* VM's securityGroups re-renders the template yet never
// relabels the live pod — the change wouldn't take effect until the VM was
// restarted. AWS applies a security-group change to a running instance instantly;
// this reconciler matches that by patching the launcher pod's sg-* labels to the
// current spec. A label change is enforced by the CNI within seconds.
//
// It reconciles by polling (cheap: one VM list + one pod list) rather than via an
// informer, matching startDataFlowGC's style and keeping the BFF dependency-light.

const sgLabelPrefix = "openinfra.dev/sg-"

func startSGSync(host *url.URL, transport http.RoundTripper, logger *slog.Logger) {
	if getenv("SG_SYNC", "on") != "on" {
		return
	}
	interval := 15 * time.Second
	if d, err := time.ParseDuration(getenv("SG_SYNC_INTERVAL", "")); err == nil && d >= 5*time.Second {
		interval = d
	}
	go func() {
		time.Sleep(30 * time.Second) // let the platform settle on boot
		for {
			sgSyncOnce(host, transport, logger)
			time.Sleep(interval)
		}
	}()
	logger.Info("sg sync: started", slog.Duration("interval", interval))
}

func sgSyncOnce(host *url.URL, transport http.RoundTripper, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hc := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	desired, err := desiredVMSecurityGroups(ctx, hc, host)
	if err != nil {
		logger.Warn("sg sync: list VMs failed; skipping", slog.String("error", err.Error()))
		return // never reconcile on an API error — only against a trustworthy set
	}
	pods, err := listLauncherPods(ctx, hc, host)
	if err != nil {
		logger.Warn("sg sync: list launcher pods failed; skipping", slog.String("error", err.Error()))
		return
	}
	for _, p := range pods {
		want, ok := desired[p.ns+"/"+p.vm]
		if !ok {
			continue // no matching VM claim; leave foreign pods alone
		}
		patch := sgLabelPatch(p.labels, want)
		if patch == nil {
			continue
		}
		if err := patchPodLabels(ctx, hc, host, p.ns, p.name, patch); err != nil {
			logger.Warn("sg sync: patch failed",
				slog.String("pod", p.ns+"/"+p.name), slog.String("error", err.Error()))
			continue
		}
		logger.Info("sg sync: reconciled launcher SG labels live",
			slog.String("vm", p.ns+"/"+p.vm), slog.String("pod", p.name))
	}
}

// sgLabelPatch returns a JSON-merge-patch labels object that makes current match
// the desired SG set — missing labels added as "", stale sg-* labels removed via
// null — or nil when the pod is already in sync. Only openinfra.dev/sg-* labels
// are ever touched; every other pod label is left alone.
func sgLabelPatch(current map[string]string, want map[string]bool) map[string]any {
	labels := map[string]any{}
	for sg := range want {
		if key := sgLabelPrefix + sg; !hasKey(current, key) {
			labels[key] = ""
		}
	}
	for key := range current {
		if !strings.HasPrefix(key, sgLabelPrefix) {
			continue
		}
		if !want[strings.TrimPrefix(key, sgLabelPrefix)] {
			labels[key] = nil // JSON merge patch: a null value deletes the label
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

type launcherPod struct {
	ns, name, vm string
	labels       map[string]string
}

// desiredVMSecurityGroups maps "<ns>/<name>" -> the set of SGs the VM claim wants.
func desiredVMSecurityGroups(ctx context.Context, hc *http.Client, host *url.URL) (map[string]map[string]bool, error) {
	u := *host
	u.Path = "/apis/openinfra.dev/v1/virtualmachines"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &sgStatusError{resp.StatusCode}
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				SecurityGroups []string `json:"securityGroups"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]bool, len(list.Items))
	for _, it := range list.Items {
		set := make(map[string]bool, len(it.Spec.SecurityGroups))
		for _, sg := range it.Spec.SecurityGroups {
			set[sg] = true
		}
		out[it.Metadata.Namespace+"/"+it.Metadata.Name] = set
	}
	return out, nil
}

// listLauncherPods returns the VM launcher pods (identified by kubevirt.io/domain,
// whose value is the VM name) with their current labels.
func listLauncherPods(ctx context.Context, hc *http.Client, host *url.URL) ([]launcherPod, error) {
	u := *host
	u.Path = "/api/v1/pods"
	u.RawQuery = "labelSelector=" + url.QueryEscape("kubevirt.io/domain")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &sgStatusError{resp.StatusCode}
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	pods := make([]launcherPod, 0, len(list.Items))
	for _, it := range list.Items {
		dom := it.Metadata.Labels["kubevirt.io/domain"]
		if dom == "" {
			continue
		}
		pods = append(pods, launcherPod{
			ns:     it.Metadata.Namespace,
			name:   it.Metadata.Name,
			vm:     dom,
			labels: it.Metadata.Labels,
		})
	}
	return pods, nil
}

func patchPodLabels(ctx context.Context, hc *http.Client, host *url.URL, ns, name string, labels map[string]any) error {
	body, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": labels}})
	if err != nil {
		return err
	}
	u := *host
	u.Path = "/api/v1/namespaces/" + ns + "/pods/" + name
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &sgStatusError{resp.StatusCode}
	}
	return nil
}

type sgStatusError struct{ code int }

func (e *sgStatusError) Error() string { return "kube API returned status " + http.StatusText(e.code) }
