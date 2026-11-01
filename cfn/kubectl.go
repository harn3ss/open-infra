// The live Applier: shells out to kubectl. Kept deliberately thin — all deploy ordering,
// state, and rollback logic lives in deploy.go and is tested against a fake Applier; this file
// is the only part that touches a real cluster.
package cfn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type kubectlApplier struct {
	namespace string
}

func (k kubectlApplier) run(ctx context.Context, stdin []byte, args ...string) error {
	full := append([]string{"-n", k.namespace}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func (k kubectlApplier) Apply(ctx context.Context, manifestYAML []byte) error {
	return k.run(ctx, manifestYAML, "apply", "-f", "-")
}

// Create makes the object only if none of that kind and name exists (Creator). --save-config records the
// applied configuration as `kubectl apply` does, so a later Apply prunes what the template stops setting.
func (k kubectlApplier) Create(ctx context.Context, manifestYAML []byte) (bool, error) {
	err := k.run(ctx, manifestYAML, "create", "--save-config", "-f", "-")
	if err != nil && strings.Contains(err.Error(), "AlreadyExists") {
		return false, nil
	}
	return err == nil, err
}

// List returns the objects of a kind in the namespace (Lister).
func (k kubectlApplier) List(ctx context.Context, apiVersion, kind string) ([]LiveObject, error) {
	out, err := k.runOut(ctx, "get", resourceArg(apiVersion, kind), "-o", "json")
	if err != nil {
		return nil, err
	}
	var l struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec map[string]any `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &l); err != nil {
		return nil, fmt.Errorf("could not read the %s list: %w", kind, err)
	}
	objs := make([]LiveObject, 0, len(l.Items))
	for _, it := range l.Items {
		objs = append(objs, LiveObject{Name: it.Metadata.Name, Labels: it.Metadata.Labels, Spec: it.Spec})
	}
	return objs, nil
}

func (k kubectlApplier) Delete(ctx context.Context, apiVersion, kind, name string) error {
	return k.run(ctx, nil, "delete", resourceArg(apiVersion, kind), name, "--ignore-not-found", "--wait=false")
}

// WaitReady polls until the resource is ready, accepting EITHER open-infra's `status.ready:
// true` convention OR the Crossplane `Ready` condition. Both are needed: some open-infra
// kinds (e.g. EncryptionKey, whose Vault key is provisioned by a CronJob reconciler) set
// status.ready=true while the composite's Ready condition stays "Creating" — waiting only on
// the condition would spuriously roll back a resource that is, in fact, provisioned.
func (k kubectlApplier) WaitReady(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	res := resourceArg(apiVersion, kind) + "/" + name
	jsonpath := `{.status.ready}|{.status.conditions[?(@.type=="Ready")].status}`
	deadline := time.Now().Add(timeout)
	var last string
	for {
		out, err := k.runOut(ctx, "get", res, "-o", "jsonpath="+jsonpath)
		if err == nil {
			last = strings.TrimSpace(out)
			ready, cond, _ := strings.Cut(last, "|")
			if ready == "true" || cond == "True" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not ready within %s (last status.ready|condition = %q)", timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// WaitGone polls until the resource is fully removed from the cluster, so a DELETE_COMPLETE
// means the object is actually gone, not merely marked for deletion behind a finalizer.
// Absence is signalled by `--ignore-not-found`: a missing object exits 0 with empty stdout, so
// we never parse kubectl's error text (whose wording is not a stable contract) to decide "gone".
func (k kubectlApplier) WaitGone(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	res := resourceArg(apiVersion, kind) + "/" + name
	deadline := time.Now().Add(timeout)
	for {
		out, err := k.runOut(ctx, "get", res, "--ignore-not-found", "-o", "name")
		if err == nil && strings.TrimSpace(out) == "" {
			return nil // gone
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s still present after %s", res, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// GetSpec reads a live resource's .spec for drift comparison. Uses `--ignore-not-found`, so an
// absent object is an empty result, not an error to string-match.
func (k kubectlApplier) GetSpec(ctx context.Context, apiVersion, kind, name string) (map[string]any, bool, error) {
	out, err := k.runOut(ctx, "get", resourceArg(apiVersion, kind), name, "--ignore-not-found", "-o", "json")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, false, nil // not found
	}
	var obj struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, false, fmt.Errorf("could not read %s/%s spec: %w", kind, name, err)
	}
	return obj.Spec, true, nil
}

// GetStatus reads a live resource's .status (StatusReader) — stack Outputs naming a post-deploy
// attribute (a VM's LAN IP) resolve through it. `--ignore-not-found`: an absent object is found=false.
func (k kubectlApplier) GetStatus(ctx context.Context, apiVersion, kind, name string) (map[string]any, bool, error) {
	out, err := k.runOut(ctx, "get", resourceArg(apiVersion, kind), name, "--ignore-not-found", "-o", "json")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, false, nil
	}
	var obj struct {
		Status map[string]any `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, false, fmt.Errorf("could not read %s/%s status: %w", kind, name, err)
	}
	if obj.Status == nil {
		obj.Status = map[string]any{}
	}
	return obj.Status, true, nil
}

// GetLabels reads a live resource's metadata.labels (LabelReader) — a rollback of an interrupted
// operation's write-ahead entries deletes only objects carrying the stack's label. `--ignore-not-found`:
// an absent object is found=false.
func (k kubectlApplier) GetLabels(ctx context.Context, apiVersion, kind, name string) (map[string]string, bool, error) {
	out, err := k.runOut(ctx, "get", resourceArg(apiVersion, kind), name, "--ignore-not-found", "-o", "json")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, false, nil
	}
	var obj struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return nil, false, fmt.Errorf("could not read %s/%s labels: %w", kind, name, err)
	}
	return obj.Metadata.Labels, true, nil
}

// GetStack reads the persisted stack record ConfigMap. Uses `--ignore-not-found`, so a
// missing record is an empty result, not an error to string-match.
func (k kubectlApplier) GetStack(ctx context.Context, stackName string) (*StackRecord, bool, error) {
	out, err := k.runOut(ctx, "get", "configmap", "cfn-stack-"+stackName, "--ignore-not-found", "-o", `jsonpath={.data.stack\.json}`)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, false, nil
	}
	var rec StackRecord
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		return nil, false, fmt.Errorf("stack record is corrupt: %w", err)
	}
	return &rec, true, nil
}

// runOut runs kubectl and returns stdout (for reads).
func (k kubectlApplier) runOut(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-n", k.namespace}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// resourceArg builds the kubectl resource selector "<kind>.<group>" (or just "<kind>" for the
// core group), which disambiguates open-infra kinds from any same-named built-in.
func resourceArg(apiVersion, kind string) string {
	group := apiVersion
	if i := strings.Index(apiVersion, "/"); i >= 0 {
		group = apiVersion[:i]
	} else {
		group = "" // core group (v1)
	}
	if group == "" {
		return strings.ToLower(kind)
	}
	return strings.ToLower(kind) + "." + group
}
