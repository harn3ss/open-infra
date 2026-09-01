// The live Applier: shells out to kubectl. Kept deliberately thin — all deploy ordering,
// state, and rollback logic lives in deploy.go and is tested against a fake Applier; this file
// is the only part that touches a real cluster.
package main

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

// WaitGone polls until the resource is fully removed from the cluster (a kubectl get returns
// NotFound), so a DELETE_COMPLETE means the object is actually gone, not merely marked for
// deletion behind a finalizer.
func (k kubectlApplier) WaitGone(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	res := resourceArg(apiVersion, kind) + "/" + name
	deadline := time.Now().Add(timeout)
	for {
		_, err := k.runOut(ctx, "get", res, "-o", "name")
		if err != nil && (strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "not found")) {
			return nil
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

// GetStack reads the persisted stack record ConfigMap.
func (k kubectlApplier) GetStack(ctx context.Context, stackName string) (*StackRecord, bool, error) {
	out, err := k.runOut(ctx, "get", "configmap", "cfn-stack-"+stackName, "-o", `jsonpath={.data.stack\.json}`)
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "not found") {
			return nil, false, nil
		}
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
