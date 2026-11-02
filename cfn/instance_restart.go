// Stop and start an instance whose update needs it (AWS's "Update requires: Some interruptions").
//
// A kind: VirtualMachine reads most of its spec only when it starts: its CPU and memory (the
// InstanceType), its user data, its disks, firmware and metadata options. KubeVirt takes a changed
// spec into the VM's template and reports RestartRequired, but the running VM keeps its old size.
// AWS stops and starts the instance for such an update and completes it once the instance runs again,
// so an update that changes one of those fields does the same here: it stops the VM (spec.running
// false, the console's Stop), waits until it has stopped, starts it (spec.running true) and waits
// until it runs on the new spec. A change only to what a running VM takes live (its security groups,
// its LAN exposure and ports) restarts nothing, as on AWS.
package cfn

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PowerSetter is an optional Applier capability: stop or start a kind: VirtualMachine by setting its
// spec.running, as the console's Start/Stop does, with the same authority as every other step.
type PowerSetter interface {
	SetRunning(ctx context.Context, apiVersion, kind, name string, running bool) error
}

// liveVMFields are the kind: VirtualMachine spec fields a running VM takes without a restart: its
// security groups (network policy), its LAN exposure (Services) and its power state.
var liveVMFields = map[string]bool{
	"securityGroups": true, "expose": true, "elasticIp": true, "ports": true, "running": true,
}

// restartPollInterval is how often a restart reads the VM's status.
var restartPollInterval = 3 * time.Second

// restartWaitDefault bounds each half of a restart (stopping, then starting) when the operation sets no
// shorter -timeout; a VM with an encrypted root still copying its image may take up to outputBootWaitCap
// to start.
var restartWaitDefault = 15 * time.Minute

// isStackVM reports whether a stack resource is a kind: VirtualMachine claim.
func isStackVM(r StackResource) bool {
	return r.Kind == "VirtualMachine" && strings.HasPrefix(r.APIVersion, "openinfra.dev/")
}

// restartFields returns the spec fields, sorted, whose change from prior to next takes effect only when
// the VM starts — empty when every change is one a running VM takes live.
func restartFields(prior, next map[string]any) []string {
	keys := map[string]bool{}
	for k := range prior {
		keys[k] = true
	}
	for k := range next {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if liveVMFields[k] {
			continue
		}
		if !jsonEqual(prior[k], next[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// restartReason is the resource event's reason while the instance is stopped and started.
func restartReason(fields []string) string {
	return "Stopping and starting the instance to apply its new " + strings.Join(fields, ", ") +
		" (an update with some interruptions, as AWS stops and starts an instance for a new InstanceType or UserData)"
}

// restartInstance stops a running kind: VirtualMachine and starts it again, returning once it runs on its
// current spec. A VM that is stopped (spec.running false) is left stopped: the change applies when it is
// next started, as on AWS.
func restartInstance(ctx context.Context, opts DeployOptions, ap Applier, r StackResource) error {
	ps, okP := ap.(PowerSetter)
	sr, okS := ap.(StatusReader)
	if !okP || !okS {
		return fmt.Errorf("%s/%s needs a restart to apply this update, and this environment cannot stop and start it", r.Kind, r.Name)
	}
	live, found, err := ap.GetSpec(ctx, r.APIVersion, r.Kind, r.Name)
	if err != nil {
		return fmt.Errorf("reading %s/%s: %w", r.Kind, r.Name, err)
	}
	if !found {
		return fmt.Errorf("%s/%s no longer exists", r.Kind, r.Name)
	}
	if run, ok := live["running"].(bool); ok && !run {
		return nil
	}
	wait := opts.Timeout
	if wait <= 0 || wait > restartWaitDefault {
		wait = restartWaitDefault
	}
	if err := ps.SetRunning(ctx, r.APIVersion, r.Kind, r.Name, false); err != nil {
		return fmt.Errorf("stopping %s/%s: %w", r.Kind, r.Name, err)
	}
	if err := waitPower(ctx, sr, r, wait, false, func(st map[string]any) bool {
		return powerState(st) == "Stopped"
	}); err != nil {
		// Never leave the instance stopped because the wait gave up.
		_ = ps.SetRunning(context.WithoutCancel(ctx), r.APIVersion, r.Kind, r.Name, true)
		return fmt.Errorf("%s/%s did not stop: %w", r.Kind, r.Name, err)
	}
	if err := ps.SetRunning(ctx, r.APIVersion, r.Kind, r.Name, true); err != nil {
		return fmt.Errorf("starting %s/%s: %w", r.Kind, r.Name, err)
	}
	if err := waitPower(ctx, sr, r, wait, encryptedRoot(r), func(st map[string]any) bool {
		return powerState(st) == "Running" && !boolField(st, "restartRequired")
	}); err != nil {
		return fmt.Errorf("%s/%s did not start on its new spec: %w", r.Kind, r.Name, err)
	}
	return nil
}

// waitPower polls the VM's status until done reports true, for up to wait — or, for an encrypted root
// still copying its OS image (it starts only once the copy is done), up to outputBootWaitCap. The
// operation's own deadline is kept, less the time its record needs.
func waitPower(ctx context.Context, sr StatusReader, r StackResource, wait time.Duration, encRoot bool, done func(map[string]any) bool) error {
	start := time.Now()
	deadline, bootDeadline := start.Add(wait), start.Add(outputBootWaitCap)
	if dl, ok := ctx.Deadline(); ok {
		last := dl.Add(-outputRecordReserve)
		if last.Before(deadline) {
			deadline = last
		}
		if last.Before(bootDeadline) {
			bootDeadline = last
		}
	}
	last := "no status yet"
	for {
		st, found, err := sr.GetStatus(ctx, r.APIVersion, r.Kind, r.Name)
		copying := false
		switch {
		case err != nil:
			last = err.Error()
		case !found:
			return fmt.Errorf("%s/%s no longer exists", r.Kind, r.Name)
		default:
			if done(st) {
				return nil
			}
			last = fmt.Sprintf("state %q, restart required %v", powerState(st), boolField(st, "restartRequired"))
			copying = encRoot && !boolField(st, "rootPopulated")
		}
		now := time.Now()
		if now.After(deadline) && !(copying && now.Before(bootDeadline)) {
			return fmt.Errorf("gave up after %s (last: %s)", now.Sub(start).Round(time.Second), last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(restartPollInterval):
		}
	}
}

// powerState is a VM's status.powerState (KubeVirt's printableStatus).
func powerState(st map[string]any) string {
	s, _ := st["powerState"].(string)
	return s
}

// boolField reads a status boolean, accepting the string form a rendered status may carry.
func boolField(st map[string]any, k string) bool {
	switch v := st[k].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}
