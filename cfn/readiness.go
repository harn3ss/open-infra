// Readiness: when a created resource is complete, and when what depends on it may be created.
//
// AWS creates a stack's resources in parallel, each one as soon as everything it depends on is complete.
// The engine applies resources one at a time in dependency order, but it does not wait for each one to be
// complete before applying the next. A resource's wait — the cluster reporting it ready, an instance's VM
// running, the signals its CreationPolicy (or a WaitCondition) waits for — is deferred until a resource
// that depends on it is about to be applied, or the operation's end; the waits that are due then run
// together. So a WaitCondition with no DependsOn waits while the instance whose UserData signals it is
// created and boots, as on AWS, instead of blocking it until the condition times out; and a resource is
// never applied before everything it depends on is complete.
package cfn

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// baseID is the template logical id of a built resource (a companion's "Parent/name" -> "Parent").
func baseID(logicalID string) string {
	if i := strings.Index(logicalID, "/"); i >= 0 {
		return logicalID[:i]
	}
	return logicalID
}

// ancestors is every resource id deps leads to from id (transitively, so a resource that folds into
// nothing — an internet gateway, a route — still carries what it depends on through to its dependents).
func ancestors(deps map[string][]string, id string) map[string]bool {
	out := map[string]bool{}
	var walk func(string)
	walk = func(n string) {
		for _, d := range deps[n] {
			if !out[d] {
				out[d] = true
				walk(d)
			}
		}
	}
	walk(id)
	return out
}

// waitQueue holds the resources an operation has created whose wait has not run yet, in creation order.
type waitQueue struct{ pending []builtResource }

func (q *waitQueue) add(b builtResource) { q.pending = append(q.pending, b) }

// due removes and returns the pending resources a resource depends on (after: the template logical ids
// of its ancestors, builtResource.after).
func (q *waitQueue) due(after map[string]bool) []builtResource {
	if len(q.pending) == 0 || len(after) == 0 {
		return nil
	}
	var due, keep []builtResource
	for _, p := range q.pending {
		if after[baseID(p.res.LogicalID)] {
			due = append(due, p)
		} else {
			keep = append(keep, p)
		}
	}
	q.pending = keep
	return due
}

// all removes and returns every pending resource.
func (q *waitQueue) all() []builtResource {
	out := q.pending
	q.pending = nil
	return out
}

// ids lists the pending resources' logical ids.
func (q *waitQueue) ids() []string {
	out := make([]string, 0, len(q.pending))
	for _, p := range q.pending {
		out = append(out, p.res.LogicalID)
	}
	return out
}

// hasReadiness reports whether a resource reports readiness at all: a ConfigMap (a CLI-deployed inline
// Lambda's source) has no status, so it is complete once applied.
func hasReadiness(r StackResource) bool {
	return !(r.APIVersion == "v1" && r.Kind == "ConfigMap")
}

// resourceWait is what one created resource waits for before it is complete: the cluster reporting it
// ready, an instance's VM running (waitInstanceRunning), then the signals its CreationPolicy waits for —
// or, for a WaitCondition (nothing applied), its signals alone. It returns the signals received.
func resourceWait(ctx context.Context, opts DeployOptions, ap Applier, b builtResource) ([]Signal, error) {
	if IsSignalWait(b.res) {
		return waitForSignals(ctx, opts, *b.signals, b.res.LogicalID)
	}
	if opts.Wait && hasReadiness(b.res) {
		if err := ap.WaitReady(ctx, b.res.APIVersion, b.res.Kind, b.res.Name, opts.Timeout); err != nil {
			return nil, fmt.Errorf("%s/%s did not become ready: %w", b.res.Kind, b.res.Name, err)
		}
		if err := waitInstanceRunning(ctx, opts, ap, b.res); err != nil {
			return nil, err
		}
	}
	if b.signals != nil {
		return waitForSignals(ctx, opts, *b.signals, b.res.LogicalID)
	}
	return nil, nil
}

// settleWaits runs the waits of set together (resourceWait). done is called, on the caller's goroutine,
// for each resource as it completes; the first failure cancels the others, and is returned with its
// resource once every wait has returned (so nothing still runs while the caller rolls back).
func settleWaits(ctx context.Context, opts DeployOptions, ap Applier, set []builtResource, done func(builtResource, []Signal)) (*builtResource, error) {
	switch len(set) {
	case 0:
		return nil, nil
	case 1:
		sigs, err := resourceWait(ctx, opts, ap, set[0])
		if err != nil {
			return &set[0], err
		}
		done(set[0], sigs)
		return nil, nil
	}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		i    int
		sigs []Signal
		err  error
	}
	results := make(chan result, len(set))
	for i := range set {
		go func(i int) {
			sigs, err := resourceWait(wctx, opts, ap, set[i])
			results <- result{i, sigs, err}
		}(i)
	}
	var failed *builtResource
	var ferr error
	for n := 0; n < len(set); n++ {
		r := <-results
		switch {
		case r.err != nil && failed == nil:
			failed, ferr = &set[r.i], r.err
			cancel()
		case r.err == nil && failed == nil:
			done(set[r.i], r.sigs)
		}
	}
	return failed, ferr
}

// vmErrorStates are the KubeVirt states in which a VM is not going to run without someone changing
// something: an instance whose VM stays in one (vmErrorGrace) fails, as an instance that cannot launch
// fails on AWS. A state it passes through (a PVC still binding makes it briefly ErrorUnschedulable) is
// waited out.
var vmErrorStates = map[string]bool{
	"ErrorUnschedulable": true, "ErrImagePull": true, "ImagePullBackOff": true, "ErrorPvcNotFound": true,
	"ErrorDataVolumeNotFound": true, "DataVolumeError": true, "CrashLoopBackOff": true,
}

// vmErrorGrace is how long a VM may stay in an error state before its instance fails.
var vmErrorGrace = 3 * time.Minute

// launchRefusedGrace is how long a VM's launch may stay refused (status.launchRefused) before its instance
// fails with that refusal: AWS refuses such a launch at once; the grace only rides out a refusal that clears
// by itself (a restarted instance's earlier launcher still being torn down, still counted).
var launchRefusedGrace = 45 * time.Second

// launchRefusals are the EC2 errors a launch is refused with, as AWS writes them: the account's limits
// (HTTP 400) and a lack of capacity (HTTP 500).
var launchRefusals = map[string]struct {
	status  int
	message string
}{
	"VcpuLimitExceeded": {400, "You have requested more vCPU capacity than your current vCPU limit allows for the instance bucket that " +
		"the specified instance type belongs to. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment to this limit."},
	"VolumeLimitExceeded": {400, "You have exceeded your maximum storage limit in this region. Please contact AWS Support to request an " +
		"Elastic Block Store service limit increase."},
	"InstanceLimitExceeded": {400, "You have requested more instances than your current instance limit allows for the specified instance " +
		"type. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment to this limit."},
	"InsufficientInstanceCapacity": {500, "We currently do not have sufficient capacity in the Availability Zone you requested. Our system " +
		"will be working on provisioning additional capacity."},
}

// launchRefusal is the EC2 error a VM's launch is refused with (its status.launchRefused), "" when none.
func launchRefusal(st map[string]any) string {
	code, _ := st["launchRefused"].(string)
	if _, known := launchRefusals[code]; !known {
		return ""
	}
	return code
}

// LaunchRefusedError is an instance's failure for a launch EC2 refuses (Code), as CloudFormation reports
// EC2's refusal of an AWS::EC2::Instance.
type LaunchRefusedError struct{ Code string }

func (e *LaunchRefusedError) Error() string {
	r := launchRefusals[e.Code]
	return fmt.Sprintf("%s (Service: AmazonEC2; Status Code: %d; Error Code: %s; Proxy: null)", r.message, r.status, e.Code)
}

func launchRefusedError(code string) error { return &LaunchRefusedError{Code: code} }

// refusalTracker fails a wait whose VM stays refused for launchRefusedGrace.
type refusalTracker struct {
	code  string
	since time.Time
}

// observe records st's refusal and returns the instance's failure once it has lasted launchRefusedGrace.
func (t *refusalTracker) observe(st map[string]any) error {
	code := launchRefusal(st)
	switch {
	case code == "":
		t.code = ""
	case code != t.code:
		t.code, t.since = code, time.Now()
	case time.Since(t.since) >= launchRefusedGrace:
		return launchRefusedError(code)
	}
	return nil
}

// waitInstanceRunning holds an instance (a stack's kind: VirtualMachine) until its VM runs: on AWS an
// instance is complete once it is running, and one that cannot start fails its stack. It waits up to the
// operation's -timeout (at most restartWaitDefault) — or, while its disks are still being made (Provisioning:
// its root cloned from its image, a Windows one a full copy of a 100 GiB image) or an encrypted root is still
// being copied (the VM starts only once the copy is done), up to outputBootWaitCap — and fails sooner when the VM stays
// in a state it will not run from. A VM whose status does not report its power state (an environment
// whose composition predates it), or an Applier that cannot read status, is not waited for.
func waitInstanceRunning(ctx context.Context, opts DeployOptions, ap Applier, r StackResource) error {
	if !isStackVM(r) || (r.Type != "" && r.Type != "AWS::EC2::Instance") {
		return nil
	}
	if run, ok := r.Spec["running"].(bool); ok && !run {
		return nil
	}
	sr, ok := ap.(StatusReader)
	if !ok {
		return nil
	}
	wait := opts.Timeout
	if wait <= 0 || wait > restartWaitDefault {
		wait = restartWaitDefault
	}
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
	encRoot := encryptedRoot(r)
	last, errSince, errState := "no status yet", time.Time{}, ""
	var refused refusalTracker
	for {
		st, found, err := sr.GetStatus(ctx, r.APIVersion, r.Kind, r.Name)
		copying := false
		switch {
		case err != nil:
			last = err.Error()
		case !found:
			return fmt.Errorf("%s/%s no longer exists", r.Kind, r.Name)
		default:
			ps, reported := st["powerState"].(string)
			if !reported {
				return nil // this environment does not report a VM's power state
			}
			if ps == "Running" {
				return nil
			}
			// A launch the account's limits or the platform's capacity refuse fails, as on AWS, even while
			// its disks would otherwise still be being made.
			if err := refused.observe(st); err != nil {
				return err
			}
			copying = (encRoot && !boolField(st, "rootPopulated")) || ps == "Provisioning"
			if ps == "" {
				ps = "not reported yet"
			}
			last = "state " + ps
			switch {
			case encRoot && !boolField(st, "rootPopulated"):
				last += ", its encrypted root still being copied"
			case ps == "Provisioning":
				last += ", its disks still being made from its image"
			}
			if vmErrorStates[ps] && !copying {
				if errState != ps {
					errState, errSince = ps, time.Now()
				} else if time.Since(errSince) >= vmErrorGrace {
					return fmt.Errorf("%s/%s cannot run: its VM has been %s for %s", r.Kind, r.Name, ps, time.Since(errSince).Round(time.Second))
				}
			} else {
				errState = ""
			}
		}
		now := time.Now()
		if now.After(deadline) && !(copying && now.Before(bootDeadline)) {
			return fmt.Errorf("%s/%s did not start running within %s (last: %s)", r.Kind, r.Name, now.Sub(start).Round(time.Second), last)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s/%s: %w while waiting for it to run", r.Kind, r.Name, ctx.Err())
		case <-time.After(restartPollInterval):
		}
	}
}
