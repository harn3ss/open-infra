// Resource signals (#347 item M): CreationPolicy ResourceSignal, AWS::CloudFormation::WaitCondition and
// AWS::CloudFormation::WaitConditionHandle.
//
// On AWS a resource with a CreationPolicy ResourceSignal is not CREATE_COMPLETE when it exists but when
// its instances say so: cfn-signal (or the SignalResource API) sends Count SUCCESS signals within the
// Timeout; a FAILURE signal, or the timeout, fails the resource and rolls the stack back. A WaitCondition
// does the same for a WaitConditionHandle — a pre-signed URL the guest PUTs its signal to — and its
// Fn::GetAtt Data is the signals' data, keyed by UniqueId.
//
// The engine waits the same way: after a resource is applied and Ready it reads the stack's signals for
// that resource from opts.Signals (the front door stores what SignalResource and handle PUTs deliver)
// until enough have arrived. A deploy path that cannot receive signals (the CLI) refuses such a stack
// rather than waiting for something that cannot come.
package cfn

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signal is one resource signal.
type Signal struct {
	UniqueID string `json:"uniqueId"`
	Status   string `json:"status"` // SUCCESS | FAILURE
	Reason   string `json:"reason,omitempty"`
	Data     string `json:"data,omitempty"`
	Time     string `json:"time"`
}

// SignalSource reads the signals a stack's resource (or wait-condition handle) has received.
type SignalSource interface {
	Signals(ctx context.Context, stackName, logicalID string) ([]Signal, error)
}

// signalPollInterval is how often a waiting resource re-reads its signals.
var signalPollInterval = 3 * time.Second

const (
	waitConditionType       = "AWS::CloudFormation::WaitCondition"
	waitConditionHandleType = "AWS::CloudFormation::WaitConditionHandle"
	waitAPIVersion          = "cfn.openinfra.dev/v1"
	waitKind                = "SignalWait"
	maxWaitTimeout          = 12 * time.Hour // AWS's ceiling for a WaitCondition (43200 s)
)

// signalSpec is what one resource waits for: Count SUCCESS signals sent to source within Timeout.
type signalSpec struct {
	source  string // the logical id the signals are sent to (the resource itself, or a handle)
	count   int
	timeout time.Duration
}

func init() {
	translators[waitConditionType] = translateWaitCondition
	translators[waitConditionHandleType] = translateWaitConditionHandle
	mappingTable[waitConditionType] = MapEntry{Kind: "(signal wait)", Status: Supported, Note: "a WaitCondition waits for Count SUCCESS signals sent to its WaitConditionHandle's URL (or, with a CreationPolicy, to SignalResource on the WaitCondition itself) within Timeout; a FAILURE signal or the timeout fails the stack, as on AWS. Fn::GetAtt Data is the signals' data by UniqueId (usable in Outputs)."}
	mappingTable[waitConditionHandleType] = MapEntry{Kind: "(signal URL)", Status: Supported, Note: "a WaitConditionHandle's Ref is a pre-signed URL on the aws-shim that a guest PUTs its signal to (the cfn-signal / curl pattern)."}
}

// IsSignalWait reports whether a recorded resource is a wait condition (a wait, not an object).
func IsSignalWait(r StackResource) bool { return r.APIVersion == waitAPIVersion && r.Kind == waitKind }

// translateWaitCondition records the wait: it provisions nothing; deploy waits for its signals at its
// place in dependency order.
func translateWaitCondition(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	var f []Finding
	f = append(f, blockUnknownProps(id, props, map[string]bool{"Handle": true, "Count": true, "Timeout": true})...)
	res := ctx.template.Resources[id]
	spec, err := waitConditionSpec(id, res, ctx)
	if err != "" {
		f = append(f, Finding{"Resource " + id, err})
	}
	if len(f) > 0 {
		return nil, f
	}
	return &Manifest{APIVersion: waitAPIVersion, Kind: waitKind, Name: ctx.name(id),
		Spec: map[string]any{"source": spec.source, "count": spec.count, "timeoutSeconds": int(spec.timeout / time.Second)}}, nil
}

// translateWaitConditionHandle provisions nothing: its Ref (the signal URL) is all it is.
func translateWaitConditionHandle(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if f := blockUnknownProps(id, props, map[string]bool{}); len(f) > 0 {
		return nil, f
	}
	return nil, nil
}

// waitConditionSpec reads what a WaitCondition waits for: its Handle's signals (Count, Timeout seconds),
// or — the newer form — its own CreationPolicy ResourceSignal.
func waitConditionSpec(id string, res Resource, ctx *stackCtx) (signalSpec, string) {
	if spec, ok, err := creationSignals(res); err != "" {
		return signalSpec{}, err
	} else if ok {
		spec.source = id
		return spec, ""
	}
	raw, _ := ctx.rawProps(id)
	handle, ok := refTarget(raw["Handle"])
	if !ok {
		return signalSpec{}, "a WaitCondition needs a Handle that is a Ref to an in-stack AWS::CloudFormation::WaitConditionHandle (or a CreationPolicy ResourceSignal)"
	}
	if h, in := ctx.template.Resources[handle]; !in || h.Type != waitConditionHandleType {
		return signalSpec{}, "Handle " + handle + " is not an in-stack AWS::CloudFormation::WaitConditionHandle"
	}
	props, _ := ctx.resolveProps(id)
	count := 1
	if v, ok := props["Count"]; ok {
		n, err := strconv.Atoi(fmt.Sprint(v))
		if err != nil || n < 1 {
			return signalSpec{}, fmt.Sprintf("Count %v is not a positive integer", v)
		}
		count = n
	}
	tv, ok := props["Timeout"]
	if !ok {
		return signalSpec{}, "a WaitCondition with a Handle requires Timeout (seconds)"
	}
	secs, err := strconv.Atoi(fmt.Sprint(tv))
	if err != nil || secs < 1 || time.Duration(secs)*time.Second > maxWaitTimeout {
		return signalSpec{}, fmt.Sprintf("Timeout %v is not a number of seconds between 1 and 43200", tv)
	}
	return signalSpec{source: handle, count: count, timeout: time.Duration(secs) * time.Second}, ""
}

// creationSignals reads a resource's CreationPolicy ResourceSignal (Count default 1, Timeout an ISO 8601
// duration, default PT5M). ok=false when it has none.
func creationSignals(res Resource) (signalSpec, bool, string) {
	cp, _ := res.CreationPolicy.(map[string]any)
	rs, ok := cp["ResourceSignal"].(map[string]any)
	if !ok {
		return signalSpec{}, false, ""
	}
	spec := signalSpec{count: 1, timeout: 5 * time.Minute}
	if v, ok := rs["Count"]; ok {
		n, err := strconv.Atoi(fmt.Sprint(v))
		if err != nil || n < 1 {
			return signalSpec{}, false, fmt.Sprintf("CreationPolicy ResourceSignal Count %v is not a positive integer", v)
		}
		spec.count = n
	}
	if v, ok := rs["Timeout"]; ok {
		d, err := parseISODuration(fmt.Sprint(v))
		if err != nil || d <= 0 || d > maxWaitTimeout {
			return signalSpec{}, false, fmt.Sprintf("CreationPolicy ResourceSignal Timeout %v is not an ISO 8601 duration of at most 12 hours (e.g. PT15M)", v)
		}
		spec.timeout = d
	}
	return spec, true, ""
}

var isoDurationRe = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$`)

// parseISODuration parses the PT#H#M#S durations CloudFormation uses.
func parseISODuration(s string) (time.Duration, error) {
	m := isoDurationRe.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(s)))
	if m == nil || (m[1] == "" && m[2] == "" && m[3] == "") {
		return 0, fmt.Errorf("not an ISO 8601 duration: %q", s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute, time.Second} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1])
			d += time.Duration(n) * unit
		}
	}
	return d, nil
}

// signalSpecOf is what a built resource waits for after it is applied and Ready, if anything: a wait
// condition's signals, or a resource's CreationPolicy ResourceSignal.
func signalSpecOf(res Resource, m *Manifest, id string) (*signalSpec, error) {
	if m != nil && m.APIVersion == waitAPIVersion && m.Kind == waitKind {
		src, _ := m.Spec["source"].(string)
		n, _ := m.Spec["count"].(int)
		secs, _ := m.Spec["timeoutSeconds"].(int)
		return &signalSpec{source: src, count: n, timeout: time.Duration(secs) * time.Second}, nil
	}
	spec, ok, err := creationSignals(res)
	if err != "" {
		return nil, fmt.Errorf("%s: %s", id, err)
	}
	if !ok {
		return nil, nil
	}
	spec.source = id
	return &spec, nil
}

// needsSignals reports whether a template waits for any signal (a CreationPolicy ResourceSignal or a
// WaitCondition) — such a stack needs a deploy path that can receive them.
func needsSignals(t *Template) bool {
	for _, res := range t.Resources {
		if res.Type == waitConditionType {
			return true
		}
		if _, ok, _ := creationSignals(res); ok {
			return true
		}
	}
	return false
}

// waitForSignals blocks until spec's Count SUCCESS signals (distinct UniqueIds) have arrived, a FAILURE
// signal arrives, or the timeout passes — AWS's three outcomes. It returns the SUCCESS signals.
func waitForSignals(ctx context.Context, opts DeployOptions, spec signalSpec, forID string) ([]Signal, error) {
	if opts.Signals == nil {
		return nil, fmt.Errorf("%s waits for %d resource signal(s), and this deploy path cannot receive signals (deploy through the aws-shim CloudFormation front door)", forID, spec.count)
	}
	deadline := time.Now().Add(spec.timeout)
	for {
		sigs, err := opts.Signals.Signals(ctx, opts.StackName, spec.source)
		if err != nil {
			return nil, fmt.Errorf("%s: reading its signals: %w", forID, err)
		}
		ok := map[string]Signal{}
		for _, s := range sigs {
			if strings.EqualFold(s.Status, "FAILURE") {
				reason := s.Reason
				if reason == "" {
					reason = "no reason given"
				}
				return nil, fmt.Errorf("%s: received a FAILURE signal with UniqueId %s (%s)", forID, s.UniqueID, reason)
			}
			if strings.EqualFold(s.Status, "SUCCESS") {
				ok[s.UniqueID] = s
			}
		}
		if len(ok) >= spec.count {
			out := make([]Signal, 0, len(ok))
			for _, s := range ok {
				out = append(out, s)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].UniqueID < out[j].UniqueID })
			return out, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%s: failed to receive %d resource signal(s) within the specified duration (%s; %d received)", forID, spec.count, spec.timeout, len(ok))
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w while waiting for resource signals", forID, ctx.Err())
		case <-time.After(signalPollInterval):
		}
	}
}

// signalData is a WaitCondition's Fn::GetAtt Data: a JSON object of each signal's Data by UniqueId.
func signalData(sigs []Signal) string {
	m := map[string]string{}
	for _, s := range sigs {
		m[s.UniqueID] = s.Data
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// handleURL is a WaitConditionHandle's Ref: the signal URL the front door serves, or a placeholder on a
// path that has none (plan, the CLI — which then refuses the stack, needsSignals).
func handleURL(opts func(string, string) string, stackName, id string) string {
	if opts != nil {
		return opts(stackName, id)
	}
	return "https://cloudformation-waitcondition.invalid/" + stackName + "/" + id
}
