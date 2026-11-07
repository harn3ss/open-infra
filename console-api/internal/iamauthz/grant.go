package iamauthz

import (
	"context"
	"regexp"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Temporary access (kind: Grant). A Grant asks that a principal hold more policies for a while. Once a
// second person approves it, its policies are attached to its subject — a User, or every member of a
// Group — from the approval until approval + duration (at most MaxGrantDuration), exactly as if they
// were on the subject's spec.policies. It attaches nothing while it awaits approval, when its approver is
// its requester, or once its window has passed. The window is checked whenever a principal's policies
// are gathered (each request the evaluator decides, each pass of the IAM compiler), so a Grant stops
// counting the moment it expires, whether or not the grant reconciler has deleted it yet.

// MaxGrantDuration is the longest a Grant may last.
const MaxGrantDuration = 24 * time.Hour

// GrantGVR is the kind: Grant resource.
var GrantGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "grants"}

// grantDuration is the duration form a Grant takes (whole hours, minutes and seconds, e.g. "4h", "1h30m").
// The grant reconciler reads the same form, so a duration it could not read never lives longer here.
var grantDuration = regexp.MustCompile(`^([0-9]+h)?([0-9]+m)?([0-9]+s)?$`)

// TemporaryAttachment is one approved Grant's policies on its subject, for its window.
type TemporaryAttachment struct {
	// Grant is the Grant's canonical name (QualifiedName).
	Grant string
	// Policies are the canonical names of the Policies it attaches.
	Policies []string
	// From and Until bound the window: attached at From, no longer at Until.
	From, Until time.Time
}

// ActiveAt reports whether the attachment's window is open at t.
func (a TemporaryAttachment) ActiveAt(t time.Time) bool {
	return !t.Before(a.From) && t.Before(a.Until)
}

// GrantSpec is what deciding a Grant reads from its spec.
type GrantSpec struct {
	SubjectKind string // "User" or "Group"
	SubjectName string
	Policies    []string
	Duration    string
	RequestedBy string
	ApprovedBy  string
	ApprovedAt  string
}

// GrantSpecOf reads a Grant's spec (as the API server returns it).
func GrantSpecOf(spec map[string]any) GrantSpec {
	subject, _ := spec["subject"].(map[string]any)
	approval, _ := spec["approval"].(map[string]any)
	return GrantSpec{
		SubjectKind: str(subject["kind"]), SubjectName: str(subject["name"]),
		Policies: toStrings(spec["policies"]), Duration: str(spec["duration"]),
		RequestedBy: str(spec["requestedBy"]), ApprovedBy: str(approval["approvedBy"]), ApprovedAt: str(approval["approvedAt"]),
	}
}

// ParseGrantDuration reads a Grant's duration: whole hours, minutes and seconds, more than zero and at
// most MaxGrantDuration.
func ParseGrantDuration(s string) (time.Duration, bool) {
	if s == "" || !grantDuration.MatchString(s) {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > MaxGrantDuration {
		return 0, false
	}
	return d, true
}

// GrantWindow is when a Grant's policies are attached: from its approval for its duration. why says, in
// a sentence, why it attaches nothing ("" when it has a window):
//   - nobody has approved it;
//   - its approver is its requester (approving your own request is not a second person's approval);
//   - its approval time or its duration cannot be read, or its duration is over MaxGrantDuration;
//   - it names no subject, a subject outside its own namespace, or no policy.
func GrantWindow(g GrantSpec) (from, until time.Time, why string) {
	switch {
	case (g.SubjectKind != "User" && g.SubjectKind != "Group") || g.SubjectName == "":
		return from, until, "the grant names no user or group"
	case strings.Contains(g.SubjectName, "/"):
		// A subject is a user or group of the grant's own namespace (its account): "<ns>/<name>" would
		// reach a principal of another namespace from the IAM home namespace.
		return from, until, "the grant's user or group must be in the grant's own namespace"
	case len(g.Policies) == 0:
		return from, until, "the grant names no policy"
	case g.ApprovedBy == "":
		return from, until, "awaiting approval by a second person"
	case g.ApprovedBy == g.RequestedBy:
		return from, until, "the approver must be someone other than the requester"
	}
	d, ok := ParseGrantDuration(g.Duration)
	if !ok {
		return from, until, "the duration must be whole hours, minutes or seconds (30m, 4h), at most 24h"
	}
	t, err := time.Parse(time.RFC3339, g.ApprovedAt)
	if err != nil {
		return from, until, "the approval has no valid time (spec.approval.approvedAt)"
	}
	return t, t.Add(d), ""
}

// ActiveTemporary is the temporary attachments that apply to a principal at now: its own and its groups'.
func (w World) ActiveTemporary(ptype, pid string, groups []string, now time.Time) []TemporaryAttachment {
	if len(w.Temporary) == 0 {
		return nil
	}
	keys := []string{PolicyKey(ptype, pid)}
	for _, g := range groups {
		keys = append(keys, PolicyKey("Group", strings.TrimPrefix(g, "openinfra:")))
	}
	var out []TemporaryAttachment
	for _, k := range keys {
		for _, a := range w.Temporary[k] {
			if a.ActiveAt(now) {
				out = append(out, a)
			}
		}
	}
	return out
}

// loadGrants adds every approved Grant whose window has not passed to the World. A cluster without the
// Grant kind has no grants; any other list error fails the load (a Grant may attach a Deny).
func loadGrants(ctx context.Context, dc dynamic.Interface, home string, defined func(string) bool, now time.Time, w *World) error {
	list, err := dc.Resource(GrantGVR).List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for i := range list.Items {
		obj := list.Items[i]
		spec, _ := obj.Object["spec"].(map[string]any)
		g := GrantSpecOf(spec)
		from, until, why := GrantWindow(g)
		if why != "" || !now.Before(until) {
			continue
		}
		ns := obj.GetNamespace()
		if ns == "" {
			ns = home
		}
		var names []string
		for _, ref := range g.Policies {
			if n := ResolvePolicyRef(home, ns, ref, defined); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			continue
		}
		key := PolicyKey(g.SubjectKind, QualifiedName(home, ns, g.SubjectName))
		if w.Temporary == nil {
			w.Temporary = map[string][]TemporaryAttachment{}
		}
		w.Temporary[key] = append(w.Temporary[key], TemporaryAttachment{
			Grant: QualifiedName(home, ns, obj.GetName()), Policies: names, From: from, Until: until,
		})
	}
	return nil
}
