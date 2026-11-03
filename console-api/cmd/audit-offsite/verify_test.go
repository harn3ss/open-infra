package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"github.com/harn3ss/open-infra/console-api/internal/auditchain"
)

// fakeStore is a versioned, object-locked segment bucket in memory.
type fakeStore struct {
	versions map[string][]minio.ObjectInfo
	data     map[string][]byte    // key@versionID
	until    map[string]time.Time // key@versionID -> COMPLIANCE retain-until
	segs     []auditchain.Segment
	written  []time.Time
}

func (f *fakeStore) listVersions(context.Context) (map[string][]minio.ObjectInfo, error) {
	out := map[string][]minio.ObjectInfo{}
	for k, vs := range f.versions {
		out[k] = append([]minio.ObjectInfo(nil), vs...)
	}
	return out, nil
}

func (f *fakeStore) getVersion(_ context.Context, key, versionID string) ([]byte, error) {
	d, ok := f.data[key+"@"+versionID]
	if !ok {
		return nil, fmt.Errorf("no version %s of %s", versionID, key)
	}
	return d, nil
}

func (f *fakeStore) retainUntil(_ context.Context, key, versionID string) (time.Time, bool) {
	t, ok := f.until[key+"@"+versionID]
	return t, ok
}

// chainStore ships n chained segments, the first at start and one every 5 minutes, each locked for
// retention from the moment it is written.
func chainStore(t *testing.T, n int, start time.Time, retention time.Duration) *fakeStore {
	t.Helper()
	f := &fakeStore{versions: map[string][]minio.ObjectInfo{}, data: map[string][]byte{}, until: map[string]time.Time{}}
	var prev *auditchain.Segment
	for i := 0; i < n; i++ {
		seg := auditchain.BuildSegment(prev, []string{fmt.Sprintf(`{"auditID":"a%d"}`, i)}, "", "")
		blob, err := json.Marshal(seg)
		if err != nil {
			t.Fatal(err)
		}
		at := start.Add(time.Duration(i) * 5 * time.Minute)
		key := segmentKey(i)
		f.versions[key] = []minio.ObjectInfo{{Key: key, VersionID: "v1", LastModified: at}}
		f.data[key+"@v1"] = blob
		f.until[key+"@v1"] = at.Add(retention)
		f.segs = append(f.segs, seg)
		f.written = append(f.written, at)
		prev = &f.segs[i]
	}
	return f
}

// marker lays a delete marker on segment i at time at (what lifecycle expiry, or a shadowing attempt, does).
func (f *fakeStore) marker(i int, at time.Time) {
	key := segmentKey(i)
	f.versions[key] = append(f.versions[key], minio.ObjectInfo{Key: key, VersionID: fmt.Sprintf("dm%d", len(f.versions[key])),
		IsDeleteMarker: true, LastModified: at})
}

// removeOriginal deletes segment i's original (lifecycle noncurrent expiry), keeping its markers; with
// no markers left the key is gone.
func (f *fakeStore) removeOriginal(i int) {
	key := segmentKey(i)
	var keep []minio.ObjectInfo
	for _, v := range f.versions[key] {
		if v.IsDeleteMarker {
			keep = append(keep, v)
		}
	}
	if len(keep) == 0 {
		delete(f.versions, key)
		return
	}
	f.versions[key] = keep
}

// overwrite lays a newer real version on segment i.
func (f *fakeStore) overwrite(i int, content []byte, at time.Time) {
	key := segmentKey(i)
	vid := fmt.Sprintf("v%d", len(f.versions[key])+1)
	f.versions[key] = append(f.versions[key], minio.ObjectInfo{Key: key, VersionID: vid, LastModified: at})
	f.data[key+"@"+vid] = content
}

func (f *fakeStore) anchorAt(i int) *anchorState {
	return &anchorState{HeadSeq: f.segs[i].Seq, HeadHash: f.segs[i].Hash}
}

const day = 24 * time.Hour

func runVerify(t *testing.T, f *fakeStore, now time.Time, retention time.Duration, anchor *anchorState) verifyOutcome {
	t.Helper()
	out, err := verifySegments(context.Background(), f, now, retention, anchor)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func intact(o verifyOutcome) bool { return o.res.OK && o.shadow == 0 }

// Retain-then-dispose: lifecycle expiry lays a delete marker on each segment once its retention has
// lapsed. That is disposal, not tampering — the old verifier counted every such marker as a shadowing
// attempt, so a configured disposal read as tampering forever.
func TestVerify_DisposalAfterRetentionIsNotTampering(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"full", "anchored"} {
		f := chainStore(t, 20, now.Add(-3*day), day)
		for i := 0; i < 10; i++ {
			f.marker(i, f.written[i].Add(day)) // expiry exactly at the end of retention
		}
		var anchor *anchorState
		if mode == "anchored" {
			anchor = f.anchorAt(14)
		}
		o := runVerify(t, f, now, day, anchor)
		if !intact(o) || o.disposalMarkers != 10 || o.res.HeadSeq != 19 {
			t.Errorf("%s: markers laid after retention are disposal: ok=%v shadow=%d disposalMarkers=%d head=%d (%s)",
				mode, o.res.OK, o.shadow, o.disposalMarkers, o.res.HeadSeq, o.res.Reason)
		}
	}

	// Without a readable retain-until, the write time plus the configured retention decides.
	f := chainStore(t, 5, now.Add(-3*day), day)
	f.marker(1, f.written[1].Add(day))
	delete(f.until, segmentKey(1)+"@v1")
	if o := runVerify(t, f, now, day, nil); !intact(o) || o.disposalMarkers != 1 {
		t.Errorf("fallback to the configured retention: shadow=%d disposalMarkers=%d", o.shadow, o.disposalMarkers)
	}
	if o := runVerify(t, f, now, 7*day, nil); o.shadow != 1 {
		t.Errorf("under a 7-day retention the same marker is laid while locked: shadow=%d, want 1", o.shadow)
	}
}

// A delete marker laid while the original was still locked is a shadowing attempt — and stays one after
// the lock has lapsed, so an old attempt can't age into "disposal".
func TestVerify_MarkerWhileLockedIsTampering(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		start  time.Time
		anchor int
	}{
		"still locked":            {now.Add(-6 * time.Hour), -1},
		"locked then, lapsed now": {now.Add(-3 * day), -1},
		"in the anchored prefix":  {now.Add(-3 * day), 15},
	} {
		f := chainStore(t, 20, c.start, day)
		f.marker(5, f.written[5].Add(2*time.Hour))
		var anchor *anchorState
		if c.anchor >= 0 {
			anchor = f.anchorAt(c.anchor)
		}
		if o := runVerify(t, f, now, day, anchor); intact(o) || o.shadow != 1 || o.disposalMarkers != 0 {
			t.Errorf("%s: shadow=%d disposalMarkers=%d, want one shadowing attempt", name, o.shadow, o.disposalMarkers)
		}
	}
}

// An extra version laid over a segment with different content is a shadowing attempt, before or after
// its retention; a byte-identical re-ship is not. An edited original breaks the chain.
func TestVerify_ExtraVersionAndContentTamper(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := chainStore(t, 10, now.Add(-6*time.Hour), day)
	f.overwrite(7, []byte(`{"seq":7,"records":["forged"]}`), now.Add(-time.Hour))
	if o := runVerify(t, f, now, day, nil); intact(o) || o.shadow != 1 {
		t.Errorf("a different-content version: shadow=%d, want 1", o.shadow)
	}
	if o := runVerify(t, f, now, day, f.anchorAt(8)); o.shadow != 1 {
		t.Errorf("a different-content version in the anchored prefix: shadow=%d, want 1", o.shadow)
	}

	f = chainStore(t, 10, now.Add(-6*time.Hour), day)
	f.overwrite(3, f.data[segmentKey(3)+"@v1"], now.Add(-time.Hour))
	if o := runVerify(t, f, now, day, nil); !intact(o) {
		t.Errorf("a byte-identical re-ship is benign: shadow=%d", o.shadow)
	}

	f = chainStore(t, 10, now.Add(-6*time.Hour), day)
	var s auditchain.Segment
	_ = json.Unmarshal(f.data[segmentKey(4)+"@v1"], &s)
	s.Records = []string{"edited"}
	f.data[segmentKey(4)+"@v1"], _ = json.Marshal(s)
	if o := runVerify(t, f, now, day, nil); o.res.OK || o.res.BrokenAt == nil || *o.res.BrokenAt != 4 {
		t.Errorf("an edited original must break the chain at 4: %+v", o.res)
	}
}

// Once disposal has removed the oldest originals, the chain is verified from the oldest retained
// segment. Lifecycle removes them roughly, not strictly, in order: a straggler still present below the
// retained chain is disposal in progress, and a disposed segment's lone marker is disposal too.
func TestVerify_DisposedPrefixWithIntactRemainder(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := chainStore(t, 20, now.Add(-3*day), day)
	for i := 0; i < 8; i++ {
		f.marker(i, f.written[i].Add(day))
	}
	for i := 0; i < 8; i++ {
		if i != 3 { // 3 is a straggler: its original is still there
			f.removeOriginal(i)
		}
	}
	for i := 0; i < 5; i++ {
		if i != 3 {
			delete(f.versions, segmentKey(i)) // their markers have been cleaned up too
		}
	}
	for name, anchor := range map[string]*anchorState{
		"full":                   nil,
		"anchored":               f.anchorAt(12),
		"anchored head disposed": {HeadSeq: 4, HeadHash: f.segs[4].Hash},
	} {
		o := runVerify(t, f, now, day, anchor)
		if !intact(o) || o.retainedFrom != 8 || o.disposed != 8 || o.res.HeadSeq != 19 {
			t.Errorf("%s: ok=%v shadow=%d retainedFrom=%d disposed=%d head=%d (%s)",
				name, o.res.OK, o.shadow, o.retainedFrom, o.disposed, o.res.HeadSeq, o.res.Reason)
		}
		if anchor == nil && o.res.BaseSeq != 8 {
			t.Errorf("%s: the chain is verified from the oldest retained segment 8, got base %d", name, o.res.BaseSeq)
		}
	}
}

// Retention lowered over time: older segments, written under a long retention, are still locked while
// later ones (written under a short one) have been disposed. A marker laid on such an older segment while
// it is locked is still a shadowing attempt, even below the retained chain.
func TestVerify_LockedSegmentBelowTheRetainedChain(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := chainStore(t, 20, now.Add(-3*day), day)
	for i := 0; i < 4; i++ {
		f.until[segmentKey(i)+"@v1"] = f.written[i].Add(7 * 365 * day) // written under a 7-year retention
		f.marker(i, f.written[i].Add(day))                             // expired after a day: still locked
	}
	f.removeOriginal(5) // a later, short-retention segment, disposed
	o := runVerify(t, f, now, day, nil)
	if o.retainedFrom != 6 || o.shadow != 4 || o.disposalMarkers != 0 || intact(o) {
		t.Errorf("markers on still-locked segments below the retained chain must count: retainedFrom=%d shadow=%d disposalMarkers=%d",
			o.retainedFrom, o.shadow, o.disposalMarkers)
	}
}

// A segment missing while the one after it is still under retention was removed, not disposed: the
// chain fails. That holds for a hole in the middle and for a front truncation alike.
func TestVerify_GapInTheRetainedChainFails(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := chainStore(t, 20, now.Add(-6*time.Hour), day)
	f.removeOriginal(10)
	o := runVerify(t, f, now, day, nil)
	if o.res.OK || !strings.Contains(o.res.Reason, "gap") || o.res.BrokenAt == nil || *o.res.BrokenAt != 10 {
		t.Errorf("a hole at 10 inside retention must fail: %+v", o.res)
	}
	if o := runVerify(t, f, now, day, f.anchorAt(15)); o.res.OK {
		t.Errorf("the hole fails with an anchor past it too: %+v", o.res)
	}

	f = chainStore(t, 20, now.Add(-6*time.Hour), day)
	f.removeOriginal(0)
	f.removeOriginal(1)
	if o := runVerify(t, f, now, day, nil); o.res.OK {
		t.Errorf("a front truncation while segment 2 is still locked is not disposal: %+v", o.res)
	}

	// Past retention, the same hole near the disposal frontier is disposal (out-of-order removal).
	f = chainStore(t, 20, now.Add(-3*day), day)
	f.removeOriginal(10)
	if o := runVerify(t, f, now, day, nil); !intact(o) || o.retainedFrom != 11 {
		t.Errorf("a hole after retention lapsed is disposal: ok=%v retainedFrom=%d (%s)", o.res.OK, o.retainedFrom, o.res.Reason)
	}
}
