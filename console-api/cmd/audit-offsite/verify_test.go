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

// An anchor past the bucket's newest segment — the chain lost its newest segments, or was restarted in
// a new bucket below an old anchor — is not trusted. Seeding from it skipped every listed segment as
// already verified (count 0), reported the anchor's head as the chain's, and so the anchor cross-check
// could never see the regression: the run read intact while verifying nothing.
func TestVerify_AnchorPastTheBucketHeadIsNotTrusted(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for name, disposedBelow := range map[string]int{"whole chain": 0, "after disposal": 6} {
		f := chainStore(t, 20, now.Add(-3*day), day)
		for i := 0; i < disposedBelow; i++ {
			f.removeOriginal(i)
		}
		prior := anchorState{HeadSeq: 500, HeadHash: "4645900e"} // an older chain's head
		o := runVerify(t, f, now, day, &prior)
		if o.res.HeadSeq != 19 || o.res.Count != 20-disposedBelow || o.maxReal != 19 {
			t.Errorf("%s: the chain must be re-derived to its real head 19: head=%d count=%d maxReal=%d",
				name, o.res.HeadSeq, o.res.Count, o.maxReal)
		}
		if !strings.Contains(o.anchorNote, "past the bucket's newest segment") {
			t.Errorf("%s: the run must say why the anchor was not trusted: %q", name, o.anchorNote)
		}
		if v := anchorVerdict(prior, true, o.heads, o.res); v != "regressed" {
			t.Errorf("%s: an anchor ahead of the bucket's head is a regression, got %q", name, v)
		}
	}
}

// The anchored segment must carry the anchored hash. When the anchor IS the bucket's head there is no
// later segment whose PrevHash would expose a wrong anchor, so seeding from it verified nothing and the
// cross-check compared the anchor with itself.
func TestVerify_AnchorWithAnotherHashIsNotTrusted(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, at := range []int{19, 12} { // the head itself, and inside the chain
		f := chainStore(t, 20, now.Add(-6*time.Hour), day)
		prior := anchorState{HeadSeq: at, HeadHash: "deadbeef"}
		o := runVerify(t, f, now, day, &prior)
		if !o.res.OK || o.res.Count != 20 || !strings.Contains(o.anchorNote, "does not have the anchored hash") {
			t.Errorf("anchor at %d: re-derive the chain from contents: ok=%v count=%d note=%q (%s)",
				at, o.res.OK, o.res.Count, o.anchorNote, o.res.Reason)
		}
		if v := anchorVerdict(prior, true, o.heads, o.res); v != "rewritten" {
			t.Errorf("anchor at %d: a different hash at the anchored seq is a rewrite, got %q", at, v)
		}
	}
	// The right anchor is still used: only the segments after it are re-derived.
	f := chainStore(t, 20, now.Add(-6*time.Hour), day)
	o := runVerify(t, f, now, day, f.anchorAt(12))
	if !o.res.OK || o.res.Count != 7 || o.anchorNote != "" || anchorVerdict(*f.anchorAt(12), true, o.heads, o.res) != "ok" {
		t.Errorf("a consistent anchor: ok=%v count=%d note=%q", o.res.OK, o.res.Count, o.anchorNote)
	}
}

// The rotating re-sweep never walks past the newest listed segment, whatever head it is handed (the
// caller passed the anchor's seq, so an anchor ahead of the bucket read as a missing segment past the
// chain's end), and a segment disposed between the listing and its read ends the window instead of
// failing it — unless it was removed while still locked.
func TestResweep_BoundedByTheListedChain(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := chainStore(t, 20, now.Add(-3*day), day)
	c := chainCheck{ctx: context.Background(), st: f, now: now, retention: day}
	perKey, _ := f.listVersions(context.Background())
	msg, ok, next := resweepWindow(c, perKey, 0, 16067, 0, 2000)
	if !ok || !strings.Contains(msg, "re-derived seq 0..19") || next != 0 {
		t.Errorf("a head past the listing: %q ok=%v next=%d, want 0..19 and a wrap to 0", msg, ok, next)
	}

	delete(f.data, segmentKey(7)+"@v1") // disposed after the listing: its lock had lapsed
	msg, ok, next = resweepWindow(c, perKey, 0, 19, 0, 2000)
	if !ok || !strings.Contains(msg, "re-derived seq 0..6") || next != 8 {
		t.Errorf("disposed during the sweep: %q ok=%v next=%d, want 0..6 then 8", msg, ok, next)
	}

	f = chainStore(t, 20, now.Add(-6*time.Hour), day) // still locked
	c.st = f
	perKey, _ = f.listVersions(context.Background())
	delete(f.data, segmentKey(7)+"@v1")
	if _, ok, _ := resweepWindow(c, perKey, 0, 19, 0, 2000); ok {
		t.Error("a still-locked segment gone during the sweep is not disposal")
	}
}

// The shipper resumes from the highest segment whose original exists, and refuses rather than fork or
// silently restart the chain when keys exist whose originals are gone at or beyond that point.
func TestChainHeadKey(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if k, err := chainHeadKey(map[string][]minio.ObjectInfo{}); k != "" || err != nil {
		t.Errorf("an empty bucket starts a chain: %q %v", k, err)
	}
	f := chainStore(t, 10, now.Add(-3*day), day)
	f.marker(0, f.written[0].Add(day))
	f.removeOriginal(0) // an old, disposed segment: its lone marker below the head is fine
	if k, err := chainHeadKey(f.versions); k != segmentKey(9) || err != nil {
		t.Errorf("resume from the head: %q %v", k, err)
	}

	f.marker(8, f.written[8].Add(day))
	f.marker(9, f.written[9].Add(day))
	f.removeOriginal(8)
	f.removeOriginal(9) // the newest originals gone: resuming at 7 would re-use 8 and 9
	if _, err := chainHeadKey(f.versions); err == nil || !strings.Contains(err.Error(), "fork") {
		t.Errorf("newest originals gone: want a refusal, got %v", err)
	}
	for i := 1; i < 8; i++ {
		f.marker(i, f.written[i].Add(day))
		f.removeOriginal(i) // every original gone, the markers left
	}
	if _, err := chainHeadKey(f.versions); err == nil || !strings.Contains(err.Error(), "Refusing to start a new chain at 0") {
		t.Errorf("only markers left: want a refusal, got %v", err)
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
