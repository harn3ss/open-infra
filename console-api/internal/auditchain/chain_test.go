package auditchain

import "testing"

// buildChain forges a valid n-segment chain, each with a couple of records.
func buildChain(t *testing.T, n int) []Segment {
	t.Helper()
	var segs []Segment
	var prev *Segment
	for i := 0; i < n; i++ {
		recs := []string{
			`{"verb":"create","objectRef":{"resource":"users","name":"alice"}}`,
			`{"verb":"delete","objectRef":{"resource":"grants","name":"jit-bob"}}`,
		}
		s := BuildSegment(prev, recs, "2026-08-10T00:00:00Z", "2026-08-10T00:04:59Z")
		segs = append(segs, s)
		prev = &segs[len(segs)-1]
	}
	return segs
}

func TestVerify_IntactChain(t *testing.T) {
	segs := buildChain(t, 5)
	r := Verify(segs)
	if !r.OK {
		t.Fatalf("intact chain reported broken: %+v", r)
	}
	if r.BaseSeq != 0 || r.HeadSeq != 4 || r.Count != 5 {
		t.Fatalf("wrong bounds: %+v", r)
	}
	if r.Records != 10 {
		t.Fatalf("expected 10 records, got %d", r.Records)
	}
	if r.HeadHash != segs[4].Hash {
		t.Fatalf("head hash mismatch")
	}
}

func TestStreamVerifier_MatchesVerify(t *testing.T) {
	segs := buildChain(t, 6)
	want := Verify(segs)

	var sv StreamVerifier
	for i := range segs {
		sv.Push(segs[i])
		segs[i].Records = nil // the verifier must retain nothing from the caller's slice after Push
	}
	got := sv.Result()

	if !got.OK || got.HeadSeq != want.HeadSeq || got.HeadHash != want.HeadHash ||
		got.Count != want.Count || got.Records != want.Records || got.BaseSeq != want.BaseSeq {
		t.Fatalf("stream result %+v does not match Verify %+v", got, want)
	}
}

func TestStreamVerifier_DetectsTamperMidChain(t *testing.T) {
	segs := buildChain(t, 5)
	segs[2].Records[0] = `{"verb":"create","objectRef":{"resource":"roles","name":"mallory-admin"}}`
	var sv StreamVerifier
	for _, s := range segs {
		sv.Push(s)
	}
	if r := sv.Result(); r.OK || r.BrokenAt == nil || *r.BrokenAt != 2 {
		t.Fatalf("stream verifier missed mid-chain tamper: %+v", r)
	}
}

func TestVerify_EmptyChain(t *testing.T) {
	if r := Verify(nil); !r.OK || r.Count != 0 {
		t.Fatalf("empty chain should verify: %+v", r)
	}
}

func TestVerify_OutOfOrderInputStillVerifies(t *testing.T) {
	segs := buildChain(t, 4)
	segs[0], segs[3] = segs[3], segs[0] // Verify sorts by Seq internally
	if r := Verify(segs); !r.OK {
		t.Fatalf("chain given out of order should still verify: %+v", r)
	}
}

func TestVerify_EditedRecordDetected(t *testing.T) {
	segs := buildChain(t, 3)
	// Tamper with a record in the middle segment WITHOUT touching the hashes.
	segs[1].Records[0] = `{"verb":"create","objectRef":{"resource":"users","name":"mallory"}}`
	r := Verify(segs)
	if r.OK {
		t.Fatal("edited record was not detected")
	}
	if r.BrokenAt == nil || *r.BrokenAt != 1 {
		t.Fatalf("expected break at seq 1, got %+v", r)
	}
}

func TestVerify_EditedRecordWithRecomputedRecordsHashStillDetected(t *testing.T) {
	segs := buildChain(t, 3)
	// A cleverer tamper: edit the record AND fix recordsHash to match, but leave Hash alone.
	segs[1].Records[0] = `{"verb":"create","objectRef":{"resource":"users","name":"mallory"}}`
	segs[1].RecordsHash = HashRecords(segs[1].Records)
	r := Verify(segs)
	if r.OK || r.BrokenAt == nil || *r.BrokenAt != 1 {
		t.Fatalf("edited record with fixed recordsHash should break at seq 1: %+v", r)
	}
}

func TestVerify_FullyReforgedSegmentBreaksTheLink(t *testing.T) {
	segs := buildChain(t, 3)
	// The most thorough single-segment forgery: rewrite the record and recompute BOTH the
	// record hash and the segment hash so the segment is internally consistent. This must still
	// fail, because segment 2's PrevHash still points at the ORIGINAL segment 1 hash.
	segs[1].Records[0] = `{"verb":"create","objectRef":{"resource":"roles","name":"mallory-admin"}}`
	segs[1].RecordsHash = HashRecords(segs[1].Records)
	segs[1].Hash = segmentHash(segs[1].Seq, segs[1].PrevHash, segs[1].Count, segs[1].FirstTS, segs[1].LastTS, segs[1].RecordsHash)
	r := Verify(segs)
	if r.OK {
		t.Fatal("reforged segment not detected — chain link should catch it at the next segment")
	}
	if r.BrokenAt == nil || *r.BrokenAt != 2 {
		t.Fatalf("expected break at seq 2 (the successor's PrevHash), got %+v", r)
	}
}

func TestVerify_DeletedMiddleSegmentDetected(t *testing.T) {
	segs := buildChain(t, 5)
	segs = append(segs[:2], segs[3:]...) // drop seq 2
	r := Verify(segs)
	if r.OK {
		t.Fatal("hole in the chain was not detected")
	}
	if r.BrokenAt == nil || *r.BrokenAt != 3 {
		t.Fatalf("expected break at seq 3 (the gap), got %+v", r)
	}
}

func TestVerify_ReorderedSegmentsDetected(t *testing.T) {
	segs := buildChain(t, 4)
	// Swap the Seq numbers of two adjacent segments (a genuine reorder, not just input order).
	segs[1].Seq, segs[2].Seq = segs[2].Seq, segs[1].Seq
	r := Verify(segs)
	if r.OK {
		t.Fatal("reordered chain was not detected")
	}
}

func TestVerify_FrontTruncationIsAllowed(t *testing.T) {
	// Old segments aged past WORM retention and were removed from the FRONT. This is legitimate:
	// the remaining chain is contiguous and internally linked; only BaseSeq > 0 reveals it.
	segs := buildChain(t, 5)
	remaining := segs[2:] // seq 2,3,4
	r := Verify(remaining)
	if !r.OK {
		t.Fatalf("front-truncated chain should verify: %+v", r)
	}
	if r.BaseSeq != 2 || r.HeadSeq != 4 {
		t.Fatalf("expected base 2 head 4, got %+v", r)
	}
}

func TestVerify_FirstSegmentMustLinkToGenesis(t *testing.T) {
	segs := buildChain(t, 2)
	segs[0].PrevHash = "deadbeef"
	// Recompute so the segment is internally consistent — only the genesis link is wrong.
	segs[0].Hash = segmentHash(segs[0].Seq, segs[0].PrevHash, segs[0].Count, segs[0].FirstTS, segs[0].LastTS, segs[0].RecordsHash)
	r := Verify(segs)
	if r.OK || r.BrokenAt == nil || *r.BrokenAt != 0 {
		t.Fatalf("seq-0 segment not linking to genesis should break at 0: %+v", r)
	}
}

func TestBuildSegment_LinksToPrev(t *testing.T) {
	s0 := BuildSegment(nil, []string{"a"}, "", "")
	if s0.Seq != 0 || s0.PrevHash != GenesisPrev {
		t.Fatalf("genesis segment malformed: %+v", s0)
	}
	s1 := BuildSegment(&s0, []string{"b"}, "", "")
	if s1.Seq != 1 || s1.PrevHash != s0.Hash {
		t.Fatalf("segment 1 does not link to segment 0: %+v", s1)
	}
}

// The operational resume fields (EndOffset/SourceInode) must NOT be part of the hash — they
// describe the shipper's position, not the audit evidence, and verification must not depend on them.
func TestVerify_OperationalFieldsDoNotAffectHash(t *testing.T) {
	segs := buildChain(t, 3)
	// Set resume metadata after the fact; the chain must still verify unchanged.
	for i := range segs {
		segs[i].EndOffset = int64(1000 * (i + 1))
		segs[i].SourceInode = 424242
	}
	if r := Verify(segs); !r.OK {
		t.Fatalf("resume metadata must not affect verification: %+v", r)
	}
	// And the segment hash is independent of them.
	s := segs[1]
	if s.Hash != segmentHash(s.Seq, s.PrevHash, s.Count, s.FirstTS, s.LastTS, s.RecordsHash) {
		t.Fatal("segment hash must be independent of EndOffset/SourceInode")
	}
}

func TestHashRecords_OrderAndSplitSensitive(t *testing.T) {
	// Different order → different hash.
	if HashRecords([]string{"a", "b"}) == HashRecords([]string{"b", "a"}) {
		t.Fatal("record order must affect the hash")
	}
	// Different split of the same concatenation → different hash (no framing ambiguity).
	if HashRecords([]string{"ab", "c"}) == HashRecords([]string{"a", "bc"}) {
		t.Fatal("record framing must be unambiguous")
	}
}
