// Package auditchain is the tamper-evident core of audit off-siting.
//
// The authoritative "who did what" record is the k3s API-server audit log. On its own it
// lives on one node's disk and in Loki — both mutable, both deletable by whoever holds the
// cluster. Government audit-protection controls (NIST SP 800-53 AU-9, AU-9(2), AU-9(3),
// AU-10) want that record (a) copied to a separate system, (b) protected from modification,
// and (c) able to prove it wasn't altered. This package provides (c): the audit log is shipped
// off in SEGMENTS linked into a hash chain, so deleting, reordering, or editing any segment —
// or any record inside one — breaks the chain and is detectable on re-verification. Immutability
// itself (a, b) is provided by writing the segments to a WORM object store (MinIO Object Lock
// in COMPLIANCE mode) and optionally mirroring to an off-site bucket; see cmd/audit-offsite.
//
// This package is deliberately pure — no I/O, no clock — so the linking rules are unit-testable
// and identical in the exporter (cmd/audit-offsite) and the console's integrity check
// (cmd/server, /api/audit/integrity). Nothing here trusts any external state: Verify recomputes
// every hash from the segment contents, so a forged state cursor or a rewritten segment cannot
// make a broken chain look intact.
package auditchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// GenesisPrev is the PrevHash of the first segment (Seq 0): there is no predecessor.
const GenesisPrev = ""

// Segment is one shipped batch of raw audit-log lines, self-contained and independently
// verifiable. It carries the actual records (so the off-site copy IS the audit trail, not just
// a fingerprint of it) plus the hashes that link it into the chain.
type Segment struct {
	Seq         int      `json:"seq"`         // 0-based, contiguous across the whole chain
	PrevHash    string   `json:"prevHash"`    // Hash of segment Seq-1 (GenesisPrev for Seq 0)
	Count       int      `json:"count"`       // len(Records)
	FirstTS     string   `json:"firstTs"`     // timestamp of the first record (informational)
	LastTS      string   `json:"lastTs"`      // timestamp of the last record (informational)
	RecordsHash string   `json:"recordsHash"` // hash over Records (see HashRecords)
	Hash        string   `json:"hash"`        // the chain link: hash over all fields above
	Records     []string `json:"records"`     // the raw audit-log lines, verbatim
}

// HashRecords hashes a slice of records unambiguously: it hashes the hash of each record and
// folds those in order, so no concatenation of adjacent records can collide with a different
// split (a length-prefix-free join could). An empty slice hashes to the hash of no bytes, which
// is still a well-defined, verifiable value (empty segments are never shipped, but the function
// stays total).
func HashRecords(records []string) string {
	h := sha256.New()
	for _, r := range records {
		rh := sha256.Sum256([]byte(r))
		h.Write(rh[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// segmentHash computes the chain link over every field that must not change. The serialization
// is fixed and labeled so no two distinct field sets can produce the same preimage. Records are
// covered transitively via recordsHash, so editing a record changes recordsHash changes Hash.
func segmentHash(seq int, prevHash string, count int, firstTS, lastTS, recordsHash string) string {
	h := sha256.New()
	fmt.Fprintf(h, "seq:%d\n", seq)
	fmt.Fprintf(h, "prev:%s\n", prevHash)
	fmt.Fprintf(h, "count:%d\n", count)
	fmt.Fprintf(h, "first:%s\n", firstTS)
	fmt.Fprintf(h, "last:%s\n", lastTS)
	fmt.Fprintf(h, "records:%s\n", recordsHash)
	return hex.EncodeToString(h.Sum(nil))
}

// BuildSegment forges the next link. prev is the current chain head, or nil to start the chain
// at Seq 0. It fills RecordsHash and Hash; the caller supplies the records and their (best-effort)
// first/last timestamps.
func BuildSegment(prev *Segment, records []string, firstTS, lastTS string) Segment {
	seq := 0
	prevHash := GenesisPrev
	if prev != nil {
		seq = prev.Seq + 1
		prevHash = prev.Hash
	}
	rh := HashRecords(records)
	return Segment{
		Seq:         seq,
		PrevHash:    prevHash,
		Count:       len(records),
		FirstTS:     firstTS,
		LastTS:      lastTS,
		RecordsHash: rh,
		Hash:        segmentHash(seq, prevHash, len(records), firstTS, lastTS, rh),
		Records:     records,
	}
}

// VerifyResult reports the outcome of walking a chain.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Count    int    `json:"count"`              // number of segments examined
	BaseSeq  int    `json:"baseSeq"`            // Seq of the earliest present segment
	HeadSeq  int    `json:"headSeq"`            // Seq of the latest present segment
	HeadHash string `json:"headHash"`           // Hash of the head (the value to anchor externally)
	Records  int    `json:"records"`            // total records across all segments
	BrokenAt *int   `json:"brokenAt,omitempty"` // Seq where verification first failed, if any
	Reason   string `json:"reason,omitempty"`   // human-readable failure reason
}

// Verify walks the segments in Seq order and confirms the chain is intact:
//   - every segment's recomputed RecordsHash and Hash match what it claims (no record or field
//     was edited),
//   - Seq numbers are contiguous with no gap (no segment was removed from the middle),
//   - each segment's PrevHash equals the prior segment's Hash (no reorder / substitution),
//   - the earliest segment links to genesis only if it is Seq 0. A chain whose BaseSeq > 0 is
//     treated as validly front-truncated (old segments aged past their WORM retention and were
//     removed from the front) — legitimate, and distinguishable from tampering because the front
//     is contiguous and the caller can see BaseSeq > 0. A HOLE in the middle is never legitimate.
//
// Verify recomputes every hash from segment contents; it trusts nothing it is told. A caller that
// wants to detect front-truncation as an attack should compare BaseSeq/HeadSeq against an
// externally anchored expectation (e.g. the last HeadHash it recorded).
func Verify(segs []Segment) VerifyResult {
	if len(segs) == 0 {
		return VerifyResult{OK: true, Count: 0}
	}
	sorted := make([]Segment, len(segs))
	copy(sorted, segs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })

	res := VerifyResult{
		Count:   len(sorted),
		BaseSeq: sorted[0].Seq,
		HeadSeq: sorted[len(sorted)-1].Seq,
	}
	broke := func(seq int, reason string) VerifyResult {
		s := seq
		res.OK = false
		res.BrokenAt = &s
		res.Reason = reason
		return res
	}

	var prev *Segment
	for i := range sorted {
		s := sorted[i]
		res.Records += s.Count

		// (1) contents match their own hashes — catches an edited record or field.
		if HashRecords(s.Records) != s.RecordsHash {
			return broke(s.Seq, "records do not match recordsHash (a record was altered)")
		}
		if s.Count != len(s.Records) {
			return broke(s.Seq, "count does not match the number of records")
		}
		if segmentHash(s.Seq, s.PrevHash, s.Count, s.FirstTS, s.LastTS, s.RecordsHash) != s.Hash {
			return broke(s.Seq, "segment hash does not match its contents (a field was altered)")
		}

		if prev == nil {
			// The earliest present segment. If it claims to be the start of the chain it must
			// link to genesis; otherwise it is a front-truncated chain, which is allowed.
			if s.Seq == 0 && s.PrevHash != GenesisPrev {
				return broke(s.Seq, "first segment does not link to genesis")
			}
		} else {
			// (2) no gap, and (3) the link holds.
			if s.Seq != prev.Seq+1 {
				return broke(s.Seq, fmt.Sprintf("gap in sequence: expected %d, got %d (a segment is missing)", prev.Seq+1, s.Seq))
			}
			if s.PrevHash != prev.Hash {
				return broke(s.Seq, "prevHash does not match the prior segment (chain reordered or substituted)")
			}
		}
		prev = &sorted[i]
	}

	res.OK = true
	res.HeadHash = prev.Hash
	return res
}
