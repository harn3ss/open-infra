// Command audit-offsite ships the k3s API-server audit log to a WORM object store as a
// hash-chained sequence of segments, and verifies that chain — the tamper-evident,
// off-site half of audit-record protection (NIST SP 800-53 AU-9, AU-9(2), AU-9(3), AU-11).
//
// It reads the audit log at its SOURCE (the file on the control-plane node), not from Loki, so
// off-siting does not depend on the integrity of the in-cluster log store: an attacker who wipes
// Loki cannot stop, or retroactively alter, what has already been shipped off.
//
//	audit-offsite ship    — resume from the BUCKET HEAD (the WORM record of truth), read new
//	                        audit-log lines, forge the next chain segment, and write it under
//	                        COMPLIANCE object lock (and, if configured, an off-site bucket).
//	audit-offsite verify  — read every segment's LOCKED ORIGINAL version back, re-verify the whole
//	                        chain from its contents alone, cross-check the head against an anchor
//	                        held in a different trust domain (a Kubernetes ConfigMap), and publish
//	                        the result for the console. Exits non-zero if anything is off.
//
// Threat model note. COMPLIANCE Object Lock makes a specific object VERSION undeletable and
// un-shortenable — but S3 versioning still lets a bucket-writer lay down a NEWER version (or a
// delete marker) that shadows the locked original at the "latest" layer. So:
//   - ship resumes from the bucket head, never a mutable side cursor, so a crash can't fork the chain;
//   - verify reads each segment's OLDEST (locked) version, and counts any content-differing newer
//     version, or a delete marker laid while the original was locked, as a tamper attempt — a
//     latest-version read would be fooled. A delete marker laid after the lock lapsed, and a segment
//     removed after its retention, are retain-then-dispose (a lifecycle rule), reported separately;
//   - the head (seq+hash) is anchored in a Kubernetes ConfigMap, a different trust domain than the
//     bucket, so forging the record undetectably would require compromising BOTH. The strongest
//     anchor is the optional external off-site bucket (AU-9(2)).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/auditchain"
)

const (
	segmentPrefix   = "segments/"
	statusKey       = "status/latest.json"
	anchorConfigMap = "audit-offsite-anchor"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "audit-offsite: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: audit-offsite ship|verify")
	}
	switch os.Args[1] {
	case "ship":
		ship()
	case "verify":
		if !verify() {
			os.Exit(2) // chain broken or shadowed — make the CronJob go red so it can alert
		}
	default:
		fatalf("unknown subcommand %q (want ship|verify)", os.Args[1])
	}
}

// ── object-store clients ─────────────────────────────────────────────────────────

func minioClient(endpointEnv, akEnv, skEnv, secureEnv string) (*minio.Client, error) {
	endpoint := os.Getenv(endpointEnv)
	if endpoint == "" {
		return nil, fmt.Errorf("%s not set", endpointEnv)
	}
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv(akEnv), os.Getenv(skEnv), ""),
		Secure: os.Getenv(secureEnv) == "true",
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpointEnv, err)
	}
	return cl, nil
}

func primaryClient() (*minio.Client, string) {
	cl, err := minioClient("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_SECURE")
	if err != nil {
		fatalf("primary object store: %v", err)
	}
	return cl, getenv("AUDIT_BUCKET", "openinfra-audit")
}

// offsiteClient is an optional second sink on a separate system (AU-9(2)); it returns (nil, "")
// when OFFSITE_ENDPOINT is unset.
func offsiteClient() (*minio.Client, string) {
	if os.Getenv("OFFSITE_ENDPOINT") == "" {
		return nil, ""
	}
	cl, err := minioClient("OFFSITE_ENDPOINT", "OFFSITE_ACCESS_KEY", "OFFSITE_SECRET_KEY", "OFFSITE_SECURE")
	if err != nil {
		fatalf("off-site object store: %v", err)
	}
	return cl, getenv("OFFSITE_BUCKET", "openinfra-audit")
}

func retentionDays() int {
	n, err := strconv.Atoi(getenv("RETENTION_DAYS", "2555")) // ~7 years, a common AU-11 floor
	if err != nil || n <= 0 {
		return 2555
	}
	return n
}

// putSegment writes one segment under COMPLIANCE object lock, so its version cannot be deleted or
// have its retention shortened (even by root) until retention expires. Content-MD5 is required for
// a locked PUT.
func putSegment(ctx context.Context, cl *minio.Client, bucket, key string, blob []byte) error {
	_, err := cl.PutObject(ctx, bucket, key, bytes.NewReader(blob), int64(len(blob)), minio.PutObjectOptions{
		ContentType:     "application/json",
		Mode:            minio.Compliance,
		RetainUntilDate: time.Now().Add(time.Duration(retentionDays()) * 24 * time.Hour),
		SendContentMd5:  true,
	})
	return err
}

func segmentKey(seq int) string { return fmt.Sprintf("%s%012d.json", segmentPrefix, seq) }

// ── reading the bucket (the WORM record of truth) ────────────────────────────────

// oldestReal returns the earliest non-delete-marker version among a key's versions — the immutable,
// object-locked original. Nobody can create a version older than it, and COMPLIANCE keeps it from
// being deleted, so it is the authoritative content regardless of any newer shadowing versions.
func oldestReal(versions []minio.ObjectInfo) *minio.ObjectInfo {
	sort.Slice(versions, func(i, j int) bool { return versions[i].LastModified.Before(versions[j].LastModified) })
	for i := range versions {
		if !versions[i].IsDeleteMarker {
			return &versions[i]
		}
	}
	return nil
}

func getVersion(ctx context.Context, cl *minio.Client, bucket, key, versionID string) ([]byte, error) {
	rc, err := cl.GetObject(ctx, bucket, key, minio.GetObjectOptions{VersionID: versionID})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

// bucketHead returns the highest-sequence segment (its locked original), or nil if the chain is
// empty. The shipper resumes from this, not from any mutable side state.
func bucketHead(ctx context.Context, cl *minio.Client, bucket string) *auditchain.Segment {
	perKey := map[string][]minio.ObjectInfo{}
	for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: segmentPrefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			fatalf("list bucket head: %v", obj.Err)
		}
		perKey[obj.Key] = append(perKey[obj.Key], obj)
	}
	best := ""
	for key, vs := range perKey {
		if oldestReal(vs) != nil && key > best {
			best = key // keys are zero-padded, so lexicographic max == highest seq
		}
	}
	if best == "" {
		return nil
	}
	orig := oldestReal(perKey[best])
	data, err := getVersion(ctx, cl, bucket, best, orig.VersionID)
	if err != nil {
		fatalf("get bucket head %s: %v", best, err)
	}
	var s auditchain.Segment
	if err := json.Unmarshal(data, &s); err != nil {
		fatalf("parse bucket head %s: %v", best, err)
	}
	return &s
}

// ── ship ─────────────────────────────────────────────────────────────────────────

func fileInode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func ship() {
	ctx := context.Background()
	pcl, pbucket := primaryClient()

	// Resume from the bucket head — the WORM record of truth — so a crash between the object write
	// and anything else can never fork the chain (the next run just continues from what actually
	// landed). No mutable side cursor is trusted.
	head := bucketHead(ctx, pcl, pbucket)
	var prev *auditchain.Segment
	resumeOffset := int64(0)
	var prevInode uint64
	if head != nil {
		prev = head
		resumeOffset = head.EndOffset
		prevInode = head.SourceInode
	}

	path := getenv("AUDIT_LOG_PATH", "/var/lib/rancher/k3s/server/logs/audit.log")
	f, err := os.Open(path)
	if err != nil {
		fatalf("open audit log %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		fatalf("stat audit log: %v", err)
	}
	curInode := fileInode(fi)

	// Rotation handling by file IDENTITY, not size: k3s rotates by rename + fresh file, and the
	// fresh file can grow PAST our old offset before the next run — a size-only check would then
	// seek into the middle of a different file and silently skip records. If the inode changed,
	// start the new file at 0. (A shrink is the belt-and-suspenders fallback.)
	if prev != nil && prevInode != 0 && curInode != prevInode {
		fmt.Fprintf(os.Stderr, "audit-offsite: log rotated (inode %d→%d), restarting at 0 (bounded coverage gap)\n", prevInode, curInode)
		resumeOffset = 0
	} else if fi.Size() < resumeOffset {
		fmt.Fprintf(os.Stderr, "audit-offsite: log shrank (size %d < offset %d), restarting at 0\n", fi.Size(), resumeOffset)
		resumeOffset = 0
	}

	// Ship in bounded segments: a segment's bytes are held a few times over (the raw lines, their strings,
	// the segment's JSON), so reading the whole unshipped log at once — a large log after a rotation
	// restarts it at 0 — got the job OOM-killed and it never caught up. A run ships as many bounded
	// segments as it takes, each chained to the one before.
	maxBytes, hardMax := segmentBytes(), int64(256<<20)
	shipped := 0
	ocl, obucket := offsiteClient()
	for {
		// Only COMPLETE lines: up to and including the last newline. A trailing partial line waits until
		// it is finished, so a segment never contains half a record.
		lines, consumed, err := readSegment(f, resumeOffset, maxBytes, hardMax)
		if err != nil {
			fatalf("read: %v", err)
		}
		if consumed == 0 {
			break
		}
		if len(lines) == 0 { // only blank lines: carried into the next segment's EndOffset
			resumeOffset += consumed
			continue
		}
		seg := auditchain.BuildSegment(prev, lines, tsOf(lines[0]), tsOf(lines[len(lines)-1]))
		seg.EndOffset = resumeOffset + consumed
		seg.SourceInode = curInode
		blob, err := json.Marshal(seg)
		if err != nil {
			fatalf("marshal segment: %v", err)
		}
		key := segmentKey(seg.Seq)

		// Write to every configured sink. Because resume is derived from the bucket head, a crash after
		// this PUT (before the off-site copy, or before the process exits) simply re-derives the SAME
		// next segment next run — no fork.
		if err := putSegment(ctx, pcl, pbucket, key, blob); err != nil {
			fatalf("put segment to primary: %v", err)
		}
		if ocl != nil {
			if err := putSegment(ctx, ocl, obucket, key, blob); err != nil {
				fatalf("put segment to off-site: %v", err)
			}
		}
		fmt.Printf("shipped segment seq=%d records=%d endOffset=%d head=%s\n", seg.Seq, seg.Count, seg.EndOffset, seg.Hash[:12])
		prev, resumeOffset = &seg, seg.EndOffset
		shipped++
	}
	if shipped == 0 {
		fmt.Fprintln(os.Stderr, "audit-offsite: no complete new line to ship")
	}
}

// segmentBytes is how much of the log one segment carries at most (SEGMENT_MAX_BYTES, default 16 MiB).
func segmentBytes() int64 {
	if v, err := strconv.ParseInt(getenv("SEGMENT_MAX_BYTES", ""), 10, 64); err == nil && v > 0 {
		return v
	}
	return 16 << 20
}

// readSegment reads at most max bytes of r from off and returns the complete lines in them (up to and
// including the last newline; blank lines dropped) and how many bytes those span. A line longer than
// max is read through to its end, up to hardMax (beyond that it is an error, not a silent skip). consumed
// is 0 when no complete line follows off yet.
func readSegment(r io.ReaderAt, off, max, hardMax int64) ([]string, int64, error) {
	for want := max; ; want *= 2 {
		if want > hardMax {
			want = hardMax
		}
		b := make([]byte, want)
		n, err := r.ReadAt(b, off)
		if err != nil && err != io.EOF {
			return nil, 0, err
		}
		b = b[:n]
		if nl := bytes.LastIndexByte(b, '\n'); nl >= 0 {
			var lines []string
			for _, l := range bytes.Split(b[:nl+1], []byte{'\n'}) {
				if len(bytes.TrimSpace(l)) > 0 {
					lines = append(lines, string(l))
				}
			}
			return lines, int64(nl + 1), nil
		}
		if int64(n) < want { // the end of the file, inside an unfinished line
			return nil, 0, nil
		}
		if want == hardMax {
			return nil, 0, fmt.Errorf("an audit record longer than %d bytes at offset %d", hardMax, off)
		}
	}
}

// tsOf best-effort extracts an audit line's requestReceivedTimestamp for the segment's
// first/last markers. These are informational only — never trusted by Verify.
func tsOf(line string) string {
	var e struct {
		TS string `json:"requestReceivedTimestamp"`
	}
	_ = json.Unmarshal([]byte(line), &e)
	return e.TS
}

// ── verify ───────────────────────────────────────────────────────────────────────

type statusReport struct {
	Result auditchain.VerifyResult `json:"result"` // hash-chain integrity of the authoritative (locked) segments
	// Object-lock shadowing attempts: COMPLIANCE lock keeps each segment's original version, but
	// versioning still lets someone add a newer version or a delete marker that shadows it. We read
	// through to the locked original and count any delete marker or content-differing newer version
	// as a tamper attempt (a benign byte-identical re-ship is not counted).
	ShadowVersions int `json:"shadowVersions"`
	// Retain-then-dispose, reported apart from tampering: segments before the retained chain (disposed,
	// or being disposed, after their retention lapsed), and the delete markers lifecycle expiry laid on
	// segments after their lock lapsed. Neither counts against Intact.
	DisposedSegments int `json:"disposedSegments"`
	DisposalMarkers  int `json:"disposalMarkers"`
	// Anchor cross-check against a Kubernetes ConfigMap (a different trust domain than the bucket):
	// "ok" | "new" | "regressed" | "rewritten" | "unavailable".
	Anchor string `json:"anchor"`
	// Intact = chain verifies AND nothing shadows the originals AND the anchor agrees. This — not
	// Result.OK alone — is what the console should trust.
	Intact     bool   `json:"intact"`
	HeadSeq    int    `json:"headSeq"`
	HeadHash   string `json:"headHash"`
	VerifiedAt string `json:"verifiedAt"`
	Bucket     string `json:"bucket"`
	// Resweep reports the rotating prefix re-derivation (mode=rotating, #294): "" when not rotating,
	// else "ok seq A..B (cursor->C)" or a tamper reason. A non-ok resweep makes the run NOT Intact.
	Resweep string `json:"resweep,omitempty"`
}

// readAnchor reads the external head anchor (a different trust domain than the bucket). Returns ok=false
// when no valid anchor exists yet (first run) — incremental verification falls back to full then.
func readAnchor(ctx context.Context) (anchorState, bool) {
	cs, ns := k8sClient()
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, anchorConfigMap, metav1.GetOptions{})
	if err != nil {
		return anchorState{}, false
	}
	var a anchorState
	if json.Unmarshal([]byte(cm.Data["anchor.json"]), &a) != nil || a.HeadHash == "" {
		return anchorState{}, false
	}
	return a, true
}

// seqFromKey extracts a segment's Seq from its object key (segments/<012d>.json) without a GET, so the
// incremental path can decide "already-verified prefix vs new" from the listing alone.
func seqFromKey(key string) (int, bool) {
	if !strings.HasPrefix(key, segmentPrefix) || !strings.HasSuffix(key, ".json") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(key, segmentPrefix), ".json"))
	if err != nil {
		return 0, false
	}
	return n, true
}

// lockSkew absorbs clock skew between the shipper, which computes a segment's retain-until, and the
// object store, which stamps versions and lays lifecycle delete markers.
const lockSkew = time.Hour

// segStore is what verification reads from the bucket: minioStore for the real one, a fake in tests.
type segStore interface {
	listVersions(ctx context.Context) (map[string][]minio.ObjectInfo, error)
	getVersion(ctx context.Context, key, versionID string) ([]byte, error)
	// retainUntil is a version's COMPLIANCE retain-until date; ok=false when it cannot be read.
	retainUntil(ctx context.Context, key, versionID string) (time.Time, bool)
}

type minioStore struct {
	cl     *minio.Client
	bucket string
}

func (m minioStore) listVersions(ctx context.Context) (map[string][]minio.ObjectInfo, error) {
	perKey := map[string][]minio.ObjectInfo{}
	for obj := range m.cl.ListObjects(ctx, m.bucket, minio.ListObjectsOptions{Prefix: segmentPrefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		perKey[obj.Key] = append(perKey[obj.Key], obj)
	}
	return perKey, nil
}

func (m minioStore) getVersion(ctx context.Context, key, versionID string) ([]byte, error) {
	return getVersion(ctx, m.cl, m.bucket, key, versionID)
}

func (m minioStore) retainUntil(ctx context.Context, key, versionID string) (time.Time, bool) {
	_, until, err := m.cl.GetObjectRetention(ctx, m.bucket, key, versionID)
	if err != nil || until == nil {
		return time.Time{}, false
	}
	return *until, true
}

// verifyOutcome is what one pass over the segments found.
type verifyOutcome struct {
	res   auditchain.VerifyResult
	heads []auditchain.Segment // Seq+Hash per verified segment, for the anchor cross-check
	// shadow counts object-lock shadowing attempts: a delete marker laid on a segment while its original
	// was still locked, or an extra version laid over it.
	shadow int
	// disposed counts the segments before the retained chain: retain-then-dispose has removed them, or is
	// removing them, after their retention lapsed. disposalMarkers counts the delete markers lifecycle
	// expiry laid on segments after their lock lapsed (the first step of that disposal).
	disposed        int
	disposalMarkers int
	retainedFrom    int // Seq of the oldest segment of the retained chain
	perKey          map[string][]minio.ObjectInfo
}

type chainCheck struct {
	ctx       context.Context
	st        segStore
	now       time.Time
	retention time.Duration // the configured retention: the fallback when a version's retain-until can't be read
}

// lapsedBy reports whether a segment version's lock had lapsed by t: its retain-until as the store
// reports it, or, when that can't be read, its write time plus the configured retention.
func (c chainCheck) lapsedBy(key string, v minio.ObjectInfo, t time.Time) bool {
	until, ok := c.st.retainUntil(c.ctx, key, v.VersionID)
	if !ok {
		until = v.LastModified.Add(c.retention)
	}
	return !t.Add(lockSkew).Before(until)
}

// classifyMarkers sorts the delete markers on a segment whose original exists. A marker laid after the
// original's lock lapsed is disposal (lifecycle expiry); one laid while it was locked is a shadowing
// attempt, and stays one after the lock lapses.
func (c chainCheck) classifyMarkers(out *verifyOutcome, key string, versions []minio.ObjectInfo, orig *minio.ObjectInfo) {
	for _, v := range versions {
		if !v.IsDeleteMarker {
			continue
		}
		if c.lapsedBy(key, *orig, v.LastModified) {
			out.disposalMarkers++
		} else {
			out.shadow++
		}
	}
}

// pushSegment re-derives one segment from its locked original into the chain, and counts any extra
// version whose content differs from it (a byte-identical re-ship is benign).
func (c chainCheck) pushSegment(out *verifyOutcome, sv *auditchain.StreamVerifier, key string, versions []minio.ObjectInfo, orig *minio.ObjectInfo) error {
	origData, err := c.st.getVersion(c.ctx, key, orig.VersionID)
	if err != nil {
		return fmt.Errorf("get %s (original version): %w", key, err)
	}
	var s auditchain.Segment
	if err := json.Unmarshal(origData, &s); err != nil {
		return fmt.Errorf("parse %s: %w", key, err)
	}
	sv.Push(s)
	out.heads = append(out.heads, auditchain.Segment{Seq: s.Seq, Hash: s.Hash})
	for _, v := range versions {
		if v.IsDeleteMarker || v.VersionID == orig.VersionID {
			continue
		}
		d, err := c.st.getVersion(c.ctx, key, v.VersionID)
		if err != nil {
			return fmt.Errorf("get %s (shadow version %s): %w", key, v.VersionID, err)
		}
		if !bytes.Equal(d, origData) {
			out.shadow++
		}
	}
	return nil
}

// verifySegments checks the chain and its object-lock state. With an anchor (incremental and rotating
// modes) it trusts the anchored, locked prefix and re-derives only the segments after it; without one
// it re-derives every retained segment from its contents.
//
// Retain-then-dispose (a lifecycle rule) removes a segment's original only once its lock has lapsed —
// Object Lock refuses it any earlier — oldest first, though not strictly in order. So a missing
// segment is disposal only when the segment after it is itself past retention: written later, its lock
// lapses later, so the missing one had certainly lapsed. The retained chain starts after the highest
// missing segment; if the segment after it is still locked, the missing one is a gap (removed, not
// disposed) and the chain fails.
func verifySegments(ctx context.Context, st segStore, now time.Time, retention time.Duration, anchor *anchorState) (verifyOutcome, error) {
	c := chainCheck{ctx: ctx, st: st, now: now, retention: retention}
	perKey, err := st.listVersions(ctx)
	if err != nil {
		return verifyOutcome{}, fmt.Errorf("list segment versions: %w", err)
	}
	out := verifyOutcome{perKey: perKey}
	keys := make([]string, 0, len(perKey))
	for k := range perKey {
		keys = append(keys, k)
	}
	sort.Strings(keys) // segments/%012d.json: a lexical sort IS a Seq sort

	present := map[int]string{} // Seq -> key, for segments whose original exists
	maxReal := -1
	for _, k := range keys {
		if seq, ok := seqFromKey(k); ok && oldestReal(perKey[k]) != nil {
			present[seq] = k
			if seq > maxReal {
				maxReal = seq
			}
		}
	}
	gap := -1
	for seq := maxReal - 1; seq >= 0; seq-- {
		if _, ok := present[seq]; !ok {
			out.retainedFrom = seq + 1
			next := present[seq+1]
			if !c.lapsedBy(next, *oldestReal(perKey[next]), now) {
				gap = seq
			}
			break
		}
	}
	out.disposed = out.retainedFrom

	for _, key := range keys {
		seq, ok := seqFromKey(key)
		if !ok {
			continue
		}
		versions := perKey[key]
		orig := oldestReal(versions)
		switch {
		case seq < out.retainedFrom && gap < 0 && orig == nil:
			// Disposed: its original is gone, which Object Lock allows only after its retain-until. The
			// markers left on it are disposal. (A segment still present below the retained chain is
			// classified like any other: it may be locked longer than later ones, if retention was lowered.)
			out.disposalMarkers += countMarkers(versions)
		case orig == nil:
			out.shadow++ // only delete markers, and not a disposed segment: the original is shadowed
		default:
			c.classifyMarkers(&out, key, versions, orig)
		}
	}

	var sv *auditchain.StreamVerifier
	verifiedSeq := -1
	if anchor != nil && anchor.HeadSeq >= out.retainedFrom {
		// Seed with the trusted anchor so checkAndUpdateAnchor cross-checks the new head against it.
		verifiedSeq = anchor.HeadSeq
		sv = auditchain.NewStreamVerifierFrom(anchor.HeadSeq, anchor.HeadHash)
		out.heads = append(out.heads, auditchain.Segment{Seq: anchor.HeadSeq, Hash: anchor.HeadHash})
	} else {
		// No anchor, or the anchored head itself has been disposed: re-derive the retained chain.
		sv = &auditchain.StreamVerifier{}
	}
	for _, key := range keys {
		seq, ok := seqFromKey(key)
		if !ok || seq < out.retainedFrom || seq > maxReal {
			continue
		}
		versions := perKey[key]
		if seq <= verifiedSeq {
			// Already-verified, WORM-locked prefix: skip the GET + chain re-derivation, but any extra real
			// version on it is a bypass ATTEMPT (its markers were classified above).
			if n := len(versions) - countMarkers(versions); n > 1 {
				out.shadow += n - 1
			}
			continue
		}
		if err := c.pushSegment(&out, sv, key, versions, oldestReal(versions)); err != nil {
			return out, err
		}
	}

	// Catch up to the current tip. A full pass can take tens of minutes, during which new segments arrive
	// (the hourly incremental advances the external anchor meanwhile) — so a slow full verify would finish
	// behind a head it simply had not listed yet and read as "regressed" against the anchor (a false alarm,
	// not a tamper). Re-list and verify (from contents, trust-nothing) any segment beyond our head until
	// converged, so the anchor cross-check is tip-vs-tip. Append-only growth converges in a round or two;
	// bounded as a backstop against pathological churn.
	for round := 0; round < 8; round++ {
		curHead := sv.Result().HeadSeq
		fresh, err := st.listVersions(ctx)
		if err != nil {
			return out, fmt.Errorf("re-list segment versions (catch-up): %w", err)
		}
		var newKeys []string
		for k := range fresh {
			if seq, ok := seqFromKey(k); ok && seq > curHead && seq > maxReal {
				newKeys = append(newKeys, k)
			}
		}
		if len(newKeys) == 0 {
			break
		}
		sort.Strings(newKeys)
		for _, key := range newKeys {
			orig := oldestReal(fresh[key])
			if orig == nil {
				out.shadow++
				continue
			}
			c.classifyMarkers(&out, key, fresh[key], orig)
			if err := c.pushSegment(&out, sv, key, fresh[key], orig); err != nil {
				return out, err
			}
			out.perKey[key] = fresh[key]
		}
		if seq, ok := seqFromKey(newKeys[len(newKeys)-1]); ok && seq > maxReal {
			maxReal = seq
		}
	}

	out.res = sv.Result()
	if gap >= 0 {
		g := gap
		out.res.OK = false
		out.res.BrokenAt = &g
		out.res.Reason = fmt.Sprintf("segment %d is missing while segment %d after it is still under retention: a gap in the retained chain (removed, not disposed)", gap, gap+1)
	} else if out.shadow > 0 && out.res.OK {
		out.res.Reason = fmt.Sprintf("%d object-lock shadowing attempt(s) detected (overwrite/delete-marker on locked segments)", out.shadow)
	}
	return out, nil
}

func countMarkers(versions []minio.ObjectInfo) int {
	n := 0
	for _, v := range versions {
		if v.IsDeleteMarker {
			n++
		}
	}
	return n
}

func verify() bool {
	ctx := context.Background()
	cl, bucket := primaryClient()
	st := minioStore{cl: cl, bucket: bucket}

	// Full (default) re-derives every retained segment from its locked contents, trusting nothing.
	// Incremental (AUDIT_VERIFY_MODE=incremental) trusts the external anchor for the already-verified prefix
	// and only re-GETs + chain-verifies segments NEWER than it — O(new) instead of O(chain) — while still
	// checking the WORM-locked prefix cheaply from the version LIST (a delete-marker laid while a segment was
	// locked, or any extra version on it, is a lock-bypass attempt, visible without a GET). PAIR it with a
	// periodic FULL or rotating run so a prefix content-tamper is still re-derived from contents.
	// "rotating" (the durable anti-treadmill mode, #294) behaves like "incremental" for the head/anchor
	// (O(new) GETs), but ALSO re-derives a bounded WINDOW of the already-locked prefix from contents each
	// run — a rotating cursor sweeps the whole chain over N runs.
	mode := getenv("AUDIT_VERIFY_MODE", "full")
	var anchor *anchorState
	if mode == "incremental" || mode == "rotating" {
		if a, ok := readAnchor(ctx); ok {
			anchor = &a
		} else {
			fmt.Fprintln(os.Stderr, "audit-offsite: "+mode+" requested but no anchor yet — doing a full verify")
		}
	}
	out, err := verifySegments(ctx, st, time.Now(), time.Duration(retentionDays())*24*time.Hour, anchor)
	if err != nil {
		fatalf("%v", err)
	}
	res := out.res

	anchorStatus := checkAndUpdateAnchor(ctx, out.heads, res)

	// Rotating mode (#294): re-derive a bounded window of the locked prefix from contents, advancing a
	// persisted cursor so the whole chain is content-re-verified over successive runs at fixed per-run
	// cost. A tamper found in the swept window makes the run NOT Intact (same weight as the main chain).
	resweep, resweepOK := "", true
	if mode == "rotating" {
		resweep, resweepOK = resweepPrefix(ctx, st, out.perKey, out.retainedFrom, res.HeadSeq)
	}

	report := statusReport{
		Result:           res,
		ShadowVersions:   out.shadow,
		DisposedSegments: out.disposed,
		DisposalMarkers:  out.disposalMarkers,
		Anchor:           anchorStatus,
		Intact:           res.OK && out.shadow == 0 && (anchorStatus == "ok" || anchorStatus == "new") && resweepOK,
		HeadSeq:          res.HeadSeq,
		HeadHash:         res.HeadHash,
		VerifiedAt:       time.Now().UTC().Format(time.RFC3339),
		Bucket:           bucket,
		Resweep:          resweep,
	}
	blob, _ := json.MarshalIndent(report, "", "  ")

	// Publish the result WITHOUT object lock (a mutable cache for the console). It is NOT trusted on
	// its own: the console cross-checks its headHash against the ConfigMap anchor below.
	if _, err := cl.PutObject(ctx, bucket, statusKey, bytes.NewReader(blob), int64(len(blob)),
		minio.PutObjectOptions{ContentType: "application/json"}); err != nil {
		fmt.Fprintf(os.Stderr, "audit-offsite: publish status: %v\n", err)
	}

	fmt.Println(string(blob))
	return report.Intact
}

// ── the head anchor (a different trust domain than the bucket) ────────────────────

type anchorState struct {
	HeadSeq    int    `json:"headSeq"`
	HeadHash   string `json:"headHash"`
	VerifiedAt string `json:"verifiedAt"`
}

func k8sClient() (kubernetes.Interface, string) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		fatalf("in-cluster config: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fatalf("kube client: %v", err)
	}
	return cs, getenv("STATE_NAMESPACE", "monitoring")
}

// checkAndUpdateAnchor compares the freshly verified head against the last one recorded in a
// Kubernetes ConfigMap, then advances it. Because the ConfigMap lives in a different trust domain
// than the object bucket, an attacker who controls only the bucket cannot make the two agree:
//   - "regressed": the head sequence went BACKWARD — impossible in normal growth (tamper / DoS).
//   - "rewritten": the segment at the previously anchored sequence no longer has the anchored hash
//     (history below the last anchor was changed) — unless it aged out past retention (legit).
//   - "ok"/"new": consistent; the anchor is advanced to the current head.
func checkAndUpdateAnchor(ctx context.Context, segs []auditchain.Segment, res auditchain.VerifyResult) string {
	cs, ns := k8sClient()
	hashBySeq := map[int]string{}
	baseSeq := 1 << 30
	for _, s := range segs {
		hashBySeq[s.Seq] = s.Hash
		if s.Seq < baseSeq {
			baseSeq = s.Seq
		}
	}

	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, anchorConfigMap, metav1.GetOptions{})
	prior := anchorState{}
	have := false
	if err == nil {
		if e := json.Unmarshal([]byte(cm.Data["anchor.json"]), &prior); e == nil && prior.HeadHash != "" {
			have = true
		}
	} else if !apierrors.IsNotFound(err) {
		fmt.Fprintf(os.Stderr, "audit-offsite: read anchor: %v\n", err)
		return "unavailable"
	}

	status := "new"
	if have {
		switch {
		case res.HeadSeq < prior.HeadSeq:
			status = "regressed"
		case prior.HeadSeq < baseSeq:
			status = "ok" // the previously anchored head aged out past retention — legitimate
		case hashBySeq[prior.HeadSeq] != "" && hashBySeq[prior.HeadSeq] != prior.HeadHash:
			status = "rewritten"
		default:
			status = "ok"
		}
	}

	// Advance the anchor to the current head only when nothing looks wrong; on regressed/rewritten,
	// leave the prior anchor in place so the alarm persists until an operator resolves it.
	if status == "ok" || status == "new" {
		next := anchorState{HeadSeq: res.HeadSeq, HeadHash: res.HeadHash, VerifiedAt: time.Now().UTC().Format(time.RFC3339)}
		blob, _ := json.Marshal(next)
		target := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: anchorConfigMap, Namespace: ns},
			Data:       map[string]string{"anchor.json": string(blob)},
		}
		_, uerr := cs.CoreV1().ConfigMaps(ns).Update(ctx, target, metav1.UpdateOptions{})
		if apierrors.IsNotFound(uerr) {
			_, uerr = cs.CoreV1().ConfigMaps(ns).Create(ctx, target, metav1.CreateOptions{})
		}
		if uerr != nil {
			fmt.Fprintf(os.Stderr, "audit-offsite: update anchor: %v\n", uerr)
		}
	}
	return status
}

// ── the rotating prefix re-sweep (#294): bounded trust-nothing re-derivation ──────

const resweepConfigMap = "audit-offsite-resweep"

type resweepCursor struct {
	NextSeq int    `json:"nextSeq"`
	SweptAt string `json:"sweptAt"`
}

// readResweepCursor returns the persisted next-to-re-derive seq, or -1 if none yet (caller starts at base).
func readResweepCursor(ctx context.Context) int {
	cs, ns := k8sClient()
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, resweepConfigMap, metav1.GetOptions{})
	if err != nil {
		return -1
	}
	var c resweepCursor
	if json.Unmarshal([]byte(cm.Data["cursor.json"]), &c) != nil {
		return -1
	}
	return c.NextSeq
}

func writeResweepCursor(ctx context.Context, nextSeq int) {
	cs, ns := k8sClient()
	blob, _ := json.Marshal(resweepCursor{NextSeq: nextSeq, SweptAt: time.Now().UTC().Format(time.RFC3339)})
	target := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: resweepConfigMap, Namespace: ns},
		Data:       map[string]string{"cursor.json": string(blob)},
	}
	_, err := cs.CoreV1().ConfigMaps(ns).Update(ctx, target, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().ConfigMaps(ns).Create(ctx, target, metav1.CreateOptions{})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-offsite: update resweep cursor: %v\n", err)
	}
}

// resweepPrefix re-derives a bounded WINDOW of the locked prefix from its contents (trust-nothing), a
// front-truncated mini-verify, advancing a persisted cursor that wraps at the head — so over successive
// runs the whole chain's contents are re-verified at FIXED per-run cost (the #294 anti-treadmill). The
// window overlaps the previous one by one segment so every chain LINK is re-checked across windows too.
// A content-tamper or lock-shadow in the swept window returns ok=false (making the run not Intact).
// base is the oldest segment of the retained chain: those before it have been disposed.
func resweepPrefix(ctx context.Context, st segStore, perKey map[string][]minio.ObjectInfo, base, head int) (string, bool) {
	window := 2000
	if w, err := strconv.Atoi(getenv("AUDIT_RESWEEP_WINDOW", "2000")); err == nil && w > 0 {
		window = w
	}
	if len(perKey) == 0 || head < base {
		return "rotating: empty chain, nothing to re-sweep", true
	}
	cursor := readResweepCursor(ctx)
	if cursor < base || cursor > head {
		cursor = base // first run, or wrapped past the head / below retention
	}
	end := cursor + window - 1
	if end > head {
		end = head
	}
	lo := cursor - 1 // overlap the prior window by one so the cross-window LINK is re-verified
	if lo < base {
		lo = base
	}
	// Re-derive [lo..end] from their LOCKED ORIGINALS as a front-truncated sub-chain (trust-nothing).
	var sv auditchain.StreamVerifier
	for seq := lo; seq <= end; seq++ {
		key := segmentKey(seq)
		versions, ok := perKey[key]
		if !ok {
			return fmt.Sprintf("rotating: segment seq=%d missing in [%d..%d] (gap — chain truncated/tampered)", seq, lo, end), false
		}
		orig := oldestReal(versions)
		if orig == nil {
			return fmt.Sprintf("rotating: segment seq=%d is fully shadowed (no locked original)", seq), false
		}
		data, err := st.getVersion(ctx, key, orig.VersionID)
		if err != nil {
			return fmt.Sprintf("rotating: get seq=%d failed: %v", seq, err), false
		}
		var s auditchain.Segment
		if json.Unmarshal(data, &s) != nil {
			return fmt.Sprintf("rotating: parse seq=%d failed", seq), false
		}
		sv.Push(s)
	}
	if r := sv.Result(); !r.OK {
		return fmt.Sprintf("rotating: prefix re-sweep [%d..%d] FAILED: %s", lo, end, r.Reason), false
	}
	next := end + 1
	if next > head {
		next = base // wrap: one full rotation complete, start the prefix over
	}
	writeResweepCursor(ctx, next)
	return fmt.Sprintf("rotating: re-derived seq %d..%d (next cursor %d, window %d)", lo, end, next, window), true
}
