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
	"path/filepath"
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
	best, err := chainHeadKey(perKey)
	if err != nil {
		fatalf("%v", err)
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

// chainHeadKey picks the segment the shipper resumes from — the highest-sequence segment whose
// original exists — from a versioned listing; "" means the bucket holds no segment at all (a new
// chain starts at 0). It refuses, rather than fork or silently restart the chain, when segment keys
// exist whose originals are gone at or beyond that point: when retain-then-dispose has removed every
// original (shipping stopped for longer than the retention plus the noncurrent expiry), or the newest
// segments' originals (disposed out of order, or shadowed). Resuming there would write a segment under
// a key the chain already used, or start a second chain at 0 under the first one's keys.
func chainHeadKey(perKey map[string][]minio.ObjectInfo) (string, error) {
	best, highest := "", ""
	for key, vs := range perKey {
		if _, ok := seqFromKey(key); !ok {
			continue
		}
		if key > highest {
			highest = key // keys are zero-padded, so lexicographic max == highest seq
		}
		if oldestReal(vs) != nil && key > best {
			best = key
		}
	}
	switch {
	case highest == "":
		return "", nil
	case best == "":
		return "", fmt.Errorf("the bucket holds segment keys up to %s but no segment's original: every one was disposed or shadowed, "+
			"so the chain's head is unknown. Refusing to start a new chain at 0 under the old chain's keys "+
			"(see docs/audit-offsite.md, \"When the chain restarts\")", highest)
	case highest != best:
		return "", fmt.Errorf("the newest segment keys (after %s, up to %s) have no original: resuming from %s would fork the chain. "+
			"Refusing (see docs/audit-offsite.md, \"When the chain restarts\")", best, highest, best)
	}
	return best, nil
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
	ocl, obucket := offsiteClient()

	// Write to every configured sink. Because resume is derived from the bucket head, a crash after
	// the primary PUT (before the off-site copy, or before the process exits) simply re-derives the SAME
	// next segment next run — no fork.
	put := func(seg auditchain.Segment, blob []byte) error {
		key := segmentKey(seg.Seq)
		if err := putSegment(ctx, pcl, pbucket, key, blob); err != nil {
			return fmt.Errorf("put segment to primary: %w", err)
		}
		if ocl != nil {
			if err := putSegment(ctx, ocl, obucket, key, blob); err != nil {
				return fmt.Errorf("put segment to off-site: %w", err)
			}
		}
		fmt.Printf("shipped segment seq=%d records=%d endOffset=%d inode=%d head=%s\n", seg.Seq, seg.Count, seg.EndOffset, seg.SourceInode, seg.Hash[:12])
		return nil
	}

	path := getenv("AUDIT_LOG_PATH", "/var/lib/rancher/k3s/server/logs/audit.log")
	shipped, note, err := shipRun(path, head, put, segmentBytes(), 256<<20)
	if note != "" {
		fmt.Fprintf(os.Stderr, "audit-offsite: %s\n", note)
	}
	if err != nil {
		fatalf("%v", err)
	}
	if shipped == 0 {
		fmt.Fprintln(os.Stderr, "audit-offsite: no complete new line to ship")
	}
}

// logFile is one audit log file a run can read — the live log or one of its rotated backups — held
// open, so its identity cannot change under the run (the live log may be rotated while it is read).
type logFile struct {
	name  string   // base name in the log directory
	f     *os.File // the open file (nil only in tests that plan without reading)
	inode uint64
	size  int64
	mtime time.Time
}

// logSource is one file a run reads, and the byte offset it starts at.
type logSource struct {
	file *logFile
	from int64
}

// gatherLogs opens the live log, then lists and opens its rotated backups. kube-apiserver rotates its
// audit log (lumberjack) by renaming it <stem>-<UTC timestamp><ext> and opening a fresh <stem><ext>, so
// the backups' name order is their rotation order. The live log is opened FIRST: if it is rotated
// meanwhile, the open file is the renamed one, which the listing then also finds — it is dropped from
// the backups, so it is read once, to its end. Compressed backups (.gz) cannot be read in place and are
// not listed.
func gatherLogs(path string) (cur *logFile, rotated []*logFile, closeAll func(), err error) {
	var opened []*os.File
	closeAll = func() {
		for _, f := range opened {
			_ = f.Close()
		}
	}
	open := func(p string) (*logFile, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		opened = append(opened, f)
		return &logFile{name: filepath.Base(p), f: f, inode: fileInode(fi), size: fi.Size(), mtime: fi.ModTime()}, nil
	}
	if cur, err = open(path); err != nil {
		return nil, nil, closeAll, fmt.Errorf("open audit log %s: %w", path, err)
	}
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext) + "-"
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return cur, nil, closeAll, fmt.Errorf("list the audit log directory: %w", err)
	}
	for _, e := range entries {
		n := e.Name()
		if n == base || !e.Type().IsRegular() || !strings.HasPrefix(n, stem) || !strings.HasSuffix(n, ext) {
			continue
		}
		lf, oerr := open(filepath.Join(dir, n))
		if oerr != nil {
			continue // removed by the rotation's own cleanup since the listing
		}
		if lf.inode == cur.inode {
			continue // the live log, rotated after it was opened: read once, as the live log
		}
		rotated = append(rotated, lf)
	}
	sort.Slice(rotated, func(i, j int) bool { return rotated[i].name < rotated[j].name })
	return cur, rotated, closeAll, nil
}

// planSources decides what a run reads, so that a rotation never loses the rotated file's tail.
//
// The chain records, on each segment, the identity (inode) of the file it was read from and the byte
// offset it ended at. When the live log is that file, the run continues it from that offset. When the
// log has been rotated since, the file the chain last read is now a backup: the run FINISHES it from that
// offset, then reads every backup rotated after it, whole and in rotation order, then the new live log
// from 0. A backup is taken for the chain's file only if it also ends the head segment's last record at
// that offset (endsAt) — an inode alone can be reused by a later file once the original is deleted.
//
// note is non-empty when records were unavoidably missed (or the log shrank in place): the file the
// chain last read is gone (it aged out of the backups — the shipper was down longer than the log keeps
// them), so the run starts from the backups written after the head's last record.
func planSources(cur *logFile, rotated []*logFile, head *auditchain.Segment, endsAt func(lf *logFile, off int64, rec string) bool) ([]logSource, string) {
	if head == nil {
		return []logSource{{file: cur}}, ""
	}
	if head.SourceInode == 0 || head.SourceInode == cur.inode {
		// The same file as the head (or a head from before inodes were recorded): continue it. A file
		// shorter than the offset was truncated in place, so its records restart at 0.
		if cur.size < head.EndOffset {
			return []logSource{{file: cur}}, fmt.Sprintf("log shrank (size %d < offset %d): reading it from 0", cur.size, head.EndOffset)
		}
		return []logSource{{file: cur, from: head.EndOffset}}, ""
	}
	last := ""
	if n := len(head.Records); n > 0 {
		last = head.Records[n-1]
	}
	for i, lf := range rotated {
		if lf.inode != head.SourceInode || lf.size < head.EndOffset || last == "" || !endsAt(lf, head.EndOffset, last) {
			continue
		}
		plan := []logSource{{file: lf, from: head.EndOffset}}
		for _, later := range rotated[i+1:] {
			plan = append(plan, logSource{file: later})
		}
		return append(plan, logSource{file: cur}), ""
	}
	// The chain's file is gone. Read what was written after the head's last record: the backups last
	// written after it (whole), then the live log.
	note := fmt.Sprintf("the file the chain last read (inode %d, to byte %d, last record %s) is no longer among the log's backups: "+
		"records written after it and before the oldest file read now were not shipped", head.SourceInode, head.EndOffset, head.LastTS)
	var plan []logSource
	if after, err := time.Parse(time.RFC3339Nano, head.LastTS); err == nil {
		for _, lf := range rotated {
			if lf.mtime.After(after) {
				plan = append(plan, logSource{file: lf})
			}
		}
	}
	return append(plan, logSource{file: cur}), note
}

// endsAtRecord reports whether the bytes of lf just before off end with rec (blank lines between them
// allowed: a segment's EndOffset includes the blank lines after its last record).
func endsAtRecord(lf *logFile, off int64, rec string) bool {
	if lf.f == nil || off <= 0 {
		return false
	}
	w := int64(len(rec)) + 4096
	if w > off {
		w = off
	}
	b := make([]byte, w)
	n, err := lf.f.ReadAt(b, off-w)
	if err != nil && err != io.EOF {
		return false
	}
	return bytes.HasSuffix(bytes.TrimRight(b[:n], " \t\r\n"), bytes.TrimRight([]byte(rec), " \t\r\n"))
}

// shipRun ships everything not yet in the chain after head: it plans the files to read (planSources),
// then reads each in bounded segments of complete lines, chaining every segment to the one before and
// handing it to put. A segment never spans two files: each records the inode of the file it came from
// and the offset it ended at, which is where the next run resumes.
func shipRun(path string, head *auditchain.Segment, put func(auditchain.Segment, []byte) error, maxBytes, hardMax int64) (int, string, error) {
	cur, rotated, closeAll, err := gatherLogs(path)
	defer closeAll()
	if err != nil {
		return 0, "", err
	}
	plan, note := planSources(cur, rotated, head, endsAtRecord)
	prev, shipped := head, 0
	for _, src := range plan {
		if src.file != cur {
			fmt.Fprintf(os.Stderr, "audit-offsite: reading rotated %s (inode %d) from byte %d\n", src.file.name, src.file.inode, src.from)
		}
		// Ship in bounded segments: a segment's bytes are held a few times over (the raw lines, their
		// strings, the segment's JSON), so reading a whole backlog at once got the job OOM-killed and it
		// never caught up. A run ships as many bounded segments as it takes.
		off := src.from
		for {
			// Only COMPLETE lines: up to and including the last newline. A trailing partial line waits
			// until it is finished, so a segment never contains half a record.
			lines, consumed, err := readSegment(src.file.f, off, maxBytes, hardMax)
			if err != nil {
				return shipped, note, fmt.Errorf("read %s: %w", src.file.name, err)
			}
			if consumed == 0 {
				break
			}
			if len(lines) == 0 { // only blank lines: carried into the next segment's EndOffset
				off += consumed
				continue
			}
			seg := auditchain.BuildSegment(prev, lines, tsOf(lines[0]), tsOf(lines[len(lines)-1]))
			seg.EndOffset = off + consumed
			seg.SourceInode = src.file.inode
			blob, err := json.Marshal(seg)
			if err != nil {
				return shipped, note, fmt.Errorf("marshal segment: %w", err)
			}
			if err := put(seg, blob); err != nil {
				return shipped, note, err
			}
			prev, off = &seg, seg.EndOffset
			shipped++
		}
	}
	return shipped, note, nil
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
	// AnchorNote says why the anchor was not trusted for the prefix (the chain was re-derived from
	// contents instead), e.g. an anchored head past the bucket's newest segment. "" when it was used.
	AnchorNote string `json:"anchorNote,omitempty"`
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
	maxReal         int // Seq of the newest segment whose original is listed (-1: none)
	// anchorNote says why the anchor was not trusted for the prefix (it is past the bucket's newest
	// segment, its segment is missing, or that segment's hash differs): the chain was then re-derived
	// from contents, and the anchor cross-check reports what it found. "" when the anchor was used.
	anchorNote string
	perKey     map[string][]minio.ObjectInfo
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

	out.maxReal = maxReal

	// The anchor stands for the verified prefix only if the bucket's chain can contain it: its segment is
	// listed, within the retained chain, with the anchored hash. An anchor past the bucket's newest
	// segment (the chain lost its newest segments, or was restarted) or one whose segment differs is not
	// trusted: seeding from it would skip every listed segment as "already verified", report the anchor's
	// head as the chain's, and so hide the very regression the anchor exists to catch. The chain is then
	// re-derived from contents, and checkAndUpdateAnchor compares that real head with the anchor.
	trustAnchor := false
	if anchor != nil && anchor.HeadSeq >= out.retainedFrom { // below it, the anchored head was disposed
		switch key, ok := present[anchor.HeadSeq]; {
		case anchor.HeadSeq > maxReal:
			out.anchorNote = fmt.Sprintf("the anchored head seq=%d is past the bucket's newest segment seq=%d: "+
				"the chain lost its newest segments or was restarted (re-derived from contents)", anchor.HeadSeq, maxReal)
		case !ok:
			out.anchorNote = fmt.Sprintf("the anchored head seq=%d has no original in the bucket (re-derived from contents)", anchor.HeadSeq)
		default:
			data, err := st.getVersion(ctx, key, oldestReal(perKey[key]).VersionID)
			var s auditchain.Segment
			switch {
			case err != nil:
				return out, fmt.Errorf("get %s (the anchored head): %w", key, err)
			case json.Unmarshal(data, &s) != nil || s.Seq != anchor.HeadSeq || s.Hash != anchor.HeadHash:
				out.anchorNote = fmt.Sprintf("the segment at the anchored head seq=%d does not have the anchored hash (re-derived from contents)", anchor.HeadSeq)
			default:
				trustAnchor = true
			}
		}
	}

	var sv *auditchain.StreamVerifier
	verifiedSeq := -1
	if trustAnchor {
		// Seed with the trusted anchor so checkAndUpdateAnchor cross-checks the new head against it.
		verifiedSeq = anchor.HeadSeq
		sv = auditchain.NewStreamVerifierFrom(anchor.HeadSeq, anchor.HeadHash)
		out.heads = append(out.heads, auditchain.Segment{Seq: anchor.HeadSeq, Hash: anchor.HeadHash})
	} else {
		// No anchor, the anchored head disposed, or an anchor the bucket can't contain: re-derive the
		// retained chain from contents.
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
	out.maxReal = maxReal

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
	// Retain-then-dispose runs concurrently: an original the listing held can be removed (its lock lapsed)
	// before it is read. A fresh listing then sees it disposed, so a failed read is retried on one.
	var out verifyOutcome
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if out, err = verifySegments(ctx, st, time.Now(), time.Duration(retentionDays())*24*time.Hour, anchor); err == nil {
			break
		}
		fmt.Fprintf(os.Stderr, "audit-offsite: verify pass %d: %v (re-listing)\n", attempt+1, err)
	}
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
		// Bounded by the newest segment actually listed: res.HeadSeq would be the anchor's when it is
		// seeded from one, and an anchor past the bucket's head walks the window off the chain's end.
		c := chainCheck{ctx: ctx, st: st, now: time.Now(), retention: time.Duration(retentionDays()) * 24 * time.Hour}
		resweep, resweepOK = resweepPrefix(c, out.perKey, out.retainedFrom, out.maxReal)
	}
	if out.anchorNote != "" {
		fmt.Fprintln(os.Stderr, "audit-offsite: "+out.anchorNote)
	}

	report := statusReport{
		Result:           res,
		ShadowVersions:   out.shadow,
		DisposedSegments: out.disposed,
		DisposalMarkers:  out.disposalMarkers,
		Anchor:           anchorStatus,
		AnchorNote:       out.anchorNote,
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

	status := anchorVerdict(prior, have, segs, res)

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

// anchorVerdict compares the verified head (res, and the Seq+Hash of the segments verified) with the
// prior anchor: "new" without one, "regressed" when the head went backward (the chain lost its newest
// segments, or was restarted), "rewritten" when the segment at the anchored Seq no longer has the
// anchored hash, "ok" otherwise — including when the anchored head aged out past retention.
func anchorVerdict(prior anchorState, have bool, segs []auditchain.Segment, res auditchain.VerifyResult) string {
	if !have {
		return "new"
	}
	hashBySeq := map[int]string{}
	baseSeq := 1 << 30
	for _, s := range segs {
		hashBySeq[s.Seq] = s.Hash
		if s.Seq < baseSeq {
			baseSeq = s.Seq
		}
	}
	switch {
	case res.HeadSeq < prior.HeadSeq:
		return "regressed"
	case prior.HeadSeq < baseSeq:
		return "ok" // the previously anchored head aged out past retention — legitimate
	case hashBySeq[prior.HeadSeq] != "" && hashBySeq[prior.HeadSeq] != prior.HeadHash:
		return "rewritten"
	}
	return "ok"
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
// base is the oldest segment of the retained chain (those before it have been disposed) and head the
// newest segment the listing holds.
func resweepPrefix(c chainCheck, perKey map[string][]minio.ObjectInfo, base, head int) (string, bool) {
	window := 2000
	if w, err := strconv.Atoi(getenv("AUDIT_RESWEEP_WINDOW", "2000")); err == nil && w > 0 {
		window = w
	}
	msg, ok, next := resweepWindow(c, perKey, base, head, readResweepCursor(c.ctx), window)
	if ok && next >= 0 {
		writeResweepCursor(c.ctx, next)
	}
	return msg, ok
}

// resweepWindow re-derives the window [cursor-1 .. cursor+window-1] of the retained chain [base..head],
// bounded by the newest segment actually listed, and returns the next cursor (-1: leave it). A segment
// the listing held but whose original is gone by the time it is read was disposed during the sweep when
// its lock had lapsed (retain-then-dispose runs concurrently): the window ends before it and the next one
// starts after it. Removed while still locked, it is a gap.
func resweepWindow(c chainCheck, perKey map[string][]minio.ObjectInfo, base, head, cursor, window int) (string, bool, int) {
	listed := -1
	for k, vs := range perKey {
		if seq, ok := seqFromKey(k); ok && seq > listed && oldestReal(vs) != nil {
			listed = seq
		}
	}
	if head > listed {
		head = listed // never sweep past the chain's newest listed segment
	}
	if len(perKey) == 0 || head < base {
		return "rotating: empty chain, nothing to re-sweep", true, -1
	}
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
	next := -2
	for seq := lo; seq <= end; seq++ {
		key := segmentKey(seq)
		versions, ok := perKey[key]
		if !ok {
			return fmt.Sprintf("rotating: segment seq=%d missing in [%d..%d] (gap — chain truncated/tampered)", seq, lo, end), false, -1
		}
		orig := oldestReal(versions)
		if orig == nil {
			return fmt.Sprintf("rotating: segment seq=%d is fully shadowed (no locked original)", seq), false, -1
		}
		data, err := c.st.getVersion(c.ctx, key, orig.VersionID)
		if err != nil {
			if c.lapsedBy(key, *orig, c.now) {
				end, next = seq-1, seq+1 // disposed while sweeping: the window ends before it
				break
			}
			return fmt.Sprintf("rotating: get seq=%d failed: %v", seq, err), false, -1
		}
		var s auditchain.Segment
		if json.Unmarshal(data, &s) != nil {
			return fmt.Sprintf("rotating: parse seq=%d failed", seq), false, -1
		}
		sv.Push(s)
	}
	if r := sv.Result(); !r.OK {
		return fmt.Sprintf("rotating: prefix re-sweep [%d..%d] FAILED: %s", lo, end, r.Reason), false, -1
	}
	if next == -2 {
		next = end + 1
	}
	if next > head {
		next = base // wrap: one full rotation complete, start the prefix over
	}
	return fmt.Sprintf("rotating: re-derived seq %d..%d (next cursor %d, window %d)", lo, end, next, window), true, next
}
