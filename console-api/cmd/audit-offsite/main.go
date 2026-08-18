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
//     version or delete marker as a tamper attempt — a latest-version read would be fooled;
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

	if _, err := f.Seek(resumeOffset, io.SeekStart); err != nil {
		fatalf("seek: %v", err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		fatalf("read: %v", err)
	}

	// Ship only COMPLETE lines: up to and including the last newline. A trailing partial line waits
	// until it is finished, so a segment never contains half a record.
	nl := bytes.LastIndexByte(raw, '\n')
	if nl < 0 {
		fmt.Fprintln(os.Stderr, "audit-offsite: no complete new line to ship")
		return
	}
	consumed := int64(nl + 1)
	var lines []string
	for _, l := range bytes.Split(raw[:consumed], []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) > 0 {
			lines = append(lines, string(l))
		}
	}
	if len(lines) == 0 {
		return
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
	if ocl, obucket := offsiteClient(); ocl != nil {
		if err := putSegment(ctx, ocl, obucket, key, blob); err != nil {
			fatalf("put segment to off-site: %v", err)
		}
	}
	fmt.Printf("shipped segment seq=%d records=%d endOffset=%d head=%s\n", seg.Seq, seg.Count, seg.EndOffset, seg.Hash[:12])
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
}

func verify() bool {
	ctx := context.Background()
	cl, bucket := primaryClient()

	// Read every segment's LOCKED ORIGINAL version (see oldestReal). A latest-version read would be
	// fooled by a shadowing overwrite; this cannot be.
	perKey := map[string][]minio.ObjectInfo{}
	for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: segmentPrefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			fatalf("list segment versions: %v", obj.Err)
		}
		perKey[obj.Key] = append(perKey[obj.Key], obj)
	}

	// Stream segments in Seq order — keys are segments/%012d.json, so a lexical key sort IS a
	// Seq sort — and push each into a StreamVerifier, freeing its records right after. This keeps
	// verification memory O(1) in the chain length; the previous whole-chain load OOM-killed the
	// verify job once the chain had grown to thousands of segments (the anchor stalled for days).
	keys := make([]string, 0, len(perKey))
	for k := range perKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sv auditchain.StreamVerifier
	// heads holds only Seq+Hash per segment (never records) — the anchor cross-check needs no more.
	heads := make([]auditchain.Segment, 0, len(keys))
	shadow := 0
	for _, key := range keys {
		versions := perKey[key]
		orig := oldestReal(versions)
		if orig == nil {
			shadow++ // only delete markers — the original is fully shadowed
			continue
		}
		origData, err := getVersion(ctx, cl, bucket, key, orig.VersionID)
		if err != nil {
			fatalf("get %s (original version): %v", key, err)
		}
		var s auditchain.Segment
		if err := json.Unmarshal(origData, &s); err != nil {
			fatalf("parse %s: %v", key, err)
		}
		sv.Push(s)
		heads = append(heads, auditchain.Segment{Seq: s.Seq, Hash: s.Hash})
		for i := range versions {
			v := versions[i]
			if v.VersionID == orig.VersionID {
				continue
			}
			if v.IsDeleteMarker {
				shadow++
				continue
			}
			d, err := getVersion(ctx, cl, bucket, key, v.VersionID)
			if err != nil {
				fatalf("get %s (shadow version %s): %v", key, v.VersionID, err)
			}
			if !bytes.Equal(d, origData) {
				shadow++
			}
		}
	}

	res := sv.Result()
	if shadow > 0 && res.OK {
		res.Reason = fmt.Sprintf("%d object-lock shadowing attempt(s) detected (overwrite/delete-marker on locked segments)", shadow)
	}

	anchor := checkAndUpdateAnchor(ctx, heads, res)

	report := statusReport{
		Result:         res,
		ShadowVersions: shadow,
		Anchor:         anchor,
		Intact:         res.OK && shadow == 0 && (anchor == "ok" || anchor == "new"),
		HeadSeq:        res.HeadSeq,
		HeadHash:       res.HeadHash,
		VerifiedAt:     time.Now().UTC().Format(time.RFC3339),
		Bucket:         bucket,
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
