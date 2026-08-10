// Command audit-offsite ships the k3s API-server audit log to a WORM object store as a
// hash-chained sequence of segments, and verifies that chain — the tamper-evident,
// off-site half of audit-record protection (NIST SP 800-53 AU-9, AU-9(2), AU-9(3), AU-10).
//
// It reads the audit log at its SOURCE (the file on the control-plane node), not from Loki, so
// off-siting does not depend on the integrity of the in-cluster log store: an attacker who wipes
// Loki cannot stop, or retroactively alter, what has already been shipped off.
//
//	audit-offsite ship    — read new audit-log lines since the last cursor, forge the next chain
//	                        segment, and write it to the WORM bucket (COMPLIANCE object lock) and,
//	                        if configured, an off-site bucket. Run frequently (a CronJob).
//	audit-offsite verify  — read every segment back and re-verify the whole chain from its
//	                        contents alone, then publish the result to status/latest.json for the
//	                        console. Exits non-zero if the chain is broken. Run periodically.
//
// The immutability guarantee is the object store's (COMPLIANCE-mode Object Lock keeps a segment
// undeletable — by anyone, including root — until its retention expires). The tamper-EVIDENCE
// guarantee is this program's: every segment links to the previous one by hash, and Verify
// recomputes every hash from segment contents, so a deleted, reordered, or edited segment — or
// any edited record within one — is detected.
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
	segmentPrefix = "segments/"
	statusKey     = "status/latest.json"
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
			os.Exit(2) // chain broken — make the CronJob go red so it can alert
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

// primaryClient is the in-cluster WORM MinIO. offsiteClient is an optional second sink on a
// separate system (AU-9(2)); it returns (nil, nil) when OFFSITE_ENDPOINT is unset.
func primaryClient() (*minio.Client, string) {
	cl, err := minioClient("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_SECURE")
	if err != nil {
		fatalf("primary object store: %v", err)
	}
	return cl, getenv("AUDIT_BUCKET", "openinfra-audit")
}

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

// putSegment writes one segment under COMPLIANCE object lock, so it cannot be deleted or
// overwritten (even by root) until retention expires. Content-MD5 is required for a locked PUT.
func putSegment(ctx context.Context, cl *minio.Client, bucket, key string, blob []byte) error {
	_, err := cl.PutObject(ctx, bucket, key, bytes.NewReader(blob), int64(len(blob)), minio.PutObjectOptions{
		ContentType:     "application/json",
		Mode:            minio.Compliance,
		RetainUntilDate: time.Now().Add(time.Duration(retentionDays()) * 24 * time.Hour),
		SendContentMd5:  true,
	})
	return err
}

// ── the cursor (a ConfigMap) ─────────────────────────────────────────────────────

type cursor struct {
	Offset   int64  `json:"offset"`   // byte offset into the audit log already shipped
	Seq      int    `json:"seq"`      // Seq of the last shipped segment, or -1 if none
	HeadHash string `json:"headHash"` // Hash of the last shipped segment
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

const stateConfigMap = "audit-offsite-state"

func readCursor(ctx context.Context, cs kubernetes.Interface, ns string) cursor {
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, stateConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cursor{Seq: -1} // no segments shipped yet
	}
	if err != nil {
		fatalf("read cursor: %v", err)
	}
	var c cursor
	if err := json.Unmarshal([]byte(cm.Data["state.json"]), &c); err != nil {
		fatalf("parse cursor: %v", err)
	}
	return c
}

func writeCursor(ctx context.Context, cs kubernetes.Interface, ns string, c cursor) {
	blob, _ := json.Marshal(c)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: stateConfigMap, Namespace: ns},
		Data:       map[string]string{"state.json": string(blob)},
	}
	_, err := cs.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
	}
	if err != nil {
		fatalf("write cursor: %v", err)
	}
}

// ── ship ─────────────────────────────────────────────────────────────────────────

func ship() {
	ctx := context.Background()
	cs, ns := k8sClient()
	cur := readCursor(ctx, cs, ns)

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

	// Handle log rotation/truncation: if the file is now shorter than our cursor, it was rotated
	// out from under us. Restart from the top of the current file. (Lines written to the rotated
	// file between our last read and the rotation are a known, bounded gap; keep the interval
	// short. Verify still reports a contiguous chain — the gap is in coverage, not integrity.)
	if fi.Size() < cur.Offset {
		fmt.Fprintf(os.Stderr, "audit-offsite: log rotated (size %d < cursor %d), restarting from 0\n", fi.Size(), cur.Offset)
		cur.Offset = 0
	}
	if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
		fatalf("seek: %v", err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		fatalf("read: %v", err)
	}

	// Ship only COMPLETE lines: everything up to and including the last newline. A trailing
	// partial line stays unread until it is finished, so a segment never contains half a record.
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

	var prev *auditchain.Segment
	if cur.Seq >= 0 {
		prev = &auditchain.Segment{Seq: cur.Seq, Hash: cur.HeadHash}
	}
	seg := auditchain.BuildSegment(prev, lines, tsOf(lines[0]), tsOf(lines[len(lines)-1]))
	blob, err := json.Marshal(seg)
	if err != nil {
		fatalf("marshal segment: %v", err)
	}
	key := fmt.Sprintf("%s%012d.json", segmentPrefix, seg.Seq)

	// Write to every configured sink BEFORE advancing the cursor. A crash between a successful
	// PUT and the cursor write re-ships the identical segment next run (same seq, same content,
	// same hash) — idempotent. A sink failure leaves the cursor untouched, so it is retried.
	pcl, pbucket := primaryClient()
	if err := putSegment(ctx, pcl, pbucket, key, blob); err != nil {
		fatalf("put segment to primary: %v", err)
	}
	if ocl, obucket := offsiteClient(); ocl != nil {
		if err := putSegment(ctx, ocl, obucket, key, blob); err != nil {
			// Off-site is the AU-9(2) separate-system copy; do NOT advance the cursor without it.
			fatalf("put segment to off-site: %v", err)
		}
	}

	cur.Offset += consumed
	cur.Seq = seg.Seq
	cur.HeadHash = seg.Hash
	writeCursor(ctx, cs, ns, cur)
	fmt.Printf("shipped segment seq=%d records=%d bytes=%d head=%s\n", seg.Seq, seg.Count, consumed, seg.Hash[:12])
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

// statusReport is what verify publishes to status/latest.json for the console to read.
type statusReport struct {
	Result     auditchain.VerifyResult `json:"result"`
	VerifiedAt string                  `json:"verifiedAt"`
	Bucket     string                  `json:"bucket"`
}

func verify() bool {
	ctx := context.Background()
	cl, bucket := primaryClient()

	var segs []auditchain.Segment
	for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: segmentPrefix, Recursive: true}) {
		if obj.Err != nil {
			fatalf("list segments: %v", obj.Err)
		}
		rc, err := cl.GetObject(ctx, bucket, obj.Key, minio.GetObjectOptions{})
		if err != nil {
			fatalf("get %s: %v", obj.Key, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			fatalf("read %s: %v", obj.Key, err)
		}
		var s auditchain.Segment
		if err := json.Unmarshal(data, &s); err != nil {
			fatalf("parse %s: %v", obj.Key, err)
		}
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].Seq < segs[j].Seq })

	res := auditchain.Verify(segs)
	report := statusReport{Result: res, VerifiedAt: time.Now().UTC().Format(time.RFC3339), Bucket: bucket}
	blob, _ := json.MarshalIndent(report, "", "  ")

	// Publish the result WITHOUT object lock so it can be overwritten each run (it is a mutable
	// cache for the console). The segments it attests to are the locked, authoritative record.
	if _, err := cl.PutObject(ctx, bucket, statusKey, bytes.NewReader(blob), int64(len(blob)),
		minio.PutObjectOptions{ContentType: "application/json"}); err != nil {
		fmt.Fprintf(os.Stderr, "audit-offsite: publish status: %v\n", err)
	}

	fmt.Println(string(blob))
	return res.OK
}
