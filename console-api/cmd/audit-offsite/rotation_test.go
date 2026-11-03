package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/auditchain"
)

// rec is one audit line with a timestamp, as kube-apiserver writes them.
func rec(id string, ts time.Time) string {
	b, _ := json.Marshal(map[string]string{"auditID": id, "requestReceivedTimestamp": ts.UTC().Format(time.RFC3339Nano)})
	return string(b)
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// rotate does what kube-apiserver's log rotation does: rename the live log to a timestamped backup and
// start a fresh one.
func rotate(t *testing.T, path string, at time.Time) string {
	t.Helper()
	backup := filepath.Join(filepath.Dir(path), "audit-"+at.UTC().Format("2006-01-02T15-04-05.000")+".log")
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	appendLines(t, path) // a fresh, empty live log
	return backup
}

// chainSink collects what a run ships, as the bucket would.
type chainSink struct{ segs []auditchain.Segment }

func (c *chainSink) put(seg auditchain.Segment, _ []byte) error {
	c.segs = append(c.segs, seg)
	return nil
}

func (c *chainSink) head() *auditchain.Segment {
	if len(c.segs) == 0 {
		return nil
	}
	h := c.segs[len(c.segs)-1]
	return &h
}

func (c *chainSink) records() []string {
	var out []string
	for _, s := range c.segs {
		for _, r := range s.Records {
			var e struct {
				ID string `json:"auditID"`
			}
			_ = json.Unmarshal([]byte(r), &e)
			out = append(out, e.ID)
		}
	}
	return out
}

func (c *chainSink) run(t *testing.T, path string) string {
	t.Helper()
	_, note, err := shipRun(path, c.head(), c.put, 1<<20, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	return note
}

func (c *chainSink) mustVerify(t *testing.T) {
	t.Helper()
	if r := auditchain.Verify(c.segs); !r.OK {
		t.Fatalf("the shipped chain does not verify: %s", r.Reason)
	}
}

// The records written between a run and the log's next rotation are the rotated file's tail. The
// shipper used to restart at 0 of the new live log, so that tail was never shipped (measured live: about
// a third of all records, with rotation every ~5 minutes and a run every 5). Now the next run finishes
// the rotated file from the chain's offset first.
func TestShipRun_RotationFinishesTheRotatedFilesTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	t0 := time.Date(2026, 11, 3, 14, 0, 0, 0, time.UTC)
	appendLines(t, path, rec("a1", t0), rec("a2", t0.Add(time.Second)))
	var c chainSink
	c.run(t, path)
	// After the run: more records, then the rotation, then records in the new live log.
	appendLines(t, path, rec("a3", t0.Add(2*time.Second)), rec("a4", t0.Add(3*time.Second)))
	rotate(t, path, t0.Add(4*time.Second))
	appendLines(t, path, rec("b1", t0.Add(5*time.Second)))
	if note := c.run(t, path); note != "" {
		t.Fatalf("an ordinary rotation reported a gap: %s", note)
	}
	if got := strings.Join(c.records(), ","); got != "a1,a2,a3,a4,b1" {
		t.Fatalf("shipped %s, want every record once, in order (a1,a2,a3,a4,b1)", got)
	}
	c.mustVerify(t)
	// No segment spans two files: the rotated tail and the new log are separate segments, each with
	// its own file's inode and offset.
	if n := len(c.segs); n != 3 || c.segs[1].SourceInode == c.segs[2].SourceInode {
		t.Fatalf("segments %d, inodes %d/%d: want the tail and the new log in separate segments", n, c.segs[1].SourceInode, c.segs[2].SourceInode)
	}
	// A third run with nothing new ships nothing.
	before := len(c.segs)
	c.run(t, path)
	if len(c.segs) != before {
		t.Fatalf("a run with nothing new shipped %d segments", len(c.segs)-before)
	}
}

// Several rotations between runs (a run missed): the chain's file is finished, every backup rotated
// after it is read whole and in rotation order, then the live log.
func TestShipRun_SeveralRotationsBetweenRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	t0 := time.Date(2026, 11, 3, 14, 0, 0, 0, time.UTC)
	appendLines(t, path, rec("a1", t0))
	var c chainSink
	c.run(t, path)
	appendLines(t, path, rec("a2", t0.Add(time.Second)))
	rotate(t, path, t0.Add(2*time.Second))
	appendLines(t, path, rec("b1", t0.Add(3*time.Second)), rec("b2", t0.Add(4*time.Second)))
	rotate(t, path, t0.Add(5*time.Second))
	appendLines(t, path, rec("c1", t0.Add(6*time.Second)))
	rotate(t, path, t0.Add(7*time.Second))
	appendLines(t, path, rec("d1", t0.Add(8*time.Second)))
	c.run(t, path)
	if got := strings.Join(c.records(), ","); got != "a1,a2,b1,b2,c1,d1" {
		t.Fatalf("shipped %s, want a1,a2,b1,b2,c1,d1", got)
	}
	c.mustVerify(t)
}

// The live log rotated after the run opened it: the listing finds the same file under its backup name.
// It is read once, as the live log, not twice.
func TestGatherLogs_TheLiveLogUnderABackupNameIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendLines(t, path, rec("a1", time.Now()))
	if err := os.Link(path, filepath.Join(dir, "audit-2026-11-03T14-00-00.000.log")); err != nil {
		t.Skip("hard links not supported here:", err)
	}
	cur, rotated, closeAll, err := gatherLogs(path)
	defer closeAll()
	if err != nil {
		t.Fatal(err)
	}
	if cur == nil || len(rotated) != 0 {
		t.Fatalf("rotated %d, want the live log's other name dropped", len(rotated))
	}
}

// The chain's file aged out of the backups (the shipper was down longer than the log keeps them): the
// loss is reported, and the run reads what was written after the head's last record.
func TestShipRun_ChainsFileGoneIsReportedAndTheRestShipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	t0 := time.Date(2026, 11, 3, 14, 0, 0, 0, time.UTC)
	appendLines(t, path, rec("a1", t0))
	var c chainSink
	c.run(t, path)
	appendLines(t, path, rec("a2", t0.Add(time.Second)))
	gone := rotate(t, path, t0.Add(2*time.Second))
	appendLines(t, path, rec("b1", t0.Add(3*time.Second)))
	b := rotate(t, path, t0.Add(4*time.Second))
	appendLines(t, path, rec("c1", t0.Add(5*time.Second)))
	if err := os.Remove(gone); err != nil { // aged out
		t.Fatal(err)
	}
	if err := os.Chtimes(b, t0.Add(4*time.Second), t0.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	note := c.run(t, path)
	if !strings.Contains(note, "no longer among the log's backups") {
		t.Fatalf("note %q, want the missed records reported", note)
	}
	if got := strings.Join(c.records(), ","); got != "a1,b1,c1" {
		t.Fatalf("shipped %s, want a1,b1,c1 (a2 is lost with its file)", got)
	}
	c.mustVerify(t)
}

// A backup is the chain's file only if it ends the head's last record at the head's offset: an inode
// can be reused by a later file once the original is deleted.
func TestPlanSources_AnInodeAloneDoesNotIdentifyTheFile(t *testing.T) {
	head := &auditchain.Segment{Seq: 7, SourceInode: 42, EndOffset: 100, Records: []string{"x"}, LastTS: "2026-11-03T14:00:00Z"}
	cur := &logFile{name: "audit.log", inode: 99, size: 10}
	reused := &logFile{name: "audit-2026-11-03T14-05-00.000.log", inode: 42, size: 500, mtime: time.Date(2026, 11, 3, 14, 5, 0, 0, time.UTC)}
	plan, note := planSources(cur, []*logFile{reused}, head, func(*logFile, int64, string) bool { return false })
	if note == "" {
		t.Fatal("a file with the chain's inode but other contents was taken for the chain's file")
	}
	if len(plan) != 2 || plan[0].file != reused || plan[0].from != 0 || plan[1].file != cur {
		t.Fatalf("plan %+v, want the reused-inode backup read whole (it was written after the head) and then the live log", plan)
	}
	// With the record at the offset, it is the chain's file, finished from the offset.
	plan, note = planSources(cur, []*logFile{reused}, head, func(_ *logFile, off int64, r string) bool { return off == 100 && r == "x" })
	if note != "" || len(plan) != 2 || plan[0].from != 100 {
		t.Fatalf("plan %+v note %q, want the chain's file finished from byte 100", plan, note)
	}
}

// The same file as the head continues from its offset; one shorter than the offset was truncated in
// place and is read from 0, reported.
func TestPlanSources_SameFileContinuesOrRestartsWhenShrunk(t *testing.T) {
	head := &auditchain.Segment{SourceInode: 5, EndOffset: 100, Records: []string{"x"}}
	if plan, note := planSources(&logFile{inode: 5, size: 300}, nil, head, nil); note != "" || plan[0].from != 100 {
		t.Fatalf("plan %+v note %q, want the live log continued from 100", plan, note)
	}
	if plan, note := planSources(&logFile{inode: 5, size: 50}, nil, head, nil); note == "" || plan[0].from != 0 {
		t.Fatalf("plan %+v note %q, want a shrunk log read from 0, reported", plan, note)
	}
	if plan, _ := planSources(&logFile{inode: 5, size: 50}, nil, nil, nil); len(plan) != 1 || plan[0].from != 0 {
		t.Fatalf("plan %+v, want a new chain to read the live log from 0", plan)
	}
}

// A segment's offset includes the blank lines after its last record; the record still identifies the file.
func TestEndsAtRecord_AllowsTrailingBlankLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.log")
	content := "one\ntwo\n\n\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	lf := &logFile{f: f}
	if !endsAtRecord(lf, int64(len(content)), "two") {
		t.Fatal("the record before trailing blank lines was not found")
	}
	if endsAtRecord(lf, int64(len(content)), "one") || endsAtRecord(lf, 4, "two") {
		t.Fatal("a record not at the offset was matched")
	}
}
