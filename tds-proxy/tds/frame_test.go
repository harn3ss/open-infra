package tds

import (
	"encoding/binary"
	"testing"
)

// txMgrBody builds a TransactionManager (0x0E) message body: an ALL_HEADERS block (here a minimal one —
// its own 4-byte length + `hdrPad` filler bytes) followed by the 2-byte RequestType.
func txMgrBody(reqType uint16, hdrPad int) []byte {
	total := 4 + hdrPad
	b := make([]byte, total+2)
	binary.LittleEndian.PutUint32(b[0:4], uint32(total))
	binary.LittleEndian.PutUint16(b[total:total+2], reqType)
	return b
}

func TestTxMgrRequestType(t *testing.T) {
	for _, rt := range []uint16{TMBeginXact, TMCommitXact, TMRollbackXact, TMSaveXact} {
		got, ok := TxMgrRequestType(txMgrBody(rt, 18)) // 18 = a realistic txn-descriptor header size
		if !ok || got != rt {
			t.Errorf("TxMgrRequestType = (%d,%v), want (%d,true)", got, ok, rt)
		}
	}
	// Too short / malformed ALL_HEADERS → not ok (caller treats as ambiguous).
	if _, ok := TxMgrRequestType([]byte{0x01, 0x02}); ok {
		t.Error("short body must return ok=false")
	}
	if _, ok := TxMgrRequestType(nil); ok {
		t.Error("nil body must return ok=false")
	}
}
