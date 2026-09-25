package main

import "testing"

func TestShardForKeyStable(t *testing.T) {
	// same key → same shard, always
	for i := 0; i < 5; i++ {
		if shardForKey("user-42", 4) != shardForKey("user-42", 4) {
			t.Fatal("same partition key must map to the same shard")
		}
	}
	// single shard → always 0
	if shardForKey("anything", 1) != 0 {
		t.Error("single-shard stream must map everything to shard 0")
	}
	// shard index in range
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		s := shardForKey(k, 4)
		if s < 0 || s >= 4 {
			t.Errorf("shardForKey(%q,4)=%d out of range", k, s)
		}
	}
	// distribution: many distinct keys should hit more than one shard
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		seen[shardForKey("key-"+string(rune('A'+i%26))+string(rune('0'+i%10))+itoa(i), 4)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected keys to distribute across shards, only saw %d", len(seen))
	}
}

func TestFormatParseSeqRoundTrip(t *testing.T) {
	for _, seq := range []int64{0, 1, 42, 1000000, 9223372036854775807} {
		s := formatSeq(seq)
		if len(s) != 21 {
			t.Errorf("formatSeq(%d) len=%d, want 21 (%q)", seq, len(s), s)
		}
		got, ok := parseSeq(s)
		if !ok || got != seq {
			t.Errorf("parseSeq(formatSeq(%d)) = (%d,%v)", seq, got, ok)
		}
	}
	// monotonic strings sort in seq order (fixed width)
	if !(formatSeq(9) < formatSeq(10) && formatSeq(10) < formatSeq(100)) {
		t.Error("fixed-width seq strings must sort in numeric order")
	}
	if _, ok := parseSeq(""); ok {
		t.Error("empty seq should not parse")
	}
	if _, ok := parseSeq("notanumber"); ok {
		t.Error("non-numeric seq should not parse")
	}
}

func TestIteratorRoundTrip(t *testing.T) {
	it := shardIterator{Stream: "orders", Shard: shardID(3), NextSeq: 57}
	enc := encodeIterator(it)
	dec, err := decodeIterator(enc)
	if err != nil {
		t.Fatalf("decodeIterator error: %v", err)
	}
	if dec != it {
		t.Errorf("round-trip mismatch: %+v vs %+v", dec, it)
	}
	if _, err := decodeIterator("not-base64!!!"); err == nil {
		t.Error("garbage iterator should error")
	}
}

func TestHashRangeDecimalContiguous(t *testing.T) {
	// shard 0 starts at 0; the last shard ends at 2^128-1; ranges are contiguous.
	lo0, _ := hashRangeDecimal(0, 4)
	if lo0 != "0" {
		t.Errorf("shard 0 start = %q, want 0", lo0)
	}
	_, hiLast := hashRangeDecimal(3, 4)
	if hiLast != "340282366920938463463374607431768211455" {
		t.Errorf("last shard end = %q, want 2^128-1", hiLast)
	}
	// contiguity: shard i's end + 1 == shard i+1's start (checked via string equality of known boundary)
	_, hi0 := hashRangeDecimal(0, 4)
	lo1, _ := hashRangeDecimal(1, 4)
	// 2^128/4 = 85070591730234615865843651857942052864; end of shard0 = that - 1; start of shard1 = that
	if lo1 != "85070591730234615865843651857942052864" || hi0 != "85070591730234615865843651857942052863" {
		t.Errorf("shard0.end=%q shard1.start=%q not contiguous at the quarter boundary", hi0, lo1)
	}
}

func TestShardIDFormat(t *testing.T) {
	if shardID(0) != "shardId-000000000000" {
		t.Errorf("shardID(0) = %q", shardID(0))
	}
	if shardID(12) != "shardId-000000000012" {
		t.Errorf("shardID(12) = %q", shardID(12))
	}
}

func TestVerbForKinesisOp(t *testing.T) {
	for _, op := range []string{"GetRecords", "GetShardIterator", "DescribeStream", "ListStreams", "ListShards"} {
		if v, ok := verbForKinesisOp(op); !ok || v != "get" {
			t.Errorf("%s => (%q,%v) want get", op, v, ok)
		}
	}
	for _, op := range []string{"CreateStream", "PutRecord", "PutRecords"} {
		if v, ok := verbForKinesisOp(op); !ok || v != "create" {
			t.Errorf("%s => (%q,%v) want create", op, v, ok)
		}
	}
	if v, ok := verbForKinesisOp("DeleteStream"); !ok || v != "delete" {
		t.Errorf("DeleteStream => (%q,%v) want delete", v, ok)
	}
	if _, ok := verbForKinesisOp("Nope"); ok {
		t.Error("unknown op should be unknown")
	}
}
