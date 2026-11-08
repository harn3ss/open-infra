package main

import (
	"encoding/base64"
	"fmt"
	"math"
	"time"
)

// shimLogTail is the log tail (X-Amz-Log-Result) of an invocation whose runtime gave none: a function on
// its own image, where the shim cannot see what the function printed. It holds the lines Lambda writes
// around a function's output (START, END and REPORT, the duration as the shim measured it), so a caller
// asking for the tail gets Lambda's shape rather than nothing. The first-party runtimes answer the
// invocation's own output between those lines (#407).
func shimLogTail(requestID, version string, took time.Duration) string {
	ms := float64(took) / float64(time.Millisecond)
	log := fmt.Sprintf("START RequestId: %s Version: %s\nEND RequestId: %s\nREPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\t\n",
		requestID, version, requestID, requestID, ms, int64(math.Ceil(ms)))
	return base64.StdEncoding.EncodeToString([]byte(log))
}

// validLogTail reports whether a runtime's tail is what Lambda answers: base64 of at most 4 KB.
func validLogTail(tail string) bool {
	if tail == "" || len(tail) > base64.StdEncoding.EncodedLen(4096) {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(tail)
	return err == nil
}
