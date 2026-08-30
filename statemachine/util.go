package main

import "encoding/json"

// jsonInto unmarshals a raw JSON message into dst.
func jsonInto(raw json.RawMessage, dst any) error {
	return json.Unmarshal(raw, dst)
}

// toJSONString marshals a value to a compact JSON string (used for status.output and
// the checkpoint context, both of which are string fields on the Execution CRD).
func toJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// maxHistory caps the number of execution-history events kept in status so a long
// or looping execution can't grow the object without bound.
const maxHistory = 200

func trimHistory(h []map[string]any) []map[string]any {
	if len(h) <= maxHistory {
		return h
	}
	return h[len(h)-maxHistory:]
}
