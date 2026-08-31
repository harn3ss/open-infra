// featurestore — open-infra's kind: FeatureGroup online store (SageMaker Feature
// Store). A small HTTP service backed by Valkey that serves the two feature-store
// operations for real-time inference:
//
//	PUT record:  POST /records            body = a JSON feature record (must contain the
//	                                       record identifier); upserts the latest values.
//	GET record:  GET  /records/{id}       returns the latest features for a record id.
//	Health:      GET  /healthz
//
// Values are stored as JSON so their types (numbers, booleans, strings) survive a
// round-trip. One service + one Valkey run per FeatureGroup (emitted by the composition).
//
// Env: FEATURE_GROUP, RECORD_IDENTIFIER, EVENT_TIME, VALKEY_ADDR, TTL_SECONDS, PORT.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type server struct {
	group     string
	recordID  string
	eventTime string
	ttl       int
	redis     *redisClient
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	s := &server{
		group:     env("FEATURE_GROUP", "default"),
		recordID:  env("RECORD_IDENTIFIER", "id"),
		eventTime: env("EVENT_TIME", ""),
		redis:     newRedis(env("VALKEY_ADDR", "localhost:6379")),
	}
	if v := os.Getenv("TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			s.ttl = n
		}
	}
	port := env("PORT", "8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/records", s.putRecord)  // POST
	mux.HandleFunc("/records/", s.getRecord) // GET /records/{id}
	log.Printf("featurestore %s: record-id=%q valkey=%s serving on :%s", s.group, s.recordID, os.Getenv("VALKEY_ADDR"), port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func (s *server) key(id string) string { return "fg:" + s.group + ":" + id }

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	if err := s.redis.ping(); err != nil {
		http.Error(w, "valkey down: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *server) putRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var rec map[string]any
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "body is not a JSON object: "+err.Error(), http.StatusBadRequest)
		return
	}
	idv, ok := rec[s.recordID]
	if !ok {
		http.Error(w, "record is missing the record identifier field "+s.recordID, http.StatusBadRequest)
		return
	}
	id := toStr(idv)
	// Store each field as its JSON encoding so types survive the round-trip.
	fields := make(map[string]string, len(rec))
	for k, v := range rec {
		b, _ := json.Marshal(v)
		fields[k] = string(b)
	}
	if err := s.redis.hset(s.key(id), fields); err != nil {
		http.Error(w, "store failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if s.ttl > 0 {
		_ = s.redis.expire(s.key(id), s.ttl)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordId": id, "features": len(fields)})
}

func (s *server) getRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/records/")
	if id == "" {
		http.Error(w, "missing record id", http.StatusBadRequest)
		return
	}
	stored, err := s.redis.hgetall(s.key(id))
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if len(stored) == 0 {
		http.Error(w, "no such record", http.StatusNotFound)
		return
	}
	// Decode each field back to its typed value.
	out := make(map[string]any, len(stored))
	for k, v := range stored {
		var val any
		if json.Unmarshal([]byte(v), &val) == nil {
			out[k] = val
		} else {
			out[k] = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(v)
		return strings.Trim(string(b), `"`)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
