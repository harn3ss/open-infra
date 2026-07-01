package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// --- MinIO ("S3") bucket browser -------------------------------------------
//
// The console reads the MinIO root credentials from the `minio` secret (the SA
// has a narrow Role granting GET on just that secret) and talks to MinIO's S3
// API in-cluster. The client is built lazily and cached on first success.

var (
	minioMu     sync.Mutex
	minioCached *minio.Client
	minioCreds  string // rootUser\x00rootPassword the cached client was built with
)

func minioClient(cs kubernetes.Interface) (*minio.Client, error) {
	ns := getenv("MINIO_SECRET_NAMESPACE", "minio")
	name := getenv("MINIO_SECRET_NAME", "minio")
	// Always re-read the secret so a MinIO credential rotation self-heals: we rebuild
	// the client whenever the creds change (previously the client was cached forever, so
	// a rotation 502'd the Buckets page until the console was restarted).
	sec, err := cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	user, pass := string(sec.Data["rootUser"]), string(sec.Data["rootPassword"])
	key := user + "\x00" + pass
	minioMu.Lock()
	defer minioMu.Unlock()
	if minioCached != nil && minioCreds == key {
		return minioCached, nil
	}
	cl, err := minio.New(getenv("MINIO_ENDPOINT", "minio.minio.svc.cluster.local:9000"), &minio.Options{
		Creds:  credentials.NewStaticV4(user, pass, ""),
		Secure: getenv("MINIO_SECURE", "") == "true",
	})
	if err != nil {
		return nil, err
	}
	minioCached, minioCreds = cl, key // rebuild only when the creds change
	return cl, nil
}

type bucketResp struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func handleBuckets(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cl, err := minioClient(cs)
		if err != nil {
			logger.Error("minio client", slog.String("error", err.Error()))
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		buckets, err := cl.ListBuckets(ctx)
		if err != nil {
			logger.Error("list buckets", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "could not list buckets")
			return
		}
		out := make([]bucketResp, 0, len(buckets))
		for _, b := range buckets {
			out = append(out, bucketResp{Name: b.Name, CreatedAt: b.CreationDate})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type objectResp struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"lastModified"`
	IsPrefix     bool      `json:"isPrefix"`
}

func handleBucketObjects(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		prefix := r.URL.Query().Get("prefix")
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		out := make([]objectResp, 0, 64)
		for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: false}) {
			if obj.Err != nil {
				logger.Error("list objects", slog.String("error", obj.Err.Error()))
				writeError(w, http.StatusBadGateway, "could not list objects")
				return
			}
			out = append(out, objectResp{
				Key:          obj.Key,
				Size:         obj.Size,
				LastModified: obj.LastModified,
				IsPrefix:     strings.HasSuffix(obj.Key, "/"),
			})
			if len(out) >= 1000 { // cap a single page
				break
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// --- NATS JetStream ("SQS/SNS") stream stats -------------------------------
//
// Reads the NATS monitoring endpoint (/jsz) and flattens JetStream streams with
// live counts. No client library needed — it's a plain HTTP/JSON endpoint.

type streamResp struct {
	Name      string   `json:"name"`
	Account   string   `json:"account"`
	Subjects  []string `json:"subjects"`
	Messages  uint64   `json:"messages"`
	Bytes     uint64   `json:"bytes"`
	Consumers int      `json:"consumers"`
}

func handleQueues(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := getenv("NATS_MONITOR_URL", "http://nats-headless.nats.svc.cluster.local:8222")
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/jsz?streams=true", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("nats jsz", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "messaging unavailable")
			return
		}
		defer resp.Body.Close()

		var jz struct {
			AccountDetails []struct {
				Name         string `json:"name"`
				StreamDetail []struct {
					Name   string `json:"name"`
					Config struct {
						Subjects []string `json:"subjects"`
					} `json:"config"`
					State struct {
						Messages      uint64 `json:"messages"`
						Bytes         uint64 `json:"bytes"`
						ConsumerCount int    `json:"consumer_count"`
					} `json:"state"`
				} `json:"stream_detail"`
			} `json:"account_details"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&jz); err != nil {
			writeError(w, http.StatusBadGateway, "could not parse JetStream status")
			return
		}
		out := make([]streamResp, 0)
		for _, a := range jz.AccountDetails {
			for _, s := range a.StreamDetail {
				out = append(out, streamResp{
					Name:      s.Name,
					Account:   a.Name,
					Subjects:  s.Config.Subjects,
					Messages:  s.State.Messages,
					Bytes:     s.State.Bytes,
					Consumers: s.State.ConsumerCount,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// --- MinIO bucket + object writes -------------------------------------------

func handleCreateBucket(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeError(w, http.StatusBadRequest, "bucket name required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.MakeBucket(ctx, body.Name, minio.MakeBucketOptions{}); err != nil {
			logger.Error("make bucket", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"name": body.Name})
	}
}

func handleDeleteBucket(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.RemoveBucket(ctx, chi.URLParam(r, "bucket")); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleUploadObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		if _, err := cl.PutObject(r.Context(), bucket, key, r.Body, r.ContentLength,
			minio.PutObjectOptions{ContentType: ct}); err != nil {
			logger.Error("put object", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"key": key})
	}
}

func handleDownloadObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		obj, err := cl.GetObject(r.Context(), bucket, key, minio.GetObjectOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		defer obj.Close()
		st, err := obj.Stat()
		if err != nil {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		if st.ContentType != "" {
			w.Header().Set("Content-Type", st.ContentType)
		}
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size, 10))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(key)))
		_, _ = io.Copy(w, obj)
	}
}

func handleDeleteObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Model chat proxy (the "playground") ------------------------------------
//
// Reads the <name>-model secret (OPENAI_BASE_URL + OPENAI_API_KEY) and forwards
// the request to the model's in-cluster OpenAI-compatible endpoint with the key,
// so the browser can chat with a Model without ever seeing the key.

func handleModelChat(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		sec, err := cs.CoreV1().Secrets(ns).Get(r.Context(), name+"-model", metav1.GetOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, "model connection secret not found")
			return
		}
		base := string(sec.Data["OPENAI_BASE_URL"])
		key := string(sec.Data["OPENAI_API_KEY"])
		if base == "" {
			writeError(w, http.StatusBadGateway, "model endpoint unknown")
			return
		}
		// Inject the model tag from the secret so callers needn't know it (the
		// OpenAI API requires a "model" field).
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			payload = map[string]any{}
		}
		if _, ok := payload["model"]; !ok {
			if m := string(sec.Data["MODEL"]); m != "" {
				payload["model"] = m
			}
		}
		buf, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(base, "/")+"/chat/completions", bytes.NewReader(buf))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "bad request")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("model chat", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "model unreachable")
			return
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// openAPIMethods are the OpenAPI/Swagger path-item keys that denote HTTP verbs
// (a path item also carries non-verb keys like "parameters"/"summary").
var openAPIMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true,
}

// functionRoute is one discovered endpoint: a path and the methods it accepts.
type functionRoute struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
}

// handleFunctionRoutes discovers a function's routes by probing it for an
// OpenAPI/Swagger document at well-known locations. If one is found, we return
// its paths and the methods each accepts so the console can offer a route
// dropdown and per-route method filtering. Functions that expose no spec return
// source="none" and the UI falls back to a free-form path + all methods — there
// is no universal way to enumerate an arbitrary HTTP server's routes.
func handleFunctionRoutes(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	specLocations := []string{
		"/openapi.json", "/swagger.json", "/v3/api-docs",
		"/q/openapi.json", "/swagger/v1/swagger.json", "/openapi",
		"/spec.json", // Swagger 2.0 (e.g. httpbin) — parsed the same way (.paths)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		if _, err := cs.CoreV1().Services(ns).Get(r.Context(), name, metav1.GetOptions{}); err != nil {
			writeError(w, http.StatusNotFound, "function service not found")
			return
		}
		base := fmt.Sprintf("http://%s.%s.svc.cluster.local", name, ns)

		var doc struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		foundAt := ""
		for _, loc := range specLocations {
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+loc, nil)
			if err != nil {
				cancel()
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				cancel()
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			cancel()
			if resp.StatusCode != http.StatusOK {
				continue
			}
			doc.Paths = nil
			if err := json.Unmarshal(body, &doc); err == nil && len(doc.Paths) > 0 {
				foundAt = loc
				break
			}
		}

		routes := []functionRoute{}
		for p, ops := range doc.Paths {
			methods := []string{}
			for m := range ops {
				if openAPIMethods[strings.ToLower(m)] {
					methods = append(methods, strings.ToUpper(m))
				}
			}
			if len(methods) > 0 {
				sort.Strings(methods)
				routes = append(routes, functionRoute{Path: p, Methods: methods})
			}
		}
		sort.Slice(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })

		source := "none"
		if foundAt != "" {
			source = "openapi"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"source":   source,
			"specPath": foundAt,
			"routes":   routes,
		})
	}
}

// handleFunctionInvoke proxies a test request from the console to a Knative
// function's cluster-internal Service. The browser can't reach
// <name>.<ns>.svc.cluster.local directly, so the BFF forwards it (and the call
// wakes a scaled-to-zero function). The target host is fixed to the function's
// own Service — only method/path/headers/body are caller-controlled — and we
// verify the Service exists first, so this can't be used to hit arbitrary
// in-cluster endpoints.
func handleFunctionInvoke(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		if _, err := cs.CoreV1().Services(ns).Get(r.Context(), name, metav1.GetOptions{}); err != nil {
			writeError(w, http.StatusNotFound, "function service not found")
			return
		}

		var in struct {
			Method  string            `json:"method"`
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		method := strings.ToUpper(strings.TrimSpace(in.Method))
		if method == "" {
			method = http.MethodGet
		}
		reqPath := in.Path
		if reqPath == "" {
			reqPath = "/"
		} else if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}
		target := fmt.Sprintf("http://%s.%s.svc.cluster.local%s", name, ns, reqPath)

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var body io.Reader
		if in.Body != "" {
			body = strings.NewReader(in.Body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
			return
		}
		for k, v := range in.Headers {
			if k != "" {
				req.Header.Set(k, v)
			}
		}

		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("function invoke", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "function unreachable: "+err.Error())
			return
		}
		defer resp.Body.Close()
		// Cap the captured body so a chatty function can't exhaust memory.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		durMs := time.Since(start).Milliseconds()

		hdrs := map[string]string{}
		for k := range resp.Header {
			hdrs[k] = resp.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     resp.StatusCode,
			"durationMs": durMs,
			"headers":    hdrs,
			"body":       string(respBody),
		})
	}
}
